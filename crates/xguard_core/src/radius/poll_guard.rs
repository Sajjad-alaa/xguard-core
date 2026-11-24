//! Minimum gap between RADIUS push polls.
//!
//! A push poll re-sends an Access-Request with the pending State and no password. Polls are not
//! charged against the MFA attempt limits (approving on a phone can take a while), so without a
//! gap a session that passed the password step could make Core send RADIUS requests as fast as it
//! can submit them. Polls that come too soon are answered "still waiting" without contacting the
//! RADIUS server.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

/// Polls closer together than this are not forwarded to the RADIUS server.
pub(crate) const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Entries older than this are dropped; a push challenge expires long before.
const ENTRY_TTL: Duration = Duration::from_secs(600);
/// Upper bound on tracked sessions, so the map cannot grow without limit.
const MAX_ENTRIES: usize = 10_000;

static LAST_POLL: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Returns `true` when a poll for `key` may be forwarded now, and records it.
pub(crate) fn allow_poll(key: &str) -> bool {
    allow_poll_at(key, Instant::now())
}

fn allow_poll_at(key: &str, now: Instant) -> bool {
    let Ok(mut last) = LAST_POLL.lock() else {
        // A poisoned lock must not block MFA: fall back to forwarding the poll.
        return true;
    };
    if let Some(previous) = last.get(key)
        && now.saturating_duration_since(*previous) < MIN_POLL_INTERVAL
    {
        return false;
    }
    if last.len() >= MAX_ENTRIES {
        last.retain(|_, seen| now.saturating_duration_since(*seen) < ENTRY_TTL);
        if last.len() >= MAX_ENTRIES {
            last.clear();
        }
    }
    last.insert(key.to_owned(), now);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polls_closer_than_the_minimum_gap_are_held_back() {
        let start = Instant::now();
        let key = "test:poll-gap";
        assert!(allow_poll_at(key, start));
        assert!(!allow_poll_at(key, start + Duration::from_millis(200)));
        assert!(!allow_poll_at(key, start + Duration::from_millis(999)));
        assert!(allow_poll_at(key, start + MIN_POLL_INTERVAL));
        // Other sessions are independent.
        assert!(allow_poll_at(
            "test:other-session",
            start + Duration::from_millis(100)
        ));
    }
}
