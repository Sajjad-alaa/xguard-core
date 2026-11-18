//! XGuard device posture checks.
//!
//! Admins attach posture policies to locations ([`policy`]). When a desktop client connects to
//! such a location it reports posture facts about its device ([`facts`]); core evaluates them
//! ([`evaluate`]) and refuses the connection with the failed checks when the device does not
//! comply.
//!
//! - Evaluation happens when the client starts MFA (fail fast, before the user is asked for a
//!   code), again when the session is authorized at the end of MFA (against the stored snapshot
//!   and the policies as they are then), and on the posture-only connect path for locations
//!   without MFA.
//! - The last snapshot of each device is stored for admins ([`PostureSnapshot`]).
//! - When policies or assignments change, [`worker`] re-evaluates active sessions of the
//!   affected locations against the stored snapshots and disconnects devices that no longer
//!   comply.
//!
//! Posture facts are an attestation by the client, not proof. A modified client can report
//! anything; posture checks keep honest-but-misconfigured devices out, they do not stop an
//! attacker who controls the device.

pub mod evaluate;
pub mod facts;
pub mod policy;
pub mod version;
pub mod worker;

#[cfg(test)]
mod tests;

use chrono::{TimeDelta, Utc};
use sqlx::PgConnection;
use xguard_common::db::{
    Id,
    models::device_posture::{DevicePosture, PostureSnapshot},
};
use xguard_proto::client_types::DevicePostureFacts;

pub use self::{
    evaluate::{PostureResult, evaluate},
    facts::PostureFacts,
};

/// A snapshot older than this is not accepted when an MFA login completes; the client has to
/// start again and report fresh facts. Covers the longest MFA session.
pub const SNAPSHOT_MAX_AGE: TimeDelta = TimeDelta::minutes(15);

/// The outcome of a connection-time posture check.
#[derive(Debug)]
pub struct PostureCheck {
    pub result: PostureResult,
    /// The validated facts, `None` when the client sent none.
    pub facts: Option<PostureFacts>,
}

/// Evaluates the posture of `device_id` for `location_id` and stores the snapshot.
///
/// Returns `None` when the location has no posture policies (nothing is stored then).
pub async fn check_connection(
    conn: &mut PgConnection,
    location_id: Id,
    device_id: Id,
    reported: Option<&DevicePostureFacts>,
) -> sqlx::Result<Option<PostureCheck>> {
    let policies = DevicePosture::find_for_location(&mut *conn, location_id).await?;
    if policies.is_empty() {
        return Ok(None);
    }
    let facts = reported.map(PostureFacts::from_proto);
    let now = Utc::now();
    let result = evaluate(&policies, facts.as_ref(), now.date_naive());
    PostureSnapshot {
        device_id,
        facts: facts.clone().unwrap_or_default().to_json(),
        reported_at: now.naive_utc(),
        location_id: Some(location_id),
        compliant: result.is_pass(),
        failed_checks: result.failures().to_vec(),
    }
    .upsert(&mut *conn)
    .await?;
    Ok(Some(PostureCheck { result, facts }))
}

/// Checks the stored snapshot of a device right before a session is authorized.
///
/// Passes when the location has no posture policies. Otherwise the snapshot must be recent and
/// comply with the policies as they are now.
pub async fn check_stored_snapshot(
    conn: &mut PgConnection,
    location_id: Id,
    device_id: Id,
) -> sqlx::Result<PostureResult> {
    let policies = DevicePosture::find_for_location(&mut *conn, location_id).await?;
    if policies.is_empty() {
        return Ok(PostureResult::Pass);
    }
    let now = Utc::now();
    let Some(snapshot) = PostureSnapshot::find(&mut *conn, device_id).await? else {
        return Ok(PostureResult::Fail(vec![
            "no device posture was reported; connect again".into(),
        ]));
    };
    if now.naive_utc() - snapshot.reported_at > SNAPSHOT_MAX_AGE {
        return Ok(PostureResult::Fail(vec![
            "the device posture report is too old; connect again".into(),
        ]));
    }
    let facts = PostureFacts::from_json(&snapshot.facts);
    let result = evaluate(&policies, facts.as_ref(), now.date_naive());
    if result.is_pass() != snapshot.compliant {
        PostureSnapshot::set_result(&mut *conn, device_id, result.is_pass(), result.failures())
            .await?;
    }
    Ok(result)
}
