use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use secrecy::SecretString;
use tokio::net::UdpSocket;

use super::client::{
    Attribute, RadiusClientConfig, RadiusError, RadiusOutcome, RadiusServerConfig, attr,
    authenticate, build_response, code, decrypt_password, verify_request,
};

async fn spawn_mock_radius<F>(handler: F) -> SocketAddr
where
    F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            if let Some(reply) = handler(&buf[..len]) {
                let _ = socket.send_to(&reply, peer).await;
            }
        }
    });
    addr
}

fn config_for(
    primary: SocketAddr,
    secondary: Option<SocketAddr>,
    secret: &str,
) -> RadiusClientConfig {
    RadiusClientConfig {
        primary: RadiusServerConfig {
            host: primary.ip().to_string(),
            port: primary.port(),
            secret: SecretString::from(secret.to_owned()),
        },
        secondary: secondary.map(|addr| RadiusServerConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            secret: SecretString::from(secret.to_owned()),
        }),
        timeout: Duration::from_millis(250),
        retries: 2,
        nas_identifier: "xguard-test".to_owned(),
        nas_ip_address: Some("127.0.0.1".parse().unwrap()),
    }
}

#[tokio::test]
async fn mock_radius_accept_reject_and_challenge_flow() {
    let secret = b"test-secret-123";
    let addr = spawn_mock_radius(move |raw| {
        let req =
            verify_request(raw, secret).expect("request must carry valid Message-Authenticator");
        let user = req
            .attributes
            .iter()
            .find(|a| a.kind == attr::USER_NAME)
            .map(|a| String::from_utf8_lossy(&a.value).to_string())
            .unwrap();
        let hidden = req
            .attributes
            .iter()
            .find(|a| a.kind == attr::USER_PASSWORD)
            .map(|a| a.value.as_slice())
            .unwrap();
        let pass = decrypt_password(hidden, secret, &req.authenticator).unwrap();
        let state = req
            .attributes
            .iter()
            .find(|a| a.kind == attr::STATE)
            .map(|a| a.value.as_slice());

        let (resp_code, attrs) = match (user.as_str(), pass.as_slice(), state) {
            ("alice", b"123456", None) => (
                code::ACCESS_ACCEPT,
                vec![Attribute {
                    kind: attr::REPLY_MESSAGE,
                    value: b"Welcome\x07!".to_vec(),
                }],
            ),
            ("bob", b"", None) => (
                code::ACCESS_CHALLENGE,
                vec![
                    Attribute {
                        kind: attr::REPLY_MESSAGE,
                        value: b"Enter SMS code".to_vec(),
                    },
                    Attribute {
                        kind: attr::STATE,
                        value: b"challenge-state-1".to_vec(),
                    },
                ],
            ),
            ("bob", b"999888", Some(b"challenge-state-1")) => (code::ACCESS_ACCEPT, vec![]),
            _ => (
                code::ACCESS_REJECT,
                vec![Attribute {
                    kind: attr::REPLY_MESSAGE,
                    value: b"Bad OTP".to_vec(),
                }],
            ),
        };
        Some(
            build_response(
                resp_code,
                req.identifier,
                &req.authenticator,
                secret,
                attrs,
                true,
            )
            .unwrap(),
        )
    })
    .await;

    let cfg = config_for(addr, None, "test-secret-123");

    // Accept (also verifies control char stripping in Reply-Message).
    let ok = authenticate(&cfg, "alice", "123456", None).await.unwrap();
    assert_eq!(
        ok,
        RadiusOutcome::Accept {
            reply_message: Some("Welcome!".to_owned())
        }
    );

    // Reject.
    let rej = authenticate(&cfg, "alice", "000000", None).await.unwrap();
    assert_eq!(
        rej,
        RadiusOutcome::Reject {
            reply_message: Some("Bad OTP".to_owned())
        }
    );

    // Access-Challenge -> Access-Accept with State.
    let chal = authenticate(&cfg, "bob", "", None).await.unwrap();
    let state = match chal {
        RadiusOutcome::Challenge {
            reply_message,
            state,
        } => {
            assert_eq!(reply_message.as_deref(), Some("Enter SMS code"));
            assert_eq!(state, b"challenge-state-1");
            state
        }
        other => panic!("expected challenge, got {other:?}"),
    };
    let accepted = authenticate(&cfg, "bob", "999888", Some(&state))
        .await
        .unwrap();
    assert_eq!(
        accepted,
        RadiusOutcome::Accept {
            reply_message: None
        }
    );
}

#[tokio::test]
async fn mock_radius_drops_unsigned_forged_response_and_fails_over() {
    let secret = b"failover-secret";
    // Primary returns an unsigned Access-Accept (BlastRADIUS forgery attempt).
    let primary = spawn_mock_radius(move |raw| {
        let req = verify_request(raw, secret).unwrap();
        Some(
            build_response(
                code::ACCESS_ACCEPT,
                req.identifier,
                &req.authenticator,
                secret,
                vec![],
                false,
            )
            .unwrap(),
        )
    })
    .await;

    let secondary_hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&secondary_hits);
    let secondary = spawn_mock_radius(move |raw| {
        hits_clone.fetch_add(1, Ordering::SeqCst);
        let req = verify_request(raw, secret).unwrap();
        Some(
            build_response(
                code::ACCESS_ACCEPT,
                req.identifier,
                &req.authenticator,
                secret,
                vec![Attribute {
                    kind: attr::REPLY_MESSAGE,
                    value: b"From secondary".to_vec(),
                }],
                true,
            )
            .unwrap(),
        )
    })
    .await;

    // Without secondary, primary's unsigned response must time out rather than accept.
    let no_failover = config_for(primary, None, "failover-secret");
    assert!(matches!(
        authenticate(&no_failover, "alice", "123456", None).await,
        Err(RadiusError::Timeout)
    ));

    // With secondary, failover succeeds.
    let with_failover = config_for(primary, Some(secondary), "failover-secret");
    let outcome = authenticate(&with_failover, "alice", "123456", None)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        RadiusOutcome::Accept {
            reply_message: Some("From secondary".to_owned())
        }
    );
    assert_eq!(secondary_hits.load(Ordering::SeqCst), 1);
}
