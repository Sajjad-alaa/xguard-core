use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use xguard_common::db::setup_pool;

use super::{ActivityLogStream, MAX_STREAMS, StreamError, StreamInput, StreamType};

fn input(url: &str) -> StreamInput {
    StreamInput {
        name: "siem".into(),
        stream_type: StreamType::VectorHttp,
        url: url.into(),
        username: None,
        password: None,
        cert: None,
    }
}

#[test]
fn validation() {
    assert!(
        input("https://logs.example.org:8080/xguard")
            .into_config(None)
            .is_ok()
    );
    assert!(input("http://logs.example.org").into_config(None).is_ok());
    for bad in [
        "ftp://logs.example.org",
        "not a url",
        "https://user:pass@logs.example.org",
    ] {
        assert!(input(bad).into_config(None).is_err(), "{bad}");
    }
    // Credentials only over HTTPS, or to this machine.
    let with_credentials = |url: &str| StreamInput {
        username: Some("vector".into()),
        password: Some("secret".into()),
        ..input(url)
    };
    assert!(
        with_credentials("http://logs.example.org")
            .into_config(None)
            .is_err()
    );
    assert!(
        with_credentials("http://127.0.0.1:9000")
            .into_config(None)
            .is_ok()
    );
    assert!(
        with_credentials("https://logs.example.org")
            .into_config(None)
            .is_ok()
    );
    // A password needs a username; an empty one removes the stored password.
    let orphan = StreamInput {
        password: Some("secret".into()),
        ..input("https://logs.example.org")
    };
    assert!(orphan.into_config(None).is_err());
    let (_, _, kept) = StreamInput {
        username: Some("vector".into()),
        ..input("https://logs.example.org")
    }
    .into_config(Some("stored".into()))
    .unwrap();
    assert_eq!(kept.password.as_deref(), Some("stored"));
    let (_, _, cleared) = StreamInput {
        username: Some("vector".into()),
        password: Some(String::new()),
        ..input("https://logs.example.org")
    }
    .into_config(Some("stored".into()))
    .unwrap();
    assert_eq!(cleared.password, None);
    // Names and certificates are checked.
    let mut bad_name = input("https://logs.example.org");
    bad_name.name = "<b>siem</b>".into();
    assert!(bad_name.into_config(None).is_err());
    let bad_cert = StreamInput {
        cert: Some("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----".into()),
        ..input("https://logs.example.org")
    };
    assert!(bad_cert.into_config(None).is_err());
}

#[sqlx::test]
async fn test_crud_and_limit(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let mut conn = pool.acquire().await.unwrap();
    let created = ActivityLogStream::create(
        &mut conn,
        StreamInput {
            username: Some("vector".into()),
            password: Some("secret".into()),
            ..input("https://logs.example.org")
        },
    )
    .await
    .unwrap();
    assert!(created.password_set);
    let json = serde_json::to_string(&created).unwrap();
    assert!(!json.contains("secret"));

    // Updating without a password keeps it.
    let updated = ActivityLogStream::update(
        &mut conn,
        created.id,
        StreamInput {
            name: "siem-2".into(),
            username: Some("vector".into()),
            ..input("https://logs.example.org")
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.name, "siem-2");
    assert!(updated.password_set);
    let targets = ActivityLogStream::targets(&pool).await.unwrap();
    assert_eq!(targets[0].config.password.as_deref(), Some("secret"));

    for i in 1..MAX_STREAMS {
        let mut extra = input("https://logs.example.org");
        extra.name = format!("s{i}");
        ActivityLogStream::create(&mut conn, extra).await.unwrap();
    }
    assert!(matches!(
        ActivityLogStream::create(&mut conn, input("https://logs.example.org")).await,
        Err(StreamError::TooMany)
    ));

    ActivityLogStream::delete(&pool, created.id).await.unwrap();
    assert!(matches!(
        ActivityLogStream::delete(&pool, created.id).await,
        Err(StreamError::NotFound)
    ));
}

/// A collector that refuses the first request, then records what it receives.
#[sqlx::test]
async fn test_delivery_with_retry(_: PgPoolOptions, options: PgConnectOptions) {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{Router, extract::State, http::HeaderMap, routing::post};
    use bytes::Bytes;
    use tokio::{net::TcpListener, sync::broadcast};

    #[derive(Clone, Default)]
    struct Collector {
        calls: Arc<AtomicUsize>,
        bodies: Arc<Mutex<Vec<String>>>,
        auth: Arc<Mutex<Vec<String>>>,
    }

    async fn receive(
        State(collector): State<Collector>,
        headers: HeaderMap,
        body: String,
    ) -> axum::http::StatusCode {
        if collector.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE;
        }
        collector.auth.lock().unwrap().push(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
        collector.bodies.lock().unwrap().push(body);
        axum::http::StatusCode::OK
    }

    let collector = Collector::default();
    let app = Router::new()
        .route("/ingest", post(receive))
        .with_state(collector.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let pool = setup_pool(options).await;
    let mut conn = pool.acquire().await.unwrap();
    let stream = ActivityLogStream::create(
        &mut conn,
        StreamInput {
            username: Some("vector".into()),
            password: Some("secret".into()),
            ..input(&format!("http://{address}/ingest"))
        },
    )
    .await
    .unwrap();

    let (messages, _keep) = broadcast::channel::<Bytes>(16);
    let sender_task = tokio::spawn(super::sender::run(pool.clone(), messages.clone()));
    // Give the worker time to subscribe.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    messages
        .send(Bytes::from_static(
            b"{\"event\":\"user_login\"}\n{\"event\":\"user_logout\"}\n",
        ))
        .unwrap();

    // The first attempt fails; the retry a second later delivers both entries once.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while collector.bodies.lock().unwrap().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "nothing was delivered"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    sender_task.abort();
    let bodies = collector.bodies.lock().unwrap().clone();
    assert_eq!(
        bodies,
        ["{\"event\":\"user_login\"}\n{\"event\":\"user_logout\"}\n"]
    );
    assert!(collector.calls.load(Ordering::SeqCst) >= 2);
    // Basic auth: base64("vector:secret").
    assert_eq!(
        collector.auth.lock().unwrap()[0],
        "Basic dmVjdG9yOnNlY3JldA=="
    );
    let status = super::sender::status(stream.id);
    assert!(status.last_delivery.is_some());
    assert!(status.last_error.is_some());
    assert_eq!(status.pending_bytes, 0);
}
