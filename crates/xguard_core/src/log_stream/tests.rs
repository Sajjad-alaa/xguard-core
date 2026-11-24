use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, extract::State, http::HeaderMap, routing::post};
use bytes::Bytes;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, IsCa, KeyPair};
use rustls::{
    RootCertStore, ServerConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, UdpSocket},
    sync::broadcast,
};
use tokio_rustls::TlsAcceptor;
use xguard_common::db::setup_pool;

use super::{
    ActivityLogStream, BodyFormat, HeaderInput, MAX_STREAMS, SplunkOptions, StoredConfig,
    StreamError, StreamInput, StreamType, SyslogFormat, SyslogFraming, SyslogOptions,
    output::Output,
    syslog::{format_entry, frame_tcp},
};

fn input(url: &str) -> StreamInput {
    StreamInput {
        name: "siem".into(),
        stream_type: StreamType::VectorHttp,
        url: url.into(),
        username: None,
        password: None,
        cert: None,
        tls_verify: None,
        client_cert: None,
        client_key: None,
        body_format: None,
        headers: None,
        syslog: None,
        splunk: None,
        token: None,
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
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
        "http://[fe80::1]/ingest",
        "http://[::ffff:169.254.169.254]/ingest",
        "http://0.0.0.0:8080/ingest",
        "http://metadata.google.internal/computeMetadata/v1/",
    ] {
        assert!(input(bad).into_config(None).is_err(), "{bad}");
    }
    for bad_syslog in [
        "udp://169.254.169.254:514",
        "tcp://0.0.0.0:514",
        "tls://[fe80::1]:6514",
        "udp://metadata.google.internal:514",
    ] {
        assert!(
            StreamInput {
                stream_type: StreamType::Syslog,
                ..input(bad_syslog)
            }
            .into_config(None)
            .is_err(),
            "{bad_syslog}"
        );
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

    let stored = StoredConfig {
        url: "https://logs.example.org/".into(),
        username: Some("vector".into()),
        password: Some("stored".into()),
        ..StoredConfig::default()
    };
    let (_, _, kept) = StreamInput {
        username: Some("vector".into()),
        ..input("https://logs.example.org")
    }
    .into_config(Some(stored.clone()))
    .unwrap();
    assert_eq!(kept.password.as_deref(), Some("stored"));

    // Changing the destination origin refuses to carry stored secrets over.
    assert!(
        StreamInput {
            username: Some("vector".into()),
            ..input("https://other.example.org")
        }
        .into_config(Some(stored.clone()))
        .is_err()
    );

    let (_, _, cleared) = StreamInput {
        username: Some("vector".into()),
        password: Some(String::new()),
        ..input("https://logs.example.org")
    }
    .into_config(Some(stored))
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

    // Syslog URL validation and default ports.
    let (_, _, udp) = StreamInput {
        stream_type: StreamType::Syslog,
        ..input("udp://siem.example.org")
    }
    .into_config(None)
    .unwrap();
    assert_eq!(udp.url, "udp://siem.example.org:514");

    let (_, _, tls) = StreamInput {
        stream_type: StreamType::Syslog,
        ..input("tls://siem.example.org")
    }
    .into_config(None)
    .unwrap();
    assert_eq!(tls.url, "tls://siem.example.org:6514");

    assert!(
        StreamInput {
            stream_type: StreamType::Syslog,
            ..input("https://siem.example.org")
        }
        .into_config(None)
        .is_err()
    );

    // Splunk HEC requires token and defaults path to /services/collector/event.
    assert!(
        StreamInput {
            stream_type: StreamType::SplunkHec,
            ..input("https://splunk.example.org:8088")
        }
        .into_config(None)
        .is_err()
    );
    let (_, _, splunk) = StreamInput {
        stream_type: StreamType::SplunkHec,
        token: Some("hec-token-123".into()),
        ..input("https://splunk.example.org:8088")
    }
    .into_config(None)
    .unwrap();
    assert_eq!(
        splunk.url,
        "https://splunk.example.org:8088/services/collector/event"
    );

    // Generic HTTP custom headers reject reserved headers and plaintext non-loopback secrets.
    assert!(
        StreamInput {
            stream_type: StreamType::Http,
            headers: Some(vec![HeaderInput {
                name: "Host".into(),
                value: Some("evil.example".into()),
            }]),
            ..input("https://hooks.example.org/events")
        }
        .into_config(None)
        .is_err()
    );
    assert!(
        StreamInput {
            stream_type: StreamType::Http,
            headers: Some(vec![HeaderInput {
                name: "Authorization".into(),
                value: Some("Bearer tok".into()),
            }]),
            ..input("http://hooks.example.org/events")
        }
        .into_config(None)
        .is_err()
    );
}

#[test]
fn syslog_formatting_and_framing() {
    let entry = br#"{"timestamp":"2026-11-24T00:00:00Z","event":"user_login","username":"alice","ip":"192.0.2.10"}"#;
    let opts = SyslogOptions {
        format: SyslogFormat::Rfc5424,
        framing: SyslogFraming::OctetCounting,
        facility: 16,
        app_name: Some("xguard".into()),
        hostname: Some("core01".into()),
    };
    let msg = format_entry(entry, &opts);
    let text = String::from_utf8(msg.clone()).unwrap();
    assert!(text.starts_with("<134>1 2026-11-24T00:00:00.000Z core01 xguard - user_login "));
    assert!(text.contains(r#"[xguard@55555 event="user_login" user="alice" ip="192.0.2.10"]"#));
    assert!(text.ends_with(std::str::from_utf8(entry).unwrap()));

    let framed = frame_tcp(&msg, SyslogFraming::OctetCounting);
    assert!(framed.starts_with(format!("{} <134>1 ", msg.len()).as_bytes()));

    let nl_framed = frame_tcp(&msg, SyslogFraming::Newline);
    assert!(nl_framed.ends_with(b"\n"));

    let bsd = format_entry(
        entry,
        &SyslogOptions {
            format: SyslogFormat::Rfc3164,
            ..opts
        },
    );
    let bsd_text = String::from_utf8(bsd).unwrap();
    assert!(bsd_text.starts_with("<134>Nov 24 00:00:00 core01 xguard: "));
}

#[tokio::test]
async fn syslog_udp_tcp_and_tls_delivery() {
    let entry = Bytes::from_static(
        b"{\"timestamp\":\"2026-11-24T00:00:00Z\",\"event\":\"vpn_connect\",\"username\":\"bob\"}\n",
    );

    // 1. UDP syslog listener
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp_sock.local_addr().unwrap();
    let mut udp_out = Output::from_target(
        StreamType::Syslog,
        StoredConfig {
            url: format!("udp://{udp_addr}"),
            syslog: Some(SyslogOptions {
                hostname: Some("xguard-test".into()),
                ..SyslogOptions::default()
            }),
            ..StoredConfig::default()
        },
    )
    .unwrap();
    udp_out
        .send_batch(std::slice::from_ref(&entry))
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = udp_sock.recv_from(&mut buf).await.unwrap();
    let received = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(received.starts_with("<134>1 "));
    assert!(received.contains("vpn_connect"));

    // 2. TCP syslog listener (RFC 6587 octet counting)
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let tcp_task = tokio::spawn(async move {
        let (mut sock, _) = tcp_listener.accept().await.unwrap();
        let mut data = Vec::new();
        let _ = sock.read_to_end(&mut data).await;
        data
    });
    {
        let mut tcp_out = Output::from_target(
            StreamType::Syslog,
            StoredConfig {
                url: format!("tcp://{tcp_addr}"),
                syslog: Some(SyslogOptions {
                    framing: SyslogFraming::OctetCounting,
                    hostname: Some("xguard-test".into()),
                    ..SyslogOptions::default()
                }),
                ..StoredConfig::default()
            },
        )
        .unwrap();
        tcp_out
            .send_batch(std::slice::from_ref(&entry))
            .await
            .unwrap();
    }
    let tcp_data = tcp_task.await.unwrap();
    let tcp_text = String::from_utf8(tcp_data).unwrap();
    let (len_str, rest) = tcp_text.split_once(' ').unwrap();
    assert_eq!(len_str.parse::<usize>().unwrap(), rest.len());
    assert!(rest.starts_with("<134>1 "));

    // 3. TLS syslog listener with CA verification + mTLS client cert
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    let server_params =
        CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()]).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let client_params = CertificateParams::new(vec!["xguard-client".to_owned()]).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_cert.pem().as_bytes()).unwrap())
        .unwrap();
    let client_verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(ring::default_provider()),
    )
    .build()
    .unwrap();
    let server_tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(server_cert.pem().as_bytes()).unwrap()],
            PrivateKeyDer::from_pem_slice(server_key.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_addr = tls_listener.local_addr().unwrap();
    let tls_task = tokio::spawn(async move {
        let (tcp, _) = tls_listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut data = Vec::new();
        let _ = tls.read_to_end(&mut data).await;
        data
    });
    {
        let mut tls_out = Output::from_target(
            StreamType::Syslog,
            StoredConfig {
                url: format!("tls://127.0.0.1:{}", tls_addr.port()),
                cert: Some(ca_cert.pem()),
                tls_verify: true,
                client_cert: Some(client_cert.pem()),
                client_key: Some(client_key.serialize_pem()),
                syslog: Some(SyslogOptions {
                    hostname: Some("xguard-tls".into()),
                    ..SyslogOptions::default()
                }),
                ..StoredConfig::default()
            },
        )
        .unwrap();
        tls_out.send_batch(&[entry]).await.unwrap();
    }
    let tls_data = tls_task.await.unwrap();
    let tls_text = String::from_utf8(tls_data).unwrap();
    let (len_str, rest) = tls_text.split_once(' ').unwrap();
    assert_eq!(len_str.parse::<usize>().unwrap(), rest.len());
    assert!(rest.contains("xguard-tls"));
}

#[tokio::test]
async fn http_json_and_splunk_hec_delivery() {
    type CapturedRequest = (String, Option<String>, Option<String>, String);

    #[derive(Clone, Default)]
    struct Capture {
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
    }

    async fn handle(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: String,
    ) -> axum::http::StatusCode {
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let custom = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        capture
            .requests
            .lock()
            .unwrap()
            .push((ct, auth, custom, body));
        axum::http::StatusCode::OK
    }

    let capture = Capture::default();
    let app = Router::new()
        .route("/hook", post(handle))
        .route("/services/collector/event", post(handle))
        .with_state(capture.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let lines = vec![
        Bytes::from_static(b"{\"timestamp\":\"2026-11-24T00:00:00Z\",\"event\":\"a\"}\n"),
        Bytes::from_static(b"{\"timestamp\":\"2026-11-24T00:00:01Z\",\"event\":\"b\"}\n"),
    ];

    // Generic HTTP JSON array + custom header
    let mut http_arr = Output::from_target(
        StreamType::Http,
        StoredConfig {
            url: format!("http://{addr}/hook"),
            body_format: BodyFormat::JsonArray,
            headers: vec![super::StoredHeader {
                name: "X-Api-Key".into(),
                value: "secret-key".into(),
            }],
            ..StoredConfig::default()
        },
    )
    .unwrap();
    http_arr.send_batch(&lines).await.unwrap();

    // Generic HTTP one-per-request JSON
    let mut http_one = Output::from_target(
        StreamType::Http,
        StoredConfig {
            url: format!("http://{addr}/hook"),
            body_format: BodyFormat::Json,
            ..StoredConfig::default()
        },
    )
    .unwrap();
    http_one.send_batch(&lines).await.unwrap();

    // Splunk HEC
    let mut splunk = Output::from_target(
        StreamType::SplunkHec,
        StoredConfig {
            url: format!("http://{addr}/services/collector/event"),
            token: Some("hec-secret".into()),
            splunk: Some(SplunkOptions {
                sourcetype: Some("xguard:audit".into()),
                source: Some("core".into()),
                index: Some("security".into()),
            }),
            ..StoredConfig::default()
        },
    )
    .unwrap();
    splunk.send_batch(&lines).await.unwrap();

    let reqs = capture.requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 4);

    // 0: JSON array
    assert_eq!(reqs[0].0, "application/json");
    assert_eq!(reqs[0].2.as_deref(), Some("secret-key"));
    let parsed_arr: serde_json::Value = serde_json::from_str(&reqs[0].3).unwrap();
    assert_eq!(parsed_arr.as_array().unwrap().len(), 2);

    // 1 & 2: single JSON objects
    assert_eq!(reqs[1].0, "application/json");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reqs[1].3).unwrap()["event"],
        "a"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reqs[2].3).unwrap()["event"],
        "b"
    );

    // 3: Splunk HEC batch
    assert_eq!(reqs[3].0, "application/json");
    assert_eq!(reqs[3].1.as_deref(), Some("Splunk hec-secret"));
    let splunk_lines: Vec<serde_json::Value> = reqs[3]
        .3
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(splunk_lines.len(), 2);
    assert_eq!(splunk_lines[0]["sourcetype"], "xguard:audit");
    assert_eq!(splunk_lines[0]["source"], "core");
    assert_eq!(splunk_lines[0]["index"], "security");
    assert_eq!(splunk_lines[0]["event"]["event"], "a");
    assert!(splunk_lines[0]["time"].as_f64().unwrap() > 1_700_000_000.0);
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
