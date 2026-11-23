//! Client download links: defaults, who may read and change them, validation, the audit event
//! and the broadcast to the Edges.

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::{sync::mpsc, time::timeout};
use xguard_common::{
    db::models::client_downloads::{
        ClientDownloadSettings, DEFAULT_CLIENT_DOWNLOAD_BASE_URL, DEFAULT_CLIENT_RELEASES_URL,
    },
    types::proxy::ProxyControlMessage,
};
use xguard_core::events::ApiEventType;

use super::common::{authenticate_admin, client::TestClient, make_test_client, setup_pool};

const PATH: &str = "/api/v1/client_downloads";

async fn get(client: &TestClient) -> Value {
    let response = client.get(PATH).send().await;
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await
}

async fn put(client: &TestClient, body: &Value) -> (StatusCode, Value) {
    let response = client.put(PATH).json(body).send().await;
    let status = response.status();
    // Rejected JSON bodies are answered in plain text.
    let text = response.text().await;
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn mirror() -> Value {
    json!({
        "base_url": " https://Mirror.Example.lan/xguard/ ",
        "releases_url": "https://mirror.example.lan/xguard/",
        "android_url": "https://mirror.example.lan/xguard/xguard.apk",
        "ios_url": "",
        "macos_installer": true,
        "allow_http": false,
    })
}

fn mirror_saved() -> ClientDownloadSettings {
    ClientDownloadSettings {
        base_url: "https://mirror.example.lan/xguard".into(),
        releases_url: "https://mirror.example.lan/xguard/".into(),
        android_url: Some("https://mirror.example.lan/xguard/xguard.apk".into()),
        ios_url: None,
        macos_installer: true,
        allow_http: false,
    }
}

async fn next_client_downloads(
    rx: &mut mpsc::Receiver<ProxyControlMessage>,
) -> ClientDownloadSettings {
    timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Some(ProxyControlMessage::BroadcastPublicSettings {
                    client_downloads, ..
                }) => return client_downloads,
                Some(_) => {}
                None => panic!("proxy control channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for BroadcastPublicSettings")
}

#[sqlx::test]
async fn test_client_downloads_defaults_and_access(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;

    // Signed-in users only.
    assert_eq!(
        client.get(PATH).send().await.status(),
        StatusCode::UNAUTHORIZED
    );

    authenticate_admin(&mut client).await;
    assert_eq!(
        get(&client).await,
        json!({
            "base_url": DEFAULT_CLIENT_DOWNLOAD_BASE_URL,
            "releases_url": DEFAULT_CLIENT_RELEASES_URL,
            "android_url": null,
            "ios_url": null,
            "macos_installer": false,
            "allow_http": false,
            "asset_names": [
                "xguard-client_amd64.deb",
                "xguard-client_arm64.deb",
                "xguard-client.x86_64.rpm",
                "xguard-client.aarch64.rpm",
                "xguard-client_x64.msi",
                "xguard-client_universal.dmg",
            ],
            "defaults": {
                "base_url": DEFAULT_CLIENT_DOWNLOAD_BASE_URL,
                "releases_url": DEFAULT_CLIENT_RELEASES_URL,
            },
        })
    );
    let (status, _) = put(&client, &mirror()).await;
    assert_eq!(status, StatusCode::OK);
    client.drain_all_events();

    // Users read the links (the add-device dialog shows them) but cannot change them.
    client.login_user("hpotter", "pass123").await;
    let body = get(&client).await;
    assert_eq!(body["base_url"], "https://mirror.example.lan/xguard");
    let (status, _) = put(
        &client,
        &json!({"base_url": "https://evil.example", "releases_url": "https://evil.example"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        get(&client).await["base_url"],
        "https://mirror.example.lan/xguard"
    );
    client.assert_event_queue_is_empty();
}

#[sqlx::test]
async fn test_client_downloads_validation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = setup_pool(options).await;
    let (mut client, _) = make_test_client(pool).await;
    authenticate_admin(&mut client).await;
    client.drain_all_events();

    let base = json!({
        "base_url": "https://mirror.example.lan/xguard",
        "releases_url": "https://mirror.example.lan/xguard/",
    });
    let with = |key: &str, value: Value| {
        let mut body = base.clone();
        body[key] = value;
        body
    };
    for (body, message) in [
        (
            with("base_url", json!("http://10.0.0.5/xguard")),
            "must use https",
        ),
        (
            with("base_url", json!("javascript:alert(1)")),
            "not a valid URL",
        ),
        (
            with("base_url", json!("https://u:p@mirror.lan/x")),
            "user name or password",
        ),
        (with("base_url", json!("https://mirror.lan/x?v=1")), "query"),
        (with("base_url", json!("")), "required"),
        (
            with("releases_url", json!("ftp://mirror.lan/")),
            "not a valid URL",
        ),
        (
            with("ios_url", json!("itms-apps://apps.apple.com/x")),
            "ios_url",
        ),
        (
            with(
                "base_url",
                json!(format!("https://mirror.lan/{}", "a".repeat(2100))),
            ),
            "longer than",
        ),
    ] {
        let (status, response) = put(&client, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let msg = response["msg"].as_str().unwrap_or_default();
        assert!(msg.contains(message), "{body}: {msg}");
    }
    // Unknown fields are rejected rather than ignored.
    let (status, _) = put(&client, &with("base_URL", json!("https://x.example"))).await;
    assert!(status.is_client_error());
    // Nothing was saved or logged.
    assert_eq!(
        get(&client).await["base_url"],
        DEFAULT_CLIENT_DOWNLOAD_BASE_URL
    );
    client.assert_event_queue_is_empty();

    // Plain HTTP with the explicit opt-in, for a server inside the network.
    let mut lan = with("base_url", json!("http://10.0.0.5/xguard"));
    lan["allow_http"] = json!(true);
    let (status, response) = put(&client, &lan).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["base_url"], "http://10.0.0.5/xguard");
    assert_eq!(response["allow_http"], true);
}

#[sqlx::test]
async fn test_client_downloads_saved_audited_and_broadcast(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = setup_pool(options).await;
    let (mut client, state) = make_test_client(pool.clone()).await;
    let mut rx = state.proxy_control_rx;
    authenticate_admin(&mut client).await;
    client.drain_all_events();

    let (status, response) = put(&client, &mirror()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["base_url"], "https://mirror.example.lan/xguard");
    assert_eq!(response["ios_url"], Value::Null);
    assert_eq!(
        ClientDownloadSettings::load(&pool).await.unwrap(),
        mirror_saved()
    );
    client.verify_api_events(&[ApiEventType::ClientDownloadsUpdated {
        before: ClientDownloadSettings::default(),
        after: mirror_saved(),
    }]);
    assert_eq!(next_client_downloads(&mut rx).await, mirror_saved());

    // Saving the same values again changes nothing and logs nothing.
    let (status, _) = put(&client, &mirror()).await;
    assert_eq!(status, StatusCode::OK);
    client.assert_event_queue_is_empty();
    assert!(rx.try_recv().is_err());

    // Back to the defaults.
    let defaults = serde_json::to_value(ClientDownloadSettings::default()).unwrap();
    let (status, _) = put(&client, &defaults).await;
    assert_eq!(status, StatusCode::OK);
    client.verify_api_events(&[ApiEventType::ClientDownloadsUpdated {
        before: mirror_saved(),
        after: ClientDownloadSettings::default(),
    }]);
    assert_eq!(
        next_client_downloads(&mut rx).await,
        ClientDownloadSettings::default()
    );
}
