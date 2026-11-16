use sqlx::PgPool;
use xguard_common::{
    config::{SERVER_CONFIG, XGuardConfig},
    db::models::{
        Settings, User,
        settings::{
            SettingsInitializationError, initialize_current_settings, update_current_settings,
        },
    },
};

/// Allows overriding the default XGuard URL for tests, as during the tests, the server has a random port, making the URL unpredictable beforehand.
// TODO: Allow customizing the whole config, not just the URL
pub(crate) async fn init_config(custom_xguard_url: Option<&str>, pool: &PgPool) -> XGuardConfig {
    let url = custom_xguard_url.unwrap_or("http://localhost:8000");
    let test_secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let config = XGuardConfig::new_test_config();
    initialize_current_settings(pool)
        .await
        .expect("Could not initialize current settings in the database");
    let mut settings = Settings::get_current_settings();
    settings.xguard_url = url.to_owned();
    settings.set_secret_key(Some(test_secret_key.to_owned()));
    update_current_settings(pool, settings)
        .await
        .expect("Could not update current settings in the database");
    Settings::initialize_runtime_defaults(pool)
        .await
        .map_err(|err| match err {
            SettingsInitializationError::Save(err) => err,
            other => {
                panic!("Could not initialize runtime default settings in the database: {other}")
            }
        })
        .expect("Could not initialize runtime default settings in the database");

    let _ = SERVER_CONFIG.set(config.clone());
    config
}

pub(crate) async fn initialize_users(pool: &PgPool) {
    User::init_admin_user(pool, "pass123").await.unwrap();

    User::new(
        "hpotter",
        Some("pass123"),
        "Potter",
        "Harry",
        "h.potter@hogwart.edu.uk",
        None,
    )
    .save(pool)
    .await
    .unwrap();
}
