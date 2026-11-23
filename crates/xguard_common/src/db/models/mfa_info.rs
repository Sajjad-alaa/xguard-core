use serde::{Deserialize, Serialize};
use sqlx::{PgPool, query_as};

use crate::db::{
    Id,
    models::{MFAMethod, radius::RadiusSettings, user::User},
};

#[derive(Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MFAInfo {
    pub mfa_method: MFAMethod,
    totp_available: bool,
    webauthn_available: bool,
    email_available: bool,
    #[serde(default)]
    pub radius_available: bool,
}

struct MfaInfoRow {
    mfa_method: MFAMethod,
    totp_available: bool,
    webauthn_available: bool,
    email_available: bool,
}

impl MFAInfo {
    pub async fn for_user(pool: &PgPool, user: &User<Id>) -> sqlx::Result<Option<Self>> {
        let row = query_as!(
            MfaInfoRow,
            "SELECT mfa_method \"mfa_method: _\", totp_enabled totp_available, \
            email_mfa_enabled email_available, \
            (SELECT count(*) > 0 FROM webauthn WHERE user_id = $1) \"webauthn_available!\" \
            FROM \"user\" WHERE \"user\".id = $1",
            user.id
        )
        .fetch_optional(pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let radius_available = RadiusSettings::get(pool).await?.is_web_login_ready();
        let mfa_method = if row.mfa_method == MFAMethod::None && radius_available {
            MFAMethod::Radius
        } else {
            row.mfa_method
        };

        Ok(Some(Self {
            mfa_method,
            totp_available: row.totp_available,
            webauthn_available: row.webauthn_available,
            email_available: row.email_available,
            radius_available,
        }))
    }

    #[must_use]
    pub fn mfa_available(&self) -> bool {
        self.webauthn_available
            || self.totp_available
            || self.email_available
            || self.radius_available
    }

    #[must_use]
    pub fn current_mfa_method(&self) -> &MFAMethod {
        &self.mfa_method
    }

    #[must_use]
    pub fn list_available_methods(&self) -> Option<Vec<MFAMethod>> {
        if !self.mfa_available() {
            return None;
        }

        let mut methods = Vec::new();
        if self.webauthn_available {
            methods.push(MFAMethod::Webauthn);
        }
        if self.totp_available {
            methods.push(MFAMethod::OneTimePassword);
        }
        if self.email_available {
            methods.push(MFAMethod::Email);
        }
        if self.radius_available {
            methods.push(MFAMethod::Radius);
        }
        Some(methods)
    }
}
