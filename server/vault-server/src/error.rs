use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// API error surface. Error *codes* are part of the client contract; the
/// human-readable messages are not.
///
/// Security note: `InvalidCredentials` is deliberately used for every
/// authentication failure mode (unknown account, wrong password, wrong MFA
/// code) so responses don't reveal which part was wrong.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("e-mail address not verified")]
    EmailNotVerified,

    #[error("a second factor is required")]
    MfaRequired,

    #[error("temporarily locked out")]
    LockedOut { retry_after_secs: i64 },

    #[error("too many requests")]
    RateLimited { retry_after_secs: i64 },

    #[error("invalid or expired token")]
    InvalidToken,

    /// Recovery cooling-off period has not elapsed yet.
    #[error("recovery is in its cooling-off period")]
    CoolingOff { retry_after_secs: i64 },

    #[error("not found")]
    NotFound,

    #[error("internal error")]
    Internal,
}

impl ApiError {
    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::InvalidCredentials => "invalid_credentials",
            ApiError::EmailNotVerified => "email_not_verified",
            ApiError::MfaRequired => "mfa_required",
            ApiError::LockedOut { .. } => "locked_out",
            ApiError::RateLimited { .. } => "rate_limited",
            ApiError::InvalidToken => "invalid_token",
            ApiError::CoolingOff { .. } => "cooling_off",
            ApiError::NotFound => "not_found",
            ApiError::Internal => "internal",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::InvalidCredentials | ApiError::InvalidToken => StatusCode::UNAUTHORIZED,
            ApiError::EmailNotVerified => StatusCode::FORBIDDEN,
            ApiError::MfaRequired => StatusCode::UNAUTHORIZED,
            ApiError::LockedOut { .. } | ApiError::RateLimited { .. } => {
                StatusCode::TOO_MANY_REQUESTS
            }
            ApiError::CoolingOff { .. } => StatusCode::TOO_EARLY,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = match &self {
            ApiError::LockedOut { retry_after_secs }
            | ApiError::RateLimited { retry_after_secs }
            | ApiError::CoolingOff { retry_after_secs } => Some(*retry_after_secs),
            _ => None,
        };
        let body = Json(json!({
            "error": self.code(),
            "message": self.to_string(),
            "retry_after_secs": retry_after,
        }));
        let mut resp = (self.status(), body).into_response();
        if let Some(secs) = retry_after {
            if let Ok(v) = secs.to_string().parse() {
                resp.headers_mut().insert("Retry-After", v);
            }
        }
        resp
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error");
        ApiError::Internal
    }
}
