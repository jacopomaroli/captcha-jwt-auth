use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum CJAError {
    #[error("Resource not Found")]
    NotFound,
    #[error("Captcha expired")]
    CaptchaExpired,
    #[error("Captcha invalid")]
    CaptchaInvalid,
    #[error("Signature expired")]
    JWTExpired,
    #[error("no auth header")]
    NoAuthHeader,
    #[error("invalid auth header")]
    InvalidAuthHeader,
    #[error("Invalid token")]
    Forbidden,
    #[error("Invalid payload")]
    InvalidPayload,
    #[error("Internal server error")]
    Unknown,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    code: u16,
    error: String,
    message: String,
}

impl CJAError {
    pub fn name(&self) -> String {
        match self {
            Self::NotFound => "NotFound".to_string(),
            Self::CaptchaExpired => "CaptchaExpired".to_string(),
            Self::CaptchaInvalid => "CaptchaInvalid".to_string(),
            Self::JWTExpired => "JWTExpired".to_string(),
            Self::NoAuthHeader => "NoAuthHeader".to_string(),
            Self::InvalidAuthHeader => "InvalidAuthHeader".to_string(),
            Self::Forbidden => "Forbidden".to_string(),
            Self::InvalidPayload => "InvalidPayload".to_string(),
            Self::Unknown => "Unknown".to_string(),
        }
    }
}

impl ResponseError for CJAError {
    fn status_code(&self) -> StatusCode {
        match *self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::CaptchaExpired => StatusCode::FORBIDDEN,
            Self::CaptchaInvalid => StatusCode::FORBIDDEN,
            Self::JWTExpired => StatusCode::FORBIDDEN,
            Self::NoAuthHeader => StatusCode::FORBIDDEN,
            Self::InvalidAuthHeader => StatusCode::FORBIDDEN,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::InvalidPayload => StatusCode::BAD_REQUEST,
            Self::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        let error_response = ErrorResponse {
            code: status_code.as_u16(),
            message: self.to_string(),
            error: self.name(),
        };
        HttpResponse::build(status_code).json(error_response)
    }
}
