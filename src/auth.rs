use crate::error::CJAError;
use chrono::prelude::*;
use jsonwebtoken::{
    decode, encode, errors, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

const JWT_SECRET: &[u8] = b"secret";

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    exp: usize,
}

fn map_error(jwt_err: &errors::Error) -> CJAError {
    match *jwt_err.kind() {
        errors::ErrorKind::ExpiredSignature => CJAError::JWTExpired,
        _ => CJAError::Forbidden,
    }
}

pub fn create_jwt() -> errors::Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(30))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        exp: expiration as usize,
    };
    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
}

pub fn validate(jwt: &String) -> Result<TokenData<Claims>, CJAError> {
    let token_data = decode::<Claims>(
        &jwt,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::new(Algorithm::HS512),
    )
    .map_err(|e| map_error(&e));
    token_data
}
