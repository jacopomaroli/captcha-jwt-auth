use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation, errors};
use serde::{Deserialize, Serialize};
use chrono::prelude::*;

const JWT_SECRET: &[u8] = b"secret";

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    exp: usize,
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

pub fn validate(jwt: &String) -> Claims {
    let token_data = decode::<Claims>(
        &jwt,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::new(Algorithm::HS512),
    ).unwrap();
    token_data.claims
}
