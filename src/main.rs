use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};
use generic_array::GenericArray;

use base64::{encode, decode};

// use std::iter::repeat;
// use rand::{OsRng};

use actix_web::{get, post, web, App, HttpServer, Responder, HttpResponse, Error};
use actix_web::http::{StatusCode};
use actix_web::web::Bytes;
use serde::{Deserialize, Serialize};
use captcha::Captcha;
use captcha::filters::{Noise, Wave, Dots};
use std::time::{SystemTime, UNIX_EPOCH};

mod auth;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PostSessionReq {
    sessionData: String,
    solution: String
}

#[derive(Serialize, Deserialize)]
struct PostSessionRes {
    jwt: String
}

#[derive(Serialize, Deserialize)]
struct CaptchaSessionData {
    exp: u64,
    solution: String
}

#[derive(Serialize, Deserialize)]
struct PostValidateReq {
    jwt: String
}

#[get("/captcha")]
async fn get_captcha_handler() -> Result<HttpResponse, Error> {
    let captcha_data = Captcha::new()
        .add_chars(5)
        .apply_filter(Noise::new(0.4))
        .apply_filter(Wave::new(2.0, 20.0).horizontal())
        .apply_filter(Wave::new(2.0, 20.0).vertical())
        .view(220, 120)
        .apply_filter(Dots::new(15))
        .as_tuple();
    let (solution, png) = captcha_data.unwrap();
    println!("solution: {}", solution);
    let data = Bytes::from(png);

    // let mut gen = OsRng::new().expect("Failed to get OS random generator");
    // let mut key: Vec<u8> = repeat(0u8).take(16).collect();
    // gen.fill_bytes(&mut key[..]);
    // let mut nonce: Vec<u8> = repeat(0u8).take(16).collect();
    // gen.fill_bytes(&mut nonce[..]);

    // let mut key = [0u8; 32];
    // let mut nonce = [0u8; 24];
    // gen.fill_bytes(&mut key);
    // gen.fill_bytes(&mut nonce);
    
    let key = decode("MOPO8/pr8f7tXkFI+2X4Ea+M6+F7FD8Y4PGXdKMcRbI=").unwrap();
    let nonce = decode("pxuKaq8bI9/OQrdX9Y9+7Iv09kztwkox").unwrap();
    
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() + (5 * 60);
    let secret = serde_json::to_string(&CaptchaSessionData {
        exp: exp,
        solution: solution
    }).unwrap();

    let cipher = XChaCha20Poly1305::new(&GenericArray::clone_from_slice(&key));

    let encrypted_data = cipher.encrypt(&GenericArray::clone_from_slice(&nonce), secret.as_ref());
    let encrypted_data_b64 = encode(&encrypted_data.unwrap());
    println!("encrypted data {}", &encrypted_data_b64);

    Ok(HttpResponse::build(StatusCode::OK)
        .append_header(("data", encrypted_data_b64))
        .content_type("image/png")
        .body(data))
}

#[post("/session")]
async fn post_session_handler(post_session_req: web::Json<PostSessionReq>) -> impl Responder {
    format!("Solution: {}", post_session_req.solution);

    let key = decode("MOPO8/pr8f7tXkFI+2X4Ea+M6+F7FD8Y4PGXdKMcRbI=").unwrap();
    let nonce = decode("pxuKaq8bI9/OQrdX9Y9+7Iv09kztwkox").unwrap();
    let cipher = XChaCha20Poly1305::new(&GenericArray::clone_from_slice(&key));

    let encrypted_data_2 = decode(&post_session_req.sessionData);
    let decrypted_data = cipher.decrypt(&GenericArray::clone_from_slice(&nonce), encrypted_data_2.unwrap().as_ref());
    let session_data_str = String::from_utf8(decrypted_data.unwrap()).unwrap();
    println!("decrypted data {}", session_data_str);
    let session_data = serde_json::from_str::<CaptchaSessionData>(&session_data_str).unwrap();

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    if post_session_req.solution != session_data.solution ||
       session_data.exp < exp
    {
        println!("error");
        return HttpResponse::Unauthorized().body({});
    }

    let token = auth::create_jwt().unwrap();
        //.map_err(|e| reject::custom(e))?;

    let body = serde_json::to_string(&PostSessionRes {
        jwt: token
    })
    .unwrap();

    HttpResponse::Ok()
        .content_type("application/json")
        .body(body)
}

#[post("/validate")]
async fn post_validate_handler(post_validate_req: web::Json<PostValidateReq>) -> impl Responder {
    let claims = auth::validate(&post_validate_req.jwt);

    let body = serde_json::to_string(&claims).unwrap();

    HttpResponse::Ok()
        .content_type("application/json")
        .body(body)
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_captcha_handler)
            .service(post_session_handler)
            .service(post_validate_handler)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
