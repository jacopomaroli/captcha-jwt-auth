use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
// use std::iter::repeat;
// use rand::OsRng;

use base64::{decode, encode};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};

use dotenv::dotenv;

use actix_web::{
    get,
    http::{
        header::{HeaderMap, AUTHORIZATION},
        StatusCode,
    },
    post, web,
    web::{Bytes, Data},
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer,
};

use captcha::filters::{Dots, Noise, Wave};
use captcha::Captcha;

use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};

#[macro_use]
extern crate slog;
use slog::Drain;
use slog_bunyan;
use slog_derive::KV;

mod auth;
mod error;
mod logger_middleware;
mod request_id_middleware;

use crate::error::CJAError;

#[derive(Serialize, Deserialize, KV, Debug)]
struct Config {
    listening_interface: String,
    listening_port: u16,
    jwt_secret: String,
    captcha_key: String,
    captcha_nonce: String,
}

struct State {
    config: Config,
    logger: slog::Logger,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct PostSessionReq {
    sessionData: String,
    solution: String,
}

#[derive(Serialize, Deserialize)]
struct PostSessionRes {
    jwt: String,
}

#[derive(Serialize, Deserialize)]
struct CaptchaSessionData {
    exp: u64,
    solution: String,
}

#[get("/captcha")]
async fn get_captcha_handler(
    req: HttpRequest,
    state: Data<Arc<State>>,
) -> Result<HttpResponse, error::CJAError> {
    let req_extensions = req.extensions();
    let req_logger = req_extensions.get::<slog::Logger>().unwrap();

    let captcha_data = Captcha::new()
        .add_chars(5)
        .apply_filter(Noise::new(0.4))
        .apply_filter(Wave::new(2.0, 20.0).horizontal())
        .apply_filter(Wave::new(2.0, 20.0).vertical())
        .view(220, 120)
        .apply_filter(Dots::new(15))
        .as_tuple();

    let (solution, png) = captcha_data.unwrap();
    // let req_logger = state.logger.new(o!("key" => "value"));
    debug!(req_logger, "solution: {}", solution);
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

    let key = decode(&state.config.captcha_key).unwrap();
    let nonce = decode(&state.config.captcha_nonce).unwrap();

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        + (5 * 60);
    let secret = serde_json::to_string(&CaptchaSessionData {
        exp: exp,
        solution: solution,
    })
    .unwrap();

    let cipher = XChaCha20Poly1305::new(&GenericArray::clone_from_slice(&key));

    let encrypted_data = cipher.encrypt(&GenericArray::clone_from_slice(&nonce), secret.as_ref());
    let encrypted_data_b64 = encode(&encrypted_data.unwrap());
    debug!(req_logger, "solution: {}", &encrypted_data_b64);

    Ok(HttpResponse::build(StatusCode::OK)
        .append_header(("data", encrypted_data_b64))
        .content_type("image/png")
        .body(data))
}

#[post("/session")]
async fn post_session_handler(
    req: HttpRequest,
    state: Data<Arc<State>>,
    post_session_req: web::Json<PostSessionReq>,
) -> Result<HttpResponse, error::CJAError> {
    let req_extensions = req.extensions();
    let req_logger = req_extensions.get::<slog::Logger>().unwrap();

    let key = decode(&state.config.captcha_key).unwrap();
    let nonce = decode(&state.config.captcha_nonce).unwrap();
    let cipher = XChaCha20Poly1305::new(&GenericArray::clone_from_slice(&key));

    let encrypted_data_2 = decode(&post_session_req.sessionData);
    let decrypted_data = cipher.decrypt(
        &GenericArray::clone_from_slice(&nonce),
        encrypted_data_2.unwrap().as_ref(),
    );
    let session_data_str = String::from_utf8(decrypted_data.unwrap()).unwrap();
    debug!(req_logger, "decrypted data: {}", &session_data_str);
    let session_data = serde_json::from_str::<CaptchaSessionData>(&session_data_str).unwrap();

    if post_session_req.solution != session_data.solution {
        return Err(error::CJAError::CaptchaInvalid);
    }

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    if session_data.exp < exp {
        return Err(error::CJAError::CaptchaExpired);
    }

    let jwt_secret: &[u8] = &state.config.jwt_secret.as_bytes();
    let token = auth::create_jwt(jwt_secret).unwrap();
    //.map_err(|e| reject::custom(e))?;

    let body = serde_json::to_string(&PostSessionRes { jwt: token }).unwrap();

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(body))
}

#[post("/validate")]
async fn post_validate_handler(
    req: HttpRequest,
    state: Data<Arc<State>>,
) -> Result<HttpResponse, error::CJAError> {
    let req_extensions = req.extensions();
    let _req_logger = req_extensions.get::<slog::Logger>().unwrap();

    let jwt_secret: &[u8] = &state.config.jwt_secret.as_bytes();
    let jwt = jwt_from_header(req.headers()).map_err(|e| return e)?;
    let token_data = auth::validate(jwt_secret, &jwt).map_err(|e| return e)?;

    let body = serde_json::to_string(&token_data.claims).unwrap();

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(body))
}

const BEARER: &str = "Bearer ";

fn jwt_from_header(headers: &HeaderMap) -> Result<String, error::CJAError> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return Err(CJAError::NoAuthHeader),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Err(CJAError::NoAuthHeader),
    };
    if !auth_header.starts_with(BEARER) {
        return Err(CJAError::InvalidAuthHeader);
    }
    Ok(auth_header.trim_start_matches(BEARER).to_owned())
}

fn get_config() -> Config {
    dotenv().ok();
    match envy::prefixed("CJA_").from_env::<Config>() {
        Ok(config) => config,
        Err(error) => panic!("{:#?}", error),
    }
}

fn get_logger() -> slog::Logger {
    slog::Logger::root(
        Mutex::new(slog_bunyan::default(std::io::stdout())).fuse(),
        o!("version" => "0.0.1"),
    )
}

fn get_json_extractor_config(state: Arc<State>) -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(4096)
        // .content_type(|mime| {
        //     // accept text/plain content type
        //     mime.type_() == mime::TEXT && mime.subtype() == mime::PLAIN
        // })
        .error_handler(move |err, _req| {
            debug!(state.logger, "{}", &err);
            CJAError::InvalidPayload.into()
        })
}

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = get_config();
    let logger = get_logger();
    info!(logger, "Loaded Config"; &config);

    let listening_interface = config.listening_interface.clone();
    let listening_port = config.listening_port.clone();
    let state = Arc::new(State { config, logger });
    let json_extractor_config = get_json_extractor_config(state.clone());
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()).clone())
            .app_data(json_extractor_config.clone())
            .wrap(logger_middleware::ReqLoggerWrapper)
            .wrap(request_id_middleware::RequestIdWrapper)
            .service(get_captcha_handler)
            .service(post_session_handler)
            .service(post_validate_handler)
    })
    .bind((listening_interface, listening_port))?
    .run()
    .await
}
