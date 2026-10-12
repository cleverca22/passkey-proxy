use axum::http::StatusCode;
use axum_cookie::prelude::{CookieManager};
use crate::types::CookieClaims;
use jsonwebtoken::{decode,Validation,DecodingKey,TokenData};

pub async fn route(cookie: CookieManager) -> StatusCode {
  if let Some(cookie) = cookie.get("session") {
    println!("Cookie value: {}", cookie.value());
    let secret = "hunter2";
    let key = DecodingKey::from_secret(secret.as_ref());
    let token_message = decode::<CookieClaims>(&cookie.value(), &key, &Validation::default());
    println!("{0:#?}", token_message);
    match token_message {
      // TODO, confirm client ip in claims matches
      Ok(TokenData{header, claims}) => StatusCode::OK,
      Err(_) => StatusCode::UNAUTHORIZED,
    }
  } else {
    StatusCode::UNAUTHORIZED
  }
}
