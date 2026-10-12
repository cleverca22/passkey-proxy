use crate::types::CookieClaims;
use core::net::IpAddr;
use jsonwebtoken::{EncodingKey,Header,encode,get_current_timestamp};
use std::time::Duration;
use axum_cookie::prelude::Cookie;

pub fn gen_new_jwt_cookie(ip: IpAddr, encoding_key: &EncodingKey, cookie_ttl: Duration) -> Cookie<'static> {
  let claims = CookieClaims {
    client_ip: ip,
    exp: get_current_timestamp() + (3600 * 24),
  };
  let token = encode(&Header::default(), &claims, &encoding_key).unwrap();
  println!("token: {0:#?}\n", token);
  let session = Cookie::new("session", token)
    .with_path("/")
    .with_http_only(true)
    .with_max_age(cookie_ttl)
    .with_secure(true);
  session
}
