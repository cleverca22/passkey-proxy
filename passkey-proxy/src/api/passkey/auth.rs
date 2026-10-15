use axum::Extension;
use axum::http::StatusCode;
use axum_client_ip::XRealIp;
use axum_cookie::prelude::{CookieManager};
use crate::types::{CookieClaims,PassKeyProxyState};
use crate::util::gen_new_jwt_cookie;
use jsonwebtoken::errors::ErrorKind::{ExpiredSignature,InvalidToken};
use jsonwebtoken::{decode,Validation,TokenData,get_current_timestamp};
use std::time::Duration;

// validates the JWT token in the cookie
// returns 200 OK if the token is valid
// returns 401 Unauthorized if the token is invalid
// may issue a Set-Cookie: header to renew the token
pub async fn route(Extension(state): Extension<PassKeyProxyState>, XRealIp(ip): XRealIp, cm: CookieManager) -> StatusCode {
  match cm.get("session") {
    Some(cookie) => {
      //println!("Cookie value: {}", cookie.value());
      let token_message = decode::<CookieClaims>(&cookie.value(), &state.decoding_key, &Validation::default());
      match token_message {
        // TODO, confirm client ip in claims matches
        Ok(TokenData{header, claims}) => {
          let now = get_current_timestamp();
          let ttl = claims.exp - now;
          println!("{0:#?} {1:#?}, ttl: {2} hours", header, claims, (ttl as f32) / 3600.0);
          if ttl < state.jwt_auto_renew {
            println!("cookie will expire in {0:#?}, renewing", Duration::from_secs(state.jwt_auto_renew));
            let cookie = gen_new_jwt_cookie(ip, &state.encoding_key, state.cookie_ttl);
            cm.add(cookie);
          }
          StatusCode::OK
        },
        Err(err) => {
          match err.into_kind() {
            ExpiredSignature => {
              println!("JWT expired, time to re-log");
              StatusCode::UNAUTHORIZED
            },
            InvalidToken => {
              println!("invalid token {0}, time to re-log", cookie.value());
              StatusCode::UNAUTHORIZED
            },
            err => {
              println!("{0:#?}", err);
              todo!()
            },
          }
        }
      }
    }
    None => StatusCode::UNAUTHORIZED
  }
}
