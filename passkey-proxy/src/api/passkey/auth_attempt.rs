use axum::extract::Json;
use axum::http::StatusCode;
use axum_client_ip::XRealIp;
use axum_cookie::prelude::{Cookie,CookieManager};
use core::net::IpAddr;
use crate::types::{AuthAttempt,AuthResult,PassKey,AuthData,auth_data_from_vec,ClientData,CookieClaims};
use jsonwebtoken::{EncodingKey,Header,encode,get_current_timestamp};
use sha2::{Sha256,Digest};
use std::io;
use std::time::Duration;

fn auth_success(ip: IpAddr, cookie: CookieManager) -> (StatusCode, Json<AuthResult>) {
  let secret = "hunter2";
  let key = EncodingKey::from_secret(secret.as_ref());
  let claims = CookieClaims {
    client_ip: ip,
    exp: get_current_timestamp() + 3600,
  };
  let token = encode(&Header::default(), &claims, &key).unwrap();
  println!("token: {0:#?}\n", token);

  let session = Cookie::new("session", token)
    .with_path("/")
    .with_http_only(true)
    .with_max_age(Duration::from_secs(3600 * 24 * 7 * 2))
    .with_secure(true);
  cookie.add(session);
  (StatusCode::OK, Json(AuthResult { success: true, msg: None }))
}

fn auth_fail(msg: &str) -> (StatusCode, Json<AuthResult>) {
  (StatusCode::OK, Json(AuthResult { success: false, msg: Some(msg.to_string()) }))
}

pub async fn route(XRealIp(ip): XRealIp, cookie: CookieManager, Json(payload): Json<AuthAttempt>) -> (StatusCode, Json<AuthResult>) {
  let passkey: PassKey = match PassKey::get_by_id(&payload.id) {
    Ok(Some(pk)) => pk,
    Ok(None) => {
      return  auth_fail("passkey not in DB");
    },
    Err(_) => {
      return auth_fail("error loading passkey");
    }
  };
  println!("passkey: {0:#?}", passkey);
  println!("auth attempt from id: {0}", payload.id);
  println!("attached via {0}", payload.authenticator_attachment);
  println!("authenticatorData: {0}", payload.response.authenticator_data);
  let m_auth_data: io::Result<AuthData> = auth_data_from_vec(payload.response.authenticator_data.get_vec());
  let auth_data: AuthData = match m_auth_data {
    Ok(ad) => ad,
    Err(_) => {
      return auth_fail("cant parse auth data");
    }
  };
  println!("auth data: {0:#?}", auth_data);

  let client_data: ClientData = match serde_json::from_slice(
    &payload.response.client_data_json.get_vec()[..]
  ) {
    Ok(cd) => cd,
    Err(_) => { return auth_fail("cant parse client json"); }
  };
  println!("client data: {0}", String::from_utf8_lossy(&payload.response.client_data_json.get_vec()[..]));
  println!("client data parsed: {0:#?}", client_data);
  println!("sig: {0}\n", payload.response.signature);
  // TODO, verify the rpId and flags
  let json_hash = Sha256::digest(&payload.response.client_data_json.get_vec());

  let message: Vec<u8> = payload.response.authenticator_data.get_vec().into_iter().chain(json_hash).collect();

  match passkey.public_key_algorithm {
    -7 => {
      let result = crate::p256::verify_sig(passkey.public_key.get_vec(), message, payload.response.signature.get_vec());
      println!("sig result: {0:#?}", result);
      match result {
        Some(true) => auth_success(ip, cookie),
        Some(false) => auth_fail("sig check fail"),
        None => auth_fail("cant parse pk or sig"),
      }
    }
    -8 => {
      let result = crate::ed25519::verify_sig(passkey.public_key.get_vec(), message, payload.response.signature.get_vec());
      match result {
        Some(true) => auth_success(ip, cookie),
        Some(false) => auth_fail("sig check fail"),
        None => auth_fail("cant parse pk or sig"),
      }
    }
    _ => {
      auth_fail("unsupported sig algo")
    }
  }
}
