use axum::Extension;
use axum::extract::Json;
use axum::http::StatusCode;
use axum_client_ip::XRealIp;
use axum_cookie::prelude::{CookieManager};
use core::net::IpAddr;
use crate::util::gen_new_jwt_cookie;
use crate::types::{AuthAttempt,AuthResult,PassKey,AuthData,auth_data_from_vec,ClientData,PassKeyProxyState};
use jsonwebtoken::{EncodingKey};
use sha2::{Sha256,Digest};
use std::io;
use std::time::Duration;

fn auth_success(ip: IpAddr, cookie: CookieManager, encoding_key: &EncodingKey, cookie_ttl: Duration) -> (StatusCode, Json<AuthResult>) {
  let session = gen_new_jwt_cookie(ip, encoding_key, cookie_ttl);

  cookie.add(session);
  (StatusCode::OK, Json(AuthResult { success: true, msg: None }))
}

fn auth_fail(msg: &str) -> (StatusCode, Json<AuthResult>) {
  (StatusCode::OK, Json(AuthResult { success: false, msg: Some(msg.to_string()) }))
}

pub async fn route(Extension(state): Extension<PassKeyProxyState>, XRealIp(ip): XRealIp, cookie: CookieManager, Json(payload): Json<AuthAttempt>) -> (StatusCode, Json<AuthResult>) {
  let passkey: PassKey = match PassKey::get_by_id(&payload.id) {
    Ok(Some(pk)) => pk,
    Ok(None) => {
      return auth_fail("passkey not in DB");
    },
    Err(_) => {
      return auth_fail("error loading passkey");
    }
  };
  // TODO, check that the passkey is enabled
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
    payload.response.client_data_json.get_vec()
  ) {
    Ok(cd) => cd,
    Err(_) => { return auth_fail("cant parse client json"); }
  };
  println!("client data: {0}", String::from_utf8_lossy(payload.response.client_data_json.get_vec()));
  println!("client data parsed: {0:#?}", client_data);
  println!("sig: {0}\n", payload.response.signature);
  // TODO, verify the rpId and flags
  // TODO, verify the challenge, type, origin, and cross-origin flags
  let json_hash = Sha256::digest(payload.response.client_data_json.get_vec());

  let prefix: Vec<u8> = payload.response.authenticator_data.get_vec().to_vec();
  let message: Vec<u8> = prefix.into_iter().chain(json_hash).collect();

  match passkey.public_key_algorithm {
    -7 => {
      let result = crate::p256::verify_sig(passkey.public_key.get_vec(), &message[..], payload.response.signature.get_vec());
      println!("sig result: {0:#?}", result);
      match result {
        Some(true) => auth_success(ip, cookie, &state.encoding_key, state.cookie_ttl),
        Some(false) => auth_fail("sig check fail"),
        None => auth_fail("cant parse pk or sig"),
      }
    }
    -8 => {
      let result = crate::ed25519::verify_sig(passkey.public_key.get_vec(), &message[..], payload.response.signature.get_vec());
      match result {
        Some(true) => auth_success(ip, cookie, &state.encoding_key, state.cookie_ttl),
        Some(false) => auth_fail("sig check fail"),
        None => auth_fail("cant parse pk or sig"),
      }
    }
    _ => {
      auth_fail("unsupported sig algo")
    }
  }
}
