use axum::extract::Request;
use axum::routing::{get,post};
use axum::{Router,ServiceExt,Extension};
use axum_cookie::prelude::*;
use jsonwebtoken::{EncodingKey,DecodingKey};
use sd_notify::{notify,NotifyState};
use std::sync::{Arc,Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;

mod api;
mod types;
mod ed25519;
mod p256;

use crate::api::{root,test,auth,passkey};

use types::{DbHandle,PassKeyProxyState};

#[tokio::main]
pub async fn main() -> Result<(),Box<dyn std::error::Error + Send + Sync>> {
  let listener:TcpListener = TcpListener::bind("[::]:3001").await?;
  let _ = notify(&[NotifyState::Ready]);

  let db = DbHandle::open();
  let secret = "hunter2";
  let db_ext = PassKeyProxyState {
    db_handle: Arc::new(Mutex::new(db)),
    encoding_key: EncodingKey::from_secret(secret.as_ref()),
    decoding_key: DecodingKey::from_secret(secret.as_ref()),
    cookie_ttl: Duration::from_secs(3600 * 24), // how long the cookie and JWT within will last
    jwt_auto_renew: 3600 * 23, // if the JWT will expire in 23h, renew it
  };

  //logic::test_parse();

  let app = Router::new()
    .route("/", get(root::route))
    .route("/passkey/auth", get(passkey::auth::route))
    .route("/passkey/auth_attempt", post(passkey::auth_attempt::route))
    .route("/passkey/gen_challenge", get(auth::gen_challenge))
    .route("/passkey/passkey.js", get(test::js))
    .route("/passkey/register", post(passkey::register::route))
    .route("/passkey/start", get(passkey::start::route))
    .route("/passkey/get_all", get(passkey::get_all::route))
    .layer(CookieLayer::default())
    .layer(Extension(db_ext))
    ;
  let app = NormalizePathLayer::trim_trailing_slash().layer(app);

  axum::serve(listener, ServiceExt::<Request>::into_make_service(app))
    .await
    .expect("Failed to start the server");
  Ok(())
}
