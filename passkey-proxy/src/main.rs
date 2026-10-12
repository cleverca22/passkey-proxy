use axum::routing::{get,post};
use std::sync::{Arc,Mutex};
use axum_cookie::prelude::*;
use axum::{Router,ServiceExt,Extension};
use axum::extract::Request;
use sd_notify::{notify,NotifyState};
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;

mod api;
mod types;
mod ed25519;
mod p256;

use crate::api::{root,test,auth,passkey};

use types::{DbHandle,DbHandleExtension};

#[tokio::main]
pub async fn main() -> Result<(),Box<dyn std::error::Error + Send + Sync>> {
  let listener:TcpListener = TcpListener::bind("[::]:3001").await?;
  let _ = notify(&[NotifyState::Ready]);

  let db = DbHandle::open();
  let db_ext = DbHandleExtension(Arc::new(Mutex::new(db)));

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
