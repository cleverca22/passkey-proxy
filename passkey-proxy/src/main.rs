use axum::routing::{get, post};
use axum_cookie::prelude::*;
use axum::{Router, ServiceExt};
//use hyper::{Request,Response};
use axum::extract::Request;
use sd_notify::{notify,NotifyState};
use tokio::net::TcpListener;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;

mod api;
mod types;
mod ed25519;
mod p256;

use crate::api::{root, test, auth, logic};

/*
#[derive(Clone)]
struct Svc {
}

impl Service<Request<IncomingBody>> for Svc {
  type Response = Response<Full<Bytes>>;
  type Error = hyper::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
  fn call(&self, _req: Request<IncomingBody>) -> Self::Future {
    let mut output: String = "hello world".to_string();
    Box::pin(async { Ok(Response::new(Full::new(Bytes::from(output)))) } )
  }
}
*/

#[tokio::main]


pub async fn main() -> Result<(),Box<dyn std::error::Error + Send + Sync>> {
  let listener:TcpListener = TcpListener::bind("[::]:3001").await?;
  let _ = notify(&[NotifyState::Ready]);

  //logic::test_parse();

  let app = Router::new()
    .route("/", get(root::route))
    .route("/test", get(test::test))
    .route("/passkey.js", get(test::js))
    .route("/passkey/auth", get(auth::route))
    .route("/passkey/start", get(auth::start))
    .route("/passkey/passkey.js", get(test::js))
    .route("/passkey/register", post(logic::register))
    .route("/passkey/auth_attempt", post(logic::auth_attempt))
    .route("/passkey/get_all", get(logic::get_all))
    .layer(CookieLayer::default())
    ;
  let app = NormalizePathLayer::trim_trailing_slash().layer(app);

  axum::serve(listener, ServiceExt::<Request>::into_make_service(app))
    .await
    .expect("Failed to start the server");
  Ok(())
  /*
  loop {
    let (tcp,_) = listener.accept().await?;
    let io = TokioIo::new(tcp);
    let svc_clone = svc.clone();
    tokio::task::spawn(async move {
      match http1::Builder::new().timer(TokioTimer::new()).serve_connection(io, svc_clone).await {
        Err(err) => println!("error serving connection {:?}", err),
        Ok(_) => {
          let _ = notify(&[NotifyState::Watchdog]);
        },
      };
    });
  }
  */
}
