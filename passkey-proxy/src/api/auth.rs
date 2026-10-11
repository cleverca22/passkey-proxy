use axum::http::StatusCode;
use axum_cookie::prelude::*;
use axum::response::Html;

pub async fn route(cookie: CookieManager) -> StatusCode {
  if let Some(cookie) = cookie.get("session") {
    println!("Cookie value: {}", cookie.value());
    // TODO some kind of signed cookie, maybe JWT
    if cookie.value() == "TODO" {
      StatusCode::OK
    } else {
      StatusCode::UNAUTHORIZED
    }
  } else {
    StatusCode::UNAUTHORIZED
  }
}

pub async fn start() -> Html<&'static str> {
  Html(include_str!("../../static/index.html"))
}
