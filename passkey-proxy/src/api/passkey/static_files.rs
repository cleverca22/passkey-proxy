use axum::response::IntoResponse;
use axum::http::header::CONTENT_TYPE;
use axum::response::Html;

pub async fn register() -> Html<&'static str> {
  Html(include_str!("../../../static/register.html"))
}

pub async fn js() -> impl IntoResponse {
  ([ (CONTENT_TYPE, "application/javascript") ], include_str!("../../../static/passkey.js"))
}

pub async fn index() -> Html<&'static str> {
  Html(include_str!("../../../static/index.html"))
}
