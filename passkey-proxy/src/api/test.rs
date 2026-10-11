use axum::response::Html;
use axum::response::IntoResponse;
use axum::http::header::self;

pub async fn test() -> Html<&'static str> {
  Html(include_str!("../../static/index.html"))
}

pub async fn js() -> impl IntoResponse {
  ([ (header::CONTENT_TYPE, "application/javascript") ], include_str!("../../static/passkey.js"))
}
