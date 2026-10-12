use axum::response::IntoResponse;
use axum::http::header::self;

pub async fn js() -> impl IntoResponse {
  ([ (header::CONTENT_TYPE, "application/javascript") ], include_str!("../../static/passkey.js"))
}
