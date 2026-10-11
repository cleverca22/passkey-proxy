use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct Response {
}

pub async fn route() -> Json<Response> {
  let response = Response {
  };

  Json(response)
}
