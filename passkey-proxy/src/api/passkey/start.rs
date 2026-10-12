use axum::response::Html;

pub async fn route() -> Html<&'static str> {
  Html(include_str!("../../../static/index.html"))
}
