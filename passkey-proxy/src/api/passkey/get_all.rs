use axum::Extension;
use axum::extract::Json;
use crate::types::PassKeyProxyState;

pub async fn route(Extension(db_ext): Extension<PassKeyProxyState>) -> Json<Vec<String>> {
  let mut arr: Vec<String> = Vec::new();
  let db = db_ext.db_handle.lock().unwrap();
  let mut stat = db.conn.prepare_cached("SELECT id FROM passkeys").unwrap();

  let rows = stat.query_map([], |row| row.get(0)).unwrap();

  for id in rows {
    arr.push(id.unwrap());
  }
  Json(arr)
}
