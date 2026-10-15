use axum::Extension;
use axum::extract::Json;
use ciborium::from_reader;
use crate::types::{PassKeyProxyState,Register,RegisterReply,ClientData,Attestation};
use rusqlite::params;
use std::io::Cursor;

pub async fn route(Extension(db_ext): Extension<PassKeyProxyState>, Json(payload): Json<Register>) -> Json<RegisterReply> {
  println!("registering {0}", payload.id);
  println!("attached via {0}", payload.authenticator_attachment);

  let client_data: ClientData = match serde_json::from_slice(
    &payload.response.client_data_json.get_vec()[..]
  ) {
    Ok(cd) => cd,
    Err(_) => { return Json(RegisterReply { msg: Some("cant parse client data json") }); },
  };
  // TODO, confirm type is webauthn.create
  println!("client data: {0}", String::from_utf8_lossy(&payload.response.client_data_json.get_vec()[..]));
  println!("client data parsed: {0:#?}", client_data);

  println!("attestationObject: {0}", payload.response.attestation_object);
  let att_bytes = payload.response.attestation_object.get_vec();
  let mut cursor = Cursor::new(&att_bytes[..]);

  let obj: Attestation = match from_reader(&mut cursor) {
    Ok(obj) => obj,
    Err(_) => { return Json(RegisterReply { msg: Some("cant parse attestation obj") }); },
  };
  if cursor.position() != att_bytes.len() as u64 {
    return Json(RegisterReply { msg: Some("trailing bytes on cbor") });
  }
  // TODO, assert that obj.attested_credential_data.credential_id match payload.id
  println!("attestation parsed: {0:#?}", obj);
  println!("authenticatorData: {0}", payload.response.authenticator_data);

  let db = db_ext.db_handle.lock().unwrap();
  let mut stat = db.conn.prepare_cached("INSERT INTO passkeys (id, publicKey, publicKeyAlgorithm, attestationObject, transports, username) VALUES (?,?,?,?,?,?)").unwrap();
  stat.insert(params![
    payload.id,
    payload.response.public_key,
    payload.response.public_key_algorithm,
    payload.response.attestation_object,
    payload.response.transports.join(","),
    payload.username
  ]).unwrap();
  // TODO, concat authenticator_data and sha256(client_data_json), but where is sig?
  Json(RegisterReply { msg: None })
}
