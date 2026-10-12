use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ciborium::from_reader;

use crate::types::*;


pub fn test_parse() {
  let conn = get_db();
  let mut stat = conn.prepare_cached("SELECT id, attestationObject FROM passkeys").unwrap();
  let rows = stat.query_map([], |row| {
    let id: String = row.get(0)?;
    let attestation_object: String = row.get(1)?;
    Ok((id, attestation_object))
  }).unwrap();

  for row in rows {
    match row {
      Ok((id, attestation_object)) => {
        let obj_bytes: Vec<u8> = BASE64_STANDARD.decode(&attestation_object).unwrap();
        let obj: Attestation = from_reader(&obj_bytes[..]).unwrap();

        println!("id: {0}\nobj: {1}\nlen: {2}\n", id, attestation_object, obj_bytes.len());
        println!("foo: {0:#?}", obj);
      }
      Err(_) => {
      }
    }
  }
}
