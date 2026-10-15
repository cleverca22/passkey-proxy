use std::env;
use passkey_proxy::types::{Base64Bytes,DbHandle,PassKey};

pub fn main() {
  let args: Vec<String> = env::args().collect();
  println!("{0:#?}", args);
  let db = DbHandle::open();
  match args[1].as_str() {
    "list" => {
      let mut stat = db.conn.prepare_cached("SELECT username, id FROM passkeys ORDER BY username").unwrap();
      let rows = stat.query_map([], |row| {
        let a: String = row.get(0)?;
        let b: Base64Bytes = row.get(1)?;
        Ok((a,b))
      }).unwrap();
      for row in rows {
        match row {
          Ok((username,id)) => println!("{0} {1} {2}", username, id.get_vec().len(), id),
          Err(err) => println!("{0:#?}", err),
        }
      }
    },
    "info" => {
      let id = Base64Bytes::from_string(&args[2]);
      let pk = PassKey::get_by_id(&id);
      println!("{0:#?}", pk);
    },
    &_ => todo!(),
  }
}
