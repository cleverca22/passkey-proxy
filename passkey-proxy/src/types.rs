use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _,engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, de};
use sqlite::{BindableWithIndex, Statement, ParameterIndex, Connection, ReadableWithIndex, ColumnIndex};
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt;
use uuid::Uuid;

#[derive(Clone)]
pub struct Base64Bytes(Vec<u8>);

impl Debug for Base64Bytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    //let encoded = hex::encode(self.0.clone());
    let encoded = BASE64_STANDARD.encode(&self.0);
    write!(f, "{}", encoded)
  }
}

impl <'de> Deserialize<'de> for Base64Bytes {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    URL_SAFE_NO_PAD.decode(s).map(Base64Bytes).map_err(de::Error::custom)
  }
}

impl Display for Base64Bytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let encoded = BASE64_STANDARD.encode(&self.0);
    write!(f, "{}", encoded)
  }
}

impl BindableWithIndex for Base64Bytes {
  fn bind<T: ParameterIndex>(self, stat: &mut Statement<'_>, index: T) -> Result<(), sqlite::Error>{
    let encoded = BASE64_STANDARD.encode(&self.0);
    stat.bind((index, encoded.as_str()))
  }
}

impl ReadableWithIndex for Base64Bytes {
  fn read<T: ColumnIndex>(stat: &Statement<'_>, index: T) -> Result<Base64Bytes, sqlite::Error> {
    let base64 = stat.read::<String,_>(index).unwrap();
    Ok(Base64Bytes(BASE64_STANDARD.decode(base64).unwrap()))
  }
}

impl Base64Bytes {
  pub fn get_vec(&self) -> Vec<u8> {
    self.0.clone()
  }
}

#[derive(Deserialize)]
pub struct AuthenticatorAttestationResponse {
  #[serde(rename = "attestationObject")]
  pub attestation_object: Base64Bytes,

  #[serde(rename = "authenticatorData")]
  pub authenticator_data: Base64Bytes,
  // base64 encoded cbor
  // cbor contains at least 3 fields
  // fmt, string "none"
  // attStmt, empty obj
  // authData, binary
  // * first 32 bytes, sha256 hash of rpId
  // * more... (116 bytes for bitwarden), 25 bytes + cbor?
  // await cbor.decodeAll(a[0].authData.slice(32+25))

  #[serde(rename = "clientDataJSON")]
  pub client_data_json: Base64Bytes,

  #[serde(rename = "publicKey")]
  pub public_key: Base64Bytes,
  // ASN.1 DER

  #[serde(rename = "publicKeyAlgorithm")]
  pub public_key_algorithm: i64,
  pub transports: Vec<String>,
}

#[derive(Deserialize)]
pub struct Register {
  #[serde(rename = "authenticatorAttachment")]
  pub authenticator_attachment: String,
  pub id: Base64Bytes,
  pub response: AuthenticatorAttestationResponse,
}

pub struct Sha256Hash(pub Vec<u8>);

impl Debug for Sha256Hash {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let encoded = hex::encode(self.0.clone());
    write!(f, "{}", encoded)
  }
}

pub struct AuthDataFlags(pub u8);

impl Debug for AuthDataFlags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let flags = self.0;
    let mut s: Vec<&str> = Vec::new();
    if flags & (1<<0) != 0 { s.push("UP"); }
    if flags & (1<<2) != 0 { s.push("UV"); }
    if flags & (1<<3) != 0 { s.push("BE"); }
    if flags & (1<<4) != 0 { s.push("BS"); }
    if flags & (1<<6) != 0 { s.push("AT"); }
    if flags & (1<<7) != 0 { s.push("ED"); }
    write!(f, "{}, {}", flags, s.join(","))
  }
}

// https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/
// d548826e-79b4-db40-a3d8-11116f7e8349 bitwarden
pub struct AaGuid(pub Vec<u8>);

impl Debug for AaGuid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let bytes: &[u8;16] = &self.0.clone().try_into().unwrap();
    let uuid = Uuid::from_bytes(*bytes);
    write!(f, "{}", uuid)
  }
}

pub fn get_db() -> Connection {
  let db = sqlite::open("db.sqlite").unwrap();
  let query = "
    CREATE TABLE IF NOT EXISTS passkeys (id, publicKey, publicKeyAlgorithm, attestationObject, transports);
  ";
  db.execute(query).unwrap();
  db
}

#[derive(Debug)]
pub struct PassKey {
  pub public_key: Base64Bytes,
  pub public_key_algorithm: i64,
}

impl PassKey {
  pub fn getById(id: &Base64Bytes) -> Option<PassKey> {
    let conn = get_db();
    let mut stat = conn.prepare("SELECT publicKey, publicKeyAlgorithm FROM passkeys WHERE id = ?").unwrap();
    stat.bind((1, id.clone())).unwrap();
    stat.next().unwrap();
    let public_key = stat.read::<Base64Bytes,_>(0).unwrap();
    let public_key_algorithm = stat.read::<i64,_>(1).unwrap();
    Some(PassKey {
      public_key,
      public_key_algorithm,
    })
  }
}
