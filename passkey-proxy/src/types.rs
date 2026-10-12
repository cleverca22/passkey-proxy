use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _,engine::general_purpose::URL_SAFE_NO_PAD};
use core::net::IpAddr;
use jsonwebtoken::{EncodingKey,DecodingKey};
use rusqlite::OptionalExtension;
use rusqlite::types::ToSqlOutput::Owned;
use rusqlite::types::Value::Text;
use rusqlite::{Connection,ToSql,types::{ToSqlOutput,FromSql,ValueRef,FromSqlError,FromSqlResult}};
use serde::{Serialize,Deserialize, Deserializer, de};
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt;
use std::io::{Cursor, Read};
use std::io;
use std::sync::{Arc,Mutex};
use std::time::Duration;
use uuid::Uuid;

#[derive(Deserialize,Debug)]
pub struct AuthenticatorAssertionResponse {
  #[serde(rename = "authenticatorData")]
  pub authenticator_data: Base64Bytes,
  #[serde(rename = "clientDataJSON")]
  pub client_data_json: Base64Bytes,

  pub signature: Base64Bytes,
  // ASN.1 DER
}

#[derive(Deserialize,Debug)]
pub struct AuthAttempt {
  #[serde(rename = "authenticatorAttachment")]
  pub authenticator_attachment: String,
  pub id: Base64Bytes,
  pub response: AuthenticatorAssertionResponse,
}

// TODO, add creation timestamp, and reject old tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct CookieClaims {
  pub client_ip: IpAddr,
  pub exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeClaims {
  pub client_ip: IpAddr,
  pub exp: u64,
}

#[derive(Debug)]
pub struct AttestedCredentialData {
  pub aaguid: AaGuid,
  pub credential_id: CredentialId,
  pub credential_public_key: ciborium::Value,
}

#[derive(Debug)]
pub struct AuthData {
  pub rp_id_hash: Sha256Hash,
  pub flags: AuthDataFlags,
  pub sign_count: u32, // initial sequence counter
  pub attested_credential_data: Option<AttestedCredentialData>,
  pub rest: Vec<u8>,
}

#[derive(Serialize, Debug)]
pub struct AuthResult {
  pub success: bool,
  pub msg: Option<String>,
}

#[derive(Deserialize,Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
  r#type: String,
  challenge: Base64Bytes,
  origin: String,
  cross_origin: bool,
}

pub struct CredentialId(pub Vec<u8>);

impl Debug for CredentialId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let encoded = hex::encode(self.0.clone());
    write!(f, "{}", encoded)
  }
}

#[derive(Clone)]
pub struct Base64Bytes(Vec<u8>);

impl <'de> Deserialize<'de> for AuthData {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let f: Vec<u8> = Vec::deserialize(deserializer)?;
    auth_data_from_vec(f).map_err(serde::de::Error::custom)
  }
}

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

impl ToSql for Base64Bytes {
  fn to_sql(&self) -> Result<ToSqlOutput<'_>, rusqlite::Error> {
    let encoded = BASE64_STANDARD.encode(&self.0);
    Ok(Owned(Text(encoded)))
  }
}

impl FromSql for Base64Bytes {
  fn column_result(value: ValueRef<'_>) -> FromSqlResult<Base64Bytes> {
    match value {
      ValueRef::Text(t) => {
        Ok(Base64Bytes(BASE64_STANDARD.decode(t).map_err(|e| FromSqlError::Other(Box::new(e)))?))
      }
      _ => Err(rusqlite::types::FromSqlError::InvalidType)
    }
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
#[serde(rename_all = "camelCase")]
pub struct Register {
  pub authenticator_attachment: String,
  pub id: Base64Bytes,
  pub response: AuthenticatorAttestationResponse,
}

#[derive(Serialize, Debug)]
pub struct RegisterReply {
  pub msg: Option<&'static str>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
  fmt: String,
  att_stmt: ciborium::value::Value,
  auth_data: AuthData,
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
  let db = Connection::open("db.sqlite").unwrap();
  let query = "
    CREATE TABLE IF NOT EXISTS passkeys (id, publicKey, publicKeyAlgorithm, attestationObject, transports);
  ";
  db.execute(query,[]).unwrap();
  db
}

#[derive(Clone)]
pub struct PassKeyProxyState {
  pub db_handle: Arc<Mutex<DbHandle>>,
  pub encoding_key: EncodingKey,
  pub decoding_key: DecodingKey,
  pub cookie_ttl: Duration,
  pub jwt_auto_renew: u64,
}

pub struct DbHandle {
  pub conn: Connection,
}

impl DbHandle {
  pub fn open() -> DbHandle {
    let conn = get_db();
    DbHandle {
      conn
    }
  }
}

#[derive(Debug)]
pub struct PassKey {
  pub public_key: Base64Bytes,
  pub public_key_algorithm: i64,
}

impl PassKey {
  pub fn get_by_id(id: &Base64Bytes) -> rusqlite::Result<Option<PassKey>> {
    let conn = get_db();
    let mut stat = conn.prepare_cached("SELECT publicKey, publicKeyAlgorithm FROM passkeys WHERE id = ?").unwrap();
    stat.query_row([id], |row| {
      let public_key: Base64Bytes = row.get(0)?;
      let public_key_algorithm: i64 = row.get(1)?;
      Ok(PassKey { public_key, public_key_algorithm })
    }).optional()
  }
}

pub fn auth_data_from_vec(f: Vec<u8>) -> io::Result<AuthData> {
  let mut cursor = Cursor::new(f.clone());
  let mut hash = vec![0u8; 32];
  cursor.read_exact(&mut hash)?;
  let flags: u8 = read_u8(&mut cursor)?;
  let sign_count = read_be_u32(&mut cursor)?;

  let attested_credential_data: Option<AttestedCredentialData>;
  if flags & (1<<6) != 0 {
    let mut aaguid = vec![0u8;16];
    cursor.read_exact(&mut aaguid)?;
    let credential_id_len = read_be_u16(&mut cursor)?.into();
    let mut credential_id = vec![0u8; credential_id_len];
    cursor.read_exact(&mut credential_id)?;

    let pk_value: ciborium::Value = ciborium::from_reader(&mut cursor)
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    attested_credential_data = Some(AttestedCredentialData {
      aaguid: AaGuid(aaguid.to_vec()),
      credential_id: CredentialId(credential_id.to_vec()),
      credential_public_key: pk_value,
    });
  } else {
    attested_credential_data = None;
  }
  let mut rest: Vec<u8> = Vec::new();
  cursor.read_to_end(&mut rest).unwrap();
  Ok(AuthData {
    rp_id_hash: Sha256Hash(hash),
    flags: AuthDataFlags(flags),
    sign_count,
    attested_credential_data,
    rest,
  })
}

fn read_u8<T>(cursor: &mut Cursor<T>) -> io::Result<u8> where T: AsRef<[u8]> {
  let mut buf = vec![0u8; 1];
  cursor.read_exact(&mut buf)?;
  Ok(buf[0])
}

fn read_be_u16<T>(cursor: &mut Cursor<T>) -> io::Result<u16> where T: AsRef<[u8]> {
  let mut buf = vec![0u8; 2];
  cursor.read_exact(&mut buf)?;
  Ok(u16::from_be_bytes(buf.try_into().unwrap()))
}

fn read_be_u32<T>(cursor: &mut Cursor<T>) -> io::Result<u32> where T: AsRef<[u8]> {
  let mut buf = vec![0u8; 4];
  cursor.read_exact(&mut buf)?;
  Ok(u32::from_be_bytes(buf.try_into().unwrap()))
}
