use axum::extract::Json;
use sha2::{Sha256,Digest};
use axum::http::StatusCode;
use axum_cookie::prelude::*;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ciborium::from_reader;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Debug;
use std::fmt;
use std::io::{Cursor, Read};
use std::time::Duration;

use crate::types::*;

#[derive(Serialize, Debug)]
pub struct AuthResult {
  success: bool,
  msg: Option<String>,
}

pub struct CredentialId(Vec<u8>);

impl Debug for CredentialId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let encoded = hex::encode(self.0.clone());
    write!(f, "{}", encoded)
  }
}

#[derive(Debug)]
pub struct AttestedCredentialData {
  aaguid: AaGuid,
  credential_id: CredentialId,
  credential_public_key: ciborium::Value,
}

#[derive(Debug)]
pub struct AuthData {
  rp_id_hash: Sha256Hash,
  flags: AuthDataFlags,
  sign_count: u32, // initial sequence counter
  attested_credential_data: Option<AttestedCredentialData>,
  rest: Vec<u8>,
}

fn read_u8<T>(cursor: &mut Cursor<T>) -> u8 where T: AsRef<[u8]> {
  let mut buf = vec![0u8; 1];
  cursor.read_exact(&mut buf).unwrap();
  buf[0]
}

fn read_be_u16<T>(cursor: &mut Cursor<T>) -> u16 where T: AsRef<[u8]> {
  let mut buf = vec![0u8; 2];
  cursor.read_exact(&mut buf).unwrap();
  u16::from_be_bytes(buf.try_into().unwrap())
}

fn read_be_u32<T>(cursor: &mut Cursor<T>) -> u32 where T: AsRef<[u8]> {
  let mut buf = vec![0u8; 4];
  cursor.read_exact(&mut buf).unwrap();
  u32::from_be_bytes(buf.try_into().unwrap())
}

fn auth_data_from_vec(f: Vec<u8>) -> AuthData {
  let mut cursor = Cursor::new(f.clone());
  let mut hash = vec![0u8; 32];
  cursor.read_exact(&mut hash).unwrap();
  let flags: u8 = read_u8(&mut cursor);
  let sign_count = read_be_u32(&mut cursor);

  let attested_credential_data: Option<AttestedCredentialData>;
  if flags & (1<<6) != 0 {
    let mut aaguid = vec![0u8;16];
    cursor.read_exact(&mut aaguid).unwrap();
    let credential_id_len = read_be_u16(&mut cursor).into();
    let mut credential_id = vec![0u8; credential_id_len];
    cursor.read_exact(&mut credential_id).unwrap();

    let pk_value: ciborium::Value = ciborium::from_reader(&mut cursor).unwrap();

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
  AuthData {
    rp_id_hash: Sha256Hash(hash),
    flags: AuthDataFlags(flags),
    sign_count,
    attested_credential_data,
    rest,
  }
}

impl <'de> Deserialize<'de> for AuthData {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let f: Vec<u8> = Vec::deserialize(deserializer)?;
    Ok(auth_data_from_vec(f))
  }
}

#[derive(Deserialize, Debug)]
pub struct Attestation {
  fmt: String,
  #[serde(rename = "attStmt")]
  att_stmt: ciborium::value::Value,
  #[serde(rename = "authData")]
  auth_data: AuthData,
}


#[derive(Deserialize,Debug)]
pub struct AuthenticatorAssertionResponse {
  #[serde(rename = "authenticatorData")]
  authenticator_data: Base64Bytes,
  #[serde(rename = "clientDataJSON")]
  client_data_json: Base64Bytes,

  signature: Base64Bytes,
  // ASN.1 DER
}

#[derive(Deserialize,Debug)]
pub struct AuthAttempt {
  #[serde(rename = "authenticatorAttachment")]
  authenticator_attachment: String,
  id: Base64Bytes,
  response: AuthenticatorAssertionResponse,
}

pub async fn register(Json(payload): Json<Register>) {
  println!("registering {0}", payload.id);
  println!("attached via {0}", payload.authenticator_attachment);
  let client_data_json = String::from_utf8(payload.response.client_data_json.get_vec()).unwrap();
  println!("client data: {0}", client_data_json);
  println!("attestationObject: {0}", payload.response.attestation_object);
  let obj: Attestation = from_reader(&payload.response.attestation_object.get_vec()[..]).unwrap();
  println!("attestation parsed: {0:#?}", obj);
  println!("authenticatorData: {0}", payload.response.authenticator_data);
  let conn = get_db();
  let mut stat = conn.prepare("INSERT INTO passkeys (id, publicKey, publicKeyAlgorithm, attestationObject, transports) VALUES (?,?,?,?,?)").unwrap();
  stat.bind((1, payload.id)).unwrap();
  stat.bind((2, payload.response.public_key)).unwrap();
  stat.bind((3, payload.response.public_key_algorithm)).unwrap();
  stat.bind((4, payload.response.attestation_object)).unwrap();
  stat.bind((5, payload.response.transports.join(",").as_str())).unwrap();
  stat.next().unwrap();
  // TODO, concat authenticator_data and sha256(client_data_json), but where is sig?
}

fn auth_success(cookie: CookieManager) -> (StatusCode, Json<AuthResult>) {
  // TODO some kind of signed cookie, maybe JWT
  let session = Cookie::new("session", "TODO")
    .with_path("/")
    .with_http_only(true)
    .with_max_age(Duration::from_secs(3600 * 24 * 7 * 2))
    .with_secure(true);
  cookie.add(session);
  (StatusCode::OK, Json(AuthResult { success: true, msg: None }))
}

fn auth_fail(msg: &str) -> (StatusCode, Json<AuthResult>) {
  (StatusCode::OK, Json(AuthResult { success: false, msg: Some(msg.to_string()) }))
}

pub async fn auth_attempt(cookie: CookieManager, Json(payload): Json<AuthAttempt>) -> (StatusCode, Json<AuthResult>) {
  let m_passkey: Option<PassKey> = PassKey::getById(&payload.id);
  println!("passkey: {0:#?}", m_passkey);
  match m_passkey {
    Some(passkey) => {
      println!("auth attempt from id: {0}", payload.id);
      println!("attached via {0}", payload.authenticator_attachment);
      println!("authenticatorData: {0}", payload.response.authenticator_data);
      let auth_data: AuthData = auth_data_from_vec(payload.response.authenticator_data.get_vec());
      println!("auth data: {0:#?}", auth_data);
      let client_data_json = String::from_utf8(payload.response.client_data_json.get_vec().clone()).unwrap();
      println!("client data: {0}", client_data_json);
      println!("sig: {0}\n", payload.response.signature);
      // TODO, verify the rpId and flags
      let jsonHash = Sha256::digest(&payload.response.client_data_json.get_vec());

      let message: Vec<u8> = payload.response.authenticator_data.get_vec().into_iter().chain(jsonHash).collect();

      match passkey.public_key_algorithm {
        -7 => {
          let result = crate::p256::verify_sig(passkey.public_key.get_vec(), message, payload.response.signature.get_vec());
          println!("sig result: {0:#?}", result);
          if result {
            auth_success(cookie)
          } else {
            auth_fail("sig check fail")
          }
        }
        -8 => {
          let res = crate::ed25519::verify_sig(passkey.public_key.get_vec(), message, payload.response.signature.get_vec());
          if res {
            auth_success(cookie)
          } else {
            auth_fail("sig check fail")
          }
        }
        _ => {
          auth_fail("unsupported sig algo")
        }
      }
    }
    None => {
      auth_fail("passkey not in DB")
    }
  }
}

pub async fn get_all() -> Json<Vec<String>> {
  let mut arr: Vec<String> = Vec::new();
  let conn = get_db();
  let stat = conn.prepare("SELECT id FROM passkeys").unwrap();
  for row in stat.into_iter().map(|row| row.unwrap()) {
    arr.push(row.read::<&str,_>("id").to_string());
  }
  Json(arr)
}

pub fn test_parse() {
  let conn = get_db();
  let stat = conn.prepare("SELECT id, attestationObject FROM passkeys").unwrap();
  for row in stat.into_iter().map(|row| row.unwrap()) {
    let id = row.read::<&str,_>("id").to_string();
    let attestation_object = row.read::<&str,_>("attestationObject").to_string();
    let obj_bytes: Vec<u8> = BASE64_STANDARD.decode(&attestation_object).unwrap();
    let obj: Attestation = from_reader(&obj_bytes[..]).unwrap();

    println!("id: {0}\nobj: {1}\nlen: {2}\n", id, attestation_object, obj_bytes.len());
    println!("foo: {0:#?}", obj);
  }
}
