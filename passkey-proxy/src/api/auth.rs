use axum::extract::Json;
use axum_client_ip::XRealIp;
use serde::{Serialize,Deserialize};
use jsonwebtoken::{EncodingKey,Header,encode,get_current_timestamp};

use crate::types::{ChallengeClaims};

#[derive(Debug, Serialize, Deserialize)]
pub struct GenChallengeReply {
  token: String
}

pub async fn gen_challenge(XRealIp(ip): XRealIp) -> Json<GenChallengeReply> {
  let secret = "hunter2";
  let key = EncodingKey::from_secret(secret.as_ref());
  let claims = ChallengeClaims {
    client_ip: ip,
    exp: get_current_timestamp() + 120,
  };
  let token = encode(&Header::default(), &claims, &key).unwrap();

  println!("gen challenge for {0}, {1}", ip, token);
  Json(GenChallengeReply { token })
}
