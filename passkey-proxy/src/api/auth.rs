use axum::Extension;
use axum::extract::Json;
use axum_client_ip::XRealIp;
use jsonwebtoken::{Header,encode,get_current_timestamp};
use serde::{Serialize,Deserialize};

use crate::types::{ChallengeClaims,PassKeyProxyState};

#[derive(Debug, Serialize, Deserialize)]
pub struct GenChallengeReply {
  token: String
}

pub async fn gen_challenge(Extension(state): Extension<PassKeyProxyState>, XRealIp(ip): XRealIp) -> Json<GenChallengeReply> {
  let claims = ChallengeClaims {
    client_ip: ip,
    exp: get_current_timestamp() + 120,
  };
  let token = encode(&Header::default(), &claims, &state.encoding_key).unwrap();

  println!("gen challenge for {0}, {1}", ip, token);
  Json(GenChallengeReply { token })
}
