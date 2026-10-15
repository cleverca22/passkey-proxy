use p256::{ecdsa::{VerifyingKey, signature::Verifier, Signature}};
use p256::pkcs8::DecodePublicKey;

pub fn verify_sig(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Option<bool> {
  let verifying_key = VerifyingKey::from_public_key_der(pubkey).ok()?;
  let signature = Signature::from_der(signature).ok()?;
  let result = verifying_key.verify(message, &signature);
  println!("sig result: {0:#?}", result);
  match result {
    Ok(()) => Some(true),
    Err(_) => Some(false),
  }
}
