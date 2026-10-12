//use spki::DecodePublicKey;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use ed25519_dalek::pkcs8::DecodePublicKey;

pub fn verify_sig(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> Option<bool> {
  let verifying_key = VerifyingKey::from_public_key_der(&pubkey[..]).ok()?;
  let sig = Signature::from_slice(&signature[..]).ok()?;
  let result = verifying_key.verify(&message[..], &sig);
  println!("pk {0:#?} {1:#?}", verifying_key, result);
  match result {
    Ok(()) => Some(true),
    Err(_) => Some(false),
  }
}
