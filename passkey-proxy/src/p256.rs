use p256::{ecdsa::{VerifyingKey, signature::Verifier, Signature}};
use p256::pkcs8::DecodePublicKey;

pub fn verify_sig(pubkey: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
  let verifying_key = VerifyingKey::from_public_key_der(&pubkey[..]).unwrap();
  let signature = Signature::from_der(&signature[..]).unwrap();
  let result = verifying_key.verify(&message[..], &signature);
  println!("sig result: {0:#?}", result);
  match result {
    Ok(()) => { true }
    Err(_) => { false }
  }
}
