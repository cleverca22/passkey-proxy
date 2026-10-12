{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "passkey-proxy";
  version = "0.0.1";
  src = ./.;
  cargoLock.lockFile = ./Cargo.lock;
}
