{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
  flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import nixpkgs { inherit system; };
  in {
    packages.default = pkgs.callPackage ./passkey-proxy {};
    devShells.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        rustc
        cargo
        openssl
        pkg-config
        bacon
      ];
    };
  });
}
