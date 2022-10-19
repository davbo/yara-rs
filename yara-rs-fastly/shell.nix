{ pkgs ? import <nixpkgs> {} }:
with pkgs;

stdenv.mkDerivation {
  name = "rust-env";
  nativeBuildInputs = [
  ];
  buildInputs = [
    rustup
    libiconv
    wasm-pack
    fastly
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;
  NO_HEADLESS = 1;
}
