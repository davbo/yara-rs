with import <nixpkgs> {
  overlays = map (uri: import (fetchTarball uri)) [
    https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz
  ];
};

stdenv.mkDerivation {
  name = "rust-env";
  nativeBuildInputs = [
    nodejs
    wasm-pack
  ];
  buildInputs = [
    # Example Run-time Additional Dependencies
    (latest.rustChannels.nightly.rust.override {
      targets = ["wasm32-unknown-unknown"];
    })
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;
  NO_HEADLESS = 1;
}
