with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "rust-env";
  nativeBuildInputs = [
    rustc cargo
  ];
  buildInputs = [
    # Example Run-time Additional Dependencies
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;
}
