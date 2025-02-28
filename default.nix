{ rustPlatform, ... }:
rustPlatform.buildRustPackage {
  name = "fabricbin";
  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };
}
