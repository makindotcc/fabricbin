{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    in
    {
      packages = nixpkgs.lib.genAttrs supportedSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        rec {
          fabricbin = pkgs.callPackage ./default.nix { };
          default = fabricbin;
        }
      );
    };
}
