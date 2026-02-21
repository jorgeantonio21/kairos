{
  description = "Kairos – high-performance consensus node";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Rust toolchains
        rustStable = pkgs.rust-bin.stable."1.90.0".default.override {
          extensions = [ "rust-src" "clippy" ];
        };
        rustNightly = pkgs.rust-bin.nightly."2025-09-19".default.override {
          extensions = [ "rustfmt" ];
        };

        src = pkgs.lib.cleanSource ./.;

        # Import modules from nix/
        kairos-node = import ./nix/package.nix { inherit pkgs src; };
        dockerImage = import ./nix/docker.nix { inherit pkgs kairos-node; };

      in {
        devShells.default = import ./nix/devshell.nix {
          inherit pkgs rustStable rustNightly;
        };

        packages = {
          default = kairos-node;
          dockerImage = dockerImage;
        };
      }
    );
}
