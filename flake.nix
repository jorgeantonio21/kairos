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
        # Stable: includes cargo-fmt (via rustfmt component) for workspace discovery.
        # The RUSTFMT env var in devshell.nix overrides which rustfmt binary is used.
        rustStable = pkgs.rust-bin.stable."1.90.0".minimal.override {
          extensions = [ "rust-src" "rust-std" "clippy" "cargo" "rustc" "rustfmt" ];
        };
        # Nightly: only rustfmt (listed first so stable shadows cargo/rustc,
        # but nightly's rustfmt remains the only one on PATH)
        rustNightly = pkgs.rust-bin.nightly."2025-09-19".minimal.override {
          extensions = [ "rustfmt" ];
        };

        src = pkgs.lib.cleanSource ./.;

        # Import modules from nix/
        kairos-node = import ./nix/package.nix { inherit pkgs src; };
        isLinux = pkgs.stdenv.isLinux;
        dockerImage = if isLinux
          then import ./nix/docker.nix { inherit pkgs kairos-node; }
          else pkgs.writeTextFile {
            name = "docker-image-unsupported";
            text = "Docker images can only be built on Linux. Use: deployments/Dockerfile";
          };

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
