# Package derivation for the Kairos node binary
{ pkgs, src }:

let
  linuxOnlyDeps = pkgs.lib.optionals pkgs.stdenv.isLinux [
    pkgs.libbsd
    pkgs.libuuid
  ];

in pkgs.rustPlatform.buildRustPackage {
  pname = "kairos-node";
  version =
    let
      cargoToml = builtins.fromTOML (builtins.readFile "${src}/node/Cargo.toml");
    in
      cargoToml.package.version;

  inherit src;
  cargoLock.lockFile = "${src}/Cargo.lock";

  nativeBuildInputs = [ pkgs.pkg-config pkgs.protobuf pkgs.libclang ];
  buildInputs = [ pkgs.openssl ] ++ linuxOnlyDeps;

  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";

  cargoBuildFlags = [ "--package" "node" ];
  doCheck = false;

  meta = with pkgs.lib; {
    description = "Kairos consensus validator node";
    license = licenses.asl20;
    mainProgram = "node";
  };
}
