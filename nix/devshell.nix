# Dev shell module
{ pkgs, rustStable, rustNightly }:

let
  linuxOnlyDeps = pkgs.lib.optionals pkgs.stdenv.isLinux [
    pkgs.libbsd
    pkgs.libuuid
  ];

  systemDeps = [
    pkgs.openssl
    pkgs.pkg-config
    pkgs.protobuf
    pkgs.libclang
  ] ++ linuxOnlyDeps;

  devTools = [
    pkgs.cargo-deny
    pkgs.git-cliff
    pkgs.taplo
  ];

in pkgs.mkShell {
  name = "kairos-dev";

  nativeBuildInputs = [ rustStable rustNightly ] ++ systemDeps ++ devTools;

  LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
  PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

  shellHook = ''
    echo "🚀 Kairos dev shell activated"
    echo "   rustc   $(rustc --version)"
    echo "   protoc  $(protoc --version)"
    echo "   cargo-deny $(cargo deny --version 2>&1 | head -1)"
  '';
}
