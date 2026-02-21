# Minimal OCI Docker image for the Kairos node
{ pkgs, kairos-node }:

pkgs.dockerTools.buildLayeredImage {
  name = "kairos-node";
  tag = "latest";

  contents = [
    kairos-node
    pkgs.cacert          # TLS root certificates
    pkgs.busybox         # wget for health checks, minimal shell for debugging
  ];

  config = {
    Entrypoint = [ "${kairos-node}/bin/node" ];
    ExposedPorts = {
      "9090/tcp" = {};   # Prometheus metrics
      "9000/tcp" = {};   # P2P
      "50051/tcp" = {};  # gRPC
    };
    Env = [
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
    ];
  };
}
