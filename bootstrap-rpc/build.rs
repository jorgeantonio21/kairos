fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/bootstrap/v1/bootstrap.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/");
    Ok(())
}
