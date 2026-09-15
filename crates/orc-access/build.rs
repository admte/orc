fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/access.proto";
    println!("cargo:rerun-if-changed={proto}");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);
    // Forwarded payloads stay as refcounted slices when they cross the public
    // protocol boundary.
    config.bytes(["."]);
    tonic_prost_build::configure()
        .build_transport(false)
        .compile_with_config(config, &[proto], &["proto"])?;
    Ok(())
}
