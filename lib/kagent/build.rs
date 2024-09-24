use anyhow::Result;
use tonic_build::configure;

fn main() -> Result<()> {
    configure()
        .build_client(false)
        .include_file("schema.rs")
        .compile(&["schema/service.proto"], &["schema"])?;
    Ok(())
}
