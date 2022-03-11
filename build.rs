use std::env;
use std::path::PathBuf;
use anyhow::Result;
use platforms::{Platform, target::OS};

fn main() -> Result<()> {
    let base     = env::var("CARGO_MANIFEST_DIR")?;
    let target   = env::var("TARGET")?;
    let platform = Platform::find(&target).unwrap();

    let mut libs = PathBuf::new();
    libs.push(base);
    libs.push("libs");
    libs.push(platform.target_arch.as_str());
    libs.push(platform.target_os.as_str());

    if let Some(env) = platform.target_env {
        libs.push(env.as_str());
    }

    if platform.target_os == OS::MacOS {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    };

    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native={}", libs.to_string_lossy());

    println!("cargo:rustc-link-lib=static=pcap");
    println!("cargo:rustc-link-lib=static=kflow");


    Ok(())
}
