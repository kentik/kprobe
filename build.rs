use std::env;
use std::path::Path;

fn main() {
    let base = env::var("CARGO_MANIFEST_DIR").unwrap();

    let path = if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        Path::new(&base).join("libs/macos")
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=static=nl-3");
        println!("cargo:rustc-link-lib=static=nl-genl-3");
        println!("cargo:rustc-link-lib=static=pcap");
        Path::new(&base).join("libs/linux")
    } else {
        panic!("unsupported platform");
    };

    println!("cargo:rustc-link-search=native={}", path.display());
}
