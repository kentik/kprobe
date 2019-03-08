use std::env;
use std::path::Path;

fn main() {
    let base = env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = env::var("TARGET").unwrap();

    let path = if target.contains("darwin") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        Path::new(&base).join("libs/macos")
    } else if target.contains("linux-musl") {
        Path::new(&base).join("libs/linux-musl")
    } else if target.contains("linux") {
        Path::new(&base).join("libs/linux")
    } else {
        panic!("unsupported platform");
    };

    println!("cargo:rustc-link-search=native={}", path.display());
    println!("cargo:rustc-link-lib=static=pcap");
    println!("cargo:rustc-link-lib=static=kflow");
}
