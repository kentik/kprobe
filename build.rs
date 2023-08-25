use std::env;
use std::path::PathBuf;
use anyhow::Result;
use git2::{DescribeOptions, Repository};
use platforms::{Platform, target::Env, target::OS};

fn main() -> Result<()> {
    let base     = env::var("CARGO_MANIFEST_DIR")?;
    let target   = env::var("TARGET")?;
    let platform = Platform::find(&target).unwrap();

    let repo = Repository::open_from_env()?;
    let head = repo.head()?;

    if let Some(name) = head.name() {
        let path = repo.path().join(name);
        let path = path.to_string_lossy();
        println!("cargo:rerun-if-changed={}", path);
    }

    let mut opts = DescribeOptions::new();
    opts.describe_all();
    opts.describe_tags();
    opts.show_commit_oid_as_fallback(true);

    let commit  = head.peel_to_commit()?;
    let hash    = commit.id();
    let desc    = repo.describe(&opts)?;
    let version = desc.format(None)?;

    println!("cargo:rustc-env=BUILD_VERSION={}", version);
    println!("cargo:rustc-env=BUILD_COMMIT={}", hash);
    println!("cargo:rustc-env=BUILD_ARCH={}", platform.target_arch.as_str());
    println!("cargo:rustc-env=BUILD_SYSTEM={}", platform.target_os.as_str());

    let mut libs = PathBuf::new();
    libs.push(base);
    libs.push("libs");
    libs.push(platform.target_arch.as_str());
    libs.push(platform.target_os.as_str());

    if platform.target_env != Env::None {
        libs.push(platform.target_env.as_str());
    }

    if platform.target_os == OS::MacOS {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }

    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native={}", libs.to_string_lossy());

    println!("cargo:rustc-link-lib=static=pcap");
    println!("cargo:rustc-link-lib=static=kflow");

    Ok(())
}
