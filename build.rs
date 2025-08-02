use std::env;
use std::path::PathBuf;

fn main() {
    // Print build information
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");

    // Note: In a real implementation, this would:
    // 1. Compile eBPF programs using aya-bpf
    // 2. Build kernel module if sources exist
    // 3. Generate bindings for kernel interfaces

    // For now, we'll just set some build flags
    println!("cargo:rustc-env=ANANSI_VERSION={}", env!("CARGO_PKG_VERSION"));

    // Check if kernel headers are available
    check_kernel_headers();
}

fn check_kernel_headers() {
    // Check if kernel headers are installed
    let kernel_headers = PathBuf::from("/lib/modules")
        .join(std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default())
        .join("build");

    if kernel_headers.exists() {
        println!("cargo:rustc-cfg=has_kernel_headers");
    } else {
        println!("cargo:warning=Kernel headers not found, some features may be unavailable");
    }
}