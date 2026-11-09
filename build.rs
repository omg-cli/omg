fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_PGP").is_some()
        && matches!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("linux"))
    {
        // Keep bundled OpenSSL symbols private from native libraries using another ABI.
        println!("cargo:rustc-link-arg=-Wl,--exclude-libs,ALL");
    }
}
