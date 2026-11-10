// Records the compile-time target triple, so `middleman upgrade` downloads the release asset
// built for exactly this target.
fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=MIDDLEMAN_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
