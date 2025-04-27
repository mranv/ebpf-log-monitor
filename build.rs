use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/log_monitor.bpf.c";

fn main() {
    // Setting the OUT_DIR env var
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let out_file = out.join("log_monitor.skel.rs");

    // Only rebuild if source file changed
    println!("cargo:rerun-if-changed={}", SRC);

    // Building the BPF skeleton
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out_file)
        .expect("Failed to build and generate skeleton");
}
