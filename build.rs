use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn runner_bin_name(target: &str) -> &'static str {
    if target.contains("windows") {
        "oakbuild-runner.exe"
    } else {
        "oakbuild-runner"
    }
}

fn profile_dir_name(profile: &str) -> &'static str {
    if profile == "release" {
        "release"
    } else {
        "debug"
    }
}

fn copy_embedded_runner(source: &Path, dest: &Path) {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).expect("failed to create embedded runner output dir");
    }
    fs::copy(source, dest).expect("failed to copy embedded runner binary");
}

fn main() {
    println!("cargo:rerun-if-changed=src/bin/oakbuild-runner.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");

    if env::var_os("OAKBUILD_EMBEDDED_RUNNER_BUILD").is_some() {
        return;
    }

    let target = env::var("TARGET").expect("TARGET is not set");
    let profile = env::var("PROFILE").expect("PROFILE is not set");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));

    let nested_target_dir = out_dir.join("embedded-runner-target");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let mut cmd = Command::new(cargo);
    cmd.current_dir(&manifest_dir)
        .env("OAKBUILD_EMBEDDED_RUNNER_BUILD", "1")
        .env("CARGO_TARGET_DIR", &nested_target_dir)
        .arg("build")
        .arg("--bin")
        .arg("oakbuild-runner")
        .arg("--features")
        .arg("internal-runner")
        .arg("--target")
        .arg(&target);

    if profile == "release" {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("failed to spawn nested cargo build for oakbuild-runner");
    assert!(status.success(), "failed to build embedded oakbuild-runner binary");

    let source_runner = nested_target_dir
        .join(&target)
        .join(profile_dir_name(&profile))
        .join(runner_bin_name(&target));

    assert!(
        source_runner.exists(),
        "embedded runner binary not found at {}",
        source_runner.display()
    );

    let embedded_runner_path = out_dir.join("oakbuild-runner.embedded");
    copy_embedded_runner(&source_runner, &embedded_runner_path);

    println!(
        "cargo:rustc-env=OAKBUILD_EMBEDDED_RUNNER_PATH={}",
        embedded_runner_path.display()
    );
}
