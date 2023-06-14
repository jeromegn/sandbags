#[cfg(target_os = "linux")]
use std::os::unix::prelude::CommandExt;
use std::time::Instant;
use std::{io::BufRead, process::Command};
use std::{io::BufReader, process::Stdio};

use camino::Utf8PathBuf;
use libc::{prctl, PR_SET_PDEATHSIG, SIGTERM};
use structopt::StructOpt;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(StructOpt, Debug)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[structopt(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,

    /// Build the release target
    #[structopt(long)]
    pub release: bool,

    /// Set the target dir
    #[structopt(long)]
    pub target_dir: Utf8PathBuf,

    /// Sets the source directory
    #[structopt(long)]
    pub source_dir: Utf8PathBuf,
}

#[cfg(target_os = "linux")]
pub fn build_ebpf(opts: Options) -> eyre::Result<()> {
    use std::collections::HashSet;

    // we're now using nightly for the non-bpf and bpf parts of this repo
    // so we don't need to have separate `rust-toolchain.toml` files, and
    // we can use `CARGO` from the environment
    let mut cmd = Command::new("cargo");

    cmd.arg("+nightly");

    cmd.arg("build");
    cmd.arg("--verbose");

    cmd.arg("--target");
    cmd.arg(opts.target.to_string());

    cmd.arg("-Z");
    cmd.arg("build-std=core");

    if opts.release {
        cmd.arg("--release");
    }

    cmd.arg("--target-dir");
    cmd.arg(opts.target_dir.as_str());

    unsafe {
        // no matter what happens, we want that cargo to die when the parent cargo dies
        cmd.pre_exec(|| match prctl(PR_SET_PDEATHSIG, SIGTERM) {
            -1 => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "prctl failed",
            )),
            _ => Ok(()),
        });
    }

    cmd.current_dir(&opts.source_dir);

    // Sanitize environment. In particular, don't inherit `RUSTFLAGS`: these may
    // have been set from the workspace's `.cargo/config.toml`
    cmd.env_clear();
    let allowlist: HashSet<&'static str> =
        ["PATH", "RUSTUP_HOME", "CARGO_HOME"].into_iter().collect();

    let mut ignored = vec![];
    for (k, v) in std::env::vars() {
        if allowlist.contains(k.as_str()) {
            println!("export {k}={v}");
            cmd.env(k, v);
        } else {
            ignored.push(k);
        }
    }
    println!("Ignored env vars: {}", ignored.join(", "));

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    println!("cmd args: {:?}", cmd.get_args());

    let output = cmd.output().expect("failed to build bpf program");

    for line in BufReader::new(&output.stderr[..]).lines() {
        let line = line?;
        println!("[stderr] {line}");
    }
    for line in BufReader::new(&output.stdout[..]).lines() {
        let line = line?;
        println!("[stdout] {line}");
    }

    assert!(output.status.success());

    Ok(())
}

/// Helper function for Cargo build scripts to build eBPF programs created with aya
///
/// # Arguments
///
/// * `prog_name` - The name of your bpf program (e.g flycast). This helper makes assumptions
///    based on the prog_name, namely that the name of the crate containing the bpf logic is
///    of the format `{prog_name}-ebpf` (e.g flycast-ebpf)
#[cfg(target_os = "linux")]
pub fn build(prog_name: &str) {
    // cargo does its own caching
    println!("cargo:rerun-if-changed=..");

    let cargo_manifest_dir = Utf8PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("Cargo manifest dir: {cargo_manifest_dir}");

    let cargo_workspace_dir = cargo_manifest_dir.parent().unwrap().parent().unwrap();
    println!("Cargo workspace dir: {cargo_workspace_dir}");

    let default_cargo_target_dir = cargo_workspace_dir.join("target");
    println!("Default cargo target dir: {default_cargo_target_dir}");

    let env_cargo_target_dir: Option<Utf8PathBuf> = std::env::var("CARGO_TARGET_DIR")
        .ok()
        .map(Utf8PathBuf::from);

    let cargo_target_dir = env_cargo_target_dir.unwrap_or(default_cargo_target_dir);
    println!("Cargo target dir: {cargo_target_dir}");

    // build into a separate target to avoid deadlocks (child cargo waiting for
    // parent cargo to release lock)
    let target_dirname = format!("{prog_name}-ebpf-target");
    let target_dir = cargo_target_dir.join(target_dirname);

    println!("Our target dir is: {target_dir}");

    let crate_name = format!("{prog_name}-ebpf");
    let ebpf_source_dir = cargo_manifest_dir.parent().unwrap().join(crate_name);
    println!("Our ebpf source dir is: {ebpf_source_dir}");

    let arch = Architecture::BpfEl;
    let profile = std::env::var("PROFILE").unwrap();

    let start = Instant::now();

    build_ebpf(Options {
        target: arch,
        release: profile == "release",
        target_dir: target_dir.clone(),
        source_dir: ebpf_source_dir,
    })
    .expect("could not build BPF program");

    println!("Building took {:?}", start.elapsed());

    let object_path = target_dir
        .join(arch.to_string())
        .join(&profile)
        .join(prog_name);

    println!("Object path is: {object_path:?}");

    let out_dir = Utf8PathBuf::from(std::env::var("OUT_DIR").unwrap());
    println!("Out dir is {out_dir:?}");
    let final_object_path = out_dir.join(prog_name);

    std::fs::copy(object_path, final_object_path).unwrap();
}

#[cfg(target_os = "macos")]
pub fn build_ebpf(opts: Options) -> eyre::Result<()> {
    Ok(())
}
