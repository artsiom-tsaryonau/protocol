//! Embed the commit this binary is built from, so `solidus-noded --version` can
//! name the code a validator is running instead of leaving its file mtime as the
//! only datable fact about it.
//!
//! ⛔ IT RUNS ON EVERY BUILD, deliberately. With the usual `rerun-if-changed`
//! lines the script reruns only when git's HEAD moves, so an edit to any crate
//! that links into this binary would ship under the last clean commit's name:
//! false provenance, in the reassuring direction. Pointing `rerun-if-changed` at
//! a path that never exists makes cargo rerun it every time; the cost is
//! relinking this one leaf crate.
//!
//! `SOLIDUS_BUILD_COMMIT` wins when set, for a build from a tree with no `.git`.
//! With neither, the binary says "unknown" rather than guessing.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SOLIDUS_BUILD_COMMIT");
    println!("cargo:rerun-if-changed=.always-rerun-no-such-file");

    let commit = match std::env::var("SOLIDUS_BUILD_COMMIT") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => {
            // The consensus workspace root: every crate linked into this binary lives under it.
            let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
            let workspace = Path::new(&manifest).join("../..");
            match git(&workspace, &["rev-parse", "--short=12", "HEAD"]) {
                Some(sha) if sha.len() == 12 => {
                    // Tracked changes only: an untracked scratch file is not in the binary.
                    let dirty = git(
                        &workspace,
                        &["status", "--porcelain", "--untracked-files=no", "--", "."],
                    )
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                    if dirty {
                        format!("{sha}, tree modified")
                    } else {
                        sha
                    }
                }
                _ => "unknown".to_string(),
            }
        }
    };
    println!("cargo:rustc-env=SOLIDUS_BUILD_COMMIT={commit}");
}
