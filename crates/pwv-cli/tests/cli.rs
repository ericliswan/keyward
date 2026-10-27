//! Runs the real `pwv` binary.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::SecretString;

const MASTER: &str = "glacier trombone pickle verdict";

fn pwv() -> Command {
    Command::cargo_bin("pwv").unwrap()
}

/// `pwv init` on `vault`, answering the prompts with `answers`, one per line.
fn init(vault: &Path, answers: &[&str], extra: &[&str]) -> assert_cmd::assert::Assert {
    pwv()
        .arg("--vault")
        .arg(vault)
        .args(["--password-stdin", "init"])
        .args(extra)
        .write_stdin(answers.join("\n") + "\n")
        .assert()
}

#[test]
fn help_lists_every_command() {
    let assert = pwv().arg("--help").assert().success();
    let mut out = predicate::str::contains("init").boxed();
    for cmd in [
        "add",
        "get",
        "list",
        "edit",
        "delete",
        "change-master",
        "gen",
    ] {
        out = out.and(predicate::str::contains(cmd)).boxed();
    }
    assert.stdout(out);
}

#[test]
fn help_marks_password_stdin_as_automation_only() {
    pwv().arg("--help").assert().success().stdout(
        predicate::str::contains("--password-stdin").and(predicate::str::contains("automation")),
    );
}

#[test]
fn version_prints_the_crate_version() {
    pwv()
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("pwv {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn usage_errors_exit_2() {
    pwv().arg("frobnicate").assert().code(2);
    pwv().assert().code(2);
}

#[test]
#[cfg_attr(
    not(feature = "insecure-test-kdf"),
    ignore = "slow production KDF; run with --features insecure-test-kdf"
)]
fn init_creates_a_vault_that_unlocks_with_the_master_password() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.pwv");
    init(&vault, &[MASTER, MASTER], &[]).success().stdout("");
    let unlocked = pwv_core::storage::unlock(&vault, &SecretString::from(MASTER)).unwrap();
    assert!(unlocked.vault.entries.is_empty());
}

#[test]
#[cfg_attr(
    not(feature = "insecure-test-kdf"),
    ignore = "slow production KDF; run with --features insecure-test-kdf"
)]
fn init_refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.pwv");
    init(&vault, &[MASTER, MASTER], &[]).success();
    let original = fs::read(&vault).unwrap();

    init(&vault, &[], &[])
        .code(1)
        .stderr(predicate::str::contains("--force"));
    assert_eq!(fs::read(&vault).unwrap(), original);

    init(&vault, &[MASTER, MASTER], &["--force"]).success();
    assert_ne!(fs::read(&vault).unwrap(), original);
    assert_eq!(
        fs::read(dir.path().join("vault.pwv.bak")).unwrap(),
        original
    );
}

#[test]
#[cfg_attr(
    not(feature = "insecure-test-kdf"),
    ignore = "slow production KDF; run with --features insecure-test-kdf"
)]
fn init_rejects_mismatched_or_weak_passwords_without_echoing_them() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.pwv");
    let other = "glacier trombone pickle verdicts";
    init(&vault, &[MASTER, other], &[]).code(1).stderr(
        predicate::str::contains("do not match").and(predicate::str::contains("glacier").not()),
    );
    init(&vault, &["letmeinletmein", "letmeinletmein"], &[])
        .code(1)
        .stderr(
            predicate::str::contains("too weak").and(predicate::str::contains("letmein").not()),
        );
    assert!(!vault.exists());
}
