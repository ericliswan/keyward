//! Runs the real `pwv` binary.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

fn pwv() -> Command {
    Command::cargo_bin("pwv").unwrap()
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
