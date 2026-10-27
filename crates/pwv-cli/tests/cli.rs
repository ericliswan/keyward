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

/// `pwv <args>` on `vault`, answering the prompts with `answers`, one per line.
fn run(vault: &Path, args: &[&str], answers: &[&str]) -> assert_cmd::assert::Assert {
    pwv()
        .arg("--vault")
        .arg(vault)
        .arg("--password-stdin")
        .args(args)
        .write_stdin(answers.join("\n") + "\n")
        .assert()
}

fn init(vault: &Path, answers: &[&str], extra: &[&str]) -> assert_cmd::assert::Assert {
    run(vault, &[&["init"], extra].concat(), answers)
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
    // edit takes exactly one field flag.
    pwv().args(["edit", "mail"]).assert().code(2);
    pwv()
        .args(["edit", "mail", "--username", "--notes"])
        .assert()
        .code(2);
    pwv().args(["get", "mail", "--force"]).assert().code(2);
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

#[test]
#[cfg_attr(
    not(feature = "insecure-test-kdf"),
    ignore = "slow production KDF; run with --features insecure-test-kdf"
)]
fn added_entries_are_listed_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.pwv");
    init(&vault, &[MASTER, MASTER], &[]).success();
    let no_secrets = || {
        predicate::str::contains("s3cret")
            .or(predicate::str::contains("4321"))
            .not()
    };

    run(
        &vault,
        &["add", "mail.example"],
        &[MASTER, "alice", "s3cret-mail", "pin 4321"],
    )
    .success()
    .stdout("")
    .stderr(no_secrets());
    run(
        &vault,
        &["add", "Bank"],
        &[MASTER, "bob", "s3cret-bank", ""],
    )
    .success();
    run(&vault, &["add", "empty"], &[MASTER, "carol", ""])
        .code(1)
        .stderr(predicate::str::contains("must not be empty"));

    run(&vault, &["list"], &[MASTER])
        .success()
        .stdout("SITE          USERNAME\nBank          bob\nmail.example  alice\n")
        .stderr(no_secrets());
    run(&vault, &["list", "--search", "MAIL"], &[MASTER])
        .success()
        .stdout("SITE          USERNAME\nmail.example  alice\n");
    run(&vault, &["list", "--search", "nothing"], &[MASTER])
        .success()
        .stdout("");

    let unlocked = pwv_core::storage::unlock(&vault, &SecretString::from(MASTER)).unwrap();
    let mail = unlocked.vault.find("mail.example");
    assert_eq!(mail[0].password.expose(), "s3cret-mail");
    assert_eq!(mail[0].notes.expose(), "pin 4321");
}

#[test]
#[cfg_attr(
    not(feature = "insecure-test-kdf"),
    ignore = "slow production KDF; run with --features insecure-test-kdf"
)]
fn get_edit_and_delete_choose_among_matching_entries() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.pwv");
    init(&vault, &[MASTER, MASTER], &[]).success();
    run(
        &vault,
        &["add", "mail"],
        &[MASTER, "alice", "s3cret-alice", ""],
    )
    .success();
    run(&vault, &["add", "Mail"], &[MASTER, "bob", "s3cret-bob", ""]).success();
    let contains = predicate::str::contains;

    // stdout is a pipe here, so these are refused before the master password is read.
    run(&vault, &["get", "mail", "--show"], &[])
        .code(1)
        .stdout("")
        .stderr(contains("--force"));
    run(&vault, &["get", "mail"], &[])
        .code(1)
        .stderr(contains("--show"));
    run(
        &vault,
        &["get", "mail", "--show", "--force"],
        &[MASTER, "2"],
    )
    .success()
    .stdout("s3cret-bob\n")
    .stderr(
        contains("1) mail  alice")
            .and(contains("2) Mail  bob"))
            .and(contains("s3cret").not()),
    );
    run(&vault, &["get", "web", "--show", "--force"], &[MASTER])
        .code(1)
        .stderr(contains("no entry for web"));

    run(
        &vault,
        &["edit", "mail", "--password"],
        &[MASTER, "1", "n3w-alice"],
    )
    .success()
    .stderr(contains("n3w").not());
    run(
        &vault,
        &["edit", "mail", "--notes"],
        &[MASTER, "1", "pin 9876"],
    )
    .success()
    .stderr(contains("9876").not());
    run(
        &vault,
        &["edit", "mail", "--username"],
        &[MASTER, "2", "robert"],
    )
    .success();
    run(&vault, &["edit", "mail", "--password"], &[MASTER, "1", ""])
        .code(1)
        .stderr(contains("must not be empty"));
    let unlocked = pwv_core::storage::unlock(&vault, &SecretString::from(MASTER)).unwrap();
    let found = unlocked.vault.find("mail");
    let (alice, robert) = (found[0], found[1]);
    assert_eq!(alice.password.expose(), "n3w-alice");
    assert_eq!(alice.notes.expose(), "pin 9876");
    assert!(alice.updated_at > alice.created_at);
    assert_eq!(robert.username, "robert");
    assert_eq!(robert.password.expose(), "s3cret-bob");

    let both = "SITE  USERNAME\nmail  alice\nMail  robert\n";
    run(&vault, &["delete", "mail"], &[MASTER, "1", "n"])
        .success()
        .stderr(contains("Nothing deleted"));
    run(&vault, &["list"], &[MASTER]).stdout(both);
    run(&vault, &["delete", "mail"], &[MASTER, "1", "YES"]).success();
    run(&vault, &["list"], &[MASTER]).stdout("SITE  USERNAME\nMail  robert\n");
    // One match left, so --yes deletes it without asking which or whether.
    run(&vault, &["delete", "mail", "--yes"], &[MASTER]).success();
    run(&vault, &["list"], &[MASTER]).stdout("");
}
