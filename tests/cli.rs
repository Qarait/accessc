use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn compile_writes_openssh_artifacts() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("accessc")
        .unwrap()
        .args(["compile", "examples/policy.yaml", "--out"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("compiled OpenSSH artifacts"));

    assert!(dir.path().join("ca/accessc_ca.pub").exists());
    assert!(dir.path().join("sshd/sshd_config.snippet").exists());
    assert!(dir.path().join("policy/compiled-policy.json").exists());
}

#[test]
fn plan_writes_safe_issuance_plan() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "plan",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "alice",
            "--out",
        ])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "planned OpenSSH certificate issuance",
        ));

    assert!(dir.path().join("ssh/issue-command.txt").exists());
    assert!(dir.path().join("ssh/config.snippet").exists());
}

#[test]
fn check_validates_policy() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args(["check", "examples/policy.yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("policy ok"));
}

#[test]
fn decide_returns_allow() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "decide",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--action",
            "ssh",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "alice",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("allow"));
}

#[test]
fn decide_denies_root() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "decide",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--action",
            "ssh",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "root",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("deny"));
}
