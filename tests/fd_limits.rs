//! Limit changes happen only in child processes, never in the parallel test runner.
use std::process::Command;

#[test]
fn raises_soft_limit_and_rejects_insufficient_hard_limit_in_subprocesses() {
    for mode in ["raise", "reject"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fd_limit_child", "--nocapture"])
            .env("GATEWAY_FD_TEST_CHILD", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn fd_limit_child() {
    let Ok(mode) = std::env::var("GATEWAY_FD_TEST_CHILD") else {
        return;
    };
    let limit = libc::rlimit {
        rlim_cur: 128,
        rlim_max: if mode == "raise" { 256 } else { 128 },
    };
    // SAFETY: this isolated subprocess owns this initialized rlimit; no parent limits change.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let result = credential_gateway::fd::ensure(32); // 64 proxy descriptors + 128 reserve.
    if mode == "raise" {
        let planned = result.unwrap();
        assert_eq!(
            (planned.previous_soft, planned.soft, planned.required),
            (128, 256, 192)
        );
        let mut actual = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: actual is writable and remains alive for the call.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut actual) },
            0
        );
        assert_eq!((actual.rlim_cur, actual.rlim_max), (256, 256));
    } else {
        assert!(result.unwrap_err().contains("hard limit is 128"));
    }
}
