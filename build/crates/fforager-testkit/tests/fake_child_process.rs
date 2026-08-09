use std::{
    io::Write,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const WAIT_LIMIT: Duration = Duration::from_secs(5);

fn fake_child() -> &'static str {
    env!("CARGO_BIN_EXE_fforager-fake-child")
}

fn wait_bounded(mut child: Child) -> Output {
    let started = Instant::now();
    loop {
        match child
            .try_wait()
            .expect("fake-child wait must be observable")
        {
            Some(_) => {
                return child
                    .wait_with_output()
                    .expect("fake-child output must collect");
            }
            None if started.elapsed() < WAIT_LIMIT => thread::sleep(Duration::from_millis(10)),
            None => {
                child
                    .kill()
                    .expect("test may terminate only the fake child it started");
                let output = child
                    .wait_with_output()
                    .expect("terminated fake-child output must collect");
                panic!(
                    "fake child exceeded {WAIT_LIMIT:?}: status={:?} stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

#[test]
fn spawned_progress_preserves_stdout_stderr_and_exit_boundaries() {
    let child = Command::new(fake_child())
        .args([
            "progress-flood",
            "--records",
            "3",
            "--payload-bytes",
            "2",
            "--delay-ms",
            "0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("fake-child binary must spawn directly without a shell");
    let output = wait_bounded(child);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let progress = String::from_utf8(output.stdout).expect("progress fixture must be UTF-8");
    assert_eq!(progress.matches("progress=continue\n").count(), 2);
    assert_eq!(progress.matches("progress=end\n").count(), 1);
    assert!(progress.ends_with("progress=end\n"));
}

#[test]
fn spawned_control_requires_one_exact_line_and_closed_input() {
    let mut child = Command::new(fake_child())
        .args([
            "control-delay",
            "--delay-ms",
            "0",
            "--max-control-bytes",
            "16",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("fake-child binary must spawn directly without a shell");
    child
        .stdin
        .take()
        .expect("piped stdin must exist")
        .write_all(b"stop\n")
        .expect("bounded command write must succeed");
    let output = wait_bounded(child);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"control=acknowledged\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("FFORAGER_FAKE_CHILD_CONTROL_READY")
    );

    let mut child = Command::new(fake_child())
        .args([
            "control-delay",
            "--delay-ms",
            "0",
            "--max-control-bytes",
            "16",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("negative fake-child binary must spawn");
    child
        .stdin
        .take()
        .expect("piped stdin must exist")
        .write_all(b"stop\njunk\n")
        .expect("bounded counterexample write must succeed");
    let output = wait_bounded(child);
    assert_eq!(output.status.code(), Some(65));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must end after"));
}
