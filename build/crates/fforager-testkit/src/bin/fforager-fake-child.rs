//! Deterministic, bounded subprocess behaviors for FFmpeg-supervisor tests.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const EXIT_USAGE: u8 = 64;
const EXIT_DATA_ERROR: u8 = 65;
const EXIT_NO_INPUT: u8 = 66;
const EXIT_IO_ERROR: u8 = 74;
const EXIT_CONFIGURATION: u8 = 78;

const DEFAULT_FLOOD_RECORDS: u32 = 256;
const DEFAULT_PAYLOAD_BYTES: u32 = 128;
const DEFAULT_STALL_MS: u64 = 1_000;
const DEFAULT_CONTROL_DELAY_MS: u64 = 250;
const DEFAULT_CONTROL_WINDOW_MS: u64 = 1_000;
const DEFAULT_PARTIAL_OUTPUT_BYTES: u64 = 257;
const DEFAULT_CRASH_EXIT_CODE: u8 = 17;
const DEFAULT_PARTIAL_EXIT_CODE: u8 = 18;
const DEFAULT_MAX_CONTROL_BYTES: usize = 64;

const MAX_FLOOD_RECORDS: u32 = 8_192;
const MAX_PAYLOAD_BYTES: u32 = 4_096;
const MAX_TOTAL_FLOOD_PAYLOAD_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_TOTAL_FLOOD_DELAY_MS: u64 = 60_000;
const MAX_DELAY_MS: u64 = 60_000;
const MAX_PARTIAL_OUTPUT_BYTES: u64 = 16 * 1_024 * 1_024;
const MAX_CONTROL_BYTES: usize = 4_096;
const REPEATED_BYTE_CHUNK: usize = 1_024;

const HELP: &str = "\
Usage: fforager-fake-child <mode> [options]\n\
\n\
Modes:\n\
  clean-exit                 Exit zero after an optional delay.\n\
  crash                      Exit with a configured nonzero code.\n\
  progress-flood             Emit bounded FFmpeg-like progress records to stdout.\n\
  progress-malformed         Emit one deterministic malformed progress record.\n\
  progress-truncated         Emit a progress record without its terminator.\n\
  progress-stall             Emit a prefix, pause, then finish the record.\n\
  stderr-flood               Emit bounded diagnostic records to stderr.\n\
  control-delay              Delay reading one exact `stop` line plus EOF, then acknowledge.\n\
  control-ignore             Never read stdin during a bounded control window.\n\
  partial-output             Create a new bounded partial file, then fail.\n\
  stale-output               Leave an existing regular file untouched, then exit zero.\n\
  descendant                Explicitly unsupported until the platform fixture is approved.\n\
  setsid-escape              Explicitly unsupported until the Unix fixture is approved.\n\
  windows-handle-inheritance Explicitly unsupported until the Windows fixture is approved.\n\
\n\
Common numeric options are decimal integers and reject duplicates or unknown flags.\n\
Use `fforager-fake-child --help` for this text.\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MalformedKind {
    MissingEquals,
    InvalidUtf8,
    InvalidProgress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnsupportedKind {
    Descendant,
    SetsidEscape,
    WindowsHandleInheritance,
}

#[derive(Debug, Eq, PartialEq)]
enum Mode {
    Help,
    CleanExit {
        delay_ms: u64,
    },
    Crash {
        delay_ms: u64,
        exit_code: u8,
    },
    ProgressFlood {
        records: u32,
        payload_bytes: u32,
        delay_ms: u64,
    },
    ProgressMalformed {
        kind: MalformedKind,
    },
    ProgressTruncated,
    ProgressStall {
        stall_ms: u64,
    },
    StderrFlood {
        records: u32,
        payload_bytes: u32,
        delay_ms: u64,
    },
    ControlDelay {
        delay_ms: u64,
        max_control_bytes: usize,
    },
    ControlIgnore {
        duration_ms: u64,
    },
    PartialOutput {
        output: PathBuf,
        bytes: u64,
        exit_code: u8,
    },
    StaleOutput {
        output: PathBuf,
    },
    Unsupported(UnsupportedKind),
}

#[derive(Debug)]
struct AppError {
    exit_code: u8,
    diagnostic: String,
}

impl AppError {
    fn usage(diagnostic: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_USAGE,
            diagnostic: diagnostic.into(),
        }
    }

    fn data(diagnostic: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_DATA_ERROR,
            diagnostic: diagnostic.into(),
        }
    }

    fn io(context: &str, error: &io::Error) -> Self {
        Self {
            exit_code: EXIT_IO_ERROR,
            diagnostic: format!("{context}: {error}"),
        }
    }
}

fn main() -> ExitCode {
    let mode = match parse_args(env::args_os().skip(1)) {
        Ok(mode) => mode,
        Err(error) => return report_error(&error),
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut diagnostics = stderr.lock();

    match run_mode(mode, &mut input, &mut output, &mut diagnostics) {
        Ok(exit_code) => ExitCode::from(exit_code),
        Err(error) => report_error_to(&error, &mut diagnostics),
    }
}

fn report_error(error: &AppError) -> ExitCode {
    report_error_to(error, &mut io::stderr().lock())
}

fn report_error_to(error: &AppError, diagnostics: &mut impl Write) -> ExitCode {
    let _ignored = writeln!(
        diagnostics,
        "FFORAGER_FAKE_CHILD_ERROR code={} diagnostic={}",
        error.exit_code, error.diagnostic
    );
    ExitCode::from(error.exit_code)
}

#[expect(
    clippy::too_many_lines,
    reason = "WP-FF-010-ffmpeg-supervision-spike-v1-AC-004 keeps one exhaustive mode-to-option allowlist"
)]
fn parse_args(arguments: impl Iterator<Item = OsString>) -> Result<Mode, AppError> {
    let mut arguments = arguments;
    let raw_mode = arguments
        .next()
        .ok_or_else(|| AppError::usage("missing mode"))?;
    let mode = text_argument(raw_mode, "mode")?;
    if mode == "--help" {
        if arguments.next().is_some() {
            return Err(AppError::usage("--help accepts no additional arguments"));
        }
        return Ok(Mode::Help);
    }

    let mut options = parse_options(arguments)?;
    let parsed = match mode.as_str() {
        "clean-exit" => Mode::CleanExit {
            delay_ms: take_u64(&mut options, "--delay-ms", 0, 0, MAX_DELAY_MS)?,
        },
        "crash" => Mode::Crash {
            delay_ms: take_u64(&mut options, "--delay-ms", 0, 0, MAX_DELAY_MS)?,
            exit_code: take_u8_nonzero(&mut options, "--exit-code", DEFAULT_CRASH_EXIT_CODE)?,
        },
        "progress-flood" => {
            let records = take_u32(
                &mut options,
                "--records",
                DEFAULT_FLOOD_RECORDS,
                1,
                MAX_FLOOD_RECORDS,
            )?;
            let payload_bytes = take_u32(
                &mut options,
                "--payload-bytes",
                DEFAULT_PAYLOAD_BYTES,
                0,
                MAX_PAYLOAD_BYTES,
            )?;
            let delay_ms = take_u64(&mut options, "--delay-ms", 0, 0, MAX_DELAY_MS)?;
            validate_flood_bounds(records, payload_bytes, delay_ms)?;
            Mode::ProgressFlood {
                records,
                payload_bytes,
                delay_ms,
            }
        }
        "progress-malformed" => Mode::ProgressMalformed {
            kind: take_malformed_kind(&mut options)?,
        },
        "progress-truncated" => Mode::ProgressTruncated,
        "progress-stall" => Mode::ProgressStall {
            stall_ms: take_u64(
                &mut options,
                "--stall-ms",
                DEFAULT_STALL_MS,
                1,
                MAX_DELAY_MS,
            )?,
        },
        "stderr-flood" => {
            let records = take_u32(
                &mut options,
                "--records",
                DEFAULT_FLOOD_RECORDS,
                1,
                MAX_FLOOD_RECORDS,
            )?;
            let payload_bytes = take_u32(
                &mut options,
                "--payload-bytes",
                DEFAULT_PAYLOAD_BYTES,
                0,
                MAX_PAYLOAD_BYTES,
            )?;
            let delay_ms = take_u64(&mut options, "--delay-ms", 0, 0, MAX_DELAY_MS)?;
            validate_flood_bounds(records, payload_bytes, delay_ms)?;
            Mode::StderrFlood {
                records,
                payload_bytes,
                delay_ms,
            }
        }
        "control-delay" => Mode::ControlDelay {
            delay_ms: take_u64(
                &mut options,
                "--delay-ms",
                DEFAULT_CONTROL_DELAY_MS,
                0,
                MAX_DELAY_MS,
            )?,
            max_control_bytes: take_usize(
                &mut options,
                "--max-control-bytes",
                DEFAULT_MAX_CONTROL_BYTES,
                5,
                MAX_CONTROL_BYTES,
            )?,
        },
        "control-ignore" => Mode::ControlIgnore {
            duration_ms: take_u64(
                &mut options,
                "--duration-ms",
                DEFAULT_CONTROL_WINDOW_MS,
                1,
                MAX_DELAY_MS,
            )?,
        },
        "partial-output" => Mode::PartialOutput {
            output: take_path(&mut options, "--output")?,
            bytes: take_u64(
                &mut options,
                "--bytes",
                DEFAULT_PARTIAL_OUTPUT_BYTES,
                1,
                MAX_PARTIAL_OUTPUT_BYTES,
            )?,
            exit_code: take_u8_nonzero(&mut options, "--exit-code", DEFAULT_PARTIAL_EXIT_CODE)?,
        },
        "stale-output" => Mode::StaleOutput {
            output: take_path(&mut options, "--output")?,
        },
        "descendant" => Mode::Unsupported(UnsupportedKind::Descendant),
        "setsid-escape" => Mode::Unsupported(UnsupportedKind::SetsidEscape),
        "windows-handle-inheritance" => {
            Mode::Unsupported(UnsupportedKind::WindowsHandleInheritance)
        }
        _ => return Err(AppError::usage(format!("unknown mode `{mode}`"))),
    };
    reject_unused_options(&options)?;
    Ok(parsed)
}

fn parse_options(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<BTreeMap<String, OsString>, AppError> {
    let mut options = BTreeMap::new();
    while let Some(raw_name) = arguments.next() {
        let name = text_argument(raw_name, "option name")?;
        if !name.starts_with("--") || name.len() == 2 || name.contains('=') {
            return Err(AppError::usage(format!("invalid option name `{name}`")));
        }
        let value = arguments
            .next()
            .ok_or_else(|| AppError::usage(format!("option `{name}` requires a value")))?;
        if options.insert(name.clone(), value).is_some() {
            return Err(AppError::usage(format!("duplicate option `{name}`")));
        }
    }
    Ok(options)
}

fn text_argument(value: OsString, kind: &str) -> Result<String, AppError> {
    value
        .into_string()
        .map_err(|_| AppError::usage(format!("{kind} must be valid Unicode")))
}

fn take_text(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
) -> Result<Option<String>, AppError> {
    options
        .remove(name)
        .map(|value| text_argument(value, name))
        .transpose()
}

fn take_u64(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, AppError> {
    let Some(text) = take_text(options, name)? else {
        return Ok(default);
    };
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::usage(format!(
            "option `{name}` must be an unsigned decimal integer"
        )));
    }
    let value = text
        .parse::<u64>()
        .map_err(|_| AppError::usage(format!("option `{name}` is out of range")))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(AppError::usage(format!(
            "option `{name}` must be in {minimum}..={maximum}"
        )));
    }
    Ok(value)
}

fn take_u32(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> Result<u32, AppError> {
    let value = take_u64(
        options,
        name,
        u64::from(default),
        u64::from(minimum),
        u64::from(maximum),
    )?;
    u32::try_from(value).map_err(|_| AppError::usage(format!("option `{name}` is out of range")))
}

fn take_usize(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, AppError> {
    let value = take_u64(
        options,
        name,
        u64::try_from(default).unwrap_or(u64::MAX),
        u64::try_from(minimum).unwrap_or(u64::MAX),
        u64::try_from(maximum).unwrap_or(u64::MAX),
    )?;
    usize::try_from(value).map_err(|_| AppError::usage(format!("option `{name}` is out of range")))
}

fn take_u8_nonzero(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
    default: u8,
) -> Result<u8, AppError> {
    let value = take_u64(options, name, u64::from(default), 1, u64::from(u8::MAX))?;
    u8::try_from(value).map_err(|_| AppError::usage(format!("option `{name}` is out of range")))
}

fn take_path(options: &mut BTreeMap<String, OsString>, name: &str) -> Result<PathBuf, AppError> {
    let value = options
        .remove(name)
        .ok_or_else(|| AppError::usage(format!("missing required option `{name}`")))?;
    if value.is_empty() {
        return Err(AppError::usage(format!("option `{name}` cannot be empty")));
    }
    Ok(PathBuf::from(value))
}

fn take_malformed_kind(
    options: &mut BTreeMap<String, OsString>,
) -> Result<MalformedKind, AppError> {
    match take_text(options, "--kind")?.as_deref() {
        None | Some("missing-equals") => Ok(MalformedKind::MissingEquals),
        Some("invalid-utf8") => Ok(MalformedKind::InvalidUtf8),
        Some("invalid-progress") => Ok(MalformedKind::InvalidProgress),
        Some(other) => Err(AppError::usage(format!(
            "option `--kind` has unsupported value `{other}`"
        ))),
    }
}

fn reject_unused_options(options: &BTreeMap<String, OsString>) -> Result<(), AppError> {
    if let Some(name) = options.keys().next() {
        return Err(AppError::usage(format!("unknown option `{name}`")));
    }
    Ok(())
}

fn validate_flood_bounds(records: u32, payload_bytes: u32, delay_ms: u64) -> Result<(), AppError> {
    let total = u64::from(records)
        .checked_mul(u64::from(payload_bytes))
        .ok_or_else(|| AppError::usage("flood payload multiplication overflow"))?;
    if total > MAX_TOTAL_FLOOD_PAYLOAD_BYTES {
        return Err(AppError::usage(format!(
            "flood payload must not exceed {MAX_TOTAL_FLOOD_PAYLOAD_BYTES} bytes"
        )));
    }
    let total_delay = u64::from(records)
        .checked_mul(delay_ms)
        .ok_or_else(|| AppError::usage("flood delay multiplication overflow"))?;
    if total_delay > MAX_TOTAL_FLOOD_DELAY_MS {
        return Err(AppError::usage(format!(
            "flood cumulative delay must not exceed {MAX_TOTAL_FLOOD_DELAY_MS} milliseconds"
        )));
    }
    Ok(())
}

fn run_mode(
    mode: Mode,
    input: &mut impl Read,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<u8, AppError> {
    match mode {
        Mode::Help => {
            output
                .write_all(HELP.as_bytes())
                .map_err(|error| AppError::io("write help", &error))?;
            Ok(0)
        }
        Mode::CleanExit { delay_ms } => {
            sleep_ms(delay_ms);
            Ok(0)
        }
        Mode::Crash {
            delay_ms,
            exit_code,
        } => {
            sleep_ms(delay_ms);
            Ok(exit_code)
        }
        Mode::ProgressFlood {
            records,
            payload_bytes,
            delay_ms,
        } => run_progress_flood(output, records, payload_bytes, delay_ms),
        Mode::ProgressMalformed { kind } => run_progress_malformed(output, kind),
        Mode::ProgressTruncated => {
            output
                .write_all(b"frame=0\nout_time_us=")
                .map_err(|error| AppError::io("write truncated progress", &error))?;
            output
                .flush()
                .map_err(|error| AppError::io("flush truncated progress", &error))?;
            Ok(0)
        }
        Mode::ProgressStall { stall_ms } => {
            output
                .write_all(b"frame=0\n")
                .and_then(|()| output.flush())
                .map_err(|error| AppError::io("write progress stall prefix", &error))?;
            sleep_ms(stall_ms);
            output
                .write_all(b"out_time_us=0\nprogress=end\n")
                .and_then(|()| output.flush())
                .map_err(|error| AppError::io("finish progress stall", &error))?;
            Ok(0)
        }
        Mode::StderrFlood {
            records,
            payload_bytes,
            delay_ms,
        } => run_stderr_flood(diagnostics, records, payload_bytes, delay_ms),
        Mode::ControlDelay {
            delay_ms,
            max_control_bytes,
        } => run_control_delay(input, output, diagnostics, delay_ms, max_control_bytes),
        Mode::ControlIgnore { duration_ms } => {
            diagnostics
                .write_all(b"FFORAGER_FAKE_CHILD_CONTROL_READY behavior=ignore\n")
                .and_then(|()| diagnostics.flush())
                .map_err(|error| AppError::io("write control-ignore ready", &error))?;
            sleep_ms(duration_ms);
            diagnostics
                .write_all(b"FFORAGER_FAKE_CHILD_CONTROL_WINDOW_EXPIRED behavior=ignore\n")
                .and_then(|()| diagnostics.flush())
                .map_err(|error| AppError::io("write control-ignore expiry", &error))?;
            Ok(0)
        }
        Mode::PartialOutput {
            output: path,
            bytes,
            exit_code,
        } => run_partial_output(&path, bytes, exit_code, diagnostics),
        Mode::StaleOutput { output: path } => run_stale_output(&path, diagnostics),
        Mode::Unsupported(kind) => run_unsupported(kind, diagnostics),
    }
}

fn run_progress_flood(
    output: &mut impl Write,
    records: u32,
    payload_bytes: u32,
    delay_ms: u64,
) -> Result<u8, AppError> {
    for index in 0..records {
        writeln!(output, "frame={index}")
            .and_then(|()| writeln!(output, "out_time_us={}", u64::from(index) * 1_000))
            .and_then(|()| output.write_all(b"fake_payload="))
            .map_err(|error| AppError::io("write progress record", &error))?;
        write_repeated(
            output,
            b'p',
            u64::from(payload_bytes),
            "write progress payload",
        )?;
        output
            .write_all(b"\nprogress=")
            .and_then(|()| {
                if index.saturating_add(1) == records {
                    output.write_all(b"end\n")
                } else {
                    output.write_all(b"continue\n")
                }
            })
            .and_then(|()| output.flush())
            .map_err(|error| AppError::io("finish progress record", &error))?;
        sleep_ms(delay_ms);
    }
    Ok(0)
}

fn run_progress_malformed(output: &mut impl Write, kind: MalformedKind) -> Result<u8, AppError> {
    let bytes: &[u8] = match kind {
        MalformedKind::MissingEquals => b"frame=0\nout_time_us\nprogress=continue\n",
        MalformedKind::InvalidUtf8 => b"frame=0\nfake_payload=\xff\nprogress=continue\n",
        MalformedKind::InvalidProgress => b"frame=0\nprogress=maybe\n",
    };
    output
        .write_all(bytes)
        .and_then(|()| output.flush())
        .map_err(|error| AppError::io("write malformed progress", &error))?;
    Ok(0)
}

fn run_stderr_flood(
    diagnostics: &mut impl Write,
    records: u32,
    payload_bytes: u32,
    delay_ms: u64,
) -> Result<u8, AppError> {
    for index in 0..records {
        write!(diagnostics, "stderr_record={index};payload=")
            .map_err(|error| AppError::io("write stderr record", &error))?;
        write_repeated(
            diagnostics,
            b'e',
            u64::from(payload_bytes),
            "write stderr payload",
        )?;
        diagnostics
            .write_all(b"\n")
            .and_then(|()| diagnostics.flush())
            .map_err(|error| AppError::io("finish stderr record", &error))?;
        sleep_ms(delay_ms);
    }
    Ok(0)
}

fn run_control_delay(
    input: &mut impl Read,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    delay_ms: u64,
    max_control_bytes: usize,
) -> Result<u8, AppError> {
    diagnostics
        .write_all(b"FFORAGER_FAKE_CHILD_CONTROL_READY behavior=delay\n")
        .and_then(|()| diagnostics.flush())
        .map_err(|error| AppError::io("write control-delay ready", &error))?;
    sleep_ms(delay_ms);
    let command = read_bounded_line(input, max_control_bytes)?;
    if command != b"stop\n" && command != b"stop\r\n" {
        return Err(AppError::data(
            "control command must be the exact line `stop`",
        ));
    }
    let mut trailing = [0_u8; 1];
    if input
        .read(&mut trailing)
        .map_err(|error| AppError::io("read control command terminator", &error))?
        != 0
    {
        return Err(AppError::data(
            "control stream must end after the exact `stop` line",
        ));
    }
    output
        .write_all(b"control=acknowledged\n")
        .and_then(|()| output.flush())
        .map_err(|error| AppError::io("write control acknowledgement", &error))?;
    Ok(0)
}

fn read_bounded_line(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>, AppError> {
    let mut line = Vec::with_capacity(maximum.min(DEFAULT_MAX_CONTROL_BYTES));
    let mut byte = [0_u8; 1];
    loop {
        let read = input
            .read(&mut byte)
            .map_err(|error| AppError::io("read control command", &error))?;
        if read == 0 {
            if line.is_empty() {
                return Err(AppError {
                    exit_code: EXIT_NO_INPUT,
                    diagnostic: "control stream ended before a command".to_owned(),
                });
            }
            return Err(AppError::data(
                "control command ended without a line terminator",
            ));
        }
        if line.len() == maximum {
            return Err(AppError::data(format!(
                "control command exceeds {maximum} bytes"
            )));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn run_partial_output(
    path: &PathBuf,
    bytes: u64,
    exit_code: u8,
    diagnostics: &mut impl Write,
) -> Result<u8, AppError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| AppError::io("create new partial output", &error))?;
    write_repeated(&mut file, 0xA5, bytes, "write partial output")?;
    file.flush()
        .map_err(|error| AppError::io("flush partial output", &error))?;
    writeln!(
        diagnostics,
        "FFORAGER_FAKE_CHILD_PARTIAL_OUTPUT bytes={bytes} terminal=nonzero_exit"
    )
    .and_then(|()| diagnostics.flush())
    .map_err(|error| AppError::io("write partial-output diagnostic", &error))?;
    Ok(exit_code)
}

fn run_stale_output(path: &PathBuf, diagnostics: &mut impl Write) -> Result<u8, AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let exit_code = if error.kind() == io::ErrorKind::NotFound {
            EXIT_NO_INPUT
        } else {
            EXIT_IO_ERROR
        };
        AppError {
            exit_code,
            diagnostic: format!("inspect stale output: {error}"),
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::data(
            "stale output must be an existing non-symlink regular file",
        ));
    }
    let mut file = File::open(path).map_err(|error| AppError::io("open stale output", &error))?;
    let mut probe = [0_u8; 1];
    let _observed = file
        .read(&mut probe)
        .map_err(|error| AppError::io("read stale output", &error))?;
    writeln!(
        diagnostics,
        "FFORAGER_FAKE_CHILD_STALE_OUTPUT bytes={} mutation=none terminal=zero_exit",
        metadata.len()
    )
    .and_then(|()| diagnostics.flush())
    .map_err(|error| AppError::io("write stale-output diagnostic", &error))?;
    Ok(0)
}

fn run_unsupported(kind: UnsupportedKind, diagnostics: &mut impl Write) -> Result<u8, AppError> {
    let (mode, reason) = match kind {
        UnsupportedKind::Descendant => ("descendant", "platform_process_fixture_not_yet_approved"),
        UnsupportedKind::SetsidEscape => (
            "setsid-escape",
            "unix_session_escape_fixture_not_yet_approved",
        ),
        UnsupportedKind::WindowsHandleInheritance => (
            "windows-handle-inheritance",
            "windows_handle_fixture_not_yet_approved",
        ),
    };
    writeln!(
        diagnostics,
        "FFORAGER_FAKE_CHILD_UNSUPPORTED mode={mode} reason={reason}"
    )
    .and_then(|()| diagnostics.flush())
    .map_err(|error| AppError::io("write unsupported-mode diagnostic", &error))?;
    Ok(EXIT_CONFIGURATION)
}

fn write_repeated(
    writer: &mut impl Write,
    byte: u8,
    count: u64,
    context: &str,
) -> Result<(), AppError> {
    let chunk = [byte; REPEATED_BYTE_CHUNK];
    let mut remaining = count;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(REPEATED_BYTE_CHUNK as u64))
            .map_err(|_| AppError::data("bounded byte count does not fit usize"))?;
        writer
            .write_all(&chunk[..length])
            .map_err(|error| AppError::io(context, &error))?;
        remaining -= u64::try_from(length)
            .map_err(|_| AppError::data("written byte count does not fit u64"))?;
    }
    Ok(())
}

fn sleep_ms(milliseconds: u64) {
    if milliseconds > 0 {
        thread::sleep(Duration::from_millis(milliseconds));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Mode, AppError> {
        parse_args(values.iter().map(OsString::from))
    }

    #[test]
    fn defaults_are_bounded_and_explicit() {
        assert_eq!(
            parse(&["progress-flood"]).expect("defaults must parse"),
            Mode::ProgressFlood {
                records: DEFAULT_FLOOD_RECORDS,
                payload_bytes: DEFAULT_PAYLOAD_BYTES,
                delay_ms: 0,
            }
        );
        assert_eq!(
            parse(&["control-ignore"]).expect("defaults must parse"),
            Mode::ControlIgnore {
                duration_ms: DEFAULT_CONTROL_WINDOW_MS,
            }
        );
    }

    #[test]
    fn parser_rejects_unknown_duplicate_missing_and_out_of_range_options() {
        assert!(parse(&["unknown"]).is_err());
        assert!(parse(&["clean-exit", "--delay-ms"]).is_err());
        assert!(parse(&["clean-exit", "--delay-ms", "1", "--delay-ms", "2"]).is_err());
        assert!(parse(&["clean-exit", "--unknown", "1"]).is_err());
        assert!(parse(&["clean-exit", "--delay-ms", "60001"]).is_err());
        assert!(parse(&["crash", "--exit-code", "0"]).is_err());
        assert!(parse(&["partial-output"]).is_err());
    }

    #[test]
    fn progress_flood_has_exact_record_terminators_and_final_end() {
        let mut input = io::empty();
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let exit = run_mode(
            Mode::ProgressFlood {
                records: 3,
                payload_bytes: 2,
                delay_ms: 0,
            },
            &mut input,
            &mut output,
            &mut diagnostics,
        )
        .expect("bounded progress flood must run");
        assert_eq!(exit, 0);
        assert!(diagnostics.is_empty());
        let text = String::from_utf8(output).expect("valid progress flood UTF-8");
        assert_eq!(text.matches("progress=continue\n").count(), 2);
        assert_eq!(text.matches("progress=end\n").count(), 1);
        assert!(text.ends_with("progress=end\n"));
        assert_eq!(text.matches("fake_payload=pp\n").count(), 3);
    }

    #[test]
    fn malformed_and_truncated_modes_are_behaviorally_distinct() {
        for (kind, expected) in [
            (MalformedKind::MissingEquals, b"out_time_us\n".as_slice()),
            (MalformedKind::InvalidUtf8, b"\xff".as_slice()),
            (
                MalformedKind::InvalidProgress,
                b"progress=maybe\n".as_slice(),
            ),
        ] {
            let mut input = io::empty();
            let mut output = Vec::new();
            let mut diagnostics = Vec::new();
            let exit = run_mode(
                Mode::ProgressMalformed { kind },
                &mut input,
                &mut output,
                &mut diagnostics,
            )
            .expect("malformed producer must execute");
            assert_eq!(exit, 0);
            assert!(
                output
                    .windows(expected.len())
                    .any(|window| window == expected)
            );
        }

        let mut input = io::empty();
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        run_mode(
            Mode::ProgressTruncated,
            &mut input,
            &mut output,
            &mut diagnostics,
        )
        .expect("truncated producer must execute");
        assert_eq!(output, b"frame=0\nout_time_us=");
        assert!(!output.windows(9).any(|window| window == b"progress="));
    }

    #[test]
    fn delayed_control_accepts_only_one_exact_bounded_stop_line() {
        let mut input = io::Cursor::new(b"stop\n".to_vec());
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let exit = run_mode(
            Mode::ControlDelay {
                delay_ms: 0,
                max_control_bytes: 8,
            },
            &mut input,
            &mut output,
            &mut diagnostics,
        )
        .expect("exact stop line must be acknowledged");
        assert_eq!(exit, 0);
        assert_eq!(output, b"control=acknowledged\n");
        assert!(diagnostics.starts_with(b"FFORAGER_FAKE_CHILD_CONTROL_READY"));

        let mut input = io::Cursor::new(b"stop\njunk\n".to_vec());
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let error = run_mode(
            Mode::ControlDelay {
                delay_ms: 0,
                max_control_bytes: 16,
            },
            &mut input,
            &mut output,
            &mut diagnostics,
        )
        .expect_err("trailing control bytes must fail closed");
        assert_eq!(error.exit_code, EXIT_DATA_ERROR);
        assert!(output.is_empty());

        let mut input = io::Cursor::new(b"continue\n".to_vec());
        let error = read_bounded_line(&mut input, 4).expect_err("over-limit input must fail");
        assert_eq!(error.exit_code, EXIT_DATA_ERROR);
    }

    #[test]
    fn unsupported_modes_emit_a_nonzero_fail_closed_row() {
        for kind in [
            UnsupportedKind::Descendant,
            UnsupportedKind::SetsidEscape,
            UnsupportedKind::WindowsHandleInheritance,
        ] {
            let mut input = io::empty();
            let mut output = Vec::new();
            let mut diagnostics = Vec::new();
            let exit = run_mode(
                Mode::Unsupported(kind),
                &mut input,
                &mut output,
                &mut diagnostics,
            )
            .expect("unsupported row must be emitted");
            assert_eq!(exit, EXIT_CONFIGURATION);
            assert!(output.is_empty());
            assert!(diagnostics.starts_with(b"FFORAGER_FAKE_CHILD_UNSUPPORTED"));
        }
    }

    #[test]
    fn payload_product_limit_rejects_excess_even_when_each_axis_is_valid() {
        let records = MAX_FLOOD_RECORDS;
        let payload_bytes = MAX_PAYLOAD_BYTES;
        assert!(u64::from(records) * u64::from(payload_bytes) > MAX_TOTAL_FLOOD_PAYLOAD_BYTES);
        assert!(validate_flood_bounds(records, payload_bytes, 0).is_err());
        assert!(validate_flood_bounds(61, 0, 1_000).is_err());
    }
}
