#![forbid(unsafe_code)]

use fforager_transport::{CorpusManifest, run_corpus};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MANIFEST: &str = "build/fixtures/transport-v1/manifest.json";
const DEFAULT_REPORT: &str = "build/reports/wp-ff-007-transport-report.json";
const MAX_MANIFEST_BYTES: u64 = 512 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (manifest_path, report_path) = parse_args(env::args().skip(1))?;
    let metadata = fs::metadata(&manifest_path)
        .map_err(|error| format!("FF-TRANSPORT-E-MANIFEST-READ: {error}"))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "FF-TRANSPORT-E-MANIFEST-BOUNDS: {} exceeds {MAX_MANIFEST_BYTES}",
            metadata.len()
        ));
    }
    let bytes = fs::read(&manifest_path)
        .map_err(|error| format!("FF-TRANSPORT-E-MANIFEST-READ: {error}"))?;
    let manifest: CorpusManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("FF-TRANSPORT-E-MANIFEST-SCHEMA: {error}"))?;
    let report = run_corpus(&manifest)?;
    write_report(&report_path, &report)?;
    println!(
        "{}; mandatory={}/{}; blocked={}; report={}",
        report.verdict.as_str(),
        report.summary.mandatory_passed,
        report.summary.mandatory_total,
        report.summary.mandatory_blocked,
        report_path.display()
    );
    Ok(())
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<(PathBuf, PathBuf), String> {
    let mut manifest = PathBuf::from(DEFAULT_MANIFEST);
    let mut report = PathBuf::from(DEFAULT_REPORT);
    let mut args = args;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--manifest" => {
                manifest =
                    PathBuf::from(args.next().ok_or(
                        "usage: fforager-transport-corpus [--manifest PATH] [--report PATH]",
                    )?);
            }
            "--report" => {
                report =
                    PathBuf::from(args.next().ok_or(
                        "usage: fforager-transport-corpus [--manifest PATH] [--report PATH]",
                    )?);
            }
            _ => {
                return Err(
                    "usage: fforager-transport-corpus [--manifest PATH] [--report PATH]".to_owned(),
                );
            }
        }
    }
    Ok((manifest, report))
}

fn write_report(path: &Path, report: &fforager_transport::CorpusReport) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("FF-TRANSPORT-E-REPORT-DIR: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("FF-TRANSPORT-E-REPORT-ENCODE: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, &bytes)
        .map_err(|error| format!("FF-TRANSPORT-E-REPORT-WRITE: {error}"))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("FF-TRANSPORT-E-REPORT-COMMIT: {error}"))?;
    Ok(())
}
