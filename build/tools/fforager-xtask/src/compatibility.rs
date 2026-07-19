use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
    command_output_bytes_with_timeout, command_output_with_timeout, sha256_file, slash,
    source_state,
};

const ORACLE_PATH: &str = "build/fixtures/compatibility/yt-dlp-2026.07.04/oracle-manifest.json";
const PROFILE_PATH: &str = "build/fixtures/compatibility/yt-dlp-2026.07.04/profile.json";
const CORPUS_PATH: &str = "build/fixtures/compatibility/corpus-v1/manifest.json";
const LIVE_PATH: &str = "build/fixtures/compatibility/live-canaries-v1/manifest.json";
const NEGATIVE_ROOT: &str = "build/fixtures/compatibility/negative";
const NORMALIZATION_VERSION: &str = "ff-normalization-v1";
const ORACLE_VERSION: &str = "2026.07.04";
const ORACLE_TAG_COMMIT: &str = "fdec00e0bf530dc6c3cc7b1dd780e95d9ae460e9";
const ORACLE_RELEASE_HEAD: &str = "997fa140840a08df3938b40da470c78049fef1f6";
const ORACLE_EXE_SHA256: &str = "52fe3c26dcf71fbdc85b528589020bb0b8e383155cfa81b64dd447bbe35e24b8";
const TOOL_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleManifest {
    schema_id: String,
    schema_version: String,
    oracle_id: String,
    release: OracleRelease,
    artifacts: Vec<OracleArtifact>,
    source_inputs: Vec<SourceInput>,
    generator: GeneratorPolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleRelease {
    project: String,
    version: String,
    channel: String,
    immutable: bool,
    published_at_utc: String,
    release_url: String,
    tag_commit: String,
    release_git_head: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OracleArtifact {
    artifact_id: String,
    filename: String,
    url: String,
    sha256: String,
    size_bytes: u64,
    role: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    path: String,
    sha256: String,
    role: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratorPolicy {
    normalization_version: String,
    network_allowed: bool,
    plugins_allowed: bool,
    config_allowed: bool,
    timeout_seconds: u64,
    commands: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityProfile {
    schema_id: String,
    schema_version: String,
    profile_id: String,
    oracle_id: String,
    normalization_version: String,
    source_identity: ProfileSourceIdentity,
    input_digests: BTreeMap<String, String>,
    counts: ProfileCounts,
    options: Vec<OptionRow>,
    presets: Vec<PresetRow>,
    interactions: Vec<InteractionRow>,
    extractors: Vec<ExtractorRow>,
    extractor_descriptions: Vec<DescriptionRow>,
    normalization_notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileSourceIdentity {
    version: String,
    tag_commit: String,
    release_git_head: String,
    executable_sha256: String,
    source_inputs: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileCounts {
    options: usize,
    presets: usize,
    interactions: usize,
    raw_extractor_rows: usize,
    unique_extractors: usize,
    extractor_descriptions: usize,
    collapsed_identical_extractor_rows: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OptionRow {
    id: String,
    canonical: String,
    aliases: Vec<String>,
    group: String,
    synopsis: String,
    description: String,
    takes_value: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PresetRow {
    id: String,
    name: String,
    expansion: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InteractionRow {
    id: String,
    kind: String,
    description: String,
    source: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExtractorRow {
    id: String,
    key: String,
    url_class: String,
    working: bool,
    source_occurrences: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DescriptionRow {
    id: String,
    description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifest {
    schema_id: String,
    schema_version: String,
    corpus_id: String,
    profile_id: String,
    normalization_versions: Vec<String>,
    shard_algorithm: String,
    shard_count: u32,
    planes: Vec<String>,
    cases: Vec<CorpusCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    plane: String,
    deterministic: bool,
    network_allowed: bool,
    normalization_version: String,
    fixture: String,
    fixture_sha256: String,
    expected_outcome: String,
    shard: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveManifest {
    schema_id: String,
    schema_version: String,
    suite_id: String,
    profile_id: String,
    default_enabled: bool,
    deterministic_proof: bool,
    canaries: Vec<LiveCanary>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveCanary {
    id: String,
    url_class: String,
    url: String,
    timeout_seconds: u64,
    credential_policy: String,
    expected_classification: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NegativeCase {
    schema_version: u32,
    fixture_id: String,
    mutation: String,
    expected_diagnostic: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateResults {
    schema_id: String,
    schema_version: String,
    corpus_id: String,
    profile_id: String,
    observations: Vec<CandidateObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateObservation {
    case_id: String,
    observed_digest: String,
    classification: Option<String>,
    decision_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CompatibilityReport {
    schema_id: &'static str,
    schema_version: &'static str,
    command: String,
    status: &'static str,
    source: CompatibilitySource,
    inputs: BTreeMap<String, String>,
    checks: Vec<CompatibilityCheck>,
    negative_fixtures: Vec<NegativeResult>,
    differential_rows: Vec<DifferentialRow>,
    artifacts: Vec<String>,
    proof_limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CompatibilitySource {
    git_commit: String,
    dirty: bool,
    dirty_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CompatibilityCheck {
    id: String,
    status: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct NegativeResult {
    fixture_id: String,
    status: &'static str,
    expected_diagnostic: String,
    observed_diagnostic: String,
}

#[derive(Debug, Serialize)]
struct DifferentialRow {
    case_id: String,
    status: &'static str,
    classification: String,
    decision_id: Option<String>,
    expected_digest: String,
    observed_digest: Option<String>,
}

#[derive(Debug, Serialize)]
struct InventoryDiffReport {
    schema_id: &'static str,
    schema_version: &'static str,
    before_profile_id: String,
    after_profile_id: String,
    added_options: Vec<String>,
    removed_options: Vec<String>,
    changed_options: Vec<String>,
    added_extractors: Vec<String>,
    removed_extractors: Vec<String>,
    changed_extractors: Vec<String>,
}

pub(super) fn run_generate(root: &Path, args: &[String]) -> Result<(), String> {
    let oracle_exe = required_arg(args, "--oracle-exe")?;
    let source_root = required_arg(args, "--source-root")?;
    let output = optional_arg(args, "--output").unwrap_or(PROFILE_PATH);
    require_safe_output(output)?;
    let manifest: OracleManifest = read_json(&root.join(ORACLE_PATH))?;
    validate_oracle_manifest(&manifest)?;
    let profile = generate_profile(
        root,
        Path::new(oracle_exe),
        Path::new(source_root),
        &manifest,
    )?;
    validate_profile(&profile, &manifest)?;
    atomic_json(&root.join(output), &profile)?;
    println!(
        "PASS FF-GATE-COMPAT-GENERATE-001; profile={output}; options={}; extractors={}",
        profile.counts.options, profile.counts.unique_extractors
    );
    Ok(())
}

pub(super) fn run_validate(root: &Path, args: &[String]) -> Result<(), String> {
    let manifest: OracleManifest = read_json(&root.join(ORACLE_PATH))?;
    let profile: CompatibilityProfile = read_json(&root.join(PROFILE_PATH))?;
    let corpus: CorpusManifest = read_json(&root.join(CORPUS_PATH))?;
    let live: LiveManifest = read_json(&root.join(LIVE_PATH))?;
    validate_oracle_manifest(&manifest)?;
    validate_profile(&profile, &manifest)?;
    let mut checks = Vec::new();
    validate_corpus(root, &corpus, &profile, &mut checks)?;
    validate_live_manifest(&live, &profile)?;
    checks.push(pass(
        "live-canary-separation",
        &format!(
            "suite={} default_enabled=false deterministic_proof=false canaries={}",
            live.suite_id,
            live.canaries.len()
        ),
    ));
    let negative_fixtures = validate_negative_fixtures(root, &manifest, &profile, &corpus)?;
    checks.push(pass(
        "negative-fixtures",
        &format!(
            "{} compatibility mutations produced exact stable diagnostics",
            negative_fixtures.len()
        ),
    ));
    let report = base_report(
        root,
        "compatibility-validate",
        checks,
        negative_fixtures,
        Vec::new(),
    )?;
    let path = write_compatibility_report(root, "compatibility-validate", &report)?;
    println!(
        "PASS FF-GATE-COMPAT-001; report={}; profile_options={}; corpus_cases={}",
        slash(&path),
        profile.counts.options,
        corpus.cases.len()
    );
    let _ = args;
    Ok(())
}

pub(super) fn run_replay(root: &Path, args: &[String], rest: &[String]) -> Result<(), String> {
    let profile: CompatibilityProfile = read_json(&root.join(PROFILE_PATH))?;
    let corpus: CorpusManifest = read_json(&root.join(CORPUS_PATH))?;
    let shard = optional_arg(rest, "--shard").map(parse_shard).transpose()?;
    if shard.is_some_and(|(_, total)| total != corpus.shard_count) {
        return Err(format!(
            "FF-COMP-E-SHARD: requested shard total must equal corpus shard_count {}",
            corpus.shard_count
        ));
    }
    let mut checks = Vec::new();
    validate_corpus(root, &corpus, &profile, &mut checks)?;
    let selected = corpus
        .cases
        .iter()
        .filter(|case| shard.is_none_or(|(index, _)| case.shard == index))
        .collect::<Vec<_>>();
    checks.push(pass(
        "offline-replay",
        &format!(
            "selected {} sanitized deterministic cases; shard={:?}; network_access=false",
            selected.len(),
            shard
        ),
    ));
    let report = base_report(root, "compatibility-replay", checks, Vec::new(), Vec::new())?;
    let path = write_compatibility_report(root, "compatibility-replay", &report)?;
    println!(
        "PASS FF-GATE-COMPAT-REPLAY-001; report={}; cases={}",
        slash(&path),
        selected.len()
    );
    let _ = args;
    Ok(())
}

pub(super) fn run_diff(root: &Path, args: &[String], rest: &[String]) -> Result<(), String> {
    let candidate_path = required_arg(rest, "--candidate")?;
    require_safe_input(candidate_path)?;
    let profile: CompatibilityProfile = read_json(&root.join(PROFILE_PATH))?;
    let corpus: CorpusManifest = read_json(&root.join(CORPUS_PATH))?;
    let candidate: CandidateResults = read_json(&root.join(candidate_path))?;
    let rows = differential_rows(&corpus, &profile, &candidate)?;
    let missing = rows
        .iter()
        .filter(|row| row.classification == "missing_feature")
        .count();
    let checks = vec![pass(
        "differential-completeness",
        &format!(
            "every one of {} corpus cases has an explicit row; missing_features={missing}",
            rows.len()
        ),
    )];
    let report = base_report(root, "compatibility-diff", checks, Vec::new(), rows)?;
    let path = write_compatibility_report(root, "compatibility-diff", &report)?;
    println!(
        "PASS FF-GATE-COMPAT-DIFF-001; report={}; this proves report completeness, not Ferric parity",
        slash(&path)
    );
    let _ = args;
    Ok(())
}

pub(super) fn run_inventory_diff(
    root: &Path,
    args: &[String],
    rest: &[String],
) -> Result<(), String> {
    let before_path = required_arg(rest, "--before")?;
    let after_path = required_arg(rest, "--after")?;
    require_safe_input(before_path)?;
    require_safe_input(after_path)?;
    let before: CompatibilityProfile = read_json(&root.join(before_path))?;
    let after: CompatibilityProfile = read_json(&root.join(after_path))?;
    let report = inventory_diff(&before, &after);
    let path = unique_report_path(root, "compatibility-inventory-diff")?;
    atomic_json(&path, &report)?;
    println!(
        "PASS FF-GATE-COMPAT-DIFF-002; report={}",
        slash(path.strip_prefix(root).map_err(|error| error.to_string())?)
    );
    let _ = args;
    Ok(())
}

pub(super) fn run_live_canaries(
    root: &Path,
    args: &[String],
    rest: &[String],
) -> Result<(), String> {
    if !rest.iter().any(|argument| argument == "--enable-live") {
        return Err(
            "FF-COMP-E-LIVE-OPT-IN: live canaries require the explicit --enable-live flag"
                .to_owned(),
        );
    }
    let oracle_exe = required_arg(rest, "--oracle-exe")?;
    let oracle_path = Path::new(oracle_exe);
    if !oracle_path.is_file() || sha256_file(oracle_path)? != ORACLE_EXE_SHA256 {
        return Err("FF-COMP-E-UNPINNED-ORACLE: live oracle executable mismatch".to_owned());
    }
    let profile: CompatibilityProfile = read_json(&root.join(PROFILE_PATH))?;
    let manifest: OracleManifest = read_json(&root.join(ORACLE_PATH))?;
    let live: LiveManifest = read_json(&root.join(LIVE_PATH))?;
    validate_oracle_manifest(&manifest)?;
    validate_profile(&profile, &manifest)?;
    validate_live_manifest(&live, &profile)?;
    let program = oracle_path
        .to_str()
        .ok_or("FF-COMP-E-ORACLE-INPUT: executable path is not Unicode")?;
    let mut checks = Vec::new();
    for canary in &live.canaries {
        let result = oracle_output(
            root,
            program,
            &[
                "--ignore-config",
                "--no-plugin-dirs",
                "--encoding",
                "utf-8",
                "--no-color",
                "--simulate",
                "--skip-download",
                "--no-warnings",
                "--print",
                "%(extractor_key)s|%(id)s",
                &canary.url,
            ],
            Duration::from_secs(canary.timeout_seconds),
        );
        let detail = match result {
            Ok(observation) => format!(
                "classification={}; outcome=success; observation={}",
                canary.expected_classification,
                bounded_observation(&observation)
            ),
            Err(error) => format!(
                "classification={}; outcome=failure; diagnostic={}",
                canary.expected_classification,
                bounded_observation(&error)
            ),
        };
        checks.push(CompatibilityCheck {
            id: canary.id.clone(),
            status: "OBSERVED",
            detail,
        });
    }
    let report = base_report(
        root,
        "compatibility-live-canaries",
        checks,
        Vec::new(),
        Vec::new(),
    )?;
    let path = write_compatibility_report(root, "compatibility-live-canaries", &report)?;
    println!(
        "OBSERVED FF-COMPAT-LIVE-001; report={}; canaries={}; deterministic_proof=false",
        slash(&path),
        live.canaries.len()
    );
    let _ = args;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn generate_profile(
    root: &Path,
    oracle_exe: &Path,
    source_root: &Path,
    manifest: &OracleManifest,
) -> Result<CompatibilityProfile, String> {
    if !oracle_exe.is_file() || !source_root.is_dir() {
        return Err(
            "FF-COMP-E-ORACLE-INPUT: oracle executable or source root is absent".to_owned(),
        );
    }
    let executable_sha256 = sha256_file(oracle_exe)?;
    let expected_executable = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == "yt-dlp-windows-x64")
        .ok_or("FF-COMP-E-UNPINNED-ORACLE: Windows oracle artifact is absent")?;
    if executable_sha256 != expected_executable.sha256 {
        return Err(format!(
            "FF-COMP-E-UNPINNED-ORACLE: executable expected={} observed={executable_sha256}",
            expected_executable.sha256
        ));
    }
    let program = oracle_exe
        .to_str()
        .ok_or("FF-COMP-E-ORACLE-INPUT: executable path is not Unicode")?;
    let version = oracle_output(
        root,
        program,
        &[
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--version",
        ],
        TOOL_TIMEOUT,
    )?;
    if version.trim() != ORACLE_VERSION {
        return Err(format!(
            "FF-COMP-E-UNPINNED-ORACLE: expected version {ORACLE_VERSION}, observed {:?}",
            version.trim()
        ));
    }
    let source_head = command_output_with_timeout(
        root,
        "git",
        &[
            "-C",
            source_root.to_str().ok_or("source path is not Unicode")?,
            "rev-parse",
            "HEAD",
        ],
        TOOL_TIMEOUT,
    )?;
    if source_head.trim() != ORACLE_TAG_COMMIT {
        return Err(format!(
            "FF-COMP-E-UNPINNED-ORACLE: expected source tag {ORACLE_TAG_COMMIT}, observed {:?}",
            source_head.trim()
        ));
    }
    let mut source_inputs = BTreeMap::new();
    for input in &manifest.source_inputs {
        let observed = sha256_file(&source_root.join(&input.path))?;
        if observed != input.sha256 {
            return Err(format!(
                "FF-COMP-E-UNPINNED-ORACLE: source {} expected={} observed={observed}",
                input.path, input.sha256
            ));
        }
        source_inputs.insert(input.path.clone(), observed);
    }
    let help = normalized_capture(&oracle_output(
        root,
        program,
        &[
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--no-color",
            "--help",
        ],
        TOOL_TIMEOUT,
    )?);
    let extractors = normalized_capture(&oracle_output(
        root,
        program,
        &[
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--no-color",
            "--list-extractors",
        ],
        TOOL_TIMEOUT,
    )?);
    let descriptions = normalized_oracle_descriptions(&oracle_output(
        root,
        program,
        &[
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--no-color",
            "--extractor-descriptions",
        ],
        TOOL_TIMEOUT,
    )?);
    let (mut options, mut presets) = parse_help(&help)?;
    options.sort_by(|left, right| left.id.cmp(&right.id));
    presets.sort_by(|left, right| left.id.cmp(&right.id));
    let raw_extractor_rows = extractors
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let mut extractor_map: BTreeMap<String, ExtractorRow> = BTreeMap::new();
    for line in extractors
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let (key, working) = line
            .strip_suffix(" (CURRENTLY BROKEN)")
            .map_or((line, true), |key| (key, false));
        let id = format!("extractor-{}", stable_component(key));
        match extractor_map.get_mut(&id) {
            Some(existing) if existing.key == key && existing.working == working => {
                existing.source_occurrences += 1;
            }
            Some(_) => {
                return Err(format!(
                    "FF-COMP-E-DUPLICATE-ID: conflicting extractor {id}"
                ));
            }
            None => {
                extractor_map.insert(
                    id.clone(),
                    ExtractorRow {
                        id,
                        key: key.to_owned(),
                        url_class: format!("url-class-{}", stable_component(key)),
                        working,
                        source_occurrences: 1,
                    },
                );
            }
        }
    }
    let extractor_rows = extractor_map.into_values().collect::<Vec<_>>();
    let mut description_values = descriptions
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    description_values.sort();
    description_values.dedup();
    let description_rows = description_values
        .into_iter()
        .enumerate()
        .map(|(index, description)| DescriptionRow {
            id: format!("extractor-description-{:04}", index + 1),
            description,
        })
        .collect::<Vec<_>>();
    let interactions = pinned_interactions();
    let input_digests = BTreeMap::from([
        ("help-lf".to_owned(), sha256_text(&help)),
        ("list-extractors-lf".to_owned(), sha256_text(&extractors)),
        (
            "extractor-descriptions-lf".to_owned(),
            sha256_text(&descriptions),
        ),
    ]);
    let counts = ProfileCounts {
        options: options.len(),
        presets: presets.len(),
        interactions: interactions.len(),
        raw_extractor_rows,
        unique_extractors: extractor_rows.len(),
        extractor_descriptions: description_rows.len(),
        collapsed_identical_extractor_rows: raw_extractor_rows.saturating_sub(extractor_rows.len()),
    };
    Ok(CompatibilityProfile {
        schema_id: "ff.compatibility-profile@1".to_owned(),
        schema_version: "1.0.0".to_owned(),
        profile_id: "yt-dlp-2026.07.04-profile-v1".to_owned(),
        oracle_id: manifest.oracle_id.clone(),
        normalization_version: NORMALIZATION_VERSION.to_owned(),
        source_identity: ProfileSourceIdentity {
            version: ORACLE_VERSION.to_owned(),
            tag_commit: ORACLE_TAG_COMMIT.to_owned(),
            release_git_head: manifest.release.release_git_head.clone(),
            executable_sha256,
            source_inputs,
        },
        input_digests,
        counts,
        options,
        presets,
        interactions,
        extractors: extractor_rows,
        extractor_descriptions: description_rows,
        normalization_notes: vec![
            "Line endings are normalized to LF before hashing and parsing.".to_owned(),
            "Identical repeated extractor rows collapse to one stable row while source_occurrences retains the raw multiplicity.".to_owned(),
            "Randomized extractor search examples are replaced by {{RANDOMIZED_SEARCH_EXAMPLE}} before hashing and inventory generation.".to_owned(),
            "Help, extractor, and description commands run with config, plugins, color, and network disabled by command selection.".to_owned(),
            "No current clock, absolute path, hostname, credential, or live response enters the generated profile.".to_owned(),
        ],
    })
}

fn parse_help(help: &str) -> Result<(Vec<OptionRow>, Vec<PresetRow>), String> {
    let mut group = "Ungrouped".to_owned();
    let mut entries: Vec<(String, String, String)> = Vec::new();
    let mut current: Option<(String, String, String)> = None;
    for line in help.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !line.chars().next().is_some_and(char::is_whitespace)
            || (line.starts_with("  ") && !line.starts_with("    ") && trimmed.ends_with(':'))
        {
            if trimmed.ends_with(':') {
                if let Some(entry) = current.take() {
                    entries.push(entry);
                }
                trimmed.trim_end_matches(':').clone_into(&mut group);
            }
            continue;
        }
        if line.starts_with("    -") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            let (synopsis, description) = split_help_line(trimmed);
            current = Some((group.clone(), synopsis.to_owned(), description.to_owned()));
        } else if let Some((_, _, description)) = current.as_mut() {
            if !description.is_empty() {
                description.push(' ');
            }
            description.push_str(trimmed);
        }
    }
    if let Some(entry) = current {
        entries.push(entry);
    }
    let mut options = Vec::new();
    let mut presets = Vec::new();
    let mut option_ids = BTreeSet::new();
    let mut preset_ids = BTreeSet::new();
    for (group, synopsis, description) in entries {
        if group == "Preset Aliases" {
            let name = synopsis
                .split_whitespace()
                .nth(1)
                .ok_or("FF-COMP-E-PARSE: preset has no name")?;
            let id = format!("preset-{}", stable_component(name));
            if !preset_ids.insert(id.clone()) {
                return Err(format!("FF-COMP-E-DUPLICATE-ID: {id}"));
            }
            presets.push(PresetRow {
                id,
                name: name.to_owned(),
                expansion: description,
            });
            continue;
        }
        let aliases = option_spellings(&synopsis);
        if aliases.is_empty() {
            return Err(format!(
                "FF-COMP-E-PARSE: option has no spelling: {synopsis}"
            ));
        }
        let canonical = aliases
            .iter()
            .find(|alias| alias.starts_with("--"))
            .unwrap_or(&aliases[0])
            .clone();
        let id = format!(
            "option-{}",
            stable_component(canonical.trim_start_matches('-'))
        );
        if !option_ids.insert(id.clone()) {
            return Err(format!("FF-COMP-E-DUPLICATE-ID: {id}"));
        }
        let takes_value = synopsis
            .split_whitespace()
            .any(|part| !part.starts_with('-') && part.chars().any(char::is_uppercase));
        options.push(OptionRow {
            id,
            canonical,
            aliases,
            group,
            synopsis,
            description,
            takes_value,
        });
    }
    Ok((options, presets))
}

fn split_help_line(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b' ' && bytes[index + 1] == b' ' {
            let synopsis = line[..index].trim_end();
            let description = line[index..].trim();
            return (synopsis, description);
        }
        index += 1;
    }
    (line, "")
}

fn option_spellings(synopsis: &str) -> Vec<String> {
    synopsis
        .split(|character: char| character == ',' || character.is_whitespace())
        .map(|part| {
            part.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '-'
            })
        })
        .filter(|part| {
            (part.starts_with("--") && part.len() > 2)
                || (part.starts_with('-') && !part.starts_with("--") && part.len() == 2)
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn pinned_interactions() -> Vec<InteractionRow> {
    [
        ("interaction-config-precedence", "configuration", "Command-line, portable, home, user, and system configuration sources have explicit precedence and can be disabled.", "yt_dlp/options.py:parseOpts"),
        ("interaction-environment-defaults", "default", "Environment and platform state may affect defaults and must be captured as explicit oracle inputs.", "yt_dlp/options.py:create_parser"),
        ("interaction-repeated-options", "configuration", "Repeated list, set, dictionary, and scalar options use distinct append, prepend, replace, and callback semantics.", "yt_dlp/options.py:create_parser callbacks"),
        ("interaction-runtime-alias", "alias", "User-defined aliases expand through bounded callback recursion and preserve argument provenance.", "yt_dlp/options.py:_create_alias"),
        ("interaction-preset-expansion", "preset", "Pinned preset names expand to ordered argument vectors before normal option processing.", "yt_dlp/options.py:_PRESET_ALIASES"),
        ("interaction-compat-profile", "compatibility", "Compatibility options alter defaults and downstream behavior after parsing and must remain separate from native Ferric semantics.", "yt_dlp/__init__.py:set_compat_opts"),
    ]
    .into_iter()
    .map(|(id, kind, description, source)| InteractionRow {
        id: id.to_owned(),
        kind: kind.to_owned(),
        description: description.to_owned(),
        source: source.to_owned(),
    })
    .collect()
}

#[allow(clippy::too_many_lines)]
fn validate_oracle_manifest(manifest: &OracleManifest) -> Result<(), String> {
    let expected_commands = vec![
        vec![
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--no-color",
            "--help",
        ],
        vec![
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--no-color",
            "--list-extractors",
        ],
        vec![
            "--ignore-config",
            "--no-plugin-dirs",
            "--encoding",
            "utf-8",
            "--no-color",
            "--extractor-descriptions",
        ],
    ];
    if manifest.schema_id != "ff.compatibility-oracle@1"
        || manifest.schema_version != "1.0.0"
        || manifest.oracle_id != "yt-dlp-2026.07.04-oracle-v1"
        || manifest.release.project != "yt-dlp/yt-dlp"
        || manifest.release.version != ORACLE_VERSION
        || manifest.release.channel != "stable"
        || !manifest.release.immutable
        || manifest.release.tag_commit != ORACLE_TAG_COMMIT
        || manifest.release.release_git_head != ORACLE_RELEASE_HEAD
        || manifest.release.published_at_utc != "2026-07-04T22:41:44Z"
        || manifest.release.release_url
            != "https://github.com/yt-dlp/yt-dlp/releases/tag/2026.07.04"
        || manifest.generator.normalization_version != NORMALIZATION_VERSION
        || manifest.generator.network_allowed
        || manifest.generator.plugins_allowed
        || manifest.generator.config_allowed
        || manifest.generator.timeout_seconds == 0
        || manifest.generator.commands != expected_commands
    {
        return Err(
            "FF-COMP-E-UNPINNED-ORACLE: oracle manifest identity or policy mismatch".to_owned(),
        );
    }
    let mut artifact_ids = BTreeSet::new();
    for artifact in &manifest.artifacts {
        if !artifact_ids.insert(artifact.artifact_id.as_str())
            || !valid_sha256(&artifact.sha256)
            || artifact.size_bytes == 0
            || !artifact
                .url
                .starts_with("https://github.com/yt-dlp/yt-dlp/releases/download/2026.07.04/")
        {
            return Err("FF-COMP-E-UNPINNED-ORACLE: artifact provenance is incomplete".to_owned());
        }
    }
    if !artifact_ids.contains("yt-dlp-windows-x64")
        || !artifact_ids.contains("sha2-256sums")
        || !artifact_ids.contains("source-tarball")
    {
        return Err("FF-COMP-E-UNPINNED-ORACLE: required artifact identity is absent".to_owned());
    }
    let expected_artifacts = BTreeMap::from([
        (
            "sha2-256sums",
            (
                "SHA2-256SUMS",
                "eca42575010efc77b8dc1e263c57e19c4bddc42d3e08ba789ccde72c97d48c64",
                1_595_u64,
            ),
        ),
        (
            "source-tarball",
            (
                "yt-dlp.tar.gz",
                "31c32457d1a573a341bb0929386c624fe47339a5338829e6e9c9454bdfa7397a",
                6_015_962_u64,
            ),
        ),
        (
            "yt-dlp-windows-x64",
            ("yt-dlp.exe", ORACLE_EXE_SHA256, 18_226_085_u64),
        ),
    ]);
    if manifest.artifacts.len() != expected_artifacts.len()
        || manifest.artifacts.iter().any(|artifact| {
            expected_artifacts
                .get(artifact.artifact_id.as_str())
                .is_none_or(|(filename, sha256, size)| {
                    artifact.filename != *filename
                        || artifact.sha256 != *sha256
                        || artifact.size_bytes != *size
                })
        })
    {
        return Err("FF-COMP-E-UNPINNED-ORACLE: artifact identity mismatch".to_owned());
    }
    let mut source_paths = BTreeSet::new();
    if manifest.source_inputs.iter().any(|input| {
        !source_paths.insert(input.path.as_str())
            || !safe_relative(&input.path)
            || !valid_sha256(&input.sha256)
            || input.role.trim().is_empty()
    }) {
        return Err("FF-COMP-E-UNPINNED-ORACLE: source input provenance is incomplete".to_owned());
    }
    let expected_sources = BTreeMap::from([
        (
            "yt_dlp/version.py",
            "8485c16520f205dbb8babb162c48fa30f65413230f9f8ac0317dbd2725fdecfd",
        ),
        (
            "yt_dlp/options.py",
            "b527798ae3e43213e689e6f9f6b670a3678e9998753a07d47a84ee23846d1b3a",
        ),
        (
            "yt_dlp/__init__.py",
            "f3ddb4b5759d6646aa25ff9de7026c78b14543bb1180a3f2ff5acb0757082256",
        ),
        (
            "yt_dlp/extractor/_extractors.py",
            "91c7e51ed6d369dbea1d5862afbd61adf1b53860206aedaa29b4196800acdce0",
        ),
        (
            "yt_dlp/extractor/__init__.py",
            "96b18d67eac15b220f4a557522af5d28fea7f696b3f77d44712807822eb5f5f6",
        ),
    ]);
    if manifest.source_inputs.len() != expected_sources.len()
        || manifest.source_inputs.iter().any(|input| {
            expected_sources
                .get(input.path.as_str())
                .is_none_or(|sha256| input.sha256 != *sha256)
        })
    {
        return Err("FF-COMP-E-UNPINNED-ORACLE: source identity mismatch".to_owned());
    }
    Ok(())
}

fn validate_profile(
    profile: &CompatibilityProfile,
    manifest: &OracleManifest,
) -> Result<(), String> {
    if profile.schema_id != "ff.compatibility-profile@1"
        || profile.schema_version != "1.0.0"
        || profile.profile_id != "yt-dlp-2026.07.04-profile-v1"
        || profile.oracle_id != manifest.oracle_id
        || profile.normalization_version != NORMALIZATION_VERSION
        || profile.source_identity.version != ORACLE_VERSION
        || profile.source_identity.tag_commit != ORACLE_TAG_COMMIT
        || profile.source_identity.release_git_head != manifest.release.release_git_head
    {
        return Err("FF-COMP-E-UNPINNED-ORACLE: profile identity mismatch".to_owned());
    }
    if profile.counts.options != profile.options.len()
        || profile.counts.presets != profile.presets.len()
        || profile.counts.interactions != profile.interactions.len()
        || profile.counts.unique_extractors != profile.extractors.len()
        || profile.counts.extractor_descriptions != profile.extractor_descriptions.len()
        || profile.counts.raw_extractor_rows
            != profile.counts.unique_extractors + profile.counts.collapsed_identical_extractor_rows
    {
        return Err("FF-COMP-E-INVENTORY-COUNT: profile counts do not match rows".to_owned());
    }
    require_unique_stable_ids(profile.options.iter().map(|row| row.id.as_str()))?;
    require_unique_stable_ids(profile.presets.iter().map(|row| row.id.as_str()))?;
    require_unique_stable_ids(profile.interactions.iter().map(|row| row.id.as_str()))?;
    require_unique_stable_ids(profile.extractors.iter().map(|row| row.id.as_str()))?;
    require_unique_stable_ids(
        profile
            .extractor_descriptions
            .iter()
            .map(|row| row.id.as_str()),
    )?;
    if profile.input_digests.len() != 3
        || profile
            .input_digests
            .values()
            .any(|digest| !valid_sha256(digest))
        || profile.source_identity.source_inputs.len() != manifest.source_inputs.len()
    {
        return Err("FF-COMP-E-UNPINNED-ORACLE: profile input digests are incomplete".to_owned());
    }
    for input in &manifest.source_inputs {
        if profile.source_identity.source_inputs.get(&input.path) != Some(&input.sha256) {
            return Err(format!(
                "FF-COMP-E-UNPINNED-ORACLE: profile source digest mismatch for {}",
                input.path
            ));
        }
    }
    Ok(())
}

fn validate_corpus(
    root: &Path,
    corpus: &CorpusManifest,
    profile: &CompatibilityProfile,
    checks: &mut Vec<CompatibilityCheck>,
) -> Result<(), String> {
    if corpus.schema_id != "ff.compatibility-corpus@1"
        || corpus.schema_version != "1.0.0"
        || corpus.corpus_id != "ff-ytdlp-2026.07.04-corpus-v1"
        || corpus.profile_id != profile.profile_id
        || corpus.normalization_versions != [NORMALIZATION_VERSION]
        || corpus.shard_algorithm != "sha256-stable-id-mod-v1"
        || corpus.shard_count == 0
    {
        return Err("FF-COMP-E-CORPUS-IDENTITY: corpus identity or version mismatch".to_owned());
    }
    let expected_planes = BTreeSet::from([
        "archive",
        "failure",
        "filesystem_process_artifact",
        "migration",
        "normalized_observation",
        "sanitized_network_transcript",
        "source_graph",
    ]);
    let declared_planes = corpus
        .planes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if declared_planes != expected_planes {
        return Err("FF-COMP-E-COVERAGE: corpus plane inventory is incomplete".to_owned());
    }
    require_unique_stable_ids(corpus.cases.iter().map(|case| case.id.as_str()))?;
    let mut observed_planes = BTreeSet::new();
    for case in &corpus.cases {
        observed_planes.insert(case.plane.as_str());
        if !expected_planes.contains(case.plane.as_str()) {
            return Err(format!("FF-COMP-E-COVERAGE: unknown plane {}", case.plane));
        }
        if case.normalization_version != NORMALIZATION_VERSION {
            return Err(format!(
                "FF-COMP-E-NORMALIZATION: unknown version {}",
                case.normalization_version
            ));
        }
        if case.deterministic && case.network_allowed {
            return Err(format!("FF-COMP-E-DETERMINISTIC-NETWORK: {}", case.id));
        }
        if !case.deterministic {
            return Err(format!(
                "FF-COMP-E-COVERAGE: mandatory case {} is not deterministic",
                case.id
            ));
        }
        if case.shard != shard_for(&case.id, corpus.shard_count) {
            return Err(format!("FF-COMP-E-SHARD: {} has incorrect shard", case.id));
        }
        if !case
            .fixture
            .starts_with("build/fixtures/compatibility/cases/")
            || !safe_relative(&case.fixture)
        {
            return Err(format!(
                "FF-COMP-E-FIXTURE-PATH: unsafe fixture path {}",
                case.fixture
            ));
        }
        let fixture_path = root.join(&case.fixture);
        if sha256_file(&fixture_path)? != case.fixture_sha256 {
            return Err(format!("FF-COMP-E-FIXTURE-DIGEST: {}", case.id));
        }
        let fixture: Value = read_json(&fixture_path)?;
        validate_sanitized_value(&fixture)?;
    }
    if observed_planes != expected_planes {
        return Err("FF-COMP-E-COVERAGE: one or more mandatory planes have no case".to_owned());
    }
    checks.push(pass(
        "corpus-coverage",
        &format!(
            "{} deterministic cases cover all {} mandatory planes with stable IDs and verified digests",
            corpus.cases.len(),
            observed_planes.len()
        ),
    ));
    checks.push(pass(
        "corpus-network-isolation",
        "every mandatory case declares deterministic=true and network_allowed=false",
    ));
    Ok(())
}

fn validate_live_manifest(
    live: &LiveManifest,
    profile: &CompatibilityProfile,
) -> Result<(), String> {
    if live.schema_id != "ff.compatibility-live-canaries@1"
        || live.schema_version != "1.0.0"
        || live.profile_id != profile.profile_id
        || live.default_enabled
        || live.deterministic_proof
        || live.canaries.is_empty()
    {
        return Err(
            "FF-COMP-E-LIVE-POLICY: live canary suite is not mechanically opt-in".to_owned(),
        );
    }
    require_unique_stable_ids(live.canaries.iter().map(|canary| canary.id.as_str()))?;
    if live.canaries.iter().any(|canary| {
        !canary.url.starts_with("https://")
            || canary.timeout_seconds == 0
            || canary.timeout_seconds > 60
            || !stable_id(&canary.url_class)
            || !profile
                .extractors
                .iter()
                .any(|extractor| extractor.url_class == canary.url_class)
            || canary.credential_policy != "operator-supplied-outside-repository-or-none"
            || canary.expected_classification != "nondeterministic_observation"
    }) {
        return Err("FF-COMP-E-LIVE-POLICY: live canary row violates policy".to_owned());
    }
    Ok(())
}

fn validate_negative_fixtures(
    root: &Path,
    manifest: &OracleManifest,
    profile: &CompatibilityProfile,
    corpus: &CorpusManifest,
) -> Result<Vec<NegativeResult>, String> {
    let mut results = Vec::new();
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(root.join(NEGATIVE_ROOT)).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            return Err("FF-COMP-E-NEGATIVE-INVENTORY: non-directory entry".to_owned());
        }
        let case: NegativeCase = read_json(&entry.path().join("case.json"))?;
        let directory_id = entry.file_name().to_string_lossy().into_owned();
        if case.schema_version != 1
            || case.fixture_id != directory_id
            || !ids.insert(case.fixture_id.clone())
        {
            return Err(
                "FF-COMP-E-NEGATIVE-INVENTORY: invalid or duplicate fixture identity".to_owned(),
            );
        }
        let observed = exercise_mutation(&case.mutation, manifest, profile, corpus)
            .err()
            .ok_or_else(|| {
                format!(
                    "negative fixture {} produced no diagnostic",
                    case.fixture_id
                )
            })?;
        if observed != case.expected_diagnostic {
            return Err(format!(
                "negative fixture {} failed for wrong reason: expected {:?}, observed {:?}",
                case.fixture_id, case.expected_diagnostic, observed
            ));
        }
        results.push(NegativeResult {
            fixture_id: case.fixture_id,
            status: "PASS",
            expected_diagnostic: case.expected_diagnostic.clone(),
            observed_diagnostic: observed,
        });
    }
    results.sort_by(|left, right| left.fixture_id.cmp(&right.fixture_id));
    if results.len() < 7 {
        return Err("FF-COMP-E-NEGATIVE-INVENTORY: expected at least seven mutations".to_owned());
    }
    Ok(results)
}

fn exercise_mutation(
    mutation: &str,
    manifest: &OracleManifest,
    profile: &CompatibilityProfile,
    corpus: &CorpusManifest,
) -> Result<(), String> {
    match mutation {
        "remove_option_row" => {
            let mut changed = profile.clone();
            changed.options.pop();
            validate_profile(&changed, manifest)
        }
        "duplicate_option_id" => {
            let mut changed = profile.clone();
            let duplicate = changed
                .options
                .first()
                .ok_or("profile has no option")?
                .clone();
            changed.options.push(duplicate);
            changed.counts.options += 1;
            validate_profile(&changed, manifest)
        }
        "unstable_option_id" => {
            let mut changed = profile.clone();
            "Option Has Spaces".clone_into(
                &mut changed
                    .options
                    .first_mut()
                    .ok_or("profile has no option")?
                    .id,
            );
            validate_profile(&changed, manifest)
        }
        "unpin_oracle_version" => {
            let mut changed = manifest.clone();
            "latest".clone_into(&mut changed.release.version);
            validate_oracle_manifest(&changed)
        }
        "unpin_oracle_artifact" => {
            let mut changed = manifest.clone();
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".clone_into(
                &mut changed
                    .artifacts
                    .iter_mut()
                    .find(|artifact| artifact.artifact_id == "yt-dlp-windows-x64")
                    .ok_or("oracle executable artifact is absent")?
                    .sha256,
            );
            validate_oracle_manifest(&changed)
        }
        "unsafe_oracle_command" => {
            let mut changed = manifest.clone();
            "--dump-json".clone_into(
                changed
                    .generator
                    .commands
                    .first_mut()
                    .and_then(|command| command.last_mut())
                    .ok_or("oracle command is absent")?,
            );
            validate_oracle_manifest(&changed)
        }
        "unknown_normalization" => {
            let mut changed = corpus.clone();
            "unknown".clone_into(
                &mut changed
                    .cases
                    .first_mut()
                    .ok_or("corpus has no case")?
                    .normalization_version,
            );
            validate_corpus_without_files(&changed)
        }
        "enable_network_for_deterministic_case" => {
            let mut changed = corpus.clone();
            changed
                .cases
                .first_mut()
                .ok_or("corpus has no case")?
                .network_allowed = true;
            validate_corpus_without_files(&changed)
        }
        "inject_unsanitized_secret" => validate_sanitized_value(&serde_json::json!({
            "headers": {"Authorization": "Bearer actual-secret"}
        })),
        "duplicate_shard_case" => {
            let mut changed = corpus.clone();
            let duplicate = changed.cases.first().ok_or("corpus has no case")?.clone();
            changed.cases.push(duplicate);
            require_unique_stable_ids(changed.cases.iter().map(|case| case.id.as_str()))
        }
        "invalid_candidate_digest" => {
            let candidate = candidate_with_difference(corpus, None, Some("not-a-digest"));
            differential_rows(corpus, profile, &candidate).map(|_| ())
        }
        "accepted_divergence_without_decision" => {
            let candidate = candidate_with_difference(corpus, Some("accepted_divergence"), None);
            differential_rows(corpus, profile, &candidate).map(|_| ())
        }
        other => Err(format!("FF-COMP-E-UNKNOWN-MUTATION: {other}")),
    }
}

fn candidate_with_difference(
    corpus: &CorpusManifest,
    classification: Option<&str>,
    digest: Option<&str>,
) -> CandidateResults {
    CandidateResults {
        schema_id: "ff.compatibility-candidate-results@1".to_owned(),
        schema_version: "1.0.0".to_owned(),
        corpus_id: corpus.corpus_id.clone(),
        profile_id: corpus.profile_id.clone(),
        observations: vec![CandidateObservation {
            case_id: corpus.cases[0].id.clone(),
            observed_digest: digest
                .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000")
                .to_owned(),
            classification: classification.map(str::to_owned),
            decision_id: None,
        }],
    }
}

fn validate_corpus_without_files(corpus: &CorpusManifest) -> Result<(), String> {
    require_unique_stable_ids(corpus.cases.iter().map(|case| case.id.as_str()))?;
    for case in &corpus.cases {
        if case.normalization_version != NORMALIZATION_VERSION {
            return Err("FF-COMP-E-NORMALIZATION: unknown normalization version".to_owned());
        }
        if case.deterministic && case.network_allowed {
            return Err(
                "FF-COMP-E-DETERMINISTIC-NETWORK: deterministic case permits network".to_owned(),
            );
        }
    }
    Ok(())
}

fn validate_sanitized_value(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let sensitive = matches!(
                    key.to_ascii_lowercase().as_str(),
                    "authorization"
                        | "proxy-authorization"
                        | "cookie"
                        | "set-cookie"
                        | "api_key"
                        | "token"
                        | "password"
                );
                if sensitive
                    && value
                        .as_str()
                        .is_none_or(|text| !is_sanitized_placeholder(text))
                {
                    return Err(format!("FF-COMP-E-UNSANITIZED-SECRET: key={key}"));
                }
                validate_sanitized_value(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_sanitized_value(value)?;
            }
        }
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            if lower.contains("c:\\users\\")
                || lower.starts_with("/home/")
                || contains_unsanitized_assignment(text, "bearer ")
                || contains_unsanitized_assignment(text, "api_key=")
                || contains_unsanitized_assignment(text, "token=")
            {
                return Err(
                    "FF-COMP-E-UNSANITIZED-SECRET: sensitive or machine-local string".to_owned(),
                );
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn contains_unsanitized_assignment(text: &str, assignment: &str) -> bool {
    let mut remaining = text;
    while let Some(offset) = remaining.to_ascii_lowercase().find(assignment) {
        let value = &remaining[offset + assignment.len()..];
        let Some(close) = value.find("}}") else {
            return true;
        };
        let end = close + 2;
        if !is_sanitized_placeholder(&value[..end])
            || value[end..]
                .chars()
                .next()
                .is_some_and(|character| !matches!(character, '&' | '#' | ' ' | '\t'))
        {
            return true;
        }
        remaining = &value[end..];
    }
    false
}

fn is_sanitized_placeholder(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("{{")
        .and_then(|value| value.strip_suffix("}}"))
    else {
        return false;
    };
    !inner.is_empty()
        && inner.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

fn differential_rows(
    corpus: &CorpusManifest,
    profile: &CompatibilityProfile,
    candidate: &CandidateResults,
) -> Result<Vec<DifferentialRow>, String> {
    if candidate.schema_id != "ff.compatibility-candidate-results@1"
        || candidate.schema_version != "1.0.0"
        || candidate.corpus_id != corpus.corpus_id
        || candidate.profile_id != profile.profile_id
    {
        return Err("FF-COMP-E-CANDIDATE-IDENTITY: candidate input mismatch".to_owned());
    }
    require_unique_stable_ids(
        candidate
            .observations
            .iter()
            .map(|row| row.case_id.as_str()),
    )?;
    let expected_ids = corpus
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    if candidate
        .observations
        .iter()
        .any(|row| !expected_ids.contains(row.case_id.as_str()))
    {
        return Err("FF-COMP-E-CANDIDATE-UNKNOWN: candidate contains unknown case".to_owned());
    }
    if candidate
        .observations
        .iter()
        .any(|row| !valid_sha256(&row.observed_digest))
    {
        return Err("FF-COMP-E-CANDIDATE-DIGEST: candidate digest is not SHA-256".to_owned());
    }
    let observed = candidate
        .observations
        .iter()
        .map(|row| (row.case_id.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let allowed = BTreeSet::from([
        "accepted_baseline_correction",
        "accepted_divergence",
        "ferric_defect",
        "nondeterministic_response",
    ]);
    let mut rows = Vec::new();
    for case in &corpus.cases {
        let Some(candidate_row) = observed.get(case.id.as_str()) else {
            rows.push(DifferentialRow {
                case_id: case.id.clone(),
                status: "DIFFERENT",
                classification: "missing_feature".to_owned(),
                decision_id: None,
                expected_digest: case.fixture_sha256.clone(),
                observed_digest: None,
            });
            continue;
        };
        if candidate_row.observed_digest == case.fixture_sha256 {
            rows.push(DifferentialRow {
                case_id: case.id.clone(),
                status: "EQUIVALENT",
                classification: "equivalent".to_owned(),
                decision_id: None,
                expected_digest: case.fixture_sha256.clone(),
                observed_digest: Some(candidate_row.observed_digest.clone()),
            });
            continue;
        }
        let classification = candidate_row
            .classification
            .as_deref()
            .unwrap_or("ferric_defect");
        if !allowed.contains(classification) {
            return Err(format!(
                "FF-COMP-E-CLASSIFICATION: unknown {classification}"
            ));
        }
        if classification == "accepted_divergence"
            && candidate_row
                .decision_id
                .as_deref()
                .is_none_or(|id| !stable_id(id))
        {
            return Err(
                "FF-COMP-E-DIVERGENCE-DECISION: accepted divergence lacks stable decision ID"
                    .to_owned(),
            );
        }
        rows.push(DifferentialRow {
            case_id: case.id.clone(),
            status: "DIFFERENT",
            classification: classification.to_owned(),
            decision_id: candidate_row.decision_id.clone(),
            expected_digest: case.fixture_sha256.clone(),
            observed_digest: Some(candidate_row.observed_digest.clone()),
        });
    }
    Ok(rows)
}

fn inventory_diff(
    before: &CompatibilityProfile,
    after: &CompatibilityProfile,
) -> InventoryDiffReport {
    let before_options = before
        .options
        .iter()
        .map(|row| (&row.id, row))
        .collect::<BTreeMap<_, _>>();
    let after_options = after
        .options
        .iter()
        .map(|row| (&row.id, row))
        .collect::<BTreeMap<_, _>>();
    let before_extractors = before
        .extractors
        .iter()
        .map(|row| (&row.id, row))
        .collect::<BTreeMap<_, _>>();
    let after_extractors = after
        .extractors
        .iter()
        .map(|row| (&row.id, row))
        .collect::<BTreeMap<_, _>>();
    InventoryDiffReport {
        schema_id: "ff.compatibility-inventory-diff@1",
        schema_version: "1.0.0",
        before_profile_id: before.profile_id.clone(),
        after_profile_id: after.profile_id.clone(),
        added_options: set_difference(
            after_options.keys().copied(),
            before_options.keys().copied(),
        ),
        removed_options: set_difference(
            before_options.keys().copied(),
            after_options.keys().copied(),
        ),
        changed_options: before_options
            .iter()
            .filter_map(|(id, row)| {
                after_options
                    .get(id)
                    .filter(|other| {
                        serde_json::to_value(row).ok() != serde_json::to_value(other).ok()
                    })
                    .map(|_| (*id).clone())
            })
            .collect(),
        added_extractors: set_difference(
            after_extractors.keys().copied(),
            before_extractors.keys().copied(),
        ),
        removed_extractors: set_difference(
            before_extractors.keys().copied(),
            after_extractors.keys().copied(),
        ),
        changed_extractors: before_extractors
            .iter()
            .filter_map(|(id, row)| {
                after_extractors
                    .get(id)
                    .filter(|other| {
                        serde_json::to_value(row).ok() != serde_json::to_value(other).ok()
                    })
                    .map(|_| (*id).clone())
            })
            .collect(),
    }
}

fn set_difference<'a>(
    left: impl Iterator<Item = &'a String>,
    right: impl Iterator<Item = &'a String>,
) -> Vec<String> {
    let left = left.cloned().collect::<BTreeSet<_>>();
    let right = right.cloned().collect::<BTreeSet<_>>();
    left.difference(&right).cloned().collect()
}

fn base_report(
    root: &Path,
    command: &str,
    checks: Vec<CompatibilityCheck>,
    negative_fixtures: Vec<NegativeResult>,
    differential_rows: Vec<DifferentialRow>,
) -> Result<CompatibilityReport, String> {
    let source = source_state(root)?;
    let inputs = [ORACLE_PATH, PROFILE_PATH, CORPUS_PATH, LIVE_PATH]
        .into_iter()
        .map(|path| Ok((path.to_owned(), sha256_file(&root.join(path))?)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    Ok(CompatibilityReport {
        schema_id: "ff.compatibility-report@1",
        schema_version: "1.0.0",
        command: command.to_owned(),
        status: "PASS",
        source: CompatibilitySource {
            git_commit: source.git_commit,
            dirty: source.dirty,
            dirty_paths: source.dirty_paths,
        },
        inputs,
        checks,
        negative_fixtures,
        differential_rows,
        artifacts: vec![
            PROFILE_PATH.to_owned(),
            CORPUS_PATH.to_owned(),
            "build/reports".to_owned(),
        ],
        proof_limitations: vec![
            "Corpus validation and report completeness do not prove Ferric feature parity.".to_owned(),
            "Live canaries are opt-in nondeterministic observations and never satisfy offline deterministic acceptance.".to_owned(),
            "The generated profile inventories pinned oracle surfaces; later compatibility rows remain missing features until implemented and compared.".to_owned(),
        ],
    })
}

fn pass(id: &str, detail: &str) -> CompatibilityCheck {
    CompatibilityCheck {
        id: id.to_owned(),
        status: "PASS",
        detail: detail.to_owned(),
    }
}

fn write_compatibility_report(
    root: &Path,
    prefix: &str,
    report: &CompatibilityReport,
) -> Result<PathBuf, String> {
    let path = unique_report_path(root, prefix)?;
    atomic_json(&path, report)?;
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|error| error.to_string())
}

fn unique_report_path(root: &Path, prefix: &str) -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    Ok(root
        .join("build/reports")
        .join(format!("{prefix}-{nonce}-{}.json", std::process::id())))
}

fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path.parent().ok_or("output path has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(format!("atomic JSON write {}: {error}", path.display()));
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn required_arg<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    optional_arg(args, name).ok_or_else(|| format!("missing required argument {name}"))
}

fn optional_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].as_str())
}

fn require_safe_output(path: &str) -> Result<(), String> {
    if !safe_relative(path)
        || !(path.starts_with("build/fixtures/compatibility/") || path.starts_with("build/target/"))
    {
        return Err(format!("unsafe compatibility output path {path}"));
    }
    Ok(())
}

fn require_safe_input(path: &str) -> Result<(), String> {
    if !safe_relative(path)
        || !(path.starts_with("build/fixtures/compatibility/") || path.starts_with("build/target/"))
    {
        return Err(format!("unsafe compatibility input path {path}"));
    }
    Ok(())
}

fn safe_relative(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn stable_id(id: &str) -> bool {
    !id.is_empty()
        && id.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
}

fn require_unique_stable_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Result<(), String> {
    let mut observed = BTreeSet::new();
    for id in ids {
        if !stable_id(id) {
            return Err(format!("FF-COMP-E-UNSTABLE-ID: {id}"));
        }
        if !observed.insert(id) {
            return Err(format!("FF-COMP-E-DUPLICATE-ID: {id}"));
        }
    }
    Ok(())
}

fn stable_component(value: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            if separator && !output.is_empty() {
                output.push('-');
            }
            separator = false;
            output.push(character);
        } else {
            separator = true;
        }
    }
    output.trim_matches('-').to_owned()
}

fn oracle_output(
    root: &Path,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    let bytes = command_output_bytes_with_timeout(root, program, args, timeout)?;
    decode_oracle_output(bytes)
        .map_err(|error| format!("{program} {args:?} emitted invalid oracle output: {error}"))
}

fn decode_oracle_output(bytes: Vec<u8>) -> Result<String, String> {
    match String::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) => {
            let bytes = error.into_bytes();
            let mut output = String::with_capacity(bytes.len());
            for (offset, byte) in bytes.into_iter().enumerate() {
                let character = match byte {
                    0x00..=0x7f | 0xa0..=0xff => char::from_u32(u32::from(byte)),
                    0x80 => Some('\u{20ac}'),
                    0x82 => Some('\u{201a}'),
                    0x83 => Some('\u{0192}'),
                    0x84 => Some('\u{201e}'),
                    0x85 => Some('\u{2026}'),
                    0x86 => Some('\u{2020}'),
                    0x87 => Some('\u{2021}'),
                    0x88 => Some('\u{02c6}'),
                    0x89 => Some('\u{2030}'),
                    0x8a => Some('\u{0160}'),
                    0x8b => Some('\u{2039}'),
                    0x8c => Some('\u{0152}'),
                    0x8e => Some('\u{017d}'),
                    0x91 => Some('\u{2018}'),
                    0x92 => Some('\u{2019}'),
                    0x93 => Some('\u{201c}'),
                    0x94 => Some('\u{201d}'),
                    0x95 => Some('\u{2022}'),
                    0x96 => Some('\u{2013}'),
                    0x97 => Some('\u{2014}'),
                    0x98 => Some('\u{02dc}'),
                    0x99 => Some('\u{2122}'),
                    0x9a => Some('\u{0161}'),
                    0x9b => Some('\u{203a}'),
                    0x9c => Some('\u{0153}'),
                    0x9e => Some('\u{017e}'),
                    0x9f => Some('\u{0178}'),
                    _ => None,
                }
                .ok_or_else(|| format!("undefined Windows-1252 byte 0x{byte:02x} at {offset}"))?;
                output.push(character);
            }
            Ok(output)
        }
    }
}

fn normalized_capture(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

fn bounded_observation(value: &str) -> String {
    const LIMIT: usize = 240;
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut output = normalized.chars().take(LIMIT).collect::<String>();
    if normalized.chars().count() > LIMIT {
        output.push_str("...[truncated]");
    }
    output.replace('\n', " | ")
}

fn normalized_oracle_descriptions(value: &str) -> String {
    const RANDOM_SEARCH_PHRASES: [&str; 8] = [
        "cute kittens",
        "slithering pythons",
        "falling cat",
        "angry poodle",
        "purple fish",
        "running tortoise",
        "sleeping bunny",
        "burping cow",
    ];
    normalized_capture(value)
        .lines()
        .map(|line| {
            let Some(start) = line.find(" (e.g. \"") else {
                return line.to_owned();
            };
            let Some(relative_end) = line[start + 8..].find("\")") else {
                return line.to_owned();
            };
            let end = start + 8 + relative_end;
            let example = &line[start + 8..end];
            if !RANDOM_SEARCH_PHRASES
                .iter()
                .any(|phrase| example.ends_with(phrase))
            {
                return line.to_owned();
            }
            format!(
                "{}{{{{RANDOMIZED_SEARCH_EXAMPLE}}}}{}",
                &line[..start + 8],
                &line[end..]
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn sha256_text(text: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(text.as_bytes());
    encode_hex(&digest.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn shard_for(id: &str, total: u32) -> u32 {
    let mut digest = Sha256::new();
    digest.update(id.as_bytes());
    let bytes = digest.finalize();
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    value % total
}

fn parse_shard(value: &str) -> Result<(u32, u32), String> {
    let (index, total) = value
        .split_once('/')
        .ok_or("shard must use zero-based INDEX/TOTAL syntax")?;
    let index = index.parse::<u32>().map_err(|error| error.to_string())?;
    let total = total.parse::<u32>().map_err(|error| error.to_string())?;
    if total == 0 || index >= total {
        return Err("shard index must be zero-based and less than nonzero total".to_owned());
    }
    Ok((index, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_component_is_portable() {
        assert_eq!(
            stable_component("YouTube:Tab (CURRENTLY BROKEN)"),
            "youtube-tab-currently-broken"
        );
    }

    #[test]
    fn help_parser_extracts_alias_and_value() {
        let help = "  General Options:\n    -h, --help                      Print help\n    -o, --output TEMPLATE           Output template\n\n  Preset Aliases:\n    -t mp3                          -f bestaudio -x\n";
        let (options, presets) = parse_help(help).expect("fixture help must parse");
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].aliases, ["-h", "--help"]);
        assert!(options[1].takes_value);
        assert_eq!(presets[0].name, "mp3");
    }

    #[test]
    fn help_parser_keeps_deep_option_reference_as_description() {
        let help = "  General Options:\n    --remote-components COMPONENT   Fetch components\n                                    --remote-components or defaults\n    --no-remote-components          Disable fetching\n";
        let (options, _) = parse_help(help).expect("fixture help must parse");
        assert_eq!(options.len(), 2);
        assert!(options[0].description.contains("or defaults"));
    }

    #[test]
    fn secret_scanner_rejects_bearer_value() {
        let error = validate_sanitized_value(&serde_json::json!({
            "Authorization": "Bearer private"
        }))
        .expect_err("secret must fail");
        assert!(error.starts_with("FF-COMP-E-UNSANITIZED-SECRET"));
    }

    #[test]
    fn secret_scanner_accepts_placeholder_query_value() {
        validate_sanitized_value(&serde_json::json!(
            "https://media.invalid/item?token={{QUERY_TOKEN}}"
        ))
        .expect("placeholder must be accepted");
    }

    #[test]
    fn secret_scanner_rejects_placeholder_with_secret_suffix() {
        let error = validate_sanitized_value(&serde_json::json!(
            "https://media.invalid/item?token={{QUERY_TOKEN}}actual-secret"
        ))
        .expect_err("placeholder suffix must fail");
        assert!(error.starts_with("FF-COMP-E-UNSANITIZED-SECRET"));
    }

    #[test]
    fn shard_assignment_is_stable_and_bounded() {
        let first = shard_for("case-source-graph-direct-v1", 4);
        assert_eq!(first, shard_for("case-source-graph-direct-v1", 4));
        assert!(first < 4);
    }

    #[test]
    fn oracle_decoder_preserves_windows_1252() {
        assert_eq!(
            decode_oracle_output(b"espa\xf1ol \x80".to_vec()).expect("decode"),
            "español €"
        );
    }

    #[test]
    fn description_normalizer_removes_oracle_randomness() {
        let first = normalized_oracle_descriptions(
            "search: prefix (e.g. \"ytsearch5:cute kittens\")\r\nfixed",
        );
        let second = normalized_oracle_descriptions(
            "search: prefix (e.g. \"ytsearchall:purple fish\")\nfixed",
        );
        assert_eq!(first, second);
        assert!(first.contains("{{RANDOMIZED_SEARCH_EXAMPLE}}"));
    }
}
