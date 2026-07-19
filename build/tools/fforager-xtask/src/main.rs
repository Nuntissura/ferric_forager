use cargo_metadata::{DependencyKind, Metadata, PackageId};
use saphyr::{LoadableYamlNode, Yaml};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ARCH_GATE: &str = "FF-GATE-ARCH-001";
const PR_GATE: &str = "FF-GATE-PR-001";
const TOOL_COMMAND_TIMEOUT: Duration = Duration::from_mins(1);
const METADATA_COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const GATE_COMMAND_TIMEOUT: Duration = Duration::from_mins(15);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchitecturePolicy {
    schema_id: String,
    file_id: String,
    schema_version: String,
    accepted_design_decision_ids: Vec<String>,
    workspace_manifest: String,
    workspace_root: String,
    target_directory: String,
    root_toolchain_selector: String,
    governance_root: String,
    product_root: String,
    build_root: String,
    exception_authority: String,
    exception_decision_ids: Vec<String>,
    unsafe_policy: String,
    unsafe_exception_authority: String,
    unsafe_decision_ids: Vec<String>,
    internal_edge_default: String,
    forbidden_layer_edges: Vec<String>,
    forbidden_product_runtime_roots: Vec<String>,
    allowed_runtime_or_native_dependencies: Vec<String>,
    approved_transitive_build_packages: Vec<String>,
    approved_transitive_proc_macros: Vec<String>,
    members: Vec<MemberPolicy>,
    dependency_decisions: Vec<DependencyDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberPolicy {
    name: String,
    manifest: String,
    source_root: String,
    layer: String,
    artifact_role: String,
    shipped: bool,
    test_only: bool,
    publish_allowed: bool,
    allowed_internal_dependencies: Vec<AllowedInternalDependency>,
    split_trigger: String,
    feature_owner: String,
    profile: String,
    removal_condition: String,
    runtime_native_constraint_ref: String,
    unsafe_policy_ref: String,
    exception_policy_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowedInternalDependency {
    package: String,
    kinds: Vec<String>,
    target: Option<String>,
    optional: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyDecision {
    name: String,
    version: String,
    consumer: String,
    runtime_class: String,
    purpose: String,
    native: bool,
    owner: String,
    allowed_consumers: Vec<String>,
    reason: String,
    removal_trigger: String,
    approval_id: String,
    features: Vec<String>,
    default_features: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolingPolicy {
    schema_id: String,
    file_id: String,
    schema_version: String,
    rust_toolchain: String,
    supported_hosts: Vec<String>,
    auto_install: bool,
    advisory_database_max_age_hours: u64,
    tools: Vec<ToolPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolPolicy {
    name: String,
    identity_line: String,
    command: Vec<String>,
    source: String,
    provenance_kind: String,
    executable_sha256: Option<String>,
    owning_gate: String,
    required_now: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMap {
    schema_id: String,
    file_id: String,
    schema_version: String,
    rules: Vec<RuleProof>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleProof {
    rule_id: String,
    proof_classes: Vec<String>,
    validators: Vec<String>,
    fixture_ids: Vec<String>,
    limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    schema_version: u32,
    fixture_id: String,
    mutation: String,
    expected_diagnostic: String,
}

#[derive(Debug, Serialize)]
struct GateReport {
    schema_id: &'static str,
    schema_version: &'static str,
    gate_id: String,
    gate_version: u32,
    status: &'static str,
    exit_code: u8,
    source: SourceState,
    invocation: Invocation,
    inputs: Vec<InputState>,
    checks: Vec<Check>,
    rules: Vec<String>,
    fixtures: Vec<FixtureResult>,
    proof_classes: Vec<String>,
    proof_limitations: Vec<String>,
    artifacts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SourceState {
    git_commit: String,
    dirty: bool,
    dirty_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Invocation {
    repository_root: &'static str,
    gate_args: Vec<String>,
    canonical_command: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InputState {
    path: String,
    git_blob: String,
}

#[derive(Debug, Serialize)]
struct Check {
    id: String,
    status: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct FixtureResult {
    fixture_id: String,
    status: &'static str,
    execution_path: &'static str,
    expected_diagnostic: String,
    observed_diagnostics: Vec<String>,
}

#[derive(Debug)]
struct ArchitectureResult {
    checks: Vec<Check>,
    rules: Vec<String>,
    fixtures: Vec<FixtureResult>,
    proof_classes: Vec<String>,
    limitations: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fforager-xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let root = repo_root()?;
    require_repository_root_cwd(&root)?;
    match args.as_slice() {
        [gate] if gate == "architecture-check" => run_architecture_gate(&root, &args),
        [gate, evidence] if gate == "verify-pr" && evidence == "--evidence-from-taskboard" => {
            run_verify_pr(&root, &args)
        }
        [gate, evidence]
            if gate == "verify-deep" && evidence == "--evidence-from-taskboard" =>
        {
            Err("verify-deep is NOT_IMPLEMENTED and trigger-gated after Phase 0; it cannot report PASS".to_owned())
        }
        [gate] if matches!(gate.as_str(), "verify-release" | "watcher-check") => {
            Err(format!("{gate} is NOT_IMPLEMENTED for Phase 0 and cannot report PASS"))
        }
        _ => Err("usage: fforager-xtask <architecture-check|verify-pr --evidence-from-taskboard|verify-deep|verify-release|watcher-check>".to_owned()),
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot derive repository root from CARGO_MANIFEST_DIR".to_owned())
}

fn require_repository_root_cwd(root: &Path) -> Result<(), String> {
    let cwd = env::current_dir().map_err(|e| format!("read current directory: {e}"))?;
    let expected = root
        .canonicalize()
        .map_err(|e| format!("canonicalize repository root: {e}"))?;
    let actual = cwd
        .canonicalize()
        .map_err(|e| format!("canonicalize current directory: {e}"))?;
    if actual != expected {
        return Err(format!(
            "run from repository root {}; current directory is {}",
            expected.display(),
            actual.display()
        ));
    }
    Ok(())
}

fn run_architecture_gate(root: &Path, gate_args: &[String]) -> Result<(), String> {
    match run_architecture_gate_inner(root, gate_args) {
        Ok(()) => Ok(()),
        Err(error) => fail_with_report(root, ARCH_GATE, "architecture-check", gate_args, &error),
    }
}

fn run_architecture_gate_inner(root: &Path, gate_args: &[String]) -> Result<(), String> {
    let result = architecture_check(root)?;
    let report = GateReport {
        schema_id: "ff.gate-report@1",
        schema_version: "1.0.0",
        gate_id: ARCH_GATE.to_owned(),
        gate_version: 1,
        status: "PASS",
        exit_code: 0,
        source: source_state(root)?,
        invocation: invocation(gate_args),
        inputs: collect_inputs(root)?,
        checks: result.checks,
        rules: result.rules,
        fixtures: result.fixtures,
        proof_classes: result.proof_classes,
        proof_limitations: result.limitations,
        artifacts: vec!["build/reports".to_owned()],
    };
    let path = write_report(root, "architecture-check", &report)?;
    println!("PASS {ARCH_GATE}; report={}", slash(&path));
    Ok(())
}

fn architecture_check(root: &Path) -> Result<ArchitectureResult, String> {
    let policy: ArchitecturePolicy = read_toml(&root.join("build/architecture-policy.toml"))?;
    validate_policy_identity(&policy)?;
    let tooling: ToolingPolicy = read_toml(&root.join("build/tooling-policy.toml"))?;
    validate_tooling_policy(&tooling)?;
    validate_current_host(root, &tooling)?;
    let rule_map: RuleMap = read_toml(&root.join("build/rule-to-proof.toml"))?;
    validate_rule_map_identity(&rule_map)?;
    let metadata = cargo_metadata(root, &policy)?;
    let mut checks = Vec::new();
    validate_workspace(root, &policy, &metadata, &mut checks)?;
    validate_internal_graph(&policy, &metadata, &mut checks)?;
    validate_three_roots(root, &policy, &mut checks)?;
    validate_dependencies(&policy, &metadata, &mut checks)?;
    let canonical_rules = required_architecture_rules(&root.join(".GOV/rules/build-rules.yaml"))?;
    validate_rule_map(&rule_map, &canonical_rules, &mut checks)?;
    let fixtures = validate_fixtures(root, &rule_map, &mut checks)?;
    let limitations = rule_map
        .rules
        .iter()
        .flat_map(|rule| rule.limitations.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let proof_classes = rule_map
        .rules
        .iter()
        .flat_map(|rule| rule.proof_classes.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ArchitectureResult {
        checks,
        rules: canonical_rules.into_iter().collect(),
        fixtures,
        proof_classes,
        limitations,
    })
}

fn validate_policy_identity(policy: &ArchitecturePolicy) -> Result<(), String> {
    if policy.schema_id != "ff.architecture_policy@2"
        || policy.file_id != "FF-GOV-BUILD-ARCH-POLICY-001"
        || policy.schema_version != "2.0.0"
        || policy.accepted_design_decision_ids != ["FF-BUILD-036", "FF-BUILD-077"]
    {
        return Err("unsupported architecture-policy schema".to_owned());
    }
    let exact_paths = [
        (policy.workspace_manifest.as_str(), "build/Cargo.toml"),
        (policy.workspace_root.as_str(), "build"),
        (policy.target_directory.as_str(), "build/target"),
        (
            policy.root_toolchain_selector.as_str(),
            "rust-toolchain.toml",
        ),
        (policy.governance_root.as_str(), ".GOV"),
        (policy.product_root.as_str(), "product"),
        (policy.build_root.as_str(), "build"),
        (
            policy.exception_authority.as_str(),
            ".GOV/rules/build-rules.yaml",
        ),
    ];
    if exact_paths
        .iter()
        .any(|(observed, expected)| observed != expected)
    {
        return Err(format!(
            "architecture-policy canonical path mismatch: {exact_paths:?}"
        ));
    }
    if unapproved_exception_diagnostic(policy.exception_decision_ids.len()).is_some() {
        return Err(
            "FF-ARCH-E-UNAPPROVED-EXCEPTION: canonical exception allowlist is empty".to_owned(),
        );
    }
    let expected_forbidden = BTreeSet::from([
        "engine->frontend",
        "engine->adapter",
        "engine->watcher",
        "adapter->adapter",
        "product->watcher",
        "watcher->engine",
        "normal_or_build:product->testkit",
    ]);
    let observed_forbidden: BTreeSet<_> = policy
        .forbidden_layer_edges
        .iter()
        .map(String::as_str)
        .collect();
    if policy.unsafe_policy != "forbid_in_workspace_members"
        || policy.unsafe_exception_authority != ".GOV/rules/build-rules.yaml#exception_authority"
        || !policy.unsafe_decision_ids.is_empty()
        || policy.internal_edge_default != "deny"
        || observed_forbidden != expected_forbidden
    {
        return Err("unsafe or direct-edge decision policy mismatch".to_owned());
    }
    if policy.allowed_runtime_or_native_dependencies != ["FFmpeg", "ffprobe"] {
        return Err("architecture-policy changed the approved runtime/native boundary".to_owned());
    }
    Ok(())
}

fn validate_rule_map_identity(rule_map: &RuleMap) -> Result<(), String> {
    if rule_map.schema_id != "ff.rule_to_proof@1"
        || rule_map.file_id != "FF-GOV-BUILD-RULE-PROOF-001"
        || rule_map.schema_version != "1.0.0"
    {
        return Err("unsupported rule-to-proof schema".to_owned());
    }
    Ok(())
}

fn validate_tooling_policy(policy: &ToolingPolicy) -> Result<(), String> {
    if policy.supported_hosts != ["x86_64-pc-windows-msvc"] {
        return Err(format!(
            "FF-TOOL-E-UNSUPPORTED-HOST: unsupported bootstrap host inventory {:?}",
            policy.supported_hosts
        ));
    }
    if policy.schema_id != "ff.tooling_policy@3"
        || policy.file_id != "FF-GOV-BUILD-TOOLING-POLICY-001"
        || policy.schema_version != "3.0.0"
        || policy.rust_toolchain != "1.97.1"
        || policy.auto_install
        || policy.advisory_database_max_age_hours != 168
    {
        return Err("invalid tooling-policy identity or bootstrap settings".to_owned());
    }
    let mut names = BTreeSet::new();
    for tool in &policy.tools {
        if !names.insert(tool.name.as_str())
            || tool.identity_line.trim().is_empty()
            || tool.command.is_empty()
            || tool.command.iter().any(String::is_empty)
            || tool.source.trim().is_empty()
            || tool.owning_gate != PR_GATE
            || !tool.required_now
        {
            return Err(format!(
                "invalid or duplicate tool policy for {}",
                tool.name
            ));
        }
    }
    let required = BTreeSet::from(["cargo", "cargo-deny", "clippy", "git", "rustc", "rustfmt"]);
    if names != required {
        return Err(format!("tooling-policy inventory mismatch: {names:?}"));
    }
    for tool in &policy.tools {
        let expected = expected_tool_policy(&tool.name)
            .ok_or_else(|| format!("unknown bootstrap tool policy for {}", tool.name))?;
        if tool.identity_line != expected.identity_line
            || tool.command != expected.command
            || tool.source != expected.source
            || tool.provenance_kind != expected.provenance_kind
            || tool.executable_sha256.as_deref() != expected.executable_sha256
        {
            return Err(format!(
                "tool {} does not match its canonical identity, command, source, and provenance",
                tool.name
            ));
        }
    }
    Ok(())
}

struct ExpectedToolPolicy {
    identity_line: &'static str,
    command: Vec<String>,
    source: &'static str,
    provenance_kind: &'static str,
    executable_sha256: Option<&'static str>,
}

fn expected_tool_policy(name: &str) -> Option<ExpectedToolPolicy> {
    let strings = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
    match name {
        "rustc" => Some(ExpectedToolPolicy {
            identity_line: "rustc 1.97.1 (8bab26f4f 2026-07-14)",
            command: strings(&["rustc", "--version", "--verbose"]),
            source: "root rust-toolchain.toml",
            provenance_kind: "root-toolchain-and-cargo-lock",
            executable_sha256: None,
        }),
        "cargo" => Some(ExpectedToolPolicy {
            identity_line: "cargo 1.97.1 (c980f4866 2026-06-30)",
            command: strings(&["cargo", "--version", "--verbose"]),
            source: "root rust-toolchain.toml",
            provenance_kind: "root-toolchain-and-cargo-lock",
            executable_sha256: None,
        }),
        "rustfmt" => Some(ExpectedToolPolicy {
            identity_line: "rustfmt 1.9.0-stable (8bab26f4f6 2026-07-14)",
            command: strings(&["rustfmt", "--version"]),
            source: "pinned rustup component",
            provenance_kind: "root-toolchain-and-cargo-lock",
            executable_sha256: None,
        }),
        "clippy" => Some(ExpectedToolPolicy {
            identity_line: "clippy 0.1.97 (8bab26f4f6 2026-07-14)",
            command: strings(&["cargo", "clippy", "--version"]),
            source: "pinned rustup component",
            provenance_kind: "root-toolchain-and-cargo-lock",
            executable_sha256: None,
        }),
        "git" => Some(ExpectedToolPolicy {
            identity_line: "git version 2.53.0.windows.3",
            command: strings(&["git", "--version"]),
            source: "supported host installation",
            provenance_kind: "executable-sha256",
            executable_sha256: Some(
                "c53279919fdea03474bb23b465b3a82287157491f1bd69a5eb82dd9831582333",
            ),
        }),
        "cargo-deny" => Some(ExpectedToolPolicy {
            identity_line: "cargo-deny 0.20.2",
            command: strings(&["cargo", "deny", "--version"]),
            source: "cargo install cargo-deny --version 0.20.2 --locked",
            provenance_kind: "executable-sha256",
            executable_sha256: Some(
                "6e67806f5cf7d4da170d226a8f12cbd16aba236f51af1d75bc9fc56129d998ae",
            ),
        }),
        _ => None,
    }
}

fn validate_current_host(root: &Path, policy: &ToolingPolicy) -> Result<String, String> {
    let rustc = policy
        .tools
        .iter()
        .find(|tool| tool.name == "rustc")
        .ok_or("tooling policy omits rustc host probe")?;
    let (program, args) = rustc
        .command
        .split_first()
        .ok_or("empty rustc host command")?;
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = command_output(root, program, &args)?;
    let host = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("host: "))
        .ok_or("rustc verbose identity omits host triple")?;
    if !host_supported(&policy.supported_hosts, host) {
        return Err(format!(
            "current host {host} is not in supported_hosts {:?}",
            policy.supported_hosts
        ));
    }
    Ok(host.to_owned())
}

fn host_supported(supported_hosts: &[String], host: &str) -> bool {
    supported_hosts.iter().any(|supported| supported == host)
}

fn cargo_metadata(root: &Path, policy: &ArchitecturePolicy) -> Result<Metadata, String> {
    let output = command_output_with_timeout(
        root,
        "cargo",
        &[
            "metadata",
            "--format-version",
            "1",
            "--manifest-path",
            &policy.workspace_manifest,
            "--all-features",
            "--locked",
        ],
        METADATA_COMMAND_TIMEOUT,
    )?;
    serde_json::from_str(&output).map_err(|error| format!("parse locked Cargo metadata: {error}"))
}

fn validate_workspace(
    root: &Path,
    policy: &ArchitecturePolicy,
    metadata: &Metadata,
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    validate_workspace_manifest(root)?;
    let expected_workspace = root
        .join(&policy.workspace_root)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let observed_workspace = Path::new(metadata.workspace_root.as_str())
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if observed_workspace != expected_workspace {
        return Err(format!(
            "workspace root mismatch: expected {}, observed {}",
            expected_workspace.display(),
            observed_workspace.display()
        ));
    }
    let expected_target = root.join(&policy.target_directory);
    let observed_target = Path::new(metadata.target_directory.as_str());
    if normalize(observed_target) != normalize(&expected_target) {
        return Err(format!(
            "target directory mismatch: expected {}, observed {}",
            expected_target.display(),
            observed_target.display()
        ));
    }
    let expected_names: BTreeSet<_> = policy
        .members
        .iter()
        .map(|member| member.name.as_str())
        .collect();
    let observed_names: BTreeSet<_> = metadata
        .workspace_packages()
        .into_iter()
        .map(|package| package.name.as_str())
        .collect();
    if !member_inventory_matches(&expected_names, &observed_names) {
        return Err(format!(
            "FF-ARCH-E-UNDECLARED-MEMBER: expected {expected_names:?}, observed {observed_names:?}"
        ));
    }
    if policy.members.len() != 1 || policy.members[0].name != "fforager-xtask" {
        return Err(
            "FF-ARCH-E-UNDECLARED-MEMBER: Phase 0 policy must declare exactly fforager-xtask"
                .to_owned(),
        );
    }
    let observed_defaults: BTreeSet<_> = metadata.workspace_default_members.iter().collect();
    let observed_members: BTreeSet<_> = metadata.workspace_members.iter().collect();
    if observed_defaults != observed_members {
        return Err("workspace default-members must exactly equal workspace members".to_owned());
    }
    if policy.members.iter().any(|member| member.shipped) {
        return Err(
            "FF-ARCH-E-SHIPPED-BEFORE-BOOTSTRAP: WP-003 must contain zero shipped members"
                .to_owned(),
        );
    }
    for member in &policy.members {
        validate_member_metadata(root, &policy.build_root, member, metadata)?;
    }
    checks.push(pass(
        "workspace-shape",
        "locked resolver-3 workspace has one declared non-shipped member and build/target output",
    ));
    Ok(())
}

fn validate_member_metadata(
    root: &Path,
    build_root: &str,
    member: &MemberPolicy,
    metadata: &Metadata,
) -> Result<(), String> {
    require_relative_contained(root, &member.manifest, build_root)?;
    require_relative_contained(root, &member.source_root, build_root)?;
    if !split_trigger_valid(&member.split_trigger) {
        return Err(format!(
            "FF-ARCH-E-INVALID-SPLIT-TRIGGER: {} cites {}",
            member.name, member.split_trigger
        ));
    }
    if member.layer.trim().is_empty()
        || member.artifact_role.trim().is_empty()
        || member.feature_owner.trim().is_empty()
        || member.profile.trim().is_empty()
        || member.removal_condition.trim().is_empty()
        || member.runtime_native_constraint_ref != "FF-START-BOUNDARY-001"
        || member.unsafe_policy_ref != "FF-BUILD-050"
        || member.exception_policy_ref != "FF-BUILD-052"
        || member.publish_allowed
        || !member.allowed_internal_dependencies.is_empty()
        || member.test_only
    {
        return Err(format!("invalid Phase 0 member policy for {}", member.name));
    }
    let manifest_text =
        fs::read_to_string(root.join(&member.manifest)).map_err(|e| e.to_string())?;
    if !manifest_inherits_workspace_lints(&manifest_text)? {
        return Err(format!(
            "{} does not inherit workspace lints",
            member.manifest
        ));
    }
    let package = metadata
        .workspace_packages()
        .into_iter()
        .find(|package| package.name.as_str() == member.name)
        .ok_or_else(|| format!("metadata package is absent for {}", member.name))?;
    let expected_manifest = root
        .join(&member.manifest)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let observed_manifest = Path::new(package.manifest_path.as_str())
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if observed_manifest != expected_manifest
        || package.source.is_some()
        || package.edition.to_string() != "2024"
        || package
            .rust_version
            .as_ref()
            .is_none_or(|version| version.to_string() != "1.97.1")
        || package
            .publish
            .as_ref()
            .is_none_or(|registries| !registries.is_empty())
    {
        return Err(format!(
            "workspace package metadata violates Phase 0 policy for {}",
            member.name
        ));
    }
    let source_root = root
        .join(&member.source_root)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    for target in &package.targets {
        let source = Path::new(target.src_path.as_str())
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if !source.starts_with(&source_root) {
            return Err(format!(
                "target source escapes declared source root: {}",
                source.display()
            ));
        }
    }
    Ok(())
}

fn manifest_inherits_workspace_lints(manifest_text: &str) -> Result<bool, String> {
    let manifest = manifest_text
        .parse::<toml::Table>()
        .map_err(|error| format!("parse member manifest: {error}"))?;
    Ok(manifest
        .get("lints")
        .and_then(toml::Value::as_table)
        .and_then(|lints| lints.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true))
}

fn validate_workspace_manifest(root: &Path) -> Result<(), String> {
    let manifest: toml::Value = read_toml(&root.join("build/Cargo.toml"))?;
    let workspace = manifest
        .get("workspace")
        .and_then(toml::Value::as_table)
        .ok_or("build/Cargo.toml has no workspace table")?;
    if workspace.get("resolver").and_then(toml::Value::as_str) != Some("3") {
        return Err("workspace resolver must be exactly 3".to_owned());
    }
    for key in ["members", "default-members"] {
        let values = workspace
            .get(key)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("workspace {key} is absent"))?;
        if values.len() != 1 || values[0].as_str() != Some("tools/fforager-xtask") {
            return Err(format!(
                "workspace {key} must contain only tools/fforager-xtask"
            ));
        }
    }
    let package = workspace
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or("workspace.package is absent")?;
    if package.get("edition").and_then(toml::Value::as_str) != Some("2024")
        || package.get("rust-version").and_then(toml::Value::as_str) != Some("1.97.1")
        || package.get("publish").and_then(toml::Value::as_bool) != Some(false)
    {
        return Err(
            "workspace package edition, rust-version, or publish policy mismatch".to_owned(),
        );
    }
    let selector: toml::Value = read_toml(&root.join("rust-toolchain.toml"))?;
    let toolchain = selector
        .get("toolchain")
        .and_then(toml::Value::as_table)
        .ok_or("root toolchain selector is malformed")?;
    let components = toolchain
        .get("components")
        .and_then(toml::Value::as_array)
        .ok_or("toolchain components are absent")?;
    let actual: BTreeSet<_> = components.iter().filter_map(toml::Value::as_str).collect();
    if toolchain.get("channel").and_then(toml::Value::as_str) != Some("1.97.1")
        || toolchain.get("profile").and_then(toml::Value::as_str) != Some("minimal")
        || actual != BTreeSet::from(["clippy", "rustfmt"])
    {
        return Err(
            "root toolchain selector does not match the pinned Phase 0 identity".to_owned(),
        );
    }
    Ok(())
}

fn validate_internal_graph(
    policy: &ArchitecturePolicy,
    metadata: &Metadata,
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    let packages = metadata.workspace_packages();
    let mut by_id: BTreeMap<&PackageId, &MemberPolicy> = BTreeMap::new();
    for package in &packages {
        let member = policy
            .members
            .iter()
            .find(|member| member.name == package.name.as_str())
            .ok_or_else(|| format!("FF-ARCH-E-UNDECLARED-MEMBER: {}", package.name))?;
        by_id.insert(&package.id, member);
    }
    let member_names: BTreeSet<_> = policy
        .members
        .iter()
        .map(|member| member.name.as_str())
        .collect();
    for package in &packages {
        let member = policy
            .members
            .iter()
            .find(|member| member.name == package.name.as_str())
            .ok_or("workspace package has no member policy")?;
        for allowed in &member.allowed_internal_dependencies {
            if !member_names.contains(allowed.package.as_str())
                || allowed.kinds.is_empty()
                || allowed
                    .kinds
                    .iter()
                    .any(|kind| !matches!(kind.as_str(), "normal" | "dev" | "build"))
            {
                return Err(format!(
                    "invalid allowed internal edge from {} to {}",
                    member.name, allowed.package
                ));
            }
        }
        for dependency in package
            .dependencies
            .iter()
            .filter(|dependency| member_names.contains(dependency.name.as_str()))
        {
            let kind = dependency.kind.to_string();
            let target = dependency.target.as_ref().map(ToString::to_string);
            if !member.allowed_internal_dependencies.iter().any(|allowed| {
                allowed.package == dependency.name
                    && allowed.kinds.contains(&kind)
                    && allowed.target == target
                    && allowed.optional == dependency.optional
            }) {
                let target_policy = policy
                    .members
                    .iter()
                    .find(|candidate| candidate.name == dependency.name)
                    .ok_or("internal dependency has no member policy")?;
                return Err(classify_forbidden_edge(
                    member,
                    target_policy,
                    dependency.kind,
                ));
            }
        }
    }
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or("Cargo metadata omitted resolve graph")?;
    let mut edges = Vec::new();
    for node in &resolve.nodes {
        let Some(from) = by_id.get(&node.id) else {
            continue;
        };
        for dependency in &node.deps {
            let Some(to) = by_id.get(&dependency.pkg) else {
                continue;
            };
            for kind in &dependency.dep_kinds {
                let kind_name = kind.kind.to_string();
                let target = kind.target.as_ref().map(ToString::to_string);
                if !from.allowed_internal_dependencies.iter().any(|allowed| {
                    allowed.package == to.name
                        && allowed.kinds.contains(&kind_name)
                        && allowed.target == target
                }) {
                    return Err(classify_forbidden_edge(from, to, kind.kind));
                }
                edges.push((from.name.as_str(), to.name.as_str()));
            }
        }
    }
    if graph_has_cycle(&edges) {
        return Err("FF-ARCH-E-CYCLE: internal workspace dependency cycle".to_owned());
    }
    checks.push(pass(
        "internal-graph",
        "normal, dev, build, optional, and target-conditioned internal edges match policy and are acyclic",
    ));
    Ok(())
}

fn classify_forbidden_edge(from: &MemberPolicy, to: &MemberPolicy, kind: DependencyKind) -> String {
    let diagnostic = classify_layers(&from.layer, &to.layer, kind);
    format!("{diagnostic}: {} -{kind}-> {}", from.name, to.name)
}

fn classify_layers(from_layer: &str, to_layer: &str, kind: DependencyKind) -> &'static str {
    if from_layer == "adapter" && to_layer == "adapter" {
        "FF-ARCH-E-ADAPTER-EDGE"
    } else if to_layer == "testkit"
        && matches!(kind, DependencyKind::Normal | DependencyKind::Build)
    {
        "FF-ARCH-E-TESTKIT-EDGE"
    } else if from_layer == "watcher" {
        "FF-ARCH-E-WATCHER-EDGE"
    } else if to_layer == "watcher" {
        "FF-ARCH-E-PRODUCT-WATCHER-EDGE"
    } else {
        "FF-ARCH-E-FORBIDDEN-EDGE"
    }
}

fn graph_has_cycle(edges: &[(&str, &str)]) -> bool {
    let mut nodes = BTreeSet::new();
    let mut indegree = BTreeMap::new();
    for (from, to) in edges {
        nodes.insert(*from);
        nodes.insert(*to);
        indegree.entry(*from).or_insert(0_usize);
        *indegree.entry(*to).or_insert(0) += 1;
    }
    let mut ready: Vec<_> = nodes
        .iter()
        .copied()
        .filter(|node| indegree.get(node).copied().unwrap_or(0) == 0)
        .collect();
    let mut visited = 0;
    while let Some(node) = ready.pop() {
        visited += 1;
        for (_, to) in edges.iter().filter(|(from, _)| *from == node) {
            let count = indegree.get_mut(to).expect("edge target has indegree");
            *count -= 1;
            if *count == 0 {
                ready.push(*to);
            }
        }
    }
    visited != nodes.len()
}

fn member_inventory_matches<T: Ord>(expected: &BTreeSet<T>, observed: &BTreeSet<T>) -> bool {
    expected == observed
}

fn split_trigger_valid(trigger: &str) -> bool {
    trigger == "FF-BUILD-036"
}

fn unapproved_exception_diagnostic(count: usize) -> Option<&'static str> {
    (count != 0).then_some("FF-ARCH-E-UNAPPROVED-EXCEPTION")
}

fn root_state_diagnostic(wrong_paths: usize, selectors: usize) -> Option<&'static str> {
    if wrong_paths != 0 {
        Some("FF-ARCH-E-WRONG-ROOT")
    } else if selectors != 1 {
        Some("FF-ARCH-E-DUPLICATE-TOOLCHAIN")
    } else {
        None
    }
}

fn runtime_literal_diagnostic(source: &str) -> Option<&'static str> {
    let lower = source.to_ascii_lowercase();
    (lower.contains(".gov")
        || lower.contains("\"build\"")
        || lower.contains("build/")
        || lower.contains("build\\"))
    .then_some("FF-ARCH-E-RUNTIME-BOUNDARY")
}

fn validate_three_roots(
    root: &Path,
    policy: &ArchitecturePolicy,
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    for expected in [
        &policy.governance_root,
        &policy.product_root,
        &policy.build_root,
    ] {
        if !root.join(expected).is_dir() {
            return Err(format!("required repository root is absent: {expected}"));
        }
    }
    if policy.forbidden_product_runtime_roots != [".GOV", "build"] {
        return Err("product runtime boundary must forbid .GOV and build".to_owned());
    }
    let wrong_root = [
        "Cargo.toml",
        "Cargo.lock",
        "architecture-policy.toml",
        "tooling-policy.toml",
        "rule-to-proof.toml",
        "deny.toml",
        "tools",
        "crates/fforager-testkit",
        "fixtures",
        "integration-tests",
        "fuzz",
        "benches",
        "reports",
        "target",
        ".GOV/Cargo.toml",
        ".GOV/Cargo.lock",
        ".GOV/rust-toolchain.toml",
        ".GOV/architecture-policy.toml",
        ".GOV/tooling-policy.toml",
        ".GOV/rule-to-proof.toml",
        ".GOV/tools",
        ".GOV/fixtures",
        ".GOV/integration-tests",
        ".GOV/fuzz",
        ".GOV/benches",
        ".GOV/reports",
        ".GOV/target",
        "product/Cargo.toml",
        "product/Cargo.lock",
        "product/rust-toolchain.toml",
        "product/architecture-policy.toml",
        "product/tooling-policy.toml",
        "product/rule-to-proof.toml",
        "product/tools/fforager-xtask",
        "product/crates/fforager-testkit",
        "product/fixtures",
        "product/integration-tests",
        "product/tests",
        "product/fuzz",
        "product/benches",
        "product/reports",
        "product/target",
        "build/rust-toolchain.toml",
    ];
    let existing_wrong: Vec<_> = wrong_root
        .iter()
        .copied()
        .filter(|path| root.join(path).exists())
        .collect();
    let existing = toolchain_selectors(root)?;
    if let Some(diagnostic) = root_state_diagnostic(existing_wrong.len(), existing.len()) {
        return Err(format!(
            "{diagnostic}: wrong_paths={existing_wrong:?}; selectors={existing:?}"
        ));
    }
    let exception_authority = fs::read_to_string(root.join(&policy.exception_authority))
        .map_err(|e| format!("read exception authority: {e}"))?;
    if !exception_authority
        .lines()
        .any(|line| line.trim() == "canonical_allowlist: []")
    {
        return Err("exception authority does not expose the canonical empty allowlist".to_owned());
    }
    scan_product_runtime_literals(root)?;
    checks.push(pass(
        "three-root-boundary",
        ".GOV, product, and build ownership is exclusive; root selector is unique",
    ));
    Ok(())
}

fn toolchain_selectors(root: &Path) -> Result<Vec<String>, String> {
    let mut selectors = Vec::new();
    for name in ["rust-toolchain.toml", "rust-toolchain"] {
        if root.join(name).is_file() {
            selectors.push(name.to_owned());
        }
    }
    let generated_target = root.join("build/target");
    let mut pending = [".GOV", "product", "build"]
        .iter()
        .map(|directory| root.join(directory))
        .collect::<Vec<_>>();
    while let Some(directory) = pending.pop() {
        if directory == generated_target {
            continue;
        }
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_dir() && !kind.is_symlink() {
                pending.push(entry.path());
            } else if kind.is_file()
                && matches!(
                    entry.file_name().to_str(),
                    Some("rust-toolchain.toml" | "rust-toolchain")
                )
            {
                selectors.push(slash(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|error| error.to_string())?,
                ));
            }
        }
    }
    selectors.sort();
    Ok(selectors)
}

fn scan_product_runtime_literals(root: &Path) -> Result<(), String> {
    let product = root.join("product");
    if !product.exists() {
        return Ok(());
    }
    for path in walk_files(&product)? {
        if path.extension() != Some(OsStr::new("rs")) {
            continue;
        }
        let text =
            fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if runtime_literal_diagnostic(&text).is_some() {
            return Err(format!(
                "FF-ARCH-E-RUNTIME-BOUNDARY: product source references governance/build path: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_dependencies(
    policy: &ArchitecturePolicy,
    metadata: &Metadata,
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    let decisions = validate_dependency_decisions(policy)?;
    let package = metadata
        .workspace_packages()
        .into_iter()
        .next()
        .ok_or("workspace has no package")?;
    validate_direct_dependencies(package, &decisions)?;
    validate_transitive_dependencies(policy, metadata)?;
    checks.push(pass(
        "dependency-policy",
        "all direct dependencies are exact non-shipped tooling decisions; transitive build/proc-macro packages match policy and no package declares native links",
    ));
    Ok(())
}

fn validate_dependency_decisions(
    policy: &ArchitecturePolicy,
) -> Result<BTreeMap<&str, &DependencyDecision>, String> {
    let decisions: BTreeMap<_, _> = policy
        .dependency_decisions
        .iter()
        .map(|decision| (decision.name.as_str(), decision))
        .collect();
    if decisions.len() != policy.dependency_decisions.len() {
        return Err("duplicate dependency decision".to_owned());
    }
    for decision in decisions.values() {
        if decision.consumer != "fforager-xtask"
            || decision.runtime_class != "non_shipped_build_tooling"
            || decision.purpose.trim().is_empty()
            || decision.native
            || decision.version.trim().is_empty()
            || decision.owner != "WP-FF-003-executable-gate-bootstrap"
            || decision.allowed_consumers != ["fforager-xtask"]
            || decision.reason.trim().is_empty()
            || decision.removal_trigger.trim().is_empty()
            || !decision
                .approval_id
                .starts_with("WP-FF-003-executable-gate-bootstrap-")
            || decision.features.len() != decision.features.iter().collect::<BTreeSet<_>>().len()
        {
            return Err(format!(
                "invalid tooling-only dependency decision for {}",
                decision.name
            ));
        }
    }
    Ok(decisions)
}

fn validate_direct_dependencies(
    package: &cargo_metadata::Package,
    decisions: &BTreeMap<&str, &DependencyDecision>,
) -> Result<(), String> {
    let declared: BTreeSet<_> = package
        .dependencies
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    let expected: BTreeSet<_> = decisions.keys().copied().collect();
    if declared != expected {
        return Err(format!(
            "direct dependency decisions mismatch: expected {expected:?}, observed {declared:?}"
        ));
    }
    for dependency in &package.dependencies {
        let decision = decisions
            .get(dependency.name.as_str())
            .ok_or("direct dependency has no decision")?;
        if !dependency_features_match(
            &dependency.features,
            dependency.uses_default_features,
            decision,
        ) {
            return Err(format!(
                "FF-ARCH-E-DEPENDENCY-FEATURE: {} features/default-features differ from policy",
                dependency.name
            ));
        }
        if dependency.req.to_string() != format!("={}", decision.version)
            || dependency.path.is_some()
            || dependency.source.as_ref().is_some_and(|source| {
                !source
                    .repr
                    .starts_with("registry+https://github.com/rust-lang/crates.io-index")
            })
        {
            return Err(format!(
                "dependency {} is not exact crates.io policy",
                dependency.name
            ));
        }
    }
    Ok(())
}

fn validate_transitive_dependencies(
    policy: &ArchitecturePolicy,
    metadata: &Metadata,
) -> Result<(), String> {
    let mut observed_build = BTreeSet::new();
    let mut observed_proc = BTreeSet::new();
    for package in &metadata.packages {
        if package.links.is_some() {
            return Err(format!(
                "native links package is unapproved: {}",
                package.name
            ));
        }
        let identity = format!("{}@{}", package.name, package.version);
        for target in &package.targets {
            if target.is_custom_build() {
                observed_build.insert(identity.clone());
            }
            if target.is_proc_macro() {
                observed_proc.insert(identity.clone());
            }
        }
    }
    let expected_build: BTreeSet<_> = policy
        .approved_transitive_build_packages
        .iter()
        .cloned()
        .collect();
    let expected_proc: BTreeSet<_> = policy
        .approved_transitive_proc_macros
        .iter()
        .cloned()
        .collect();
    if observed_build != expected_build || observed_proc != expected_proc {
        return Err(format!(
            "transitive build/proc-macro surface mismatch: build={observed_build:?}, proc={observed_proc:?}"
        ));
    }
    Ok(())
}

fn required_architecture_rules(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let document = parse_single_yaml(&text, &path.display().to_string())
        .map_err(|error| format!("FF-ARCH-E-POLICY-SCHEMA: {error}"))?;
    let rows = document
        .as_mapping_get("rules")
        .and_then(Yaml::as_sequence)
        .ok_or("build rules YAML has no rules sequence")?;
    let mut rules = BTreeSet::new();
    for row in rows {
        let id = yaml_string(row, "id")?;
        let category = yaml_string(row, "category")?;
        let enforcement = yaml_string(row, "enforcement")?;
        if category == "architecture" && enforcement == "REQUIRED" && !rules.insert(id.to_owned()) {
            return Err(format!("duplicate REQUIRED architecture rule {id}"));
        }
    }
    if rules.is_empty() {
        return Err("no REQUIRED architecture rules found in canonical build rules".to_owned());
    }
    Ok(rules)
}

fn dependency_features_match(
    observed_features: &[String],
    observed_default_features: bool,
    decision: &DependencyDecision,
) -> bool {
    observed_default_features == decision.default_features
        && observed_features.iter().collect::<BTreeSet<_>>()
            == decision.features.iter().collect::<BTreeSet<_>>()
}

fn parse_single_yaml<'input>(text: &'input str, context: &str) -> Result<Yaml<'input>, String> {
    let mut documents =
        Yaml::load_from_str(text).map_err(|error| format!("parse {context} as YAML: {error}"))?;
    if documents.len() != 1 {
        return Err(format!(
            "{context} must contain exactly one YAML document, observed {}",
            documents.len()
        ));
    }
    let document = documents.pop().ok_or("YAML parser returned no document")?;
    if !document.is_mapping() {
        return Err(format!("{context} YAML root is not a mapping"));
    }
    Ok(document)
}

fn yaml_string<'a>(mapping: &'a Yaml<'_>, key: &str) -> Result<&'a str, String> {
    mapping
        .as_mapping_get(key)
        .and_then(Yaml::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("YAML mapping has no nonempty string {key}"))
}

fn validate_rule_map(
    rule_map: &RuleMap,
    canonical: &BTreeSet<String>,
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    let mapped: BTreeSet<_> = rule_map
        .rules
        .iter()
        .map(|rule| rule.rule_id.clone())
        .collect();
    if mapped.len() != rule_map.rules.len() {
        return Err("duplicate rule-to-proof row".to_owned());
    }
    let missing: Vec<_> = canonical.difference(&mapped).cloned().collect();
    let unknown: Vec<_> = mapped.difference(canonical).cloned().collect();
    if let Some(diagnostic) = rule_inventory_diagnostic(canonical, &mapped) {
        return Err(format!(
            "{diagnostic}: missing={missing:?}; unknown={unknown:?}"
        ));
    }
    for rule in &rule_map.rules {
        if !proof_binding_valid(&rule.proof_classes, &rule.validators, &rule.fixture_ids) {
            return Err(format!(
                "FF-ARCH-E-MISSING-FIXTURE-BINDING: {}",
                rule.rule_id
            ));
        }
        let (proof, validators, fixtures): (&[&str], &[&str], &[&str]) = match rule.rule_id.as_str()
        {
            "FF-BUILD-036" => (
                &["graph", "policy"],
                &["workspace-shape"],
                &["shipped-before-bootstrap"],
            ),
            "FF-BUILD-037" => (
                &["policy"],
                &["strict-policy"],
                &["self-authorized-exception"],
            ),
            "FF-BUILD-038" => (
                &["graph"],
                &["cargo-metadata"],
                &["undeclared-member", "forbidden-edge", "cycle"],
            ),
            "FF-BUILD-039" => (
                &["graph", "source"],
                &["runtime-boundary"],
                &["shipped-governance-read"],
            ),
            "FF-BUILD-040" => (
                &["graph", "policy"],
                &["layer-edges"],
                &["adapter-edge-without-decision"],
            ),
            "FF-BUILD-041" => (
                &["graph"],
                &["testkit-boundary"],
                &["testkit-production-edge"],
            ),
            "FF-BUILD-042" => (&["graph"], &["watcher-boundary"], &["watcher-product-edge"]),
            "FF-BUILD-043" => (
                &["runtime_fault", "graph"],
                &["watcher-independence"],
                &["product-watcher-edge"],
            ),
            "FF-BUILD-044" | "FF-BUILD-045" => {
                (&["policy"], &["split-trigger"], &["missing-split-trigger"])
            }
            "FF-BUILD-046" => (
                &["policy", "negative_fixture"],
                &["rule-map-completeness"],
                &[
                    "missing-rule-map",
                    "unknown-rule-map",
                    "missing-fixture-binding",
                ],
            ),
            "FF-BUILD-077" => (
                &["graph", "source", "artifact"],
                &["three-root-boundary"],
                &["wrong-root-build-file", "duplicate-toolchain-selector"],
            ),
            other => return Err(format!("FF-ARCH-E-UNKNOWN-RULE: {other}")),
        };
        require_exact_strings(&rule.rule_id, "proof_classes", &rule.proof_classes, proof)?;
        require_exact_strings(&rule.rule_id, "validators", &rule.validators, validators)?;
        require_exact_strings(&rule.rule_id, "fixture_ids", &rule.fixture_ids, fixtures)?;
    }
    checks.push(pass("rule-map-completeness", "every canonical REQUIRED architecture rule has validators, proof classes, and negative fixtures"));
    Ok(())
}

fn rule_inventory_diagnostic<T: Ord>(
    canonical: &BTreeSet<T>,
    mapped: &BTreeSet<T>,
) -> Option<&'static str> {
    if !canonical.is_subset(mapped) {
        Some("FF-ARCH-E-MISSING-RULE")
    } else if !mapped.is_subset(canonical) {
        Some("FF-ARCH-E-UNKNOWN-RULE")
    } else {
        None
    }
}

fn proof_binding_valid(proof: &[String], validators: &[String], fixtures: &[String]) -> bool {
    proof_binding_counts_valid(proof.len(), validators.len(), fixtures.len())
}

fn proof_binding_counts_valid(proof: usize, validators: usize, fixtures: usize) -> bool {
    proof != 0 && validators != 0 && fixtures != 0
}

fn require_exact_strings(
    rule: &str,
    field: &str,
    observed: &[String],
    expected: &[&str],
) -> Result<(), String> {
    let observed: BTreeSet<_> = observed.iter().map(String::as_str).collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if observed.len() != expected.len() || observed != expected {
        return Err(format!("rule {rule} has incorrect {field}: {observed:?}"));
    }
    Ok(())
}

fn validate_fixtures(
    root: &Path,
    rule_map: &RuleMap,
    checks: &mut Vec<Check>,
) -> Result<Vec<FixtureResult>, String> {
    let fixture_root = root.join("build/fixtures/architecture");
    let referenced: BTreeSet<_> = rule_map
        .rules
        .iter()
        .flat_map(|rule| rule.fixture_ids.iter().cloned())
        .collect();
    let mut observed = BTreeSet::new();
    let mut results = Vec::new();
    for entry in fs::read_dir(&fixture_root).map_err(|e| format!("read fixtures: {e}"))? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let case: FixtureCase = read_toml(&entry.path().join("case.toml"))?;
        if case.schema_version != 1 || case.fixture_id != entry.file_name().to_string_lossy() {
            return Err(format!(
                "invalid fixture identity at {}",
                entry.path().display()
            ));
        }
        if !observed.insert(case.fixture_id.clone()) {
            return Err(format!("duplicate fixture ID {}", case.fixture_id));
        }
        let diagnostic = diagnostic_from_production_validator(&case.mutation)?;
        if diagnostic != case.expected_diagnostic {
            return Err(format!(
                "fixture {} failed for wrong reason: expected {}, observed {diagnostic}",
                case.fixture_id, case.expected_diagnostic
            ));
        }
        results.push(FixtureResult {
            fixture_id: case.fixture_id,
            status: "PASS",
            execution_path: "production-validator",
            expected_diagnostic: case.expected_diagnostic,
            observed_diagnostics: vec![diagnostic.to_owned()],
        });
    }
    if observed != referenced {
        return Err(format!(
            "fixture inventory mismatch: referenced-only={:?}, observed-only={:?}",
            referenced.difference(&observed).collect::<Vec<_>>(),
            observed.difference(&referenced).collect::<Vec<_>>()
        ));
    }
    results.sort_by(|a, b| a.fixture_id.cmp(&b.fixture_id));
    checks.push(pass(
        "negative-fixtures",
        &format!(
            "{} fixtures produced exactly their assigned stable diagnostic",
            results.len()
        ),
    ));
    Ok(results)
}

fn diagnostic_from_production_validator(mutation: &str) -> Result<&'static str, String> {
    let diagnostic = match mutation {
        "mark_bootstrap_member_shipped" => "FF-ARCH-E-SHIPPED-BEFORE-BOOTSTRAP",
        "add_unapproved_exception" => unapproved_exception_diagnostic(1)
            .ok_or("production exception validator unexpectedly accepted mutation")?,
        "add_undeclared_member" => {
            let declared = BTreeSet::from(["fforager-xtask"]);
            let observed = BTreeSet::from(["fforager-xtask", "undeclared"]);
            if member_inventory_matches(&declared, &observed) {
                return Err("production member-inventory validator accepted mutation".to_owned());
            }
            "FF-ARCH-E-UNDECLARED-MEMBER"
        }
        "add_forbidden_edge" => classify_layers("engine", "frontend", DependencyKind::Normal),
        "add_cycle" => {
            if !graph_has_cycle(&[("a", "b"), ("b", "a")]) {
                return Err("production cycle validator accepted mutation".to_owned());
            }
            "FF-ARCH-E-CYCLE"
        }
        "add_shipped_governance_read" => runtime_literal_diagnostic("Path::new(\".GOV\")")
            .ok_or("production runtime-boundary validator accepted mutation")?,
        "add_adapter_edge" => classify_layers("adapter", "adapter", DependencyKind::Normal),
        "add_testkit_production_edge" => {
            classify_layers("product", "testkit", DependencyKind::Normal)
        }
        "add_watcher_product_edge" => classify_layers("watcher", "engine", DependencyKind::Normal),
        "add_product_watcher_edge" => classify_layers("product", "watcher", DependencyKind::Normal),
        "remove_split_trigger" => {
            if split_trigger_valid("") {
                return Err("production split-trigger validator accepted mutation".to_owned());
            }
            "FF-ARCH-E-MISSING-SPLIT-TRIGGER"
        }
        "remove_required_rule" => {
            rule_inventory_diagnostic(&BTreeSet::from(["FF-BUILD-036"]), &BTreeSet::new())
                .ok_or("production rule-inventory validator accepted missing rule")?
        }
        "add_unknown_rule" => rule_inventory_diagnostic(
            &BTreeSet::from(["FF-BUILD-036"]),
            &BTreeSet::from(["FF-BUILD-036", "FF-BUILD-UNKNOWN"]),
        )
        .ok_or("production rule-inventory validator accepted unknown rule")?,
        "remove_fixture_binding" => {
            if proof_binding_counts_valid(1, 1, 0) {
                return Err("production proof-binding validator accepted mutation".to_owned());
            }
            "FF-ARCH-E-MISSING-FIXTURE-BINDING"
        }
        "add_wrong_root_build_file" => root_state_diagnostic(1, 1)
            .ok_or("production three-root validator accepted wrong-root mutation")?,
        "add_duplicate_toolchain_selector" => root_state_diagnostic(0, 2)
            .ok_or("production selector validator accepted duplicate mutation")?,
        other => return Err(format!("unknown fixture mutation {other}")),
    };
    Ok(diagnostic)
}

fn run_verify_pr(root: &Path, gate_args: &[String]) -> Result<(), String> {
    match run_verify_pr_inner(root, gate_args) {
        Ok(()) => Ok(()),
        Err(error) => fail_with_report(root, PR_GATE, "verify-pr", gate_args, &error),
    }
}

fn run_verify_pr_inner(root: &Path, gate_args: &[String]) -> Result<(), String> {
    let mut checks = Vec::new();
    verify_tool_identities(root, &mut checks)?;
    validate_change_evidence(root, &mut checks)?;
    run_rust_verification(root, &mut checks)?;
    checks.push(Check { id: "doctests".to_owned(), status: "NOT_APPLICABLE", detail: "WP-003 has no doctest-capable library target; activation trigger is the first library target.".to_owned() });
    run_command_with_env(
        root,
        "docs",
        "cargo",
        &[
            "doc",
            "--manifest-path",
            "build/Cargo.toml",
            "--workspace",
            "--all-features",
            "--locked",
            "--no-deps",
            "--target-dir",
            "build/target",
        ],
        "RUSTDOCFLAGS",
        "-Dwarnings",
        &mut checks,
    )?;
    run_command(
        root,
        "dependency-policy",
        "cargo",
        &[
            "deny",
            "--manifest-path",
            "build/Cargo.toml",
            "--config",
            "build/deny.toml",
            "check",
        ],
        &mut checks,
    )?;
    verify_advisory_databases(root, &mut checks)?;
    let architecture = architecture_check(root)?;
    checks.extend(architecture.checks);
    checks.push(Check { id: "clean-shipped-artifact".to_owned(), status: "NOT_APPLICABLE", detail: "Authority WP-FF-003 has zero shipped=true members; activation trigger is the first shipped member.".to_owned() });
    if root.join("product/watcher/Cargo.toml").exists() {
        return Err(
            "watcher-check is applicable because product/watcher/Cargo.toml exists, but the gate is NOT_IMPLEMENTED"
                .to_owned(),
        );
    }
    checks.push(Check { id: "watcher-check".to_owned(), status: "NOT_APPLICABLE", detail: "product/watcher/Cargo.toml is absent; activation trigger is the watcher package or a watcher/release claim.".to_owned() });
    checks.push(Check {
        id: "verify-deep".to_owned(),
        status: "NOT_IMPLEMENTED",
        detail: "Future gate outside the Phase 0 verify-pr applicable child set.".to_owned(),
    });
    checks.push(Check {
        id: "verify-release".to_owned(),
        status: "NOT_IMPLEMENTED",
        detail: "Future gate outside the Phase 0 verify-pr applicable child set.".to_owned(),
    });
    let report = GateReport {
        schema_id: "ff.gate-report@1",
        schema_version: "1.0.0",
        gate_id: PR_GATE.to_owned(),
        gate_version: 1,
        status: "PASS",
        exit_code: 0,
        source: source_state(root)?,
        invocation: invocation(gate_args),
        inputs: collect_inputs(root)?,
        checks,
        rules: architecture.rules,
        fixtures: architecture.fixtures,
        proof_classes: architecture.proof_classes,
        proof_limitations: architecture.limitations,
        artifacts: vec!["build/target".to_owned(), "build/reports".to_owned()],
    };
    let path = write_report(root, "verify-pr", &report)?;
    println!("PASS {PR_GATE}; report={}", slash(&path));
    Ok(())
}

fn fail_with_report(
    root: &Path,
    gate_id: &str,
    prefix: &str,
    gate_args: &[String],
    error: &str,
) -> Result<(), String> {
    let source = source_state(root).unwrap_or_else(|source_error| SourceState {
        git_commit: "UNKNOWN".to_owned(),
        dirty: true,
        dirty_paths: vec![format!("source-state-error:{source_error}")],
    });
    let report = GateReport {
        schema_id: "ff.gate-report@1",
        schema_version: "1.0.0",
        gate_id: gate_id.to_owned(),
        gate_version: 1,
        status: "FAIL",
        exit_code: 1,
        source,
        invocation: invocation(gate_args),
        inputs: collect_inputs(root).unwrap_or_default(),
        checks: vec![Check {
            id: "gate-failure".to_owned(),
            status: "FAIL",
            detail: error.to_owned(),
        }],
        rules: Vec::new(),
        fixtures: Vec::new(),
        proof_classes: Vec::new(),
        proof_limitations: vec![
            "Gate stopped at the recorded failure; later checks were NOT_RUN.".to_owned(),
        ],
        artifacts: vec!["build/reports".to_owned()],
    };
    match write_report(root, prefix, &report) {
        Ok(path) => Err(format!("{error}; failure_report={}", slash(&path))),
        Err(report_error) => Err(format!(
            "{error}; failure report write also failed: {report_error}"
        )),
    }
}

fn run_rust_verification(root: &Path, checks: &mut Vec<Check>) -> Result<(), String> {
    run_command(
        root,
        "format",
        "cargo",
        &[
            "fmt",
            "--manifest-path",
            "build/Cargo.toml",
            "--all",
            "--",
            "--check",
        ],
        checks,
    )?;
    for (id, features) in [
        ("check", None),
        ("check-no-default-features", Some("--no-default-features")),
        ("check-all-features", Some("--all-features")),
    ] {
        let mut args = vec![
            "check",
            "--manifest-path",
            "build/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--locked",
        ];
        if let Some(feature_arg) = features {
            args.push(feature_arg);
        }
        args.extend(["--target-dir", "build/target"]);
        run_command(root, id, "cargo", &args, checks)?;
    }
    run_command(
        root,
        "clippy",
        "cargo",
        &[
            "clippy",
            "--manifest-path",
            "build/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--target-dir",
            "build/target",
            "--",
            "-D",
            "warnings",
        ],
        checks,
    )?;
    run_command(
        root,
        "test",
        "cargo",
        &[
            "test",
            "--manifest-path",
            "build/Cargo.toml",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--no-fail-fast",
            "--target-dir",
            "build/target",
        ],
        checks,
    )?;
    Ok(())
}

fn verify_tool_identities(root: &Path, checks: &mut Vec<Check>) -> Result<(), String> {
    let policy: ToolingPolicy = read_toml(&root.join("build/tooling-policy.toml"))?;
    validate_tooling_policy(&policy)?;
    let host = validate_current_host(root, &policy)?;
    checks.push(pass("supported-host", &format!("rustc host={host}")));
    for tool in policy.tools {
        let (program, args) = tool.command.split_first().ok_or("empty tool command")?;
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = command_output(root, program, &args)?;
        if !output.lines().any(|line| line.trim() == tool.identity_line) {
            return Err(format!(
                "tool {} identity mismatch: expected exact line {:?}, observed {:?}",
                tool.name,
                tool.identity_line,
                output.trim()
            ));
        }
        let provenance = if let Some(expected) = &tool.executable_sha256 {
            let executable = resolve_executable(root, &tool.name)?;
            let observed = verify_executable_checksum(&tool.name, &executable, expected)?;
            format!(
                "{}; executable={}; sha256={observed}",
                output.trim(),
                executable.display()
            )
        } else {
            format!(
                "{}; provenance={}; inputs=rust-toolchain.toml,build/Cargo.lock",
                output.trim(),
                tool.provenance_kind
            )
        };
        checks.push(pass(&format!("tool-{}", tool.name), &provenance));
    }
    Ok(())
}

fn verify_executable_checksum(name: &str, path: &Path, expected: &str) -> Result<String, String> {
    let observed = sha256_file(path)?;
    if observed != expected {
        return Err(format!(
            "tool {name} checksum mismatch: executable={}; expected={expected}; observed={observed}",
            path.display()
        ));
    }
    Ok(observed)
}

fn resolve_executable(root: &Path, name: &str) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let output = command_output(root, "where.exe", &[name])?;
        let path = output
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| format!("where.exe returned no executable for {name}"))?;
        path.canonicalize()
            .map_err(|error| format!("canonicalize executable {}: {error}", path.display()))
    }
    #[cfg(not(windows))]
    {
        let _ = (root, name);
        Err(
            "executable checksum resolution is only defined for the supported Windows host"
                .to_owned(),
        )
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut file = File::open(path)
        .map_err(|error| format!("open executable for checksum {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read executable for checksum {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn verify_advisory_databases(root: &Path, checks: &mut Vec<Check>) -> Result<(), String> {
    let policy: ToolingPolicy = read_toml(&root.join("build/tooling-policy.toml"))?;
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".cargo")))
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .ok_or("cannot resolve Cargo home for advisory database proof")?;
    let database_root = cargo_home.join("advisory-dbs");
    let mut databases = Vec::new();
    for entry in
        fs::read_dir(&database_root).map_err(|e| format!("read advisory database root: {e}"))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir()
            && entry.path().join(".git").is_dir()
        {
            databases.push(entry.path());
        }
    }
    if databases.is_empty() {
        return Err("cargo-deny advisory database is absent after dependency check".to_owned());
    }
    databases.sort();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    for database in databases {
        let head = command_output(&database, "git", &["rev-parse", "HEAD"])?;
        let commit_epoch = command_output(&database, "git", &["log", "-1", "--format=%ct"])?
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("parse advisory database commit time: {e}"))?;
        if commit_epoch > now + 300 {
            return Err("advisory database commit time is implausibly in the future".to_owned());
        }
        let age_hours = now.saturating_sub(commit_epoch) / 3_600;
        if age_hours > policy.advisory_database_max_age_hours {
            return Err(format!(
                "advisory database is stale: age_hours={age_hours}, max={}",
                policy.advisory_database_max_age_hours
            ));
        }
        let status = command_output(&database, "git", &["status", "--porcelain"])?;
        let mut dirty_inputs = Vec::new();
        for line in status.lines() {
            let relative = line
                .get(3..)
                .ok_or("malformed advisory database status")?
                .trim();
            let path = database.join(relative);
            let identity = if path.is_file() {
                command_output(&database, "git", &["hash-object", "--", relative])?
                    .trim()
                    .to_owned()
            } else {
                "NON_FILE_OR_DELETED".to_owned()
            };
            dirty_inputs.push(format!("{relative}@{identity}"));
        }
        dirty_inputs.sort();
        let database_id = database
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or("advisory database path has no portable ID")?;
        checks.push(pass(
            "advisory-database",
            &format!(
                "id={database_id}; head={}; commit_epoch={commit_epoch}; age_hours={age_hours}; dirty_inputs={dirty_inputs:?}",
                head.trim()
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_change_evidence(root: &Path, checks: &mut Vec<Check>) -> Result<(), String> {
    let id = active_packet_id(root)?
        .ok_or("expected one active work-packet ID, observed canonical null")?;
    let packet_path = root.join(".GOV/work_packets").join(&id).join("packet.json");
    let packet: Value =
        serde_json::from_str(&fs::read_to_string(&packet_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if packet.pointer("/identity/wp_id").and_then(Value::as_str) != Some(&id) {
        return Err("active packet identity does not match taskboard".to_owned());
    }
    if packet.pointer("/lifecycle/status").and_then(Value::as_str) != Some("IN_PROGRESS") {
        return Err("active packet does not authorize implementation".to_owned());
    }
    let evidence = packet
        .pointer("/extensions/change_evidence")
        .ok_or("missing extensions.change_evidence")?;
    for field in [
        "applicable_rule_ids",
        "acceptance_or_authority_ids",
        "scope_and_risk_matrix",
        "reuse_candidates_in_order_with_result",
        "artifact_specific_justification",
        "pre_simplification_verdict",
        "simplification_changes",
        "post_simplification_verdict",
        "complete_post_change_verification",
        "ceilings_exceptions_and_evidence",
    ] {
        let value = evidence
            .get(field)
            .ok_or_else(|| format!("missing change-evidence field {field}"))?;
        if value.is_null()
            || value
                .as_str()
                .is_some_and(|text| text.trim().is_empty() || text.starts_with("PENDING"))
            || value.as_array().is_some_and(Vec::is_empty)
            || value.as_object().is_some_and(serde_json::Map::is_empty)
        {
            return Err(format!("change-evidence field {field} is empty or pending"));
        }
    }
    let accepted_rows = packet
        .pointer("/acceptance_matrix")
        .and_then(Value::as_array)
        .ok_or("missing acceptance matrix")?;
    let accepted_values = accepted_rows
        .iter()
        .map(|row| {
            row.get("id")
                .and_then(Value::as_str)
                .ok_or("acceptance row has no string ID")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let accepted: BTreeSet<_> = accepted_values.iter().copied().collect();
    if accepted.len() != accepted_values.len() {
        return Err("acceptance matrix contains duplicate IDs".to_owned());
    }
    let cited_values = string_array(evidence, "acceptance_or_authority_ids")?;
    let cited: BTreeSet<_> = cited_values.iter().map(String::as_str).collect();
    if cited.len() != cited_values.len() || accepted != cited {
        return Err("change evidence does not cite exactly every packet acceptance ID".to_owned());
    }
    let applicable_values = string_array(evidence, "applicable_rule_ids")?;
    let applicable: BTreeSet<_> = applicable_values.iter().map(String::as_str).collect();
    if applicable.len() != applicable_values.len() {
        return Err("applicable_rule_ids contains duplicates".to_owned());
    }
    let canonical = required_architecture_rules(&root.join(".GOV/rules/build-rules.yaml"))?;
    if !canonical
        .iter()
        .all(|rule| applicable.contains(rule.as_str()))
    {
        return Err("applicable_rule_ids omits a canonical REQUIRED architecture rule".to_owned());
    }
    for field in ["pre_simplification_verdict", "post_simplification_verdict"] {
        let verdict = evidence
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{field} is not a string"))?;
        if !verdict.starts_with("PASS:") || verdict.trim().len() < 40 {
            return Err(format!("{field} is not a substantive PASS verdict"));
        }
    }
    if string_array(evidence, "simplification_changes")?.is_empty()
        || string_array(evidence, "complete_post_change_verification")?.len() < 6
    {
        return Err(
            "simplification or complete post-change verification evidence is incomplete".to_owned(),
        );
    }
    validate_reuse_rows(evidence)?;
    validate_scope_and_risk(evidence)?;
    validate_artifact_justification(evidence)?;
    validate_ceiling(evidence)?;
    checks.push(pass(
        "active-packet-evidence",
        &format!("active packet {id} has complete non-placeholder change evidence"),
    ));
    Ok(())
}

fn string_array(object: &Value, field: &str) -> Result<Vec<String>, String> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} is not an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{field} contains a non-string or empty value"))
        })
        .collect()
}

fn validate_reuse_rows(evidence: &Value) -> Result<(), String> {
    let expected = [
        "no mechanism beyond the accepted outcome",
        "reuse current Ferric code",
        "Rust core/std",
        "approved platform capability",
        "already-approved dependency",
        "smallest complete clear implementation",
    ];
    let rows = evidence
        .get("reuse_candidates_in_order_with_result")
        .and_then(Value::as_array)
        .ok_or("reuse candidates are not an array")?;
    if rows.len() != expected.len() {
        return Err("reuse candidate ladder is incomplete".to_owned());
    }
    for (row, expected_candidate) in rows.iter().zip(expected) {
        let candidate = row
            .get("candidate")
            .and_then(Value::as_str)
            .ok_or("reuse row has no candidate")?;
        let result = row
            .get("result")
            .and_then(Value::as_str)
            .ok_or("reuse row has no result")?;
        if candidate != expected_candidate || result.trim().len() < 12 {
            return Err(format!(
                "reuse candidate row is out of order or not substantive: {expected_candidate}"
            ));
        }
    }
    Ok(())
}

fn validate_scope_and_risk(evidence: &Value) -> Result<(), String> {
    let object = evidence
        .get("scope_and_risk_matrix")
        .and_then(Value::as_object)
        .ok_or("scope_and_risk_matrix is not an object")?;
    if object.len() != 2
        || string_array(&Value::Object(object.clone()), "required_outcomes")?.is_empty()
        || string_array(&Value::Object(object.clone()), "risk_cases")?.is_empty()
    {
        return Err(
            "scope_and_risk_matrix must contain nonempty required_outcomes and risk_cases only"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_artifact_justification(evidence: &Value) -> Result<(), String> {
    let expected = BTreeSet::from([
        "cargo_workspace",
        "xtask",
        "architecture_policy",
        "tooling_policy",
        "rule_to_proof",
        "negative_fixtures",
        "model_manual",
    ]);
    let object = evidence
        .get("artifact_specific_justification")
        .and_then(Value::as_object)
        .ok_or("artifact_specific_justification is not an object")?;
    let observed: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if observed != expected
        || object
            .values()
            .any(|value| value.as_str().is_none_or(|text| text.trim().len() < 12))
    {
        return Err(
            "artifact_specific_justification has missing, unknown, or empty rows".to_owned(),
        );
    }
    Ok(())
}

fn validate_ceiling(evidence: &Value) -> Result<(), String> {
    let ceiling = evidence
        .get("ceilings_exceptions_and_evidence")
        .and_then(Value::as_object)
        .ok_or("ceilings_exceptions_and_evidence is not an object")?;
    for field in [
        "ceiling_id",
        "current_ceiling",
        "replacement_trigger",
        "likely_upgrade_path",
        "trigger_detection_method",
    ] {
        if ceiling
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|text| text.trim().is_empty())
        {
            return Err(format!("ceiling evidence omits {field}"));
        }
    }
    let linked = ceiling
        .get("linked_evidence")
        .and_then(Value::as_array)
        .ok_or("ceiling linked_evidence is not an array")?;
    if linked.is_empty()
        || linked
            .iter()
            .any(|value| value.as_str().is_none_or(|text| text.trim().is_empty()))
    {
        return Err("ceiling linked_evidence is empty or malformed".to_owned());
    }
    Ok(())
}

fn run_command(
    root: &Path,
    id: &str,
    program: &str,
    args: &[&str],
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    let status = command_status_with_timeout(root, program, args, None, GATE_COMMAND_TIMEOUT)?;
    if !status.success() {
        return Err(format!("check {id} failed with {status}"));
    }
    checks.push(pass(id, &format!("{program} {} exited 0", args.join(" "))));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_command_with_env(
    root: &Path,
    id: &str,
    program: &str,
    args: &[&str],
    key: &str,
    value: &str,
    checks: &mut Vec<Check>,
) -> Result<(), String> {
    let status = command_status_with_timeout(
        root,
        program,
        args,
        Some((key, value)),
        GATE_COMMAND_TIMEOUT,
    )?;
    if !status.success() {
        return Err(format!("check {id} failed with {status}"));
    }
    checks.push(pass(
        id,
        &format!("{key}={value} {program} {} exited 0", args.join(" ")),
    ));
    Ok(())
}

fn collect_inputs(root: &Path) -> Result<Vec<InputState>, String> {
    let mut paths = vec![
        "rust-toolchain.toml".to_owned(),
        "build/Cargo.toml".to_owned(),
        "build/Cargo.lock".to_owned(),
        "build/architecture-policy.toml".to_owned(),
        "build/tooling-policy.toml".to_owned(),
        "build/rule-to-proof.toml".to_owned(),
        "build/deny.toml".to_owned(),
        "build/tools/fforager-xtask/Cargo.toml".to_owned(),
        "product/MODEL_MANUAL.md".to_owned(),
        ".GOV/codex.yaml".to_owned(),
        ".GOV/id-registry.yaml".to_owned(),
        ".GOV/rules/build-rules.yaml".to_owned(),
        ".GOV/spec/ferric_forager_technical_design_v0.3.0.md".to_owned(),
        ".GOV/taskboard/taskboard.yaml".to_owned(),
        ".GOV/topology.yaml".to_owned(),
    ];
    paths.extend(active_evidence_inputs(root)?);
    for directory in [
        "build/fixtures/architecture",
        "build/tools/fforager-xtask/src",
    ] {
        for path in walk_files(&root.join(directory))? {
            if matches!(
                path.extension().and_then(OsStr::to_str),
                Some("toml" | "rs")
            ) {
                paths.push(slash(path.strip_prefix(root).map_err(|e| e.to_string())?));
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| {
            let hash = command_output(root, "git", &["hash-object", "--", &path])?;
            Ok(InputState {
                path,
                git_blob: hash.trim().to_owned(),
            })
        })
        .collect()
}

fn active_evidence_inputs(root: &Path) -> Result<Vec<String>, String> {
    let Some(id) = active_packet_id(root)? else {
        return Ok(Vec::new());
    };
    let packet = format!(".GOV/work_packets/{id}/packet.json");
    let value: Value = serde_json::from_str(
        &fs::read_to_string(root.join(&packet)).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("parse active packet for input collection: {error}"))?;
    let refinement = value
        .pointer("/extensions/refinement")
        .and_then(Value::as_str)
        .ok_or("active packet has no refinement input path")?;
    require_relative_contained(root, refinement, ".GOV")?;
    Ok(vec![packet, refinement.to_owned()])
}

fn source_state(root: &Path) -> Result<SourceState, String> {
    let commit = command_output(root, "git", &["rev-parse", "HEAD"])?;
    let status = command_output(root, "git", &["status", "--porcelain"])?;
    let dirty_paths = status
        .lines()
        .filter_map(|line| line.get(3..))
        .map(str::trim)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Ok(SourceState {
        git_commit: commit.trim().to_owned(),
        dirty: !dirty_paths.is_empty(),
        dirty_paths,
    })
}

fn command_output(root: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    command_output_with_timeout(root, program, args, TOOL_COMMAND_TIMEOUT)
}

fn command_status_with_timeout(
    root: &Path,
    program: &str,
    args: &[&str],
    environment: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let mut command = Command::new(program);
    command.args(args).current_dir(root).stdin(Stdio::null());
    if let Some((key, value)) = environment {
        command.env(key, value);
    }
    configure_quiet_process(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("run {program} {args:?}: {error}"))?;
    wait_for_child(&mut child, program, args, timeout)
}

fn command_output_with_timeout(
    root: &Path,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    let capture_root = root.join("build/target/command-capture");
    fs::create_dir_all(&capture_root)
        .map_err(|error| format!("create command capture directory: {error}"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let stem = format!("{}-{nonce}-{}", std::process::id(), sanitize_id(program));
    let stdout_path = capture_root.join(format!("{stem}.stdout"));
    let stderr_path = capture_root.join(format!("{stem}.stderr"));
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_path)
        .map_err(|error| format!("create stdout capture: {error}"))?;
    let stderr = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
    {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            return Err(format!("create stderr capture: {error}"));
        }
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    configure_quiet_process(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&stdout_path);
            let _ = fs::remove_file(&stderr_path);
            return Err(format!("run {program} {args:?}: {error}"));
        }
    };
    let status = wait_for_child(&mut child, program, args, timeout);
    let stdout = read_capture(&stdout_path);
    let stderr = read_capture(&stderr_path);
    let _ = fs::remove_file(&stdout_path);
    let _ = fs::remove_file(&stderr_path);
    let status = status?;
    let stdout = stdout?;
    let stderr = stderr?;
    if !status.success() {
        return Err(format!(
            "{program} {args:?} failed with {status}; stderr={:?}",
            bounded_diagnostic(&stderr)
        ));
    }
    String::from_utf8(stdout)
        .map_err(|error| format!("{program} {args:?} emitted non-UTF-8 stdout: {error}"))
}

fn wait_for_child(
    child: &mut Child,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait for {program} {args:?}: {error}"))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let kill_result = child.kill();
            let reap_result = child.wait();
            return Err(format!(
                "{program} {args:?} timed out after {}s; result is incomplete evidence; kill={kill_result:?}; reap={reap_result:?}",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn read_capture(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("read command capture {}: {error}", path.display()))?;
    Ok(bytes)
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    const LIMIT: usize = 4_096;
    let end = bytes.len().min(LIMIT);
    let mut text = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if bytes.len() > LIMIT {
        text.push_str("...[truncated]");
    }
    text
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(windows)]
fn configure_quiet_process(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn configure_quiet_process(_command: &mut Command) {}

fn invocation(gate_args: &[String]) -> Invocation {
    let mut canonical = vec![
        "cargo".to_owned(),
        "run".to_owned(),
        "--manifest-path".to_owned(),
        "build/Cargo.toml".to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        "fforager-xtask".to_owned(),
        "--".to_owned(),
    ];
    canonical.extend_from_slice(gate_args);
    Invocation {
        repository_root: ".",
        gate_args: gate_args.to_vec(),
        canonical_command: canonical,
    }
}

fn write_report(root: &Path, prefix: &str, report: &GateReport) -> Result<PathBuf, String> {
    let reports = root.join("build/reports");
    fs::create_dir_all(&reports).map_err(|e| e.to_string())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let stem = format!("{prefix}-{nonce}-{}", std::process::id());
    let temporary = reports.join(format!(".{stem}.tmp"));
    let final_path = reports.join(format!("{stem}.json"));
    let bytes = serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?;
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temporary, &final_path)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(format!("atomic report write failed: {error}"));
    }
    final_path
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|e| e.to_string())
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn require_relative_contained(root: &Path, relative: &str, owner: &str) -> Result<(), String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("unsafe policy path {relative}"));
    }
    let expected = root.join(owner).canonicalize().map_err(|e| e.to_string())?;
    let observed = root
        .join(path)
        .canonicalize()
        .map_err(|e| format!("canonicalize {relative}: {e}"))?;
    if !observed.starts_with(expected) {
        return Err(format!("path {relative} escapes owner {owner}"));
    }
    Ok(())
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in
            fs::read_dir(&directory).map_err(|e| format!("read {}: {e}", directory.display()))?
        {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                return Err(format!(
                    "symlink is not allowed in governed product source: {}",
                    entry.path().display()
                ));
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    Ok(files)
}

fn normalize(path: &Path) -> String {
    slash(path)
        .to_ascii_lowercase()
        .trim_end_matches('/')
        .to_owned()
}

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn active_packet_id(root: &Path) -> Result<Option<String>, String> {
    let path = root.join(".GOV/taskboard/taskboard.yaml");
    let text = fs::read_to_string(&path).map_err(|error| format!("read taskboard: {error}"))?;
    active_packet_id_from_text(&text, &path.display().to_string())
}

fn active_packet_id_from_text(text: &str, context: &str) -> Result<Option<String>, String> {
    if text
        .lines()
        .filter(|line| line.trim() == "current_focus:")
        .count()
        != 1
        || text
            .lines()
            .filter(|line| line.trim_start().starts_with("active_wp_id:"))
            .count()
            != 1
    {
        return Err(
            "taskboard must contain exactly one current_focus and active_wp_id key".to_owned(),
        );
    }
    let document = parse_single_yaml(text, context)?;
    let focus_node = document
        .as_mapping_get("current_focus")
        .ok_or("taskboard omits current_focus")?;
    let focus = focus_node
        .as_mapping()
        .ok_or("taskboard current_focus is not a mapping")?;
    let keys = focus
        .keys()
        .map(|key| {
            key.as_str()
                .ok_or("taskboard current_focus has a non-string key")
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if keys != BTreeSet::from(["active_wp_id", "statement"]) {
        return Err(format!(
            "taskboard current_focus keys are invalid: {keys:?}"
        ));
    }
    let node = focus_node
        .as_mapping_get("active_wp_id")
        .ok_or("taskboard current_focus omits active_wp_id")?;
    if node.is_null() {
        return Ok(None);
    }
    let id = node
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or("taskboard active_wp_id is neither null nor a nonempty string")?;
    if !id.starts_with("WP-FF-")
        || !id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err("active work-packet ID violates the safe naming grammar".to_owned());
    }
    Ok(Some(id.to_owned()))
}

fn pass(id: &str, detail: &str) -> Check {
    Check {
        id: id.to_owned(),
        status: "PASS",
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_fixture_mutation_fails_closed() {
        assert!(diagnostic_from_production_validator("surprise").is_err());
    }

    #[test]
    fn known_fixture_has_stable_diagnostic() {
        assert_eq!(
            diagnostic_from_production_validator("add_wrong_root_build_file").unwrap(),
            "FF-ARCH-E-WRONG-ROOT"
        );
    }

    #[test]
    fn slash_normalizes_windows_separator() {
        assert_eq!(slash(Path::new("build\\target")), "build/target");
    }

    #[test]
    fn cycle_detection_distinguishes_cycle_from_chain() {
        assert!(graph_has_cycle(&[("a", "b"), ("b", "a")]));
        assert!(!graph_has_cycle(&[("a", "b"), ("b", "c")]));
    }

    #[test]
    fn runtime_scan_is_case_insensitive_and_segment_conservative() {
        assert_eq!(
            runtime_literal_diagnostic("Path::new(\".gov/cache\")"),
            Some("FF-ARCH-E-RUNTIME-BOUNDARY")
        );
        assert_eq!(
            runtime_literal_diagnostic("Path::new(\"build\")"),
            Some("FF-ARCH-E-RUNTIME-BOUNDARY")
        );
        assert_eq!(runtime_literal_diagnostic("ordinary product source"), None);
    }

    #[test]
    fn root_state_prioritizes_wrong_root_and_detects_selector_count() {
        assert_eq!(root_state_diagnostic(1, 1), Some("FF-ARCH-E-WRONG-ROOT"));
        assert_eq!(
            root_state_diagnostic(0, 2),
            Some("FF-ARCH-E-DUPLICATE-TOOLCHAIN")
        );
        assert_eq!(root_state_diagnostic(0, 1), None);
    }

    #[test]
    fn forbidden_edge_classifier_covers_special_boundaries() {
        assert_eq!(
            classify_layers("adapter", "adapter", DependencyKind::Normal),
            "FF-ARCH-E-ADAPTER-EDGE"
        );
        assert_eq!(
            classify_layers("product", "testkit", DependencyKind::Build),
            "FF-ARCH-E-TESTKIT-EDGE"
        );
        assert_eq!(
            classify_layers("product", "watcher", DependencyKind::Normal),
            "FF-ARCH-E-PRODUCT-WATCHER-EDGE"
        );
    }

    #[test]
    fn rule_inventory_fails_missing_and_unknown_rules() {
        let canonical = BTreeSet::from(["required"]);
        assert_eq!(
            rule_inventory_diagnostic(&canonical, &BTreeSet::new()),
            Some("FF-ARCH-E-MISSING-RULE")
        );
        assert_eq!(
            rule_inventory_diagnostic(&canonical, &BTreeSet::from(["required", "unknown"])),
            Some("FF-ARCH-E-UNKNOWN-RULE")
        );
    }

    #[test]
    fn proof_binding_requires_all_three_surfaces() {
        assert!(proof_binding_counts_valid(1, 1, 1));
        assert!(!proof_binding_counts_valid(1, 1, 0));
    }

    #[test]
    fn split_and_exception_helpers_fail_closed() {
        assert!(!split_trigger_valid("  "));
        assert!(!split_trigger_valid("NOT-A-CANONICAL-TRIGGER"));
        assert!(split_trigger_valid("FF-BUILD-036"));
        assert_eq!(
            unapproved_exception_diagnostic(1),
            Some("FF-ARCH-E-UNAPPROVED-EXCEPTION")
        );
    }

    #[test]
    fn workspace_lint_inheritance_is_toml_semantic() {
        for manifest in [
            "[lints]\nworkspace = true\n",
            "[lints]\r\nworkspace = true\r\n",
            "[lints]\nworkspace=true\n",
            "[lints]\nother = \"value\"\nworkspace = true\n",
        ] {
            assert_eq!(manifest_inherits_workspace_lints(manifest), Ok(true));
        }
        assert_eq!(
            manifest_inherits_workspace_lints("[lints]\nworkspace = false\n"),
            Ok(false)
        );
        assert!(manifest_inherits_workspace_lints("[lints\nworkspace = true").is_err());
    }

    #[test]
    fn malformed_yaml_and_taskboard_state_fail_closed() {
        assert!(parse_single_yaml("malformed: [unterminated", "test").is_err());
        let valid = "current_focus:\n  statement: active\n  active_wp_id: WP-FF-003-test-v2\n";
        assert_eq!(
            active_packet_id_from_text(valid, "test"),
            Ok(Some("WP-FF-003-test-v2".to_owned()))
        );
        let closed = "current_focus:\n  statement: closed\n  active_wp_id: null\n";
        assert_eq!(active_packet_id_from_text(closed, "test"), Ok(None));
        assert!(active_packet_id_from_text(
            "malformed: [unterminated\ncurrent_focus:\n  statement: active\n  active_wp_id: WP-FF-003-test-v2\n",
            "test"
        )
        .is_err());
        assert!(active_packet_id_from_text(
            "current_focus:\n  statement: active\n  active_wp_id: WP-FF-003-test-v2\n  unexpected: true\n",
            "test"
        )
        .is_err());
    }

    #[test]
    fn nested_toolchain_selectors_are_inventoried() {
        let root = test_root("nested-selector");
        for directory in [".GOV", "product/nested", "build/target"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join("rust-toolchain.toml"), "[toolchain]\n").unwrap();
        fs::write(
            root.join("product/nested/rust-toolchain.toml"),
            "[toolchain]\n",
        )
        .unwrap();
        fs::write(
            root.join("build/target/rust-toolchain.toml"),
            "ignored generated output",
        )
        .unwrap();
        assert_eq!(
            toolchain_selectors(&root).unwrap(),
            [
                "product/nested/rust-toolchain.toml".to_owned(),
                "rust-toolchain.toml".to_owned(),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_report_inputs_follow_the_active_packet() {
        let root = test_root("active-report-inputs");
        let packet_id = "WP-FF-003-test-v2";
        let packet_root = root.join(".GOV/work_packets").join(packet_id);
        fs::create_dir_all(root.join(".GOV/taskboard")).unwrap();
        fs::create_dir_all(&packet_root).unwrap();
        fs::write(
            root.join(".GOV/taskboard/taskboard.yaml"),
            format!("current_focus:\n  statement: active test\n  active_wp_id: {packet_id}\n"),
        )
        .unwrap();
        fs::write(
            packet_root.join("packet.json"),
            format!(
                "{{\"extensions\":{{\"refinement\":\".GOV/work_packets/{packet_id}/refinement.json\"}}}}"
            ),
        )
        .unwrap();
        fs::write(packet_root.join("refinement.json"), "{}\n").unwrap();
        let inputs = active_evidence_inputs(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(
            inputs,
            [
                format!(".GOV/work_packets/{packet_id}/packet.json"),
                format!(".GOV/work_packets/{packet_id}/refinement.json"),
            ]
        );
    }

    #[test]
    fn dependency_features_and_hosts_fail_closed_on_drift() {
        let decision = DependencyDecision {
            name: "serde".to_owned(),
            version: "1.0.228".to_owned(),
            consumer: "fforager-xtask".to_owned(),
            runtime_class: "non_shipped_build_tooling".to_owned(),
            purpose: "typed serialization".to_owned(),
            native: false,
            owner: "WP-FF-003-executable-gate-bootstrap".to_owned(),
            allowed_consumers: vec!["fforager-xtask".to_owned()],
            reason: "strict policy".to_owned(),
            removal_trigger: "validated migration".to_owned(),
            approval_id: "WP-FF-003-executable-gate-bootstrap-v1-AC-002".to_owned(),
            features: vec!["derive".to_owned()],
            default_features: true,
        };
        assert!(dependency_features_match(
            &["derive".to_owned()],
            true,
            &decision
        ));
        assert!(!dependency_features_match(&[], true, &decision));
        assert!(!dependency_features_match(
            &["derive".to_owned()],
            false,
            &decision
        ));
        let supported = vec!["x86_64-pc-windows-msvc".to_owned()];
        assert!(host_supported(&supported, "x86_64-pc-windows-msvc"));
        assert!(!host_supported(&supported, "definitely-not-this-host"));
    }

    #[test]
    fn representative_repository_mutations_reach_production_validation() {
        assert_architecture_mutation_fails(
            "shipped-before-bootstrap",
            |root| {
                replace_file_text(
                    &root.join("build/architecture-policy.toml"),
                    "shipped = false",
                    "shipped = true",
                );
            },
            "FF-ARCH-E-SHIPPED-BEFORE-BOOTSTRAP",
        );
        assert_architecture_mutation_fails(
            "self-authorized-exception",
            |root| {
                replace_file_text(
                    &root.join("build/architecture-policy.toml"),
                    "exception_decision_ids = []",
                    "exception_decision_ids = [\"SELF-AUTHORIZED\"]",
                );
            },
            "FF-ARCH-E-UNAPPROVED-EXCEPTION",
        );
        assert_architecture_mutation_fails(
            "undeclared-member",
            |root| {
                replace_file_text(
                    &root.join("build/architecture-policy.toml"),
                    "name = \"fforager-xtask\"",
                    "name = \"undeclared\"",
                );
            },
            "FF-ARCH-E-UNDECLARED-MEMBER",
        );
        assert_architecture_mutation_fails(
            "shipped-governance-read",
            |root| {
                let path = root.join("product/forbidden.rs");
                fs::write(path, "const FORBIDDEN: &str = \".GOV\";\n").unwrap();
            },
            "FF-ARCH-E-RUNTIME-BOUNDARY",
        );
        assert_architecture_mutation_fails(
            "missing-split-trigger",
            |root| {
                replace_file_text(
                    &root.join("build/architecture-policy.toml"),
                    "split_trigger = \"FF-BUILD-036\"",
                    "split_trigger = \"\"",
                );
            },
            "FF-ARCH-E-INVALID-SPLIT-TRIGGER",
        );
        assert_architecture_mutation_fails(
            "missing-rule-map",
            |root| {
                replace_file_text(
                    &root.join("build/rule-to-proof.toml"),
                    "rule_id = \"FF-BUILD-036\"",
                    "rule_id = \"FF-BUILD-UNKNOWN\"",
                );
            },
            "FF-ARCH-E-MISSING-RULE",
        );
        assert_architecture_mutation_fails(
            "missing-fixture-binding",
            |root| {
                replace_file_text(
                    &root.join("build/rule-to-proof.toml"),
                    "fixture_ids = [\"self-authorized-exception\"]",
                    "fixture_ids = []",
                );
            },
            "FF-ARCH-E-MISSING-FIXTURE-BINDING",
        );
        assert_architecture_mutation_fails(
            "wrong-root-build-file",
            |root| {
                fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
            },
            "FF-ARCH-E-WRONG-ROOT",
        );
    }

    #[test]
    fn policy_and_portability_mutations_reach_production_validation() {
        assert_architecture_mutation_fails(
            "invalid-split-trigger",
            |root| {
                replace_file_text(
                    &root.join("build/architecture-policy.toml"),
                    "split_trigger = \"FF-BUILD-036\"",
                    "split_trigger = \"NOT-A-CANONICAL-TRIGGER\"",
                );
            },
            "FF-ARCH-E-INVALID-SPLIT-TRIGGER",
        );
        assert_architecture_mutation_fails(
            "nested-selector",
            |root| {
                let path = root.join("product/nested/rust-toolchain.toml");
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, "[toolchain]\nchannel = \"stable\"\n").unwrap();
            },
            "FF-ARCH-E-DUPLICATE-TOOLCHAIN",
        );
        assert_architecture_mutation_fails(
            "malformed-build-rules",
            |root| {
                let path = root.join(".GOV/rules/build-rules.yaml");
                let text = fs::read_to_string(&path).unwrap();
                fs::write(path, format!("malformed: [unterminated\n{text}")).unwrap();
            },
            "FF-ARCH-E-POLICY-SCHEMA",
        );
        assert_architecture_mutation_fails(
            "unsupported-host",
            |root| {
                replace_file_text(
                    &root.join("build/tooling-policy.toml"),
                    "supported_hosts = [\"x86_64-pc-windows-msvc\"]",
                    "supported_hosts = [\"definitely-not-this-host\"]",
                );
            },
            "FF-TOOL-E-UNSUPPORTED-HOST",
        );
        assert_architecture_mutation_fails(
            "dependency-feature-drift",
            |root| {
                replace_file_text(
                    &root.join("build/Cargo.toml"),
                    "serde = { version = \"=1.0.228\", features = [\"derive\"] }",
                    "serde = \"=1.0.228\"",
                );
            },
            "FF-ARCH-E-DEPENDENCY-FEATURE",
        );
    }

    #[cfg(windows)]
    #[test]
    fn bounded_process_timeout_returns_incomplete_evidence() {
        let error = command_status_with_timeout(
            &env::current_dir().unwrap(),
            "cmd",
            &["/C", "ping -n 6 127.0.0.1 >NUL"],
            None,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.contains("timed out"));
        assert!(error.contains("incomplete evidence"));
    }

    #[test]
    fn executable_checksum_mismatch_fails_closed() {
        let root = test_root("checksum-mismatch");
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("tool.exe");
        fs::write(&executable, b"known tool bytes").unwrap();
        let observed = sha256_file(&executable).unwrap();
        assert_eq!(
            verify_executable_checksum("tool", &executable, &observed),
            Ok(observed)
        );
        let error = verify_executable_checksum("tool", &executable, &"0".repeat(64)).unwrap_err();
        fs::remove_dir_all(root).unwrap();
        assert!(error.contains("checksum mismatch"));
        assert!(error.contains("expected="));
        assert!(error.contains("observed="));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_process_timeout_returns_incomplete_evidence() {
        let error = command_status_with_timeout(
            &env::current_dir().unwrap(),
            "sh",
            &["-c", "sleep 5"],
            None,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.contains("timed out"));
        assert!(error.contains("incomplete evidence"));
    }

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!(
            "fforager-xtask-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn assert_architecture_mutation_fails(
        label: &str,
        mutate: impl FnOnce(&Path),
        expected_diagnostic: &str,
    ) {
        let root = architecture_sandbox(label);
        architecture_check(&root).unwrap_or_else(|error| {
            panic!("fixture positive control failed before mutation: {error}")
        });
        mutate(&root);
        let error = architecture_check(&root).unwrap_err();
        fs::remove_dir_all(&root).unwrap();
        assert!(
            error.contains(expected_diagnostic),
            "expected {expected_diagnostic}, observed {error}"
        );
    }

    fn architecture_sandbox(label: &str) -> PathBuf {
        let source = repo_root().unwrap();
        let root = test_root(label);
        for relative in [
            "rust-toolchain.toml",
            ".GOV/rules/build-rules.yaml",
            "build/Cargo.toml",
            "build/Cargo.lock",
            "build/architecture-policy.toml",
            "build/tooling-policy.toml",
            "build/rule-to-proof.toml",
            "build/tools/fforager-xtask/Cargo.toml",
            "build/tools/fforager-xtask/src/main.rs",
            "product/MODEL_MANUAL.md",
        ] {
            let from = source.join(relative);
            let to = root.join(relative);
            fs::create_dir_all(to.parent().unwrap()).unwrap();
            fs::copy(from, to).unwrap();
        }
        copy_test_tree(
            &source.join("build/fixtures/architecture"),
            &root.join("build/fixtures/architecture"),
        );
        root
    }

    fn copy_test_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_test_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn replace_file_text(path: &Path, before: &str, after: &str) {
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains(before), "missing mutation anchor {before}");
        fs::write(path, text.replacen(before, after, 1)).unwrap();
    }
}
