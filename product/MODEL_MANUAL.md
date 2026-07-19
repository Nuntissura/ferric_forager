---
file_id: FF-PRODUCT-MODEL-MANUAL-001
file_kind: model_manual
updated_at: "2026-07-19"
---

<topic id="phase-0-purpose" status="active" version="2" wp="WP-FF-003-executable-gate-bootstrap-v2" updated_at="2026-07-19">

# Ferric Forager model manual

Ferric Forager is planned as a Rust-native video-acquisition and archival product. The current repository contains no shipped product crate and therefore no implemented Ferric runtime capability. Its existing executable build-and-proof tooling is a non-product prerequisite for future product work and MUST NOT be counted as product progress, a completed product phase, or a runtime deliverable.

Repository ownership is deterministic:

- `.GOV/` owns governance, work packets, task state, design, and validation authority.
- `product/` owns shipped runtime code, assets, the independent watcher, this manual, and tests local to a product package.
- `build/` owns the Cargo workspace and lockfile, build policies, non-shipped tooling, shared and cross-package test infrastructure, fixtures, reports, and `target` output.
- `rust-toolchain.toml` at repository root is the sole rustup selector.

Shipped product runtime must not read or require `.GOV/` or `build/`. Build tooling may read the active governance packet to validate proof.

</topic>

<topic id="phase-0-compatibility-oracle" status="active" version="1" wp="WP-FF-004-compatibility-inventory-corpus-v1" ingestable="true" updated_at="2026-07-19">

## Generate and validate the compatibility oracle

WP-FF-004 pins the external oracle to the official `yt-dlp 2026.07.04` Windows executable and matching source tag. The executable and source checkout are research inputs outside shipped product code; Ferric Forager has no production Python or yt-dlp dependency.

Set repository-relative paths to the separately acquired, hash-matching oracle inputs, then run:

```powershell
$oracleExe = "build/target/wp4-research/oracle/yt-dlp.exe"
$sourceRoot = "build/target/wp4-research/yt-dlp-2026.07.04"
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-generate --oracle-exe $oracleExe --source-root $sourceRoot
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-validate
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-replay
```

Generation verifies the immutable release identity, executable SHA-256, source Git commit, and selected source-file hashes before writing `build/fixtures/compatibility/yt-dlp-2026.07.04/profile.json` atomically. The generated profile contains stable option, alias, preset, interaction, extractor, description, and URL-class rows. Line endings, CP-1252 executable output, identical extractor duplicates, and upstream-randomized search examples have explicit deterministic normalization rules.

Validation reads the committed oracle manifest, generated profile, seven-plane corpus, opt-in live manifest, and every negative fixture. It checks stable IDs, counts, hashes, coverage, shard assignments, normalization versions, offline/network separation, secret placeholders, and pinned provenance. A successful run emits a unique `ff.compatibility-report@1` JSON report under `build/reports/`.

Offline replay never opens the network. Run all cases or a zero-based deterministic shard; a valid shard may contain zero cases:

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-replay --shard 0/4
```

The mandatory planes are source graph, normalized observation, sanitized network transcript, filesystem/process artifact, failure/timeout, archive duplicate handling, and configuration migration. Fixtures replace authorization, cookies, query tokens, clocks, random seeds, and machine-local state with allowlisted placeholders before commit.

</topic>

<topic id="phase-0-compatibility-comparison" status="active" version="1" wp="WP-FF-004-compatibility-inventory-corpus-v1" ingestable="true" updated_at="2026-07-19">

## Compare candidates, inspect drift, and run live canaries

A candidate results JSON file uses `ff.compatibility-candidate-results@1`, names the exact corpus and profile IDs, and supplies stable case IDs plus SHA-256 observation digests. Compare it with:

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-diff --candidate build/fixtures/compatibility/candidate-empty-v1.json
```

Every corpus case receives a row. Equal digests are `equivalent`; omitted cases are `missing_feature`; unequal observations must be `ferric_defect`, `accepted_baseline_correction`, `nondeterministic_response`, or `accepted_divergence`. An accepted divergence requires a stable decision ID. Report completeness proves that nothing was silently omitted; it does not prove Ferric parity.

Compare two generated inventories by stable ID:

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-inventory-diff --before build/fixtures/compatibility/yt-dlp-2026.07.04/profile.json --after build/fixtures/compatibility/yt-dlp-2026.07.04/profile.json
```

Live canaries are a mechanically separate, credential-free, nondeterministic observation suite. The command refuses to run unless the operator supplies both the pinned executable and the explicit opt-in flag:

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-live-canaries --enable-live --oracle-exe $oracleExe
```

The live report records `OBSERVED` success or failure for every configured URL and always states `deterministic_proof=false`. Live results never replace offline acceptance evidence and anti-bot, site drift, rate limits, or network failures are observations rather than deterministic regressions.

Recovery follows the stable diagnostic:

- `FF-COMP-E-UNPINNED-ORACLE`: reacquire the exact official artifact/source inputs; never edit hashes to fit an unverified local file.
- `FF-COMP-E-PARSE` or deterministic regeneration mismatch: preserve both outputs, inspect the pinned source and normalization rule, then fix and rerun the generator twice.
- `FF-COMP-E-UNSANITIZED-SECRET`: replace the named secret or machine-local value with an allowlisted `{{PLACEHOLDER}}`, recompute the fixture hash, and rerun validation.
- `FF-COMP-E-COVERAGE`, `FF-COMP-E-SHARD`, or `FF-COMP-E-NORMALIZATION`: repair the canonical manifest/case mapping rather than bypassing the validator.
- Candidate identity, digest, classification, or decision errors: repair the candidate file; do not remove missing rows from the emitted report.
- Report-write failure: verify `build/reports/` is writable. Atomic writes do not accept a partial final JSON report.

</topic>

<topic id="phase-0-commands" status="active" version="2" wp="WP-FF-003-executable-gate-bootstrap-v2" ingestable="true" updated_at="2026-07-19">

## Start and run

Run commands from the repository root. Do not infer state from chat history; begin at `START_HERE.yaml`, resolve the active packet from `.GOV/taskboard/taskboard.yaml`, and follow its cited authority.

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- architecture-check
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- runtime-truth-check --evidence-from-taskboard
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- verify-pr --evidence-from-taskboard
```

`architecture-check` consumes `build/architecture-policy.toml`, `build/tooling-policy.toml`, `build/rule-to-proof.toml`, locked Cargo metadata, parsed canonical YAML authority, governed source paths, and `build/fixtures/architecture/`. Its negative fixtures call production validator primitives, while focused tests apply representative mutations to isolated repository copies and invoke the composed production gate. It emits a unique versioned JSON report under `build/reports/` and exits nonzero on mismatch.

`runtime-truth-check` compares the active packet base SHA with current changed paths. A governance/build-only packet must declare `scope.product_impact` as `NONE`; its PASS proves only that no product claim is legal. A product-affecting packet must declare `RUNTIME`, supply strict `ff.runtime-proof@1` evidence, and have a declared shipped member. The gate then builds the locked release profile, hashes and stages the exact binary, copies hash-bound inputs into a clean package directory, launches the staged binary as an external process, verifies success and negative scenarios, and removes a required observable to prove the same oracle rejects the counterfactual. Missing runtime proof is `FAIL`/`BLOCKED`, never `PASS` or `NOT_APPLICABLE`.

Supporting unit, fixture, replay, fuzz, property, and mock-based tests remain useful, but `cfg(test)`, dev-dependencies, testkit, mock/fake/stub adapters, in-memory substitutes, hardcoded success, and direct internal calls cannot satisfy `ff.runtime-proof@1`. A product packet requires at least one success and one negative scenario. Exit status alone is not an observable; require stdout, stderr, or a bounded output file with optional SHA-256.

`verify-pr` also validates active packet change evidence and runs tool preflight, formatting, compile profiles, Clippy, tests, docs, dependency policy, architecture validation, and `FF-GATE-RUNTIME-001`. Governance-only runtime validation carries an explicit no-product proof ceiling. Product-affecting missing proof cannot be skipped. Doctests remain trigger-gated until a library exists, watcher proof activates with the watcher package, and deep/release gates remain `NOT_IMPLEMENTED`; none of those states may be converted into product PASS.

</topic>

<topic id="runtime-proof-contract" status="active" version="1" wp="WP-FF-012-runtime-truth-gates-v1" ingestable="true" updated_at="2026-07-19">

## Declare production runtime proof

For a product-affecting packet, set `scope.product_impact` to `RUNTIME`, give each product acceptance row `proof_class: production_runtime`, and place an `ff.runtime-proof@1` object at `extensions.runtime_proof`. Define the scenarios before implementation. This shape is strict: unknown keys, omitted keys, substitute modes, unsafe paths, and mismatched artifact or fixture hashes fail the gate.

```json
{
  "schema_id": "ff.runtime-proof@1",
  "completion_claim": "operator_usable_runtime",
  "artifact": {
    "package": "fforager",
    "binary": "fforager",
    "profile": "release",
    "features": [],
    "package_mode": "clean_staged",
    "execution_mode": "external_process",
    "compilation_mode": "production",
    "dependency_mode": "normal_only",
    "testkit_mode": "forbidden",
    "adapter_mode": "production"
  },
  "forbidden_substitutes": [
    "mock",
    "fake",
    "stub",
    "fixture-only-implementation",
    "in-memory-substitute",
    "hardcoded-success",
    "test-only-adapter",
    "direct-internal-call"
  ],
  "scenarios": [
    {
      "id": "capability-success",
      "kind": "success",
      "capability_ids": ["replace-with-stable-capability-id"],
      "args": ["replace-with-production-cli-arguments"],
      "timeout_seconds": 30,
      "inputs": [{
        "source": "build/fixtures/replace-with-committed-input",
        "destination": "inputs/representative-input",
        "sha256": "replace-with-64-lowercase-hex-digest"
      }],
      "production_boundaries": ["replace-with-real-boundary-name"],
      "expected": {
        "exit_code": 0,
        "stdout_contains": ["replace-with-required-output"],
        "stderr_contains": [],
        "output_files": []
      },
      "counterfactual": {
        "target": "stdout_contains",
        "value": "replace-with-required-output",
        "expected_diagnostic": "FF-RUNTIME-E-OBSERVABLE-MISSING"
      }
    },
    {
      "id": "capability-negative",
      "kind": "negative",
      "capability_ids": ["replace-with-stable-capability-id"],
      "args": ["replace-with-invalid-production-cli-arguments"],
      "timeout_seconds": 30,
      "inputs": [],
      "production_boundaries": ["replace-with-real-boundary-name"],
      "expected": {
        "exit_code": 2,
        "stdout_contains": [],
        "stderr_contains": ["replace-with-stable-error"],
        "output_files": []
      },
      "counterfactual": null
    }
  ]
}
```

Replace every `replace-with-*` value with the packet's real capability, production CLI arguments, boundary, observables, and committed input digest. The success scenario requires a hash-bound representative input. The negative scenario must exercise the shipped binary and return nonzero. Output files, when used, require a safe stage-relative path, positive `min_bytes`, and optional SHA-256. Inputs and outputs cannot overwrite the binary, gate receipts, or one another.

</topic>

<topic id="phase-0-safety-recovery" status="active" version="2" wp="WP-FF-003-executable-gate-bootstrap-v2" updated_at="2026-07-19">

## Inputs, outputs, safety, and recovery

Inputs are committed policies, the locked workspace, the active packet, the canonical build rules, governed Rust source, and negative fixtures. Generated outputs are confined to `build/target/` and `build/reports/`; both are non-shipped.

The gate runner never auto-installs or upgrades tools, never uses a shell to compose child commands, and refuses to run outside the repository root. Every child process is bounded; a timeout kills and reaps the child and reports incomplete evidence instead of PASS. Project-owned TOML schemas reject unknown keys, and governance YAML must parse as one structurally valid document before any value is consumed. Tool identity checks require exact output and supported-host policy; host-installed Git and cargo-deny executables also require the pinned SHA-256 digest. Unknown rule IDs, missing proof mappings, missing or unreferenced fixtures, duplicate or nested toolchain selectors, wrong-root build files, undeclared workspace members, and runtime boundary literals fail closed.

Common failures and recovery:

- Tool version mismatch: install the exact root-selected Rust toolchain/components and the tooling-policy version of `cargo-deny`, then rerun.
- Tool checksum mismatch: resolve the executable selected by `PATH`, compare it with `build/tooling-policy.toml`, and treat any intended tool update as a dedicated validated policy change.
- External command timeout: inspect the named command and environment; its evidence is incomplete, so fix the hang or resource stall and rerun the full gate.
- Governance YAML parse or shape failure: repair the canonical YAML structure; do not bypass parsing with lexical matching.
- `--locked` failure: do not remove `--locked`; reconcile `build/Cargo.toml` and intentionally regenerate `build/Cargo.lock`.
- Wrong current directory: return to the repository root and rerun the canonical command.
- Policy or fixture mismatch: use the stable diagnostic in stderr/report, correct the canonical policy or implementation, and rerun the same gate.
- Stale build output: remove only the verified repository-local `build/target/` directory or run `cargo clean --manifest-path build/Cargo.toml`; never target the repository root.
- Failed report write: verify `build/reports/` is writable. Temporary report files are removed on failure and an incomplete final report is never accepted.

An architecture report proves the declared prerequisite graph, policy, source scan, and assigned negative cases. It does not prove product runtime behavior, packaging, watcher independence, compatibility, durability, or performance. Product proof begins only when FF-GATE-RUNTIME-001 builds, hashes, stages, and externally executes the exact production artifact through a shipped entrypoint and verifies operator-visible results plus a failing counterfactual.

</topic>
