---
file_id: FF-PRODUCT-MODEL-MANUAL-001
file_kind: model_manual
updated_at: "2026-07-19"
---

<topic id="phase-0-purpose" status="active" version="3" wp="WP-FF-005-versioned-core-contracts-v1" updated_at="2026-07-19">

# Ferric Forager model manual

Ferric Forager is planned as a Rust-native video-acquisition and archival product. The repository contains shipped data-only contract crates and pure deterministic core models, but no executable Ferric runtime capability. These Phase 0 prerequisite artifacts and the executable build-and-proof tooling MUST NOT be counted as product capability progress, a completed product phase, packaging, release, or runtime completion.

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

Validation reads the committed oracle manifest, generated profile, seven-plane corpus, opt-in live manifest, and the exact required negative-fixture inventory. It binds each versioned manifest/profile to its canonical content digest, checks stable IDs, counts, coverage, shard assignments, normalization versions, offline/network separation, allowlisted secret placeholders, and pinned provenance. Case fixture digests normalize CRLF/CR to LF before hashing so clean Git checkouts remain portable. JSON inputs are bounded to 16 MiB. A successful run emits a unique `ff.compatibility-report@1` JSON report under `build/reports/`.

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

Every corpus case receives a row. The command first validates the canonical profile, corpus, and case fixtures, and the report records the candidate path and SHA-256. Equal digests are `equivalent`; omitted cases are `missing_feature`; unequal observations must be `ferric_defect`, `accepted_baseline_correction`, `nondeterministic_response`, or `accepted_divergence`. Accepted corrections/divergences require an explicitly authorized stable decision ID, and deterministic offline cases cannot be relabeled nondeterministic. Report completeness proves that nothing was silently omitted; it does not prove Ferric parity.

Compare two generated inventories by stable ID:

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-inventory-diff --before build/fixtures/compatibility/yt-dlp-2026.07.04/profile.json --after build/fixtures/compatibility/yt-dlp-2026.07.04/profile.json
```

Inventory-diff reports use `ff.compatibility-inventory-diff@2` and cover option, preset, interaction, extractor, and extractor-description additions, removals, and changes. Reusing one profile ID for changed content fails closed.

Live canaries are a mechanically separate, credential-free, nondeterministic observation suite with exact public destination allowlists. The command refuses to run unless the operator supplies both the pinned executable and the explicit opt-in flag:

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- compatibility-live-canaries --enable-live --oracle-exe $oracleExe
```

The live report status and every canary row are `OBSERVED`, and the command always states `deterministic_proof=false`. Live results never replace offline acceptance evidence and anti-bot, site drift, rate limits, or network failures are observations rather than deterministic regressions.

Recovery follows the stable diagnostic:

- `FF-COMP-E-UNPINNED-ORACLE`: reacquire the exact official artifact/source inputs; never edit hashes to fit an unverified local file.
- `FF-COMP-E-PARSE` or deterministic regeneration mismatch: preserve both outputs, inspect the pinned source and normalization rule, then fix and rerun the generator twice.
- `FF-COMP-E-UNSANITIZED-SECRET`: replace the named secret or machine-local value with an allowlisted `{{PLACEHOLDER}}`, recompute the fixture hash, and rerun validation.
- `FF-COMP-E-COVERAGE`, `FF-COMP-E-SHARD`, or `FF-COMP-E-NORMALIZATION`: repair the canonical manifest/case mapping rather than bypassing the validator.
- Profile/corpus/live integrity or unsafe canonical-path errors: restore the versioned committed artifact or use a repository-relative file physically contained under `build/fixtures/compatibility/` or `build/target/`; do not reuse an ID for changed content or route through a link outside those roots.
- Candidate identity, digest, classification, or decision errors: repair the candidate file; do not remove missing rows from the emitted report.
- Report-write failure: verify `build/reports/` is writable. Atomic writes do not accept a partial final JSON report.

</topic>

<topic id="phase-0-commands" status="active" version="2" wp="WP-FF-003-executable-gate-bootstrap-v2" ingestable="true" updated_at="2026-07-19">

## Start and run

Run commands from the repository root. Do not infer state from chat history; begin at `START_HERE.yaml`, resolve the active packet from `.GOV/taskboard/taskboard.yaml`, and follow its cited authority.

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- architecture-check
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- runtime-truth-check --evidence-from-taskboard
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- verify-deep --evidence-from-taskboard
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- verify-pr --evidence-from-taskboard
```

`architecture-check` consumes `build/architecture-policy.toml`, `build/tooling-policy.toml`, `build/rule-to-proof.toml`, locked Cargo metadata, parsed canonical YAML authority, governed source paths, and `build/fixtures/architecture/`. Its negative fixtures call production validator primitives, while focused tests apply representative mutations to isolated repository copies and invoke the composed production gate. It emits a unique versioned JSON report under `build/reports/` and exits nonzero on mismatch.

`runtime-truth-check` compares the active packet base SHA with current changed paths. A governance/build-only packet must declare `scope.product_impact` as `NONE`; its PASS proves only that no product claim is legal. A product-affecting packet must declare `RUNTIME`, supply strict `ff.runtime-proof@1` evidence, and have a declared shipped member. The gate then builds the locked release profile, hashes and stages the exact binary, copies hash-bound inputs into a clean package directory, launches the staged binary as an external process, verifies success and negative scenarios, and removes a required observable to prove the same oracle rejects the counterfactual. Missing runtime proof is `FAIL`/`BLOCKED`, never `PASS` or `NOT_APPLICABLE`.

Supporting unit, fixture, replay, fuzz, property, and mock-based tests remain useful, but `cfg(test)`, dev-dependencies, testkit, mock/fake/stub adapters, in-memory substitutes, hardcoded success, and direct internal calls cannot satisfy `ff.runtime-proof@1`. A product packet requires at least one success and one negative scenario. Exit status alone is not an observable; require stdout, stderr, or a bounded output file with optional SHA-256.

`verify-deep` is active for WP-005. It runs the pinned workspace across formatting, compile profiles, Clippy, all tests, the machine-readable contract inventory, the data-only model scan, and the architecture gate. Its report maps all seven WP-005 acceptance rows to proof and states the prerequisite-only proof ceiling.

`verify-pr` also validates active packet change evidence and runs tool preflight, formatting, compile profiles, Clippy, tests, docs, dependency policy, architecture validation, `FF-GATE-RUNTIME-001`, and the applicable WP-005 deep checks. Prerequisite runtime validation carries an explicit zero-product-progress ceiling. Runtime-affecting missing production proof cannot be skipped. Watcher proof activates with the watcher package, and the release gate remains `NOT_IMPLEMENTED`; none of those states may be converted into product PASS.

</topic>

<topic id="phase-0-contract-operation" status="active" version="1" wp="WP-FF-005-versioned-core-contracts-v1" ingestable="true" updated_at="2026-07-19">

## Inspect and change the Phase 0 contracts and models

The contract and proof surfaces are:

- `product/crates/fforager-contracts/`: versioned product identities, source graph, acquisition/sink DTOs, public/process/plugin/JavaScript-worker envelopes, bounded framing, journal/commit/archive/durability, and filesystem-capability descriptions.
- `product/crates/fforager-diagnostics-contract/`: bounded diagnostic/event/crash/cancellation/lifecycle DTOs, protocol/schema negotiation, sequence/replay/durable acknowledgement, privacy classifications, and retention descriptions.
- `product/crates/fforager-core/`: pure deterministic lifecycle, atomic resource-vector, byte-credit, durability-position, cancellation, restart, and replay models. It emits effect intents; it performs no effects.
- `build/crates/fforager-testkit/`: non-shipped shared cross-version and malformed-frame conformance harness.
- `build/fixtures/contracts/inventory.json`: canonical machine-readable stable IDs, owners, type names, version policies, limits/errors, fixtures, proof IDs, readiness gates, design anchors, and residual uncertainty.
- `build/fixtures/contracts/`: canonical prior/current/incompatible versions, unknown-kind input, and state/resource scenarios.

Inspect the inventory first, then the named owner module and proof ID. Run focused proof while editing:

```powershell
cargo test --manifest-path build/Cargo.toml --locked -p fforager-contracts
cargo test --manifest-path build/Cargo.toml --locked -p fforager-diagnostics-contract
cargo test --manifest-path build/Cargo.toml --locked -p fforager-core
cargo test --manifest-path build/Cargo.toml --locked -p fforager-testkit
cargo clippy --manifest-path build/Cargo.toml --workspace --all-targets --all-features --locked -- -D warnings
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- verify-deep --evidence-from-taskboard
```

Wire versions use incompatible major versions and inclusive trusted local reader ranges; a sender cannot self-authorize compatibility. Every envelope type binds to its exact canonical schema ID before dispatch. Unknown mandatory kinds and unnamespaced unknown fields fail. Unknown optional data is accepted only through a namespaced `ExtensionMap` inside fixed entry, key, value, and total byte budgets. Stable typed IDs reject the wrong prefix, uppercase/noncanonical characters, empty suffixes, and values above 128 bytes. Process, plugin, and JavaScript-worker framing is a four-byte big-endian length followed by JSON; declared size is rejected before payload allocation and every decoded envelope is recursively validated. The product frame defaults to 1 MiB. Diagnostics cap a JSON frame at 256 KiB, fields at 64, text at 4 KiB, IDs at 128 bytes, retained unknown optional values at 8 KiB, and schema identities at 16. Read the exported constants and inventory row before relying on any limit.

Every lifecycle transition is pure and owned. Invalid transitions leave state and trace unchanged. Traces are bounded and replayable. The commit/archive and byte-durability models enumerate effect-request and acknowledged durable-prefix states; an emitted write, sync, verification, archive, cleanup, or cancellation intent never counts as acknowledged success, and restart reconciliation never invents success from a partial prefix. Resource admission is one checked 13-dimensional vector transaction with exact grant ownership, bounded waiter item/byte counts, strict FIFO head reservation, a deterministic per-owner active-grant ceiling, explicit cancellation dispatch, transactional release, and exact ownership checks. Byte credits conserve capacity, revoke released unused credit, reject positions beyond consumed or live credited bytes, and track received, validated, written, and durable positions monotonically.

Each state-machine instance receives a caller-supplied, nonzero, stable `MachineInstanceId`. An acknowledgement is accepted only when its instance ID, effect, and generation exactly match a currently pending effect. Persist that instance identity and the next generation with the durable state. Public restoration accepts only the states returned by the machine's `durable_states` whitelist; testkit cross-checks that whitelist against the inventory's exact durable-prefix list. Initial, transient, failed, inconsistent, cancelled, and other non-enumerated states are not restart prefixes.

Byte receive consumes a named claim owned by the named owner and records that attribution. An unconsumed claim may transfer ownership, but a partially or fully consumed claim rejects transfer so historical attribution cannot be rewritten. Releasing a claim revokes its unused remainder while retaining consumed attribution for audit.

Acquisition and output-sink descriptors are data-only but still validated before adapter dispatch. Their URLs, identifiers, checksums, path references, fragment counts, expected lifetimes, and bounded-buffer sizes have explicit limits. Rooted path references reject absolute paths, parent traversal, empty segments, Windows drive/device prefixes, and trailing dot or space segments. Plugin and JavaScript-worker messages cross boundaries only inside complete envelopes carrying version compatibility, request correlation, producer/job identity, and provenance; bare payload enums are not dispatch contracts.

Before dispatching decoded boundary data:

- Apply the exported contract validator with the explicit limit set selected by the owning adapter.
- Reject incompatible schema versions before reading operation-specific payload fields.
- Keep request registration separate from correlated events and acknowledgements; only a new request consumes a new request-ID slot.
- Compare cancellation acknowledgements with the originating request ID, generation, and caller-selected expected responder before retiring ownership.
- Route lifecycle acknowledgements with the persisted stable machine instance ID plus exact effect and generation; never synthesize or reuse another instance's token.
- Treat validation failure as a typed boundary rejection; do not repair, truncate, default, or silently discard mandatory data.

To change or regenerate fixtures, never overwrite or reinterpret a supported prior-version file. Add a new versioned fixture, update `inventory.json`, add the matching reader/writer or rejection test, and run the focused testkit plus `verify-deep`. A breaking schema change requires a new major version and retained old fixture. An additive minor change must remain inside a declared compatibility range. Reusing a stable ID for changed semantics is forbidden.

Common contract failures and recovery:

- `IncompatibleMajor` or unsupported minor: select a mutually supported range or implement an explicit version migration; do not relax the check.
- `UnknownMandatoryKind`: update both peers and add a versioned fixture, or encode genuinely optional data in a bounded namespaced extension.
- `Oversized`, `PartialHeader`, `PartialPayload`, or invalid JSON: reject the frame, reset the decoder, and replay only from an owned protocol boundary; never allocate from the unvalidated length.
- Duplicate request/identity, ambiguous canonicalization, or dangling graph relationship: repair the producer; do not silently deduplicate or guess a target.
- Invalid lifecycle transition or replay mismatch: preserve the emitted trace/seed, inspect the named owner and precondition, and rerun the exact counterfactual test.
- Admission overflow, capacity, owner, or release error: leave the ledger unchanged, repair the request/ownership flow, and rerun zero, exact-capacity, one-over, cancellation, and repeated-release tests.
- Inventory or fixture failure: restore a unique stable ID, complete every required field, ensure repository-relative fixture containment, and rerun `fforager-testkit` before the deep gate.
- Canonical inventory digest mismatch: inspect the semantic diff first; if the change is authorized, update the exact inventory mappings and `CANONICAL_INVENTORY_FNV1A64` together, then rerun the representative field-mutation test and full testkit. Never update the digest merely to silence unexplained drift.
- Restore or acknowledgement failure: recover the persisted `MachineInstanceId`, generation seed, and inventory-enumerated durable state; do not acknowledge a transient effect or substitute a token from another instance.
- Consumed-claim transfer failure: retain the original owner attribution, release the claim when appropriate, and create a new claim for later ownership rather than rewriting consumed history.
- Data-only scan failure: replace runtime handles, processes, sockets, filesystem handles, threads, channels, or locks with serializable data or explicit effect-intent DTOs owned by a later adapter.

These contracts do not select or implement network, storage, archive, FFmpeg, JavaScript, plugin, scheduler, watcher, or transport adapters. A later shipped consumer must prove actual behavior through `FF-GATE-RUNTIME-001` using the exact staged production artifact.

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
