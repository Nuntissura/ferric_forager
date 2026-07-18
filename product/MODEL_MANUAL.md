---
file_id: FF-PRODUCT-MODEL-MANUAL-001
file_kind: model_manual
updated_at: "2026-07-19"
---

<topic id="phase-0-purpose" status="active" version="1" wp="WP-FF-003-executable-gate-bootstrap-v1" updated_at="2026-07-19">

# Ferric Forager model manual

Ferric Forager is planned as a Rust-native video-acquisition and archival product. Phase 0 contains no shipped product crate. Its implemented deliverable is the executable build-and-proof skeleton that future product work must pass.

Repository ownership is deterministic:

- `.GOV/` owns governance, work packets, task state, design, and validation authority.
- `product/` owns shipped runtime code, assets, the independent watcher, this manual, and tests local to a product package.
- `build/` owns the Cargo workspace and lockfile, build policies, non-shipped tooling, shared and cross-package test infrastructure, fixtures, reports, and `target` output.
- `rust-toolchain.toml` at repository root is the sole rustup selector.

Shipped product runtime must not read or require `.GOV/` or `build/`. Build tooling may read the active governance packet to validate proof.

</topic>

<topic id="phase-0-commands" status="active" version="1" wp="WP-FF-003-executable-gate-bootstrap-v1" ingestable="true" updated_at="2026-07-19">

## Start and run

Run commands from the repository root. Do not infer state from chat history; begin at `START_HERE.yaml`, resolve the active packet from `.GOV/taskboard/taskboard.yaml`, and follow its cited authority.

```powershell
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- architecture-check
cargo run --manifest-path build/Cargo.toml --locked -p fforager-xtask -- verify-pr --evidence-from-taskboard
```

`architecture-check` consumes `build/architecture-policy.toml`, `build/rule-to-proof.toml`, locked Cargo metadata, canonical architecture rules, governed source paths, and `build/fixtures/architecture/`. It emits a unique versioned JSON report under `build/reports/` and exits nonzero on mismatch.

`verify-pr` also validates the active packet change-evidence fields and runs tool preflight, formatting, compile profiles, Clippy, tests, docs, dependency policy, and the architecture checker. Doctests, clean shipped-artifact proof, and watcher proof are reported `NOT_APPLICABLE` until their trigger exists. Deep and release gates are `NOT_IMPLEMENTED`; neither state may be reported as PASS.

</topic>

<topic id="phase-0-safety-recovery" status="active" version="1" wp="WP-FF-003-executable-gate-bootstrap-v1" updated_at="2026-07-19">

## Inputs, outputs, safety, and recovery

Inputs are committed policies, the locked workspace, the active packet, the canonical build rules, governed Rust source, and negative fixtures. Generated outputs are confined to `build/target/` and `build/reports/`; both are non-shipped.

The gate runner never auto-installs or upgrades tools, never uses a shell to compose child commands, and refuses to run outside the repository root. Project-owned TOML schemas reject unknown keys. Unknown rule IDs, missing proof mappings, missing or unreferenced fixtures, duplicate toolchain selectors, wrong-root build files, undeclared workspace members, and runtime boundary literals fail closed.

Common failures and recovery:

- Tool version mismatch: install the exact root-selected Rust toolchain/components and the tooling-policy version of `cargo-deny`, then rerun.
- `--locked` failure: do not remove `--locked`; reconcile `build/Cargo.toml` and intentionally regenerate `build/Cargo.lock`.
- Wrong current directory: return to the repository root and rerun the canonical command.
- Policy or fixture mismatch: use the stable diagnostic in stderr/report, correct the canonical policy or implementation, and rerun the same gate.
- Stale build output: remove only the verified repository-local `build/target/` directory or run `cargo clean --manifest-path build/Cargo.toml`; never target the repository root.
- Failed report write: verify `build/reports/` is writable. Temporary report files are removed on failure and an incomplete final report is never accepted.

An architecture report proves the declared Phase 0 graph, policy, source scan, and assigned negative cases. It does not prove future product runtime behavior, packaging, watcher independence, compatibility, durability, or performance.

</topic>
