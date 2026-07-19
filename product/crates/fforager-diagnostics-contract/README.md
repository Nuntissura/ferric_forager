# Ferric Forager diagnostic contract

`fforager-diagnostics-contract` is the data-only boundary shared by Ferric
diagnostic producers and the independent watcher. It contains no process,
filesystem, network, Tokio, or watcher-runtime handles.

The wire contract uses protocol major/minor negotiation. A major mismatch is
incompatible. A minor overlap selects the greatest mutually supported minor.
Different schema hashes are accepted only when both peers explicitly allow
compatible schema drift. Schema hashes are lowercase SHA-256 hexadecimal over
the canonical schema input identified by `canonical_input_version`.

All identifiers, strings, collections, frames, and opaque unknown values are
bounded. Deserialization runs the same validation as constructors. Secret data
must be producer-redacted before framing. Unknown optional fields may be held
only as non-exportable bounded opaque values; unknown mandatory kinds fail.

Event sequence identity is `(producer_instance, boot_session, channel,
sequence)`. Sequences start at one and never wrap. The tracker rejects gaps,
duplicates, reordering, cross-stream identity changes, and durable
acknowledgements ahead of admitted data. Explicit reconnect replay is bounded
by a caller-supplied replay window.

The watcher lifecycle distinguishes local `Ready` from Ferric-origin
`Serving`. Health snapshots expose bounded queue counters, last admitted and
durable sequence identities, typed lifecycle state, and every loop's
Idle/Working/Blocked/Failed state. Crash evidence remains retained until an
explicit collection acknowledgement or governed expiry transition.

Run package tests from the repository root after the workspace registers this
package:

```text
cargo test --manifest-path build/Cargo.toml --locked -p fforager-diagnostics-contract
```

