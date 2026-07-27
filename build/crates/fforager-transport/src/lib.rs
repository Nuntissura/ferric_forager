#![forbid(unsafe_code)]
//! Non-shipped WP-007 transport capability and security proof surface.
//!
//! This crate is Phase 0 prerequisite evidence. It is not a product transport.

pub mod corpus;
pub mod local_server;
pub mod policy;

pub use corpus::{
    AggregateVerdict, CorpusManifest, CorpusReport, run_corpus, validate_aggregate_evidence,
};
pub use policy::{
    BlockedCapability, BodyBudget, ByteCredits, CancellationModel, CancellationStatus,
    CandidateAdapter, Capability, CapabilityDecision, Cookie, CookieJar, DnsEvidence, HeaderValue,
    HttpRequest, HttpUrl, IpPolicyError, PoolKey, PoolRegistry, PoolUse, ProxyEvidence,
    PublicSuffixSet, RedirectPolicy, RedirectResult, SanitizedExchange, TransportError,
    sanitize_exchange,
};
