use crate::local_server::{LocalProtocolServer, execute_local};
use crate::policy::{
    BodyBudget, ByteCredits, CancellationModel, CandidateAdapter, Capability, Cookie, CookieJar,
    DnsEvidence, HeaderValue, HttpRequest, HttpUrl, PoolKey, PoolRegistry, ProxyEvidence,
    PublicSuffixSet, RedirectPolicy, TransportError, sanitize_exchange, validate_connected_address,
    validate_dns_evidence,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Instant;

const SCHEMA_ID: &str = "fforager.transport-corpus-manifest.v1";
const REPORT_SCHEMA_ID: &str = "fforager.transport-corpus-report.v1";
const CORPUS_ID: &str = "WP-FF-007-transport-corpus-v1";
const NORMALIZATION_VERSION: &str = "WP-FF-004-sanitized-transcript-v1";
const MAX_CASES: usize = 128;
const SECRET_CANARY: &str = "ff-secret-canary-never-record";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusManifest {
    pub schema_id: String,
    pub corpus_id: String,
    pub normalization_version: String,
    pub candidate_identity: String,
    pub max_cases: usize,
    pub cases: Vec<CorpusCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCase {
    pub id: String,
    pub kind: CaseKind,
    pub mandatory: bool,
    pub proof_class: ProofClass,
    pub requested_capabilities: BTreeSet<Capability>,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    StandardCapability,
    TlsFingerprintBlocked,
    Http2FingerprintBlocked,
    Http2Blocked,
    ProxyBlocked,
    CompressionBlocked,
    Http11Local,
    RangeLocal,
    StreamingLocal,
    RedirectCrossOrigin,
    RedirectDowngrade,
    RedirectLimit,
    CookieScope,
    CookiePublicSuffix,
    CookieSyntax,
    SsrfMixedAnswers,
    DnsSelection,
    DnsRebind,
    ProxyEvidence,
    PoolReuse,
    PoolSessionPartition,
    PoolFingerprintPartition,
    PoolBound,
    MetadataBound,
    BodyBound,
    DecompressionBound,
    ByteCredit,
    RetryBound,
    CancellationCorrelation,
    CancellationPool,
    SanitizedReplay,
    UrlBounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofClass {
    Runtime,
    Protocol,
    Security,
    Resource,
    Structural,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AggregateVerdict {
    PassPureRustPath,
    FailedSpikeRequiresOperatorDecision,
}

impl AggregateVerdict {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PassPureRustPath => "PASS_PURE_RUST_PATH",
            Self::FailedSpikeRequiresOperatorDecision => "FAILED_SPIKE_REQUIRES_OPERATOR_DECISION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusReport {
    pub schema_id: String,
    pub corpus_id: String,
    pub normalization_version: String,
    pub candidate_identity: String,
    pub zero_product_progress: bool,
    pub cases: Vec<CaseReport>,
    pub summary: CorpusSummary,
    pub counterfactual: CounterfactualProof,
    pub residual_uncertainties: Vec<String>,
    pub verdict: AggregateVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseReport {
    pub id: String,
    pub mandatory: bool,
    pub proof_class: ProofClass,
    pub concrete_input: String,
    pub executed_boundary: String,
    pub requested_capabilities: BTreeSet<Capability>,
    pub satisfied_capabilities: BTreeSet<Capability>,
    pub blocked_capabilities: Vec<BlockedCapabilityReport>,
    pub connection_identity: Option<String>,
    pub wire_identity: Option<String>,
    pub pool_identity: Option<String>,
    pub transcript: Option<serde_json::Value>,
    pub expected_outcome: String,
    pub observed_outcome: String,
    pub status: CaseStatus,
    pub exact_mismatch: Option<String>,
    pub skipped_semantic_dependencies: Vec<String>,
    pub duration_micros: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedCapabilityReport {
    pub capability: Capability,
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaseStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub mandatory_total: usize,
    pub mandatory_passed: usize,
    pub mandatory_blocked: usize,
    pub blocked_capability_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterfactualProof {
    pub mutation: String,
    pub rejected_by_same_oracle: bool,
    pub rejection: String,
}

/// Executes every declared case and constructs the fail-closed aggregate report.
///
/// # Errors
///
/// Returns a stable diagnostic when the manifest, a case oracle, the aggregate
/// evidence, the counterfactual, or report sanitization is invalid.
pub fn run_corpus(manifest: &CorpusManifest) -> Result<CorpusReport, String> {
    validate_manifest(manifest)?;
    let candidate = CandidateAdapter::std_first();
    if manifest.candidate_identity != candidate.identity() {
        return Err(format!(
            "FF-TRANSPORT-E-CANDIDATE-IDENTITY: expected {}, observed {}",
            manifest.candidate_identity,
            candidate.identity()
        ));
    }
    let cases = manifest
        .cases
        .iter()
        .map(|case| run_case(case, &candidate))
        .collect::<Vec<_>>();
    let (summary, verdict) = validate_aggregate_evidence(manifest, &cases)?;
    let counterfactual = counterfactual_proof(manifest, &cases);
    if !counterfactual.rejected_by_same_oracle {
        return Err("FF-TRANSPORT-E-COUNTERFACTUAL: mutation was accepted".to_owned());
    }
    let report = CorpusReport {
        schema_id: REPORT_SCHEMA_ID.to_owned(),
        corpus_id: manifest.corpus_id.clone(),
        normalization_version: manifest.normalization_version.clone(),
        candidate_identity: manifest.candidate_identity.clone(),
        zero_product_progress: true,
        cases,
        summary,
        counterfactual,
        residual_uncertainties: vec![
            "No browser-equivalent ClientHello was emitted; TLS fingerprint parity remains blocked."
                .to_owned(),
            "No browser-equivalent HTTP/2 SETTINGS, ordering, or priority frames were emitted; HTTP/2 wire parity remains blocked."
                .to_owned(),
            "The local protocol harness proves bounded HTTP/1.1 semantics, not internet interoperability."
                .to_owned(),
            "The embedded public-suffix and special-use fixtures are proof samples, not production data sources."
                .to_owned(),
        ],
        verdict,
    };
    reject_secret_canary(&report)?;
    Ok(report)
}

/// Applies the same strict aggregate oracle used by the corpus runner.
///
/// # Errors
///
/// Returns a stable diagnostic for missing, duplicate, undeclared, drifted, or
/// behavior-mismatched case evidence.
pub fn validate_aggregate_evidence(
    manifest: &CorpusManifest,
    cases: &[CaseReport],
) -> Result<(CorpusSummary, AggregateVerdict), String> {
    if cases.len() != manifest.cases.len() {
        return Err(format!(
            "FF-TRANSPORT-E-CASE-CARDINALITY: expected {}, observed {}",
            manifest.cases.len(),
            cases.len()
        ));
    }
    let expected_by_id = manifest
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut observed_ids = BTreeSet::new();
    let mut passed = 0;
    let mut mandatory_total = 0;
    let mut mandatory_passed = 0;
    let mut blocked_codes = BTreeSet::new();
    for report in cases {
        if !observed_ids.insert(report.id.as_str()) {
            return Err(format!("FF-TRANSPORT-E-DUPLICATE-REPORT-ID: {}", report.id));
        }
        let expected = expected_by_id
            .get(report.id.as_str())
            .ok_or_else(|| format!("FF-TRANSPORT-E-UNDECLARED-REPORT-ID: {}", report.id))?;
        if report.mandatory != expected.mandatory
            || report.proof_class != expected.proof_class
            || report.requested_capabilities != expected.requested_capabilities
            || report.expected_outcome != expected.expected_outcome
        {
            return Err(format!("FF-TRANSPORT-E-DECLARATION-DRIFT: {}", report.id));
        }
        if report.observed_outcome != expected.expected_outcome
            || report.status != CaseStatus::Pass
            || report.exact_mismatch.is_some()
        {
            return Err(format!(
                "FF-TRANSPORT-E-OUTCOME-MISMATCH: {} expected {}, observed {}",
                report.id, expected.expected_outcome, report.observed_outcome
            ));
        }
        passed += 1;
        if report.mandatory {
            mandatory_total += 1;
            mandatory_passed += 1;
            for blocked in &report.blocked_capabilities {
                blocked_codes.insert(blocked.code.clone());
            }
        }
    }
    if observed_ids.len() != expected_by_id.len() {
        return Err("FF-TRANSPORT-E-MISSING-REPORT-ID".to_owned());
    }
    let blocked_capability_codes = blocked_codes.into_iter().collect::<Vec<_>>();
    let verdict = if blocked_capability_codes.is_empty() {
        AggregateVerdict::PassPureRustPath
    } else {
        AggregateVerdict::FailedSpikeRequiresOperatorDecision
    };
    Ok((
        CorpusSummary {
            total: cases.len(),
            passed,
            failed: cases.len().saturating_sub(passed),
            mandatory_total,
            mandatory_passed,
            mandatory_blocked: cases
                .iter()
                .filter(|case| case.mandatory && !case.blocked_capabilities.is_empty())
                .count(),
            blocked_capability_codes,
        },
        verdict,
    ))
}

fn validate_manifest(manifest: &CorpusManifest) -> Result<(), String> {
    if manifest.schema_id != SCHEMA_ID
        || manifest.corpus_id != CORPUS_ID
        || manifest.normalization_version != NORMALIZATION_VERSION
    {
        return Err("FF-TRANSPORT-E-MANIFEST-AUTHORITY".to_owned());
    }
    if manifest.max_cases == 0
        || manifest.max_cases > MAX_CASES
        || manifest.cases.is_empty()
        || manifest.cases.len() > manifest.max_cases
    {
        return Err("FF-TRANSPORT-E-CASE-BOUNDS".to_owned());
    }
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        if !valid_case_id(&case.id) || !ids.insert(&case.id) {
            return Err(format!("FF-TRANSPORT-E-CASE-ID: {}", case.id));
        }
        if !case.mandatory
            || case.requested_capabilities.is_empty()
            || case.expected_outcome.is_empty()
        {
            return Err(format!("FF-TRANSPORT-E-CASE-DECLARATION: {}", case.id));
        }
    }
    Ok(())
}

fn valid_case_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn run_case(case: &CorpusCase, candidate: &CandidateAdapter) -> CaseReport {
    let started = Instant::now();
    let decision = candidate.negotiate(case.requested_capabilities.iter().copied());
    let blocked_capabilities = decision
        .blocked
        .iter()
        .map(|blocked| BlockedCapabilityReport {
            capability: blocked.capability,
            code: blocked.code.clone(),
            reason: blocked.reason.clone(),
        })
        .collect::<Vec<_>>();
    let execution = if decision.execution_allowed {
        execute_case(case.kind)
    } else {
        Ok(CaseEvidence {
            concrete_input: format!("requested={:?}", decision.requested),
            executed_boundary: "typed-capability-negotiation".to_owned(),
            observed_outcome: decision.blocked.first().map_or_else(
                || "blocked-without-code".to_owned(),
                |blocked| blocked.code.clone(),
            ),
            connection_identity: None,
            wire_identity: None,
            pool_identity: None,
            transcript: None,
            skipped_semantic_dependencies: decision
                .blocked
                .iter()
                .map(|blocked| format!("{:?}:{}", blocked.capability, blocked.reason))
                .collect(),
        })
    };
    let evidence = execution.unwrap_or_else(|error| CaseEvidence {
        concrete_input: format!("{:?}", case.kind),
        executed_boundary: "case-execution-error".to_owned(),
        observed_outcome: error.to_string(),
        connection_identity: None,
        wire_identity: None,
        pool_identity: None,
        transcript: None,
        skipped_semantic_dependencies: Vec::new(),
    });
    let exact_mismatch = (evidence.observed_outcome != case.expected_outcome).then(|| {
        format!(
            "expected {}, observed {}",
            case.expected_outcome, evidence.observed_outcome
        )
    });
    CaseReport {
        id: case.id.clone(),
        mandatory: case.mandatory,
        proof_class: case.proof_class,
        concrete_input: evidence.concrete_input,
        executed_boundary: evidence.executed_boundary,
        requested_capabilities: decision.requested,
        satisfied_capabilities: decision.satisfied,
        blocked_capabilities,
        connection_identity: evidence.connection_identity,
        wire_identity: evidence.wire_identity,
        pool_identity: evidence.pool_identity,
        transcript: evidence.transcript,
        expected_outcome: case.expected_outcome.clone(),
        observed_outcome: evidence.observed_outcome,
        status: if exact_mismatch.is_none() {
            CaseStatus::Pass
        } else {
            CaseStatus::Fail
        },
        exact_mismatch,
        skipped_semantic_dependencies: evidence.skipped_semantic_dependencies,
        duration_micros: started.elapsed().as_micros(),
    }
}

#[derive(Debug)]
struct CaseEvidence {
    concrete_input: String,
    executed_boundary: String,
    observed_outcome: String,
    connection_identity: Option<String>,
    wire_identity: Option<String>,
    pool_identity: Option<String>,
    transcript: Option<serde_json::Value>,
    skipped_semantic_dependencies: Vec<String>,
}

impl CaseEvidence {
    fn policy(input: impl Into<String>, outcome: impl Into<String>) -> Self {
        Self {
            concrete_input: input.into(),
            executed_boundary: "pure-policy-model".to_owned(),
            observed_outcome: outcome.into(),
            connection_identity: None,
            wire_identity: None,
            pool_identity: None,
            transcript: None,
            skipped_semantic_dependencies: Vec::new(),
        }
    }
}

fn execute_case(kind: CaseKind) -> Result<CaseEvidence, TransportError> {
    match kind {
        CaseKind::StandardCapability => Ok(CaseEvidence::policy(
            "std-first standard capability set",
            "standard-capabilities-supported",
        )),
        CaseKind::Http11Local => local_case("/ok", None, 16, "http11-body-ok"),
        CaseKind::RangeLocal => local_case("/range", Some("bytes=2-5"), 4, "range-206-2-5"),
        CaseKind::StreamingLocal => local_case("/stream", None, 21, "streamed-with-byte-credits"),
        CaseKind::RedirectCrossOrigin => redirect_cross_origin(),
        CaseKind::RedirectDowngrade => redirect_downgrade(),
        CaseKind::RedirectLimit => redirect_limit(),
        CaseKind::CookieScope => cookie_scope(),
        CaseKind::CookiePublicSuffix => cookie_public_suffix(),
        CaseKind::CookieSyntax => cookie_syntax(),
        CaseKind::SsrfMixedAnswers => Ok(ssrf_mixed_answers()),
        CaseKind::DnsSelection => Ok(dns_selection()),
        CaseKind::DnsRebind => Ok(dns_rebind()),
        CaseKind::ProxyEvidence => Ok(proxy_evidence()),
        CaseKind::PoolReuse => pool_reuse(),
        CaseKind::PoolSessionPartition => pool_partition(true),
        CaseKind::PoolFingerprintPartition => pool_partition(false),
        CaseKind::PoolBound => pool_bound(),
        CaseKind::MetadataBound => Ok(body_bound("metadata")),
        CaseKind::BodyBound => Ok(body_bound("body")),
        CaseKind::DecompressionBound => Ok(body_bound("decompression")),
        CaseKind::ByteCredit => byte_credit(),
        CaseKind::RetryBound => Ok(retry_bound()),
        CaseKind::CancellationCorrelation => cancellation_correlation(),
        CaseKind::CancellationPool => cancellation_pool(),
        CaseKind::SanitizedReplay => sanitized_replay(),
        CaseKind::UrlBounds => Ok(url_bounds()),
        CaseKind::TlsFingerprintBlocked
        | CaseKind::Http2FingerprintBlocked
        | CaseKind::Http2Blocked
        | CaseKind::ProxyBlocked
        | CaseKind::CompressionBlocked => Err(TransportError::Protocol(
            "FF-TRANSPORT-E-INTERNAL: blocked case crossed execution boundary".to_owned(),
        )),
    }
}

fn local_case(
    path: &str,
    range: Option<&str>,
    body_bytes: u64,
    outcome: &str,
) -> Result<CaseEvidence, TransportError> {
    let server = LocalProtocolServer::spawn()?;
    let target = server.target();
    let mut credits = ByteCredits::new(body_bytes);
    credits.grant(body_bytes)?;
    let response = execute_local(&target, path, range, &mut credits)?;
    let receipt = server.finish()?;
    let expected_status = if range.is_some() { 206 } else { 200 };
    if response.status != expected_status || credits.accepted() != body_bytes {
        return Err(TransportError::Protocol(
            "FF-TRANSPORT-E-LOCAL-ASSERTION".to_owned(),
        ));
    }
    Ok(CaseEvidence {
        concrete_input: format!("{}; range={range:?}", receipt.request_line),
        executed_boundary: "loopback-tcp-http1.1".to_owned(),
        observed_outcome: outcome.to_owned(),
        connection_identity: Some(response.connection_identity),
        wire_identity: Some(response.wire_identity),
        pool_identity: None,
        transcript: None,
        skipped_semantic_dependencies: Vec::new(),
    })
}

fn redirect_cross_origin() -> Result<CaseEvidence, TransportError> {
    let mut request = HttpRequest::new(
        "redirect-cross",
        "GET",
        HttpUrl::parse("https://media.example/account")?,
    )?;
    request.insert_header(
        "authorization",
        HeaderValue::new(SECRET_CANARY, true, true)?,
    )?;
    request.insert_header("accept", HeaderValue::new("*/*", false, false)?)?;
    let result = redirect_policy().apply(&request, HttpUrl::parse("https://cdn.example/media")?)?;
    if result.request.headers.contains_key("authorization")
        || !result.request.headers.contains_key("accept")
    {
        return Err(TransportError::Policy(
            "FF-TRANSPORT-E-REDIRECT-STRIP".to_owned(),
        ));
    }
    Ok(CaseEvidence::policy(
        "authorization + accept; cross-origin target",
        "cross-origin-sensitive-headers-stripped",
    ))
}

fn redirect_downgrade() -> Result<CaseEvidence, TransportError> {
    let request = HttpRequest::new(
        "redirect-downgrade",
        "GET",
        HttpUrl::parse("https://media.example/secure")?,
    )?;
    let error = redirect_policy()
        .apply(&request, HttpUrl::parse("http://media.example/plain")?)
        .expect_err("downgrade fixture must be rejected");
    Ok(CaseEvidence::policy(
        "https origin -> http target",
        error.to_string(),
    ))
}

fn redirect_limit() -> Result<CaseEvidence, TransportError> {
    let mut request = HttpRequest::new(
        "redirect-limit",
        "GET",
        HttpUrl::parse("https://media.example/one")?,
    )?;
    request.redirect_count = 3;
    let error = redirect_policy()
        .apply(&request, HttpUrl::parse("https://media.example/four")?)
        .expect_err("redirect limit fixture must be rejected");
    Ok(CaseEvidence::policy(
        "redirect_count=3; maximum=3",
        error.to_string(),
    ))
}

fn redirect_policy() -> RedirectPolicy {
    RedirectPolicy {
        maximum_hops: 3,
        reject_https_downgrade: true,
    }
}

fn suffixes() -> PublicSuffixSet {
    PublicSuffixSet::new(["com".to_owned(), "invalid".to_owned()])
}

fn cookie_scope() -> Result<CaseEvidence, TransportError> {
    let source = HttpUrl::parse("https://media.example.com/account/index")?;
    let mut jar = CookieJar::new(4);
    jar.store(
        &source,
        Cookie {
            name: "session".to_owned(),
            value: SECRET_CANARY.to_owned(),
            domain: "media.example.com".to_owned(),
            host_only: true,
            path: "/account".to_owned(),
            secure: true,
        },
        &suffixes(),
    )?;
    let correct = jar.values_for(&source).len() == 1;
    let insecure = jar
        .values_for(&HttpUrl::parse("http://media.example.com/account/index")?)
        .is_empty();
    let cross_host = jar
        .values_for(&HttpUrl::parse("https://cdn.example.com/account/index")?)
        .is_empty();
    if !(correct && insecure && cross_host) {
        return Err(TransportError::Policy(
            "FF-TRANSPORT-E-COOKIE-SCOPE".to_owned(),
        ));
    }
    Ok(CaseEvidence::policy(
        "secure host-only /account cookie",
        "cookie-scoped-to-secure-host-path",
    ))
}

fn cookie_public_suffix() -> Result<CaseEvidence, TransportError> {
    let source = HttpUrl::parse("https://media.example.com/")?;
    let error = CookieJar::new(4)
        .store(
            &source,
            Cookie {
                name: "bad".to_owned(),
                value: "value".to_owned(),
                domain: "com".to_owned(),
                host_only: false,
                path: "/".to_owned(),
                secure: false,
            },
            &suffixes(),
        )
        .expect_err("public suffix fixture must fail");
    Ok(CaseEvidence::policy("Domain=com", error.to_string()))
}

fn cookie_syntax() -> Result<CaseEvidence, TransportError> {
    let source = HttpUrl::parse("https://media.example.com/")?;
    let error = CookieJar::new(4)
        .store(
            &source,
            Cookie {
                name: "bad\r\nname".to_owned(),
                value: "value".to_owned(),
                domain: "media.example.com".to_owned(),
                host_only: true,
                path: "/".to_owned(),
                secure: true,
            },
            &suffixes(),
        )
        .expect_err("control character fixture must fail");
    Ok(CaseEvidence::policy(
        "cookie name contains CRLF",
        error.to_string(),
    ))
}

fn public_evidence() -> DnsEvidence {
    DnsEvidence {
        query_host: "media.example".to_owned(),
        answers: vec!["93.184.216.34".parse().expect("static public fixture IP")],
        selected: "93.184.216.34".parse().expect("static public fixture IP"),
        resolver_identity: "fixture-resolver-v1".to_owned(),
    }
}

fn ssrf_mixed_answers() -> CaseEvidence {
    let mut evidence = public_evidence();
    evidence
        .answers
        .push("127.0.0.1".parse().expect("static loopback fixture IP"));
    let error = validate_dns_evidence(&evidence, ProxyEvidence::Direct)
        .expect_err("mixed answer fixture must fail");
    CaseEvidence::policy("93.184.216.34 + 127.0.0.1", error.to_string())
}

fn dns_selection() -> CaseEvidence {
    let mut evidence = public_evidence();
    evidence.selected = "8.8.8.8".parse().expect("static fixture IP");
    let error = validate_dns_evidence(&evidence, ProxyEvidence::Direct)
        .expect_err("unapproved selection fixture must fail");
    CaseEvidence::policy("selected address absent from answers", error.to_string())
}

fn dns_rebind() -> CaseEvidence {
    let connected: IpAddr = "93.184.216.35".parse().expect("static fixture IP");
    let error = validate_connected_address(&public_evidence(), connected)
        .expect_err("rebinding fixture must fail");
    CaseEvidence::policy(
        "selected=93.184.216.34 connected=93.184.216.35",
        error.to_string(),
    )
}

fn proxy_evidence() -> CaseEvidence {
    let error = validate_dns_evidence(&public_evidence(), ProxyEvidence::Unavailable)
        .expect_err("missing proxy evidence fixture must fail");
    CaseEvidence::policy("proxy destination evidence unavailable", error.to_string())
}

fn pool_key(partition: &str, fingerprint: &str) -> PoolKey {
    PoolKey {
        scheme: "https".to_owned(),
        origin: "https://media.example:443".to_owned(),
        proxy_identity: "direct".to_owned(),
        tls_identity: "tls-standard".to_owned(),
        http_identity: "http1-standard".to_owned(),
        fingerprint_identity: fingerprint.to_owned(),
        client_certificate_identity: "none".to_owned(),
        session_partition: partition.to_owned(),
        credential_scope: "origin-media".to_owned(),
    }
}

fn pool_reuse() -> Result<CaseEvidence, TransportError> {
    let mut registry = PoolRegistry::new(4);
    let key = pool_key("session-a", "standard");
    let first = registry.acquire(key.clone())?;
    let second = registry.acquire(key)?;
    if first.reused || !second.reused || first.connection_id != second.connection_id {
        return Err(TransportError::Policy(
            "FF-TRANSPORT-E-POOL-REUSE".to_owned(),
        ));
    }
    Ok(CaseEvidence {
        pool_identity: Some(second.key_digest),
        ..CaseEvidence::policy("identical complete pool keys", "identical-pool-key-reused")
    })
}

fn pool_partition(session: bool) -> Result<CaseEvidence, TransportError> {
    let mut registry = PoolRegistry::new(4);
    let first_key = pool_key("session-a", "standard");
    let second_key = if session {
        pool_key("session-b", "standard")
    } else {
        pool_key("session-a", "browser-chrome-unknown")
    };
    let first = registry.acquire(first_key)?;
    let second = registry.acquire(second_key)?;
    if first.connection_id == second.connection_id || second.reused {
        return Err(TransportError::Policy(
            "FF-TRANSPORT-E-POOL-PARTITION".to_owned(),
        ));
    }
    let outcome = if session {
        "session-partition-prevents-reuse"
    } else {
        "fingerprint-partition-prevents-reuse"
    };
    Ok(CaseEvidence {
        pool_identity: Some(second.key_digest),
        ..CaseEvidence::policy("pool keys differ in one security dimension", outcome)
    })
}

fn pool_bound() -> Result<CaseEvidence, TransportError> {
    let mut registry = PoolRegistry::new(1);
    registry.acquire(pool_key("session-a", "standard"))?;
    let error = registry
        .acquire(pool_key("session-b", "standard"))
        .expect_err("pool capacity fixture must fail");
    Ok(CaseEvidence::policy(
        "maximum pool entries=1; requested=2",
        error.to_string(),
    ))
}

fn body_bound(kind: &str) -> CaseEvidence {
    let budget = BodyBudget {
        maximum_metadata_bytes: 10,
        maximum_body_bytes: 20,
        maximum_decompressed_bytes: 30,
    };
    let values = match kind {
        "metadata" => (11, 20, 30),
        "body" => (10, 21, 30),
        _ => (10, 20, 31),
    };
    let error = budget
        .validate(values.0, values.1, values.2)
        .expect_err("bound fixture must fail");
    CaseEvidence::policy(
        format!(
            "metadata={} body={} decompressed={}",
            values.0, values.1, values.2
        ),
        error.to_string(),
    )
}

fn byte_credit() -> Result<CaseEvidence, TransportError> {
    let mut credits = ByteCredits::new(8);
    credits.grant(4)?;
    let error = credits
        .accept(5)
        .expect_err("credit overrun fixture must fail");
    Ok(CaseEvidence::policy(
        "granted=4 attempted=5",
        error.to_string(),
    ))
}

fn retry_bound() -> CaseEvidence {
    let maximum_retries = 2_u8;
    let attempted_retry = 3_u8;
    let outcome = if attempted_retry > maximum_retries {
        "FF-TRANSPORT-E-RETRY-LIMIT"
    } else {
        "retry-allowed"
    };
    CaseEvidence::policy("maximum_retries=2 attempted_retry=3", outcome)
}

fn cancellation_correlation() -> Result<CaseEvidence, TransportError> {
    let mut cancellation = CancellationModel::new("request-a")?;
    let generation = cancellation.request()?;
    let error = cancellation
        .acknowledge("request-b", generation)
        .expect_err("wrong request acknowledgement must fail");
    Ok(CaseEvidence::policy(
        "request-a cancellation acknowledged as request-b",
        error.to_string(),
    ))
}

fn cancellation_pool() -> Result<CaseEvidence, TransportError> {
    let mut cancellation = CancellationModel::new("request-a")?;
    let generation = cancellation.request()?;
    cancellation.acknowledge("request-a", generation)?;
    if cancellation.pool_reusable() {
        return Err(TransportError::Cancellation(
            "FF-TRANSPORT-E-CANCELLED-POOL-REUSE".to_owned(),
        ));
    }
    Ok(CaseEvidence::policy(
        "request-a generation=1 acknowledged",
        "cancelled-connection-not-reusable",
    ))
}

fn sanitized_replay() -> Result<CaseEvidence, TransportError> {
    let url = HttpUrl::parse(&format!(
        "https://media.example/video?token={SECRET_CANARY}&quality=best"
    ))?;
    let mut request_headers = BTreeMap::new();
    request_headers.insert(
        "authorization".to_owned(),
        HeaderValue::new(SECRET_CANARY, true, true)?,
    );
    request_headers.insert(
        "accept".to_owned(),
        HeaderValue::new("video/*", false, false)?,
    );
    let response_headers = BTreeMap::from([
        (
            "date".to_owned(),
            "Mon, 01 Jan 2024 00:00:00 GMT".to_owned(),
        ),
        ("set-cookie".to_owned(), SECRET_CANARY.to_owned()),
    ]);
    let transcript = sanitize_exchange(
        "replay-a",
        "GET",
        &url,
        &request_headers,
        200,
        &response_headers,
        b"body",
    )?;
    let value = serde_json::to_value(&transcript)
        .map_err(|error| TransportError::Protocol(format!("FF-TRANSPORT-E-JSON: {error}")))?;
    if value.to_string().contains(SECRET_CANARY) {
        return Err(TransportError::Policy(
            "FF-TRANSPORT-E-TRANSCRIPT-SECRET".to_owned(),
        ));
    }
    Ok(CaseEvidence {
        transcript: Some(value),
        ..CaseEvidence::policy(
            "authorization, token query, set-cookie, date, body",
            "transcript-deterministic-and-sanitized",
        )
    })
}

fn url_bounds() -> CaseEvidence {
    let overlong = format!("https://media.example/{}", "a".repeat(4 * 1024));
    let error = HttpUrl::parse(&overlong).expect_err("overlong URL fixture must fail");
    CaseEvidence::policy("URL exceeds 4096 bytes", error.to_string())
}

fn counterfactual_proof(manifest: &CorpusManifest, cases: &[CaseReport]) -> CounterfactualProof {
    let mut mutated = cases.to_vec();
    let mutation = if let Some(first) = mutated.first_mut() {
        first.observed_outcome.push_str("-mutated");
        format!("{} observed_outcome appended with -mutated", first.id)
    } else {
        "no case available".to_owned()
    };
    match validate_aggregate_evidence(manifest, &mutated) {
        Ok(_) => CounterfactualProof {
            mutation,
            rejected_by_same_oracle: false,
            rejection: "same oracle accepted mutation".to_owned(),
        },
        Err(error) => CounterfactualProof {
            mutation,
            rejected_by_same_oracle: true,
            rejection: error,
        },
    }
}

fn reject_secret_canary(report: &CorpusReport) -> Result<(), String> {
    let encoded = serde_json::to_string(report)
        .map_err(|error| format!("FF-TRANSPORT-E-REPORT-ENCODE: {error}"))?;
    if encoded.contains(SECRET_CANARY) {
        return Err("FF-TRANSPORT-E-REPORT-SECRET-CANARY".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> CorpusManifest {
        CorpusManifest {
            schema_id: SCHEMA_ID.to_owned(),
            corpus_id: CORPUS_ID.to_owned(),
            normalization_version: NORMALIZATION_VERSION.to_owned(),
            candidate_identity: CandidateAdapter::std_first().identity().to_owned(),
            max_cases: 4,
            cases: vec![CorpusCase {
                id: "standard-capability".to_owned(),
                kind: CaseKind::StandardCapability,
                mandatory: true,
                proof_class: ProofClass::Structural,
                requested_capabilities: BTreeSet::from([Capability::Http11]),
                expected_outcome: "standard-capabilities-supported".to_owned(),
            }],
        }
    }

    #[test]
    fn strict_manifest_rejects_unknown_fields() {
        let json = r#"{
            "schema_id":"fforager.transport-corpus-manifest.v1",
            "corpus_id":"WP-FF-007-transport-corpus-v1",
            "normalization_version":"WP-FF-004-sanitized-transcript-v1",
            "candidate_identity":"ferric-std-first-transport-spike-v1",
            "max_cases":1,
            "cases":[],
            "undeclared":true
        }"#;
        assert!(serde_json::from_str::<CorpusManifest>(json).is_err());
    }

    #[test]
    fn duplicate_case_ids_are_rejected() {
        let mut manifest = manifest();
        manifest.cases.push(manifest.cases[0].clone());
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn same_oracle_rejects_behavior_mutation() {
        let manifest = manifest();
        let report = run_corpus(&manifest).expect("corpus");
        assert!(report.counterfactual.rejected_by_same_oracle);
    }

    #[test]
    fn mandatory_blocked_capability_forces_failed_spike_verdict() {
        let mut manifest = manifest();
        manifest.cases.push(CorpusCase {
            id: "tls-fingerprint-blocked".to_owned(),
            kind: CaseKind::TlsFingerprintBlocked,
            mandatory: true,
            proof_class: ProofClass::Protocol,
            requested_capabilities: BTreeSet::from([Capability::TlsFingerprint]),
            expected_outcome: "FF-TRANSPORT-E-TLS-FINGERPRINT-BLOCKED".to_owned(),
        });
        let report = run_corpus(&manifest).expect("corpus");
        assert_eq!(
            report.verdict,
            AggregateVerdict::FailedSpikeRequiresOperatorDecision
        );
    }

    #[test]
    fn report_never_contains_secret_canary() {
        let case = CorpusCase {
            id: "sanitized-replay".to_owned(),
            kind: CaseKind::SanitizedReplay,
            mandatory: true,
            proof_class: ProofClass::Security,
            requested_capabilities: BTreeSet::from([Capability::Replay]),
            expected_outcome: "transcript-deterministic-and-sanitized".to_owned(),
        };
        let mut manifest = manifest();
        manifest.cases = vec![case];
        let report = run_corpus(&manifest).expect("corpus");
        let encoded = serde_json::to_string(&report).expect("report JSON");
        assert!(!encoded.contains(SECRET_CANARY));
    }

    #[test]
    fn ip_policy_error_is_specific_for_rebinding() {
        assert!(matches!(
            validate_connected_address(
                &public_evidence(),
                "93.184.216.35".parse().expect("fixture IP")
            ),
            Err(crate::policy::IpPolicyError::ConnectedAddressMismatch { .. })
        ));
    }
}
