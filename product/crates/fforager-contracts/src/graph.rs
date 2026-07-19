//! Canonical source graph, provenance, acquisition, and output sink descriptors.

use crate::{
    AssetId, ContinuationId, DerivedOutputId, EdgeId, ExtensionLimits, ExtensionMap, ItemId,
    NodeId, RepresentationId, SchemaVersion, TrackId, TriState,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Limits applied before a graph enters the domain core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphLimits {
    pub maximum_roots: usize,
    pub maximum_nodes: usize,
    pub maximum_edges: usize,
    pub maximum_continuations: usize,
    pub maximum_string_bytes: usize,
    pub maximum_redirect_depth: usize,
    pub extensions: ExtensionLimits,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            maximum_roots: 64,
            maximum_nodes: 10_000,
            maximum_edges: 40_000,
            maximum_continuations: 1_000,
            maximum_string_bytes: 16 * 1024,
            maximum_redirect_depth: 16,
            extensions: ExtensionLimits::default(),
        }
    }
}

/// Canonical, versioned, serializable source graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceGraph {
    pub schema: SchemaVersion,
    pub roots: Vec<NodeId>,
    pub nodes: Vec<SourceNode>,
    pub edges: Vec<SourceEdge>,
    pub continuations: Vec<ContinuationDescriptor>,
}

/// Source-node kind kept stable on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Media,
    Collection,
    Live,
    Redirect,
    MetadataRecord,
    UnsupportedOrProtected,
}

/// Explicit relationship between graph nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Contains,
    Embeds,
    TransparentlyOverlays,
    Alternate,
    Complementary,
    Additional,
    Continuation,
    DerivedOutput,
}

/// Stable identities associated with one node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityIdentities {
    pub item: Option<ItemId>,
    pub representations: Vec<RepresentationId>,
    pub tracks: Vec<TrackId>,
    pub assets: Vec<AssetId>,
    pub derived_outputs: Vec<DerivedOutputId>,
}

/// Origin information preserved across redirects and derivations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub extractor_key: String,
    pub source_identity: String,
    pub canonical_url: String,
    pub parent_node: Option<NodeId>,
}

/// Serializable graph node with no cursor or runtime body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub identities: EntityIdentities,
    pub provenance: Provenance,
    pub title: TriState<String>,
    pub description: TriState<String>,
    pub extensions: ExtensionMap,
}

/// Stable directed edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEdge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

/// Lazy traversal descriptor; runtime cursor state is intentionally absent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationDescriptor {
    pub id: ContinuationId,
    pub owner: NodeId,
    pub opaque_token: String,
    pub extensions: ExtensionMap,
}

/// Precise graph-validation failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphError {
    LimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    DuplicateId {
        kind: &'static str,
        id: String,
    },
    DanglingRoot {
        id: NodeId,
    },
    DanglingEdge {
        edge: EdgeId,
        node: NodeId,
    },
    DanglingContinuation {
        id: ContinuationId,
        node: NodeId,
    },
    DuplicateEntityId {
        kind: &'static str,
        id: String,
    },
    StringTooLong {
        field: &'static str,
        node: NodeId,
        actual: usize,
        maximum: usize,
    },
    InvalidExtensions {
        owner: String,
    },
    RedirectCycle {
        node: NodeId,
    },
    RedirectBudgetExceeded {
        node: NodeId,
        maximum: usize,
    },
    AmbiguousCanonicalSource {
        canonical_url: String,
        source_identity: String,
    },
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid source graph: {self:?}")
    }
}
impl std::error::Error for GraphError {}

impl SourceGraph {
    /// Validates all collection, relationship, identity, string, extension, and redirect bounds.
    ///
    /// # Errors
    ///
    /// Returns [`GraphError`] for a duplicate, dangling relationship, ambiguous
    /// canonical source, cycle, or exceeded configured bound.
    pub fn validate(&self, limits: GraphLimits) -> Result<(), GraphError> {
        check_limit("roots", self.roots.len(), limits.maximum_roots)?;
        check_limit("nodes", self.nodes.len(), limits.maximum_nodes)?;
        check_limit("edges", self.edges.len(), limits.maximum_edges)?;
        check_limit(
            "continuations",
            self.continuations.len(),
            limits.maximum_continuations,
        )?;
        let mut nodes = BTreeMap::new();
        let mut entity_ids = BTreeSet::new();
        let mut canonical = BTreeSet::new();
        for node in &self.nodes {
            if nodes.insert(node.id.clone(), node).is_some() {
                return Err(GraphError::DuplicateId {
                    kind: "node",
                    id: node.id.to_string(),
                });
            }
            validate_node(node, limits, &mut entity_ids)?;
            let key = (
                node.provenance.canonical_url.clone(),
                node.provenance.source_identity.clone(),
            );
            if !canonical.insert(key.clone()) {
                return Err(GraphError::AmbiguousCanonicalSource {
                    canonical_url: key.0,
                    source_identity: key.1,
                });
            }
        }
        for root in &self.roots {
            if !nodes.contains_key(root) {
                return Err(GraphError::DanglingRoot { id: root.clone() });
            }
        }
        let mut edge_ids = BTreeSet::new();
        for edge in &self.edges {
            if !edge_ids.insert(edge.id.clone()) {
                return Err(GraphError::DuplicateId {
                    kind: "edge",
                    id: edge.id.to_string(),
                });
            }
            if !nodes.contains_key(&edge.from) {
                return Err(GraphError::DanglingEdge {
                    edge: edge.id.clone(),
                    node: edge.from.clone(),
                });
            }
            if !nodes.contains_key(&edge.to) {
                return Err(GraphError::DanglingEdge {
                    edge: edge.id.clone(),
                    node: edge.to.clone(),
                });
            }
        }
        let mut continuation_ids = BTreeSet::new();
        for continuation in &self.continuations {
            if !continuation_ids.insert(continuation.id.clone()) {
                return Err(GraphError::DuplicateId {
                    kind: "continuation",
                    id: continuation.id.to_string(),
                });
            }
            if !nodes.contains_key(&continuation.owner) {
                return Err(GraphError::DanglingContinuation {
                    id: continuation.id.clone(),
                    node: continuation.owner.clone(),
                });
            }
            if continuation.opaque_token.len() > limits.maximum_string_bytes {
                return Err(GraphError::LimitExceeded {
                    field: "continuation_token",
                    actual: continuation.opaque_token.len(),
                    maximum: limits.maximum_string_bytes,
                });
            }
            continuation
                .extensions
                .validate(limits.extensions)
                .map_err(|_| GraphError::InvalidExtensions {
                    owner: continuation.id.to_string(),
                })?;
        }
        validate_redirects(self, &nodes, limits.maximum_redirect_depth)
    }
}

fn check_limit(field: &'static str, actual: usize, maximum: usize) -> Result<(), GraphError> {
    if actual > maximum {
        Err(GraphError::LimitExceeded {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn validate_node(
    node: &SourceNode,
    limits: GraphLimits,
    entity_ids: &mut BTreeSet<String>,
) -> Result<(), GraphError> {
    for (field, value) in [
        ("extractor_key", &node.provenance.extractor_key),
        ("source_identity", &node.provenance.source_identity),
        ("canonical_url", &node.provenance.canonical_url),
    ] {
        if value.len() > limits.maximum_string_bytes {
            return Err(GraphError::StringTooLong {
                field,
                node: node.id.clone(),
                actual: value.len(),
                maximum: limits.maximum_string_bytes,
            });
        }
    }
    for (kind, values) in [
        (
            "item",
            node.identities
                .item
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ),
        (
            "representation",
            node.identities
                .representations
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        (
            "track",
            node.identities
                .tracks
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        (
            "asset",
            node.identities
                .assets
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        (
            "derived_output",
            node.identities
                .derived_outputs
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
    ] {
        for value in values {
            if !entity_ids.insert(value.clone()) {
                return Err(GraphError::DuplicateEntityId { kind, id: value });
            }
        }
    }
    for (field, value) in [("title", &node.title), ("description", &node.description)] {
        if let TriState::Present(value) = value
            && value.len() > limits.maximum_string_bytes
        {
            return Err(GraphError::StringTooLong {
                field,
                node: node.id.clone(),
                actual: value.len(),
                maximum: limits.maximum_string_bytes,
            });
        }
    }
    node.extensions
        .validate(limits.extensions)
        .map_err(|_| GraphError::InvalidExtensions {
            owner: node.id.to_string(),
        })
}

fn validate_redirects(
    graph: &SourceGraph,
    nodes: &BTreeMap<NodeId, &SourceNode>,
    maximum: usize,
) -> Result<(), GraphError> {
    let redirects: BTreeMap<&NodeId, &NodeId> = graph
        .edges
        .iter()
        .filter(|edge| edge.kind == EdgeKind::TransparentlyOverlays)
        .map(|edge| (&edge.from, &edge.to))
        .collect();
    for node in nodes
        .values()
        .filter(|node| node.kind == NodeKind::Redirect)
    {
        let mut seen = BTreeSet::new();
        let mut current = &node.id;
        for depth in 0..=maximum {
            if !seen.insert(current.clone()) {
                return Err(GraphError::RedirectCycle {
                    node: current.clone(),
                });
            }
            let Some(next) = redirects.get(current) else {
                break;
            };
            if depth == maximum {
                return Err(GraphError::RedirectBudgetExceeded {
                    node: node.id.clone(),
                    maximum,
                });
            }
            current = next;
        }
    }
    Ok(())
}

/// Serializable acquisition source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AcquisitionSource {
    DirectUrl {
        url: String,
    },
    Manifest {
        url: String,
        manifest_identity: String,
    },
    Fragments {
        manifest_identity: String,
        fragments: Vec<FragmentDescriptor>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentDescriptor {
    pub sequence: u64,
    pub url: String,
    pub expected_bytes: Option<u64>,
    pub checksum: Option<String>,
}

/// Data-only destination descriptor. Paths and addresses are strings and require adapter validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputSinkSpec {
    AtomicFile {
        rooted_path: String,
    },
    Stdout,
    NamedPipe {
        rooted_path: String,
    },
    LocalHttp {
        bind: String,
        secret_reference: Option<String>,
    },
    Player {
        executable_reference: String,
        transport: PlayerTransport,
    },
    HostCallback {
        endpoint_id: String,
    },
    Null,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlayerTransport {
    Stdin,
    NamedPipe,
    LocalHttp,
    UrlPassthrough,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkSemantics {
    pub backpressure: BackpressureMode,
    pub seekable: bool,
    pub atomic: bool,
    pub postprocessing_requires_seekable_temporary: bool,
    pub expected_lifetime_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureMode {
    BlockProducer,
    BoundedBuffer,
    DropDeclaredTelemetryOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> Result<SourceNode, crate::IdError> {
        Ok(SourceNode {
            id: NodeId::new(format!("node_{name}"))?,
            kind: NodeKind::Media,
            identities: EntityIdentities::default(),
            provenance: Provenance {
                extractor_key: "fixture".into(),
                source_identity: name.into(),
                canonical_url: format!("https://example.test/{name}"),
                parent_node: None,
            },
            title: TriState::Unknown,
            description: TriState::NotApplicable,
            extensions: ExtensionMap::default(),
        })
    }

    #[test]
    fn rejects_dangling_root() -> Result<(), crate::IdError> {
        let graph = SourceGraph {
            schema: SchemaVersion { major: 1, minor: 0 },
            roots: vec![NodeId::new("node_missing")?],
            nodes: vec![],
            edges: vec![],
            continuations: vec![],
        };
        assert!(matches!(
            graph.validate(GraphLimits::default()),
            Err(GraphError::DanglingRoot { .. })
        ));
        Ok(())
    }

    #[test]
    fn round_trip_preserves_tri_state() -> Result<(), crate::IdError> {
        let source = node("one")?;
        let encoded = serde_json::to_vec(&source);
        assert!(encoded.is_ok());
        let decoded = encoded
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SourceNode>(&bytes).ok());
        assert_eq!(decoded, Some(source));
        Ok(())
    }
}
