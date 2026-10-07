//! The published specifications this alternative is assembled from, and the
//! field of each that it uses.
//!
//! The request a receiver sees here is not a shape this project invented. It is
//! an agent-to-agent message carrying a tool call, presented by a workload
//! whose identity is an SVID, accompanied by a credential a token exchange
//! issued. Each of those is a shipped format with a published document, and the
//! inventories below name the exact field and section every value on the wire
//! comes from.
//!
//! Two of those inventories are enforced rather than decorative. The request
//! inventory is checked against the bytes an admissible call actually
//! serializes to, so a field with no published definition cannot be added to
//! the request without the check naming it; the free-form inventory is the
//! closed list of places those documents leave open for values they do not
//! define, each recorded with the party whose signature covers it.

/// One published document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Document {
    /// Short identifier used by the field inventories.
    pub id: &'static str,
    pub name: &'static str,
    /// Revision, version or RFC number, as the document itself states it.
    pub version: &'static str,
    pub url: &'static str,
}

pub const MCP: Document = Document {
    id: "mcp",
    name: "Model Context Protocol",
    version: "2026-07-28",
    url: "https://modelcontextprotocol.io/specification/2026-07-28",
};

pub const A2A: Document = Document {
    id: "a2a",
    name: "Agent2Agent Protocol",
    version: "v1 (specification/a2a.proto, package lf.a2a.v1)",
    url: "https://a2a-protocol.org/latest/specification/",
};

pub const TOKEN_EXCHANGE: Document = Document {
    id: "rfc8693",
    name: "OAuth 2.0 Token Exchange",
    version: "RFC 8693",
    url: "https://www.rfc-editor.org/rfc/rfc8693",
};

pub const JWT: Document = Document {
    id: "rfc7519",
    name: "JSON Web Token",
    version: "RFC 7519",
    url: "https://www.rfc-editor.org/rfc/rfc7519",
};

pub const JWS: Document = Document {
    id: "rfc7515",
    name: "JSON Web Signature",
    version: "RFC 7515",
    url: "https://www.rfc-editor.org/rfc/rfc7515",
};

pub const OAUTH2: Document = Document {
    id: "rfc6749",
    name: "The OAuth 2.0 Authorization Framework",
    version: "RFC 6749",
    url: "https://www.rfc-editor.org/rfc/rfc6749",
};

pub const SPIFFE_ID: Document = Document {
    id: "spiffe-id",
    name: "SPIFFE Identity and Verifiable Identity Document",
    version: "SPIFFE-ID standard",
    url: "https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md",
};

pub const X509_SVID: Document = Document {
    id: "x509-svid",
    name: "X.509 SPIFFE Verifiable Identity Document",
    version: "X509-SVID standard",
    url: "https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md",
};

pub const JWT_SVID: Document = Document {
    id: "jwt-svid",
    name: "JWT SPIFFE Verifiable Identity Document",
    version: "JWT-SVID standard",
    url: "https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md",
};

/// Every document the alternative is built from, in the order the request is
/// assembled: the transport identity, the message, the tool call, the
/// credential.
pub const DOCUMENTS: &[Document] = &[
    SPIFFE_ID,
    X509_SVID,
    JWT_SVID,
    A2A,
    MCP,
    TOKEN_EXCHANGE,
    JWT,
    JWS,
    OAUTH2,
];

/// One field on the wire and the document that defines it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireField {
    /// Path in the serialized value, with `[]` standing for an array element.
    pub path: &'static str,
    pub document: &'static str,
    /// Section, message or claim name within that document.
    pub section: &'static str,
    /// Whether a call may leave it out. The message encoding omits a field at
    /// its default value, so an optional field is absent from a call that has
    /// nothing to put in it.
    pub optional: bool,
}

/// The request body: an A2A `SendMessageRequest` whose single data part carries
/// an MCP `tools/call` request.
pub const REQUEST_FIELDS: &[WireField] = &[
    WireField {
        path: "tenant",
        document: "a2a",
        section: "SendMessageRequest.tenant",
        optional: true,
    },
    WireField {
        path: "message",
        document: "a2a",
        section: "SendMessageRequest.message",
        optional: false,
    },
    WireField {
        path: "message.messageId",
        document: "a2a",
        section: "Message.message_id",
        optional: false,
    },
    WireField {
        path: "message.contextId",
        document: "a2a",
        section: "Message.context_id",
        optional: false,
    },
    WireField {
        path: "message.taskId",
        document: "a2a",
        section: "Message.task_id",
        optional: false,
    },
    WireField {
        path: "message.role",
        document: "a2a",
        section: "Message.role",
        optional: false,
    },
    WireField {
        path: "message.parts",
        document: "a2a",
        section: "Message.parts",
        optional: false,
    },
    WireField {
        path: "message.parts[].data",
        document: "a2a",
        section: "Part.data",
        optional: false,
    },
    WireField {
        path: "message.parts[].mediaType",
        document: "a2a",
        section: "Part.media_type",
        optional: false,
    },
    WireField {
        path: "message.parts[].metadata",
        document: "a2a",
        section: "Part.metadata",
        optional: true,
    },
    WireField {
        path: "message.metadata",
        document: "a2a",
        section: "Message.metadata",
        optional: true,
    },
    WireField {
        path: "message.extensions",
        document: "a2a",
        section: "Message.extensions",
        optional: true,
    },
    WireField {
        path: "message.referenceTaskIds",
        document: "a2a",
        section: "Message.reference_task_ids",
        optional: false,
    },
    WireField {
        path: "configuration",
        document: "a2a",
        section: "SendMessageRequest.configuration",
        optional: false,
    },
    WireField {
        path: "configuration.acceptedOutputModes",
        document: "a2a",
        section: "SendMessageConfiguration.accepted_output_modes",
        optional: false,
    },
    WireField {
        path: "configuration.returnImmediately",
        document: "a2a",
        section: "SendMessageConfiguration.return_immediately",
        optional: false,
    },
    WireField {
        path: "metadata",
        document: "a2a",
        section: "SendMessageRequest.metadata",
        optional: true,
    },
    WireField {
        path: "message.parts[].data.jsonrpc",
        document: "mcp",
        section: "basic, Requests",
        optional: false,
    },
    WireField {
        path: "message.parts[].data.id",
        document: "mcp",
        section: "basic, Requests",
        optional: false,
    },
    WireField {
        path: "message.parts[].data.method",
        document: "mcp",
        section: "basic, Requests",
        optional: false,
    },
    WireField {
        path: "message.parts[].data.params",
        document: "mcp",
        section: "basic, Requests",
        optional: false,
    },
    WireField {
        path: "message.parts[].data.params.name",
        document: "mcp",
        section: "server/tools, Calling Tools",
        optional: false,
    },
    WireField {
        path: "message.parts[].data.params.arguments",
        document: "mcp",
        section: "server/tools, Calling Tools",
        optional: false,
    },
    WireField {
        path: "message.parts[].data.params._meta",
        document: "mcp",
        section: "basic, General fields, _meta",
        optional: false,
    },
];

/// The credential, as the token endpoint returns it. The receiver sees the
/// `access_token` member on the request; the rest of the response is what the
/// caller's own exchange produced and is carried so the fixture states which
/// token type was issued.
pub const CREDENTIAL_FIELDS: &[WireField] = &[
    WireField {
        path: "access_token",
        document: "rfc8693",
        section: "2.2.1",
        optional: false,
    },
    WireField {
        path: "issued_token_type",
        document: "rfc8693",
        section: "2.2.1, 3",
        optional: false,
    },
    WireField {
        path: "token_type",
        document: "rfc8693",
        section: "2.2.1",
        optional: false,
    },
    WireField {
        path: "expires_in",
        document: "rfc8693",
        section: "2.2.1",
        optional: false,
    },
    WireField {
        path: "scope",
        document: "rfc8693",
        section: "2.2.1",
        optional: false,
    },
];

/// The claim set inside the issued token. RFC 8693 section 4 defines `act`,
/// `scope` and `client_id` and states that the rest are the registered claims
/// of RFC 7519.
pub const CLAIM_FIELDS: &[WireField] = &[
    WireField {
        path: "iss",
        document: "rfc7519",
        section: "4.1.1",
        optional: false,
    },
    WireField {
        path: "sub",
        document: "rfc7519",
        section: "4.1.2",
        optional: false,
    },
    WireField {
        path: "aud",
        document: "rfc7519",
        section: "4.1.3",
        optional: false,
    },
    WireField {
        path: "exp",
        document: "rfc7519",
        section: "4.1.4",
        optional: false,
    },
    WireField {
        path: "nbf",
        document: "rfc7519",
        section: "4.1.5",
        optional: false,
    },
    WireField {
        path: "iat",
        document: "rfc7519",
        section: "4.1.6",
        optional: false,
    },
    WireField {
        path: "jti",
        document: "rfc7519",
        section: "4.1.7",
        optional: false,
    },
    WireField {
        path: "scope",
        document: "rfc8693",
        section: "4.2",
        optional: false,
    },
    WireField {
        path: "client_id",
        document: "rfc8693",
        section: "4.3",
        optional: false,
    },
    WireField {
        path: "act",
        document: "rfc8693",
        section: "4.1",
        optional: false,
    },
    WireField {
        path: "act.sub",
        document: "rfc8693",
        section: "4.1",
        optional: false,
    },
    WireField {
        path: "act.iss",
        document: "rfc8693",
        section: "4.1",
        optional: false,
    },
];

/// The JOSE header of the issued token.
pub const HEADER_FIELDS: &[WireField] = &[
    WireField {
        path: "alg",
        document: "rfc7515",
        section: "4.1.1",
        optional: false,
    },
    WireField {
        path: "typ",
        document: "rfc7515",
        section: "4.1.9",
        optional: false,
    },
    WireField {
        path: "kid",
        document: "rfc7515",
        section: "4.1.4",
        optional: false,
    },
];

/// Who a value in a given slot is attested by: which key's signature covers the
/// bytes it sits in. This is the distinction the whole comparison turns on, so
/// it is recorded per slot rather than left to prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedBy {
    /// Covered only by the channel: the bytes reached the receiver from the
    /// holder of the pinned X509-SVID key, which is the caller itself.
    Caller,
    /// Inside the issued token, so covered by the signature of the
    /// authorization server that performed the exchange.
    IssuingAuthorizationServer,
}

impl AttestedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            AttestedBy::Caller => "caller",
            AttestedBy::IssuingAuthorizationServer => "issuing_authorization_server",
        }
    }
}

/// A place one of the documents leaves open for values it does not itself
/// define. Anything an operator adds to this composition goes in one of these,
/// so the list is the complete set of routes an invented fact can take.
#[derive(Debug, Clone, Copy)]
pub struct FreeFormSlot {
    pub path: &'static str,
    pub document: &'static str,
    pub section: &'static str,
    pub attested_by: AttestedBy,
    pub note: &'static str,
}

pub const FREE_FORM_SLOTS: &[FreeFormSlot] = &[
    FreeFormSlot {
        path: "metadata",
        document: "a2a",
        section: "SendMessageRequest.metadata",
        attested_by: AttestedBy::Caller,
        note: "A flexible key-value map for passing additional context or parameters.",
    },
    FreeFormSlot {
        path: "message.metadata",
        document: "a2a",
        section: "Message.metadata",
        attested_by: AttestedBy::Caller,
        note: "Any metadata to provide along with the message.",
    },
    FreeFormSlot {
        path: "message.parts[].metadata",
        document: "a2a",
        section: "Part.metadata",
        attested_by: AttestedBy::Caller,
        note: "Metadata associated with this part.",
    },
    FreeFormSlot {
        path: "message.parts[].data.params.arguments",
        document: "mcp",
        section: "server/tools, Tool.inputSchema",
        attested_by: AttestedBy::Caller,
        note: "The tool's own inputs, shaped by a schema the receiver publishes. The one open slot whose shape the receiver owns.",
    },
    FreeFormSlot {
        path: "message.parts[].data.params._meta",
        document: "mcp",
        section: "basic, General fields, _meta",
        attested_by: AttestedBy::Caller,
        note: "Reserved for metadata. Keys whose second label is modelcontextprotocol or mcp belong to MCP; anything else takes a vendor prefix.",
    },
    FreeFormSlot {
        path: "scope",
        document: "rfc6749",
        section: "3.3",
        attested_by: AttestedBy::IssuingAuthorizationServer,
        note: "Space-delimited case-sensitive strings whose values are defined by the authorization server. The only open slot a signature covers.",
    },
];

/// The `_meta` keys this revision of MCP reserves for itself. A request that
/// carries one of these is carrying a protocol field, not an operator's.
pub const MCP_RESERVED_META_KEYS: &[&str] = &[
    "progressToken",
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientInfo",
    "io.modelcontextprotocol/clientCapabilities",
    "io.modelcontextprotocol/logLevel",
    "io.modelcontextprotocol/subscriptionId",
    "traceparent",
    "tracestate",
    "baggage",
];

/// Whether a `_meta` key name is one MCP reserves for itself. The rule is the
/// one the specification states: a prefix whose second label is
/// `modelcontextprotocol` or `mcp` belongs to MCP.
pub fn is_mcp_reserved_meta_key(key: &str) -> bool {
    if MCP_RESERVED_META_KEYS.contains(&key) {
        return true;
    }
    let Some((prefix, _)) = key.split_once('/') else {
        return false;
    };
    let mut labels = prefix.split('.');
    let _first = labels.next();
    matches!(labels.next(), Some("modelcontextprotocol" | "mcp"))
}

pub fn document(id: &str) -> Option<&'static Document> {
    DOCUMENTS.iter().find(|document| document.id == id)
}
