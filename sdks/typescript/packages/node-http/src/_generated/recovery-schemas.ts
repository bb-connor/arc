// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.
//
// Source:     spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:       json-schema-to-typescript 15.0.4 (see xtask/codegen-tools.lock.toml)
// Pin file:   sdks/typescript/scripts/package.json
// Schema SHA: 642998d053bca84cf2974fe55bb302db51cb903e9eeddf221102f41b63988f91
//
// The schema-sha above is sha256 of `<rel-path>\0<bytes>\0` for every
// schema in lex order. It changes whenever any schema under
// spec/schemas/chio-wire/v1/ changes. The spec-drift CI lane
// asserts byte-equality of this entire file via `--check` mode.

/* eslint-disable */

export const recoveryWireSchemas: readonly object[] = [
  {
    "$defs": {
      "actorRef": {
        "additionalProperties": false,
        "properties": {
          "actor_id": {
            "minLength": 1,
            "type": "string"
          },
          "actor_kind": {
            "minLength": 1,
            "type": "string"
          }
        },
        "required": [
          "actor_id"
        ],
        "type": "object"
      },
      "bbsReceiptSignature": {
        "additionalProperties": false,
        "properties": {
          "algorithm": {
            "const": "bbs",
            "type": "string"
          },
          "ciphersuite": {
            "const": "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
            "type": "string"
          },
          "issuer_fingerprint": {
            "pattern": "^[A-Za-z0-9._:-]{1,128}$",
            "type": "string"
          },
          "issuer_public_key_hex": {
            "pattern": "^[0-9a-f]{192}$",
            "type": "string"
          },
          "message_count": {
            "const": 14,
            "type": "integer"
          },
          "projection_version": {
            "const": "chio.bbs-projection.receipt.v1",
            "type": "string"
          },
          "schema": {
            "const": "chio.receipt.bbs_signature.v1"
          },
          "signature_hex": {
            "pattern": "^([0-9a-f]{2})+$",
            "type": "string"
          }
        },
        "required": [
          "schema",
          "projection_version",
          "algorithm",
          "ciphersuite",
          "issuer_fingerprint",
          "issuer_public_key_hex",
          "message_count",
          "signature_hex"
        ],
        "type": "object"
      },
      "decision": {
        "description": "The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = \"verdict\", rename_all = \"snake_case\")]`).",
        "oneOf": [
          {
            "additionalProperties": false,
            "properties": {
              "verdict": {
                "const": "allow"
              }
            },
            "required": [
              "verdict"
            ]
          },
          {
            "additionalProperties": false,
            "properties": {
              "guard": {
                "description": "The guard or validation step that triggered the denial.",
                "type": "string"
              },
              "reason": {
                "description": "Human-readable reason for the denial.",
                "type": "string"
              },
              "verdict": {
                "const": "deny"
              }
            },
            "required": [
              "verdict",
              "reason",
              "guard"
            ]
          },
          {
            "additionalProperties": false,
            "properties": {
              "reason": {
                "description": "Human-readable reason for the cancellation.",
                "type": "string"
              },
              "verdict": {
                "const": "cancelled"
              }
            },
            "required": [
              "verdict",
              "reason"
            ]
          },
          {
            "additionalProperties": false,
            "properties": {
              "reason": {
                "description": "Human-readable reason for the incomplete terminal state.",
                "type": "string"
              },
              "verdict": {
                "const": "incomplete"
              }
            },
            "required": [
              "verdict",
              "reason"
            ]
          }
        ],
        "required": [
          "verdict"
        ],
        "type": "object"
      },
      "guardEvidence": {
        "additionalProperties": false,
        "description": "Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.",
        "properties": {
          "details": {
            "description": "Optional details about the guard's decision.",
            "type": "string"
          },
          "guard_name": {
            "description": "Name of the guard (e.g. `ForbiddenPathGuard`).",
            "minLength": 1,
            "type": "string"
          },
          "verdict": {
            "description": "Whether the guard passed (true) or denied (false).",
            "type": "boolean"
          }
        },
        "required": [
          "guard_name",
          "verdict"
        ],
        "type": "object"
      },
      "toolCallAction": {
        "additionalProperties": false,
        "description": "Describes the tool call that was evaluated. Mirrors `ToolCallAction`.",
        "properties": {
          "parameter_hash": {
            "description": "SHA-256 hex hash of the canonical JSON of `parameters`.",
            "pattern": "^[0-9a-f]{64}$",
            "type": "string"
          },
          "parameters": {
            "description": "The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`)."
          }
        },
        "required": [
          "parameters",
          "parameter_hash"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/receipt/record/v1",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "allOf": [
      {
        "else": {
          "not": {
            "required": [
              "decision"
            ]
          }
        },
        "if": {
          "properties": {
            "receipt_kind": {
              "const": "mediated_decision"
            }
          },
          "required": [
            "receipt_kind"
          ]
        },
        "then": {
          "not": {
            "required": [
              "observation_outcome"
            ]
          },
          "properties": {
            "boundary_class": {
              "const": "prevent"
            },
            "trust_level": {
              "const": "mediated"
            }
          },
          "required": [
            "decision"
          ]
        }
      },
      {
        "if": {
          "properties": {
            "receipt_kind": {
              "const": "trace_observation"
            }
          },
          "required": [
            "receipt_kind"
          ]
        },
        "then": {
          "properties": {
            "boundary_class": {
              "const": "detect_only"
            },
            "trust_level": {
              "const": "verified"
            }
          },
          "required": [
            "observation_outcome"
          ]
        }
      },
      {
        "if": {
          "properties": {
            "receipt_kind": {
              "const": "advisory_evaluation"
            }
          },
          "required": [
            "receipt_kind"
          ]
        },
        "then": {
          "properties": {
            "boundary_class": {
              "const": "advisory_only"
            },
            "trust_level": {
              "const": "advisory"
            }
          },
          "required": [
            "observation_outcome"
          ]
        }
      }
    ],
    "dependentRequired": {
      "bbs_projection_version": [
        "bbs_signature"
      ],
      "bbs_signature": [
        "bbs_projection_version"
      ]
    },
    "description": "A signed Chio receipt: proof that a tool call was evaluated by the Kernel. The receipt id is the authoritative content-addressed SHA-256 hash over the canonical ChioReceiptIdInput.",
    "properties": {
      "action": {
        "$ref": "#/$defs/toolCallAction"
      },
      "actor_chain": {
        "description": "Signed actor attribution chain. Omitted from the wire when empty.",
        "items": {
          "$ref": "#/$defs/actorRef"
        },
        "type": "array"
      },
      "algorithm": {
        "description": "Signing algorithm envelope hint. Verification dispatches off the signature hex prefix, not this field.",
        "enum": [
          "ed25519",
          "p256",
          "p384",
          "hybrid"
        ],
        "type": "string"
      },
      "bbs_projection_version": {
        "const": "chio.bbs-projection.receipt.v1",
        "description": "Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.",
        "type": "string"
      },
      "bbs_signature": {
        "$ref": "#/$defs/bbsReceiptSignature",
        "description": "Optional BBS signature material for selective disclosure. When present, the Ed25519 receipt signature covers this material through ChioReceiptSigningBody."
      },
      "boundary_class": {
        "description": "Signed runtime boundary class. `cannot_see` is planning metadata only and is not valid on signed runtime receipts.",
        "enum": [
          "prevent",
          "detect_only",
          "advisory_only"
        ],
        "type": "string"
      },
      "capability_id": {
        "description": "ID of the capability token that was exercised (or presented).",
        "minLength": 1,
        "type": "string"
      },
      "content_hash": {
        "description": "SHA-256 hex hash of the evaluated content for this receipt.",
        "pattern": "^[0-9a-f]{64}$",
        "type": "string"
      },
      "decision": {
        "$ref": "#/$defs/decision"
      },
      "evidence": {
        "description": "Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = \"Vec::is_empty\")]`).",
        "items": {
          "$ref": "#/$defs/guardEvidence"
        },
        "type": "array"
      },
      "id": {
        "description": "Authoritative content-addressed receipt id.",
        "minLength": 1,
        "pattern": "^[0-9a-f]{64}$",
        "type": "string"
      },
      "kernel_key": {
        "description": "Kernel public key (for verification without out-of-band lookup). Supports Ed25519, uncompressed SEC1 P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes accepted by `PublicKey::from_hex`.",
        "pattern": "^([0-9a-f]{64}|p256:04[0-9a-f]{128}|p384:04[0-9a-f]{192}|hybrid:[0-9a-f]{64}:[0-9a-f]{3904}:ed25519\\+mldsa65|hybrid:p256:04[0-9a-f]{128}:[0-9a-f]{3904}:p256\\+mldsa65|hybrid:p384:04[0-9a-f]{192}:[0-9a-f]{3904}:p384\\+mldsa65)$",
        "type": "string"
      },
      "metadata": {
        "description": "Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`)."
      },
      "observation_outcome": {
        "description": "Signed outcome for trace and advisory records. Omitted for mediated decisions.",
        "enum": [
          "observed",
          "evaluated",
          "dropped"
        ],
        "type": "string"
      },
      "policy_hash": {
        "description": "SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.",
        "minLength": 1,
        "type": "string"
      },
      "receipt_kind": {
        "description": "Signed semantic class for this v1 receipt.",
        "enum": [
          "mediated_decision",
          "trace_observation",
          "advisory_evaluation"
        ],
        "type": "string"
      },
      "redaction_mode": {
        "description": "Signed redaction mode applied to receipt details.",
        "enum": [
          "none",
          "summary",
          "redacted"
        ],
        "type": "string"
      },
      "signature": {
        "description": "Hex-encoded signature over canonical JSON of ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }. Supports Ed25519, byte-aligned DER P-256/P-384, and algorithm-coupled classical plus ML-DSA-65 hybrid envelopes; cryptographic DER validity is checked by the verifier.",
        "pattern": "^([0-9a-f]{128}|p256:([0-9a-f]{2})+|p384:([0-9a-f]{2})+|hybrid:[0-9a-f]{128}:[0-9a-f]{6618}:ed25519\\+mldsa65|hybrid:p256:([0-9a-f]{2})+:[0-9a-f]{6618}:p256\\+mldsa65|hybrid:p384:([0-9a-f]{2})+:[0-9a-f]{6618}:p384\\+mldsa65)$",
        "type": "string"
      },
      "tenant_id": {
        "description": "Tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields.",
        "minLength": 1,
        "type": "string"
      },
      "timestamp": {
        "description": "Unix timestamp (seconds) when the receipt was created.",
        "minimum": 0,
        "type": "integer"
      },
      "tool_name": {
        "description": "Tool that was invoked (or attempted).",
        "minLength": 1,
        "type": "string"
      },
      "tool_origin": {
        "description": "Signed classification of where the tool effect executed relative to Chio.",
        "enum": [
          "caller_executed",
          "host_executed_provider_reported",
          "host_executed_unmediated",
          "chio_internal"
        ],
        "type": "string"
      },
      "tool_server": {
        "description": "Tool server that handled the invocation.",
        "minLength": 1,
        "type": "string"
      },
      "trust_level": {
        "description": "Strength of kernel mediation that produced this receipt. Must cohere with receipt_kind: mediated_decision uses mediated, trace_observation uses verified, and advisory_evaluation uses advisory.",
        "enum": [
          "mediated",
          "verified",
          "advisory"
        ],
        "type": "string"
      }
    },
    "required": [
      "id",
      "timestamp",
      "capability_id",
      "tool_server",
      "tool_name",
      "action",
      "receipt_kind",
      "boundary_class",
      "tool_origin",
      "redaction_mode",
      "content_hash",
      "policy_hash",
      "trust_level",
      "kernel_key",
      "signature"
    ],
    "title": "Chio Receipt Record",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.world/schemas/chio-wire/v1/recovery/approval-intent.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "action_intent": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "approval_intent": {
        "$ref": "#/$defs/opaqueId"
      },
      "authorization_requirements": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "challenge": {
        "$ref": "#/$defs/opaqueId"
      },
      "expires_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      },
      "issued_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      },
      "obligations": {
        "items": {
          "oneOf": [
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "owner_release"
                },
                "owner": {
                  "maxLength": 256,
                  "minLength": 1,
                  "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
                  "type": "string",
                  "x-maxUtf8Bytes": 256
                }
              },
              "required": [
                "kind",
                "owner"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "compartment": {
                  "maxLength": 256,
                  "minLength": 1,
                  "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
                  "type": "string",
                  "x-maxUtf8Bytes": 256
                },
                "kind": {
                  "const": "compartment_release"
                }
              },
              "required": [
                "kind",
                "compartment"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "user_acceptance"
                },
                "principal": {
                  "maxLength": 256,
                  "minLength": 1,
                  "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
                  "type": "string",
                  "x-maxUtf8Bytes": 256
                }
              },
              "required": [
                "kind",
                "principal"
              ],
              "type": "object"
            },
            {
              "additionalProperties": false,
              "properties": {
                "kind": {
                  "const": "integrity_endorsement"
                },
                "principal": {
                  "maxLength": 256,
                  "minLength": 1,
                  "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
                  "type": "string",
                  "x-maxUtf8Bytes": 256
                }
              },
              "required": [
                "kind",
                "principal"
              ],
              "type": "object"
            }
          ]
        },
        "maxItems": 64,
        "minItems": 1,
        "type": "array"
      },
      "offer": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "plan": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "preview": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "purpose": {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        "type": "string",
        "x-maxUtf8Bytes": 256
      },
      "recipient": {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        "type": "string",
        "x-maxUtf8Bytes": 256
      },
      "reviewer": {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        "type": "string",
        "x-maxUtf8Bytes": 256
      },
      "schema": {
        "const": "chio.recovery.approval-intent.v1"
      },
      "scope": {
        "$ref": "#/$defs/scope"
      },
      "version": {
        "const": 1
      }
    },
    "required": [
      "schema",
      "version",
      "approval_intent",
      "challenge",
      "scope",
      "action_intent",
      "authorization_requirements",
      "offer",
      "plan",
      "preview",
      "recipient",
      "purpose",
      "reviewer",
      "obligations",
      "issued_at_unix_ms",
      "expires_at_unix_ms"
    ],
    "title": "Recovery approval intent V1",
    "type": "object"
  },
  {
    "$defs": {
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/artifact-influence.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "commitment": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "externally_influenced": {
        "type": "boolean"
      },
      "unknown": {
        "type": "boolean"
      }
    },
    "required": [
      "commitment",
      "externally_influenced",
      "unknown"
    ],
    "title": "Artifact Influence V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/artifact-reference.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "artifact": {
        "$ref": "#/$defs/opaqueId"
      },
      "provenance": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "scope": {
        "$ref": "#/$defs/scope"
      },
      "version": {
        "$ref": "#/$defs/opaqueId"
      }
    },
    "required": [
      "scope",
      "artifact",
      "version",
      "provenance"
    ],
    "title": "Artifact Reference V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "operation": {
        "additionalProperties": false,
        "properties": {
          "native_admission_digest": {
            "$ref": "#/$defs/recoveryDigest32"
          },
          "operation_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "operation_version": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          }
        },
        "required": [
          "operation_id",
          "native_admission_digest",
          "operation_version"
        ],
        "type": "object"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "recoveryEffectAdmissionUnresolvedV1": {
        "additionalProperties": false,
        "properties": {
          "admission_intent": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "admission_unresolved"
          }
        },
        "required": [
          "kind",
          "admission_intent"
        ],
        "title": "Recovery effect admission unresolved V1",
        "type": "object"
      },
      "recoveryEffectAwaitingApprovalV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_approval"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting approval V1",
        "type": "object"
      },
      "recoveryEffectAwaitingCallerReportV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_caller_report"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting caller report V1",
        "type": "object"
      },
      "recoveryEffectClosedBeforeEffectV1": {
        "additionalProperties": false,
        "properties": {
          "closure": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "closed_before_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "closure"
        ],
        "title": "Recovery effect closed before effect V1",
        "type": "object"
      },
      "recoveryEffectCompleteV1": {
        "additionalProperties": false,
        "properties": {
          "effect_count": {
            "$ref": "#/$defs/safeInteger"
          },
          "kind": {
            "const": "complete"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "effect_count"
        ],
        "title": "Recovery effect complete V1",
        "type": "object"
      },
      "recoveryEffectFailedAfterEffectV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "failed_after_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect failed after effect V1",
        "type": "object"
      },
      "recoveryEffectInFlightV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "in_flight"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect in flight V1",
        "type": "object"
      },
      "recoveryEffectNeverAdmittedV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "never_admitted"
          }
        },
        "required": [
          "kind"
        ],
        "title": "Recovery effect never admitted V1",
        "type": "object"
      },
      "recoveryEffectPartialV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "partial"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect partial V1",
        "type": "object"
      },
      "recoveryEffectUnknownV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "unknown"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect unknown V1",
        "type": "object"
      },
      "refusalCode": {
        "enum": [
          "invalid_evidence",
          "unsupported_profile",
          "stale_basis",
          "revoked",
          "expired",
          "budget_unavailable",
          "unknown_effect",
          "audience_denied",
          "resource_exhausted"
        ],
        "type": "string"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.world/schemas/chio-wire/v1/recovery/command-response.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "command_id": {
        "$ref": "#/$defs/opaqueId"
      },
      "control": {
        "enum": [
          "active",
          "cancel_requested",
          "cancelled",
          "quarantined"
        ],
        "type": "string"
      },
      "effect": {
        "oneOf": [
          {
            "$ref": "#/$defs/recoveryEffectNeverAdmittedV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectAdmissionUnresolvedV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectClosedBeforeEffectV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectAwaitingApprovalV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectInFlightV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectAwaitingCallerReportV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectUnknownV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectCompleteV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectPartialV1"
          },
          {
            "$ref": "#/$defs/recoveryEffectFailedAfterEffectV1"
          }
        ]
      },
      "release": {
        "oneOf": [
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "not_available"
              }
            },
            "required": [
              "kind"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "pending"
              },
              "release_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "release_id"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "evidence": {
                "$ref": "#/$defs/opaqueId"
              },
              "kind": {
                "const": "withheld"
              }
            },
            "required": [
              "kind",
              "evidence"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "released"
              },
              "release_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "release_id"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "denied"
              },
              "reason": {
                "$ref": "#/$defs/refusalCode"
              }
            },
            "required": [
              "kind",
              "reason"
            ],
            "type": "object"
          }
        ]
      },
      "revision": {
        "$ref": "#/$defs/safeInteger"
      },
      "workflow_id": {
        "$ref": "#/$defs/opaqueId"
      }
    },
    "required": [
      "command_id",
      "workflow_id",
      "revision",
      "control",
      "effect",
      "release"
    ],
    "title": "Recovery command response V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "operation": {
        "additionalProperties": false,
        "properties": {
          "native_admission_digest": {
            "$ref": "#/$defs/recoveryDigest32"
          },
          "operation_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "operation_version": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          }
        },
        "required": [
          "operation_id",
          "native_admission_digest",
          "operation_version"
        ],
        "type": "object"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "recoveryEffectAdmissionUnresolvedV1": {
        "additionalProperties": false,
        "properties": {
          "admission_intent": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "admission_unresolved"
          }
        },
        "required": [
          "kind",
          "admission_intent"
        ],
        "title": "Recovery effect admission unresolved V1",
        "type": "object"
      },
      "recoveryEffectAwaitingApprovalV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_approval"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting approval V1",
        "type": "object"
      },
      "recoveryEffectAwaitingCallerReportV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_caller_report"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting caller report V1",
        "type": "object"
      },
      "recoveryEffectClosedBeforeEffectV1": {
        "additionalProperties": false,
        "properties": {
          "closure": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "closed_before_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "closure"
        ],
        "title": "Recovery effect closed before effect V1",
        "type": "object"
      },
      "recoveryEffectCompleteV1": {
        "additionalProperties": false,
        "properties": {
          "effect_count": {
            "$ref": "#/$defs/safeInteger"
          },
          "kind": {
            "const": "complete"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "effect_count"
        ],
        "title": "Recovery effect complete V1",
        "type": "object"
      },
      "recoveryEffectFailedAfterEffectV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "failed_after_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect failed after effect V1",
        "type": "object"
      },
      "recoveryEffectInFlightV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "in_flight"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect in flight V1",
        "type": "object"
      },
      "recoveryEffectNeverAdmittedV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "never_admitted"
          }
        },
        "required": [
          "kind"
        ],
        "title": "Recovery effect never admitted V1",
        "type": "object"
      },
      "recoveryEffectPartialV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "partial"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect partial V1",
        "type": "object"
      },
      "recoveryEffectUnknownV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "unknown"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect unknown V1",
        "type": "object"
      },
      "refusalCode": {
        "enum": [
          "invalid_evidence",
          "unsupported_profile",
          "stale_basis",
          "revoked",
          "expired",
          "budget_unavailable",
          "unknown_effect",
          "audience_denied",
          "resource_exhausted"
        ],
        "type": "string"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.world/schemas/chio-wire/v1/recovery/command-result.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "original_response": {
        "additionalProperties": false,
        "properties": {
          "receipt": {
            "$ref": "https://chio-protocol.dev/schemas/chio-wire/v1/receipt/record/v1"
          },
          "result": {}
        },
        "required": [
          "receipt",
          "result"
        ],
        "type": "object"
      },
      "status": {
        "$ref": "https://chio.world/schemas/chio-wire/v1/recovery/command-response.schema.json"
      }
    },
    "required": [
      "status"
    ],
    "title": "Recovery command result V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.world/schemas/chio-wire/v1/recovery/command.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "command": {
        "oneOf": [
          {
            "additionalProperties": false,
            "properties": {
              "creation_key": {
                "$ref": "#/$defs/opaqueId"
              },
              "kind": {
                "const": "create_workflow"
              },
              "request_seed": {
                "maxLength": 32768,
                "minLength": 1,
                "type": "string",
                "x-maxUtf8Bytes": 32768
              },
              "template": {
                "enum": [
                  "support_ticket_public_issue"
                ],
                "type": "string"
              }
            },
            "required": [
              "kind",
              "creation_key",
              "template",
              "request_seed"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "kind": {
                "const": "inspect_workflow"
              },
              "workflow_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "workflow_id"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "expected_revision": {
                "$ref": "#/$defs/safeInteger"
              },
              "kind": {
                "const": "select_offer"
              },
              "offer_id": {
                "$ref": "#/$defs/opaqueId"
              },
              "workflow_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "workflow_id",
              "expected_revision",
              "offer_id"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "approval": {
                "maxLength": 32768,
                "minLength": 1,
                "type": "string",
                "x-maxUtf8Bytes": 32768
              },
              "expected_revision": {
                "$ref": "#/$defs/safeInteger"
              },
              "kind": {
                "const": "submit_approval"
              },
              "workflow_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "workflow_id",
              "expected_revision",
              "approval"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "expected_revision": {
                "$ref": "#/$defs/safeInteger"
              },
              "kind": {
                "const": "resume_workflow"
              },
              "workflow_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "workflow_id",
              "expected_revision"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "expected_revision": {
                "$ref": "#/$defs/safeInteger"
              },
              "kind": {
                "const": "cancel_workflow"
              },
              "workflow_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "workflow_id",
              "expected_revision"
            ],
            "type": "object"
          },
          {
            "additionalProperties": false,
            "properties": {
              "decision": {
                "enum": [
                  "accepted",
                  "declined",
                  "needs_review"
                ],
                "type": "string"
              },
              "expected_revision": {
                "$ref": "#/$defs/safeInteger"
              },
              "kind": {
                "const": "report_decision"
              },
              "workflow_id": {
                "$ref": "#/$defs/opaqueId"
              }
            },
            "required": [
              "kind",
              "workflow_id",
              "expected_revision",
              "decision"
            ],
            "type": "object"
          }
        ]
      },
      "command_id": {
        "$ref": "#/$defs/opaqueId"
      },
      "schema": {
        "const": "chio.recovery.command.v1"
      },
      "version": {
        "const": 1
      }
    },
    "required": [
      "schema",
      "version",
      "command_id",
      "command"
    ],
    "title": "Recovery command V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/decision-report-view.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "digest": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "domain_version": {
        "const": 1
      },
      "id": {
        "$ref": "#/$defs/opaqueId"
      },
      "influence": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/artifact-influence.schema.json"
      },
      "label": {
        "$ref": "https://chio.world/schemas/chio-wire/v1/security/information-label.schema.json"
      },
      "report": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/decision-report.schema.json"
      }
    },
    "required": [
      "domain_version",
      "digest",
      "report",
      "label",
      "influence",
      "id"
    ],
    "title": "Decision Report View V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/decision-report.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "attachments": {
        "items": {
          "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/artifact-reference.schema.json"
        },
        "maxItems": 8,
        "minItems": 0,
        "type": "array",
        "uniqueItems": true
      },
      "decision": {
        "enum": [
          "accepted",
          "declined",
          "needs_review"
        ]
      },
      "desired_outcome": {
        "maxLength": 1024,
        "minLength": 1,
        "type": "string"
      },
      "domain_version": {
        "const": 1
      },
      "expected_revision": {
        "maximum": 9007199254740991,
        "minimum": 1,
        "type": "integer"
      },
      "reporter_text": {
        "maxLength": 4096,
        "minLength": 1,
        "type": "string"
      },
      "scope": {
        "$ref": "#/$defs/scope"
      },
      "workflow_id": {
        "$ref": "#/$defs/opaqueId"
      }
    },
    "required": [
      "domain_version",
      "scope",
      "workflow_id",
      "expected_revision",
      "decision",
      "reporter_text",
      "desired_outcome",
      "attachments"
    ],
    "title": "Decision Report V1",
    "type": "object"
  },
  {
    "$defs": {
      "destinationId": {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        "type": "string",
        "x-maxUtf8Bytes": 256
      },
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "operation": {
        "additionalProperties": false,
        "properties": {
          "native_admission_digest": {
            "$ref": "#/$defs/recoveryDigest32"
          },
          "operation_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "operation_version": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          }
        },
        "required": [
          "operation_id",
          "native_admission_digest",
          "operation_version"
        ],
        "type": "object"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "recoveryEffectAdmissionUnresolvedV1": {
        "additionalProperties": false,
        "properties": {
          "admission_intent": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "admission_unresolved"
          }
        },
        "required": [
          "kind",
          "admission_intent"
        ],
        "title": "Recovery effect admission unresolved V1",
        "type": "object"
      },
      "recoveryEffectAwaitingApprovalV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_approval"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting approval V1",
        "type": "object"
      },
      "recoveryEffectAwaitingCallerReportV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_caller_report"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting caller report V1",
        "type": "object"
      },
      "recoveryEffectClosedBeforeEffectV1": {
        "additionalProperties": false,
        "properties": {
          "closure": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "closed_before_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "closure"
        ],
        "title": "Recovery effect closed before effect V1",
        "type": "object"
      },
      "recoveryEffectCompleteV1": {
        "additionalProperties": false,
        "properties": {
          "effect_count": {
            "$ref": "#/$defs/safeInteger"
          },
          "kind": {
            "const": "complete"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "effect_count"
        ],
        "title": "Recovery effect complete V1",
        "type": "object"
      },
      "recoveryEffectFailedAfterEffectV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "failed_after_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect failed after effect V1",
        "type": "object"
      },
      "recoveryEffectInFlightV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "in_flight"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect in flight V1",
        "type": "object"
      },
      "recoveryEffectNeverAdmittedV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "never_admitted"
          }
        },
        "required": [
          "kind"
        ],
        "title": "Recovery effect never admitted V1",
        "type": "object"
      },
      "recoveryEffectPartialV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "partial"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect partial V1",
        "type": "object"
      },
      "recoveryEffectUnknownV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "unknown"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect unknown V1",
        "type": "object"
      },
      "refusalCode": {
        "enum": [
          "invalid_evidence",
          "unsupported_profile",
          "stale_basis",
          "revoked",
          "expired",
          "budget_unavailable",
          "unknown_effect",
          "audience_denied",
          "resource_exhausted"
        ],
        "type": "string"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/explanation-view.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "expires_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      },
      "issued_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      },
      "issuer": {
        "$ref": "#/$defs/opaqueId"
      },
      "planner_version": {
        "const": "chio.recovery.planner.v1"
      },
      "projection": {
        "additionalProperties": false,
        "properties": {
          "candidates": {
            "items": {
              "additionalProperties": false,
              "properties": {
                "assessment": {
                  "enum": [
                    "feasible_under_snapshot",
                    "requires_exact_approval",
                    "requires_transformation",
                    "requires_prerequisite",
                    "needs_fresh_evidence",
                    "blocked_by_capability",
                    "unknown_outcome",
                    "no_registered_remedy",
                    "search_bound_reached"
                  ],
                  "type": "string"
                },
                "template_id": {
                  "$ref": "#/$defs/opaqueId"
                }
              },
              "required": [
                "template_id",
                "assessment"
              ],
              "type": "object"
            },
            "maxItems": 16,
            "type": "array"
          },
          "summary": {
            "enum": [
              "authorized_inspection_required",
              "no_disclosable_advice",
              "alternatives_under_snapshot",
              "search_bound_reached"
            ],
            "type": "string"
          }
        },
        "required": [
          "summary",
          "candidates"
        ],
        "type": "object"
      },
      "recipient": {
        "$ref": "#/$defs/opaqueId"
      },
      "report_ref": {
        "$ref": "#/$defs/opaqueId"
      },
      "schema": {
        "const": "chio.recovery.explanation-view.v1"
      },
      "trust_domain": {
        "$ref": "#/$defs/opaqueId"
      },
      "version": {
        "const": 1
      }
    },
    "required": [
      "schema",
      "version",
      "planner_version",
      "trust_domain",
      "issuer",
      "recipient",
      "report_ref",
      "issued_at_unix_ms",
      "expires_at_unix_ms",
      "projection"
    ],
    "title": "Recovery Explanation View V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/policy-maintenance-proposal.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "adversarial_trajectories": {
        "items": {
          "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/policy-trajectory-ref.schema.json"
        },
        "maxItems": 16,
        "minItems": 1,
        "type": "array",
        "uniqueItems": true
      },
      "affected_contracts": {
        "items": {
          "$ref": "#/$defs/recoveryDigest32"
        },
        "maxItems": 16,
        "minItems": 1,
        "type": "array",
        "uniqueItems": true
      },
      "base_deployment": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "base_policy": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "benign_trajectories": {
        "items": {
          "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/policy-trajectory-ref.schema.json"
        },
        "maxItems": 16,
        "minItems": 1,
        "type": "array",
        "uniqueItems": true
      },
      "domain_version": {
        "const": 1
      },
      "expected_effects": {
        "maxLength": 4096,
        "minLength": 1,
        "type": "string"
      },
      "proposal_id": {
        "$ref": "#/$defs/opaqueId"
      },
      "rationale": {
        "maxLength": 4096,
        "minLength": 1,
        "type": "string"
      },
      "report_id": {
        "$ref": "#/$defs/opaqueId"
      },
      "rollback_plan": {
        "maxLength": 4096,
        "minLength": 1,
        "type": "string"
      },
      "rollback_policy": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "scope": {
        "$ref": "#/$defs/scope"
      },
      "target_policy": {
        "$ref": "#/$defs/recoveryDigest32"
      }
    },
    "required": [
      "domain_version",
      "scope",
      "proposal_id",
      "report_id",
      "base_deployment",
      "base_policy",
      "target_policy",
      "rationale",
      "affected_contracts",
      "benign_trajectories",
      "adversarial_trajectories",
      "expected_effects",
      "rollback_policy",
      "rollback_plan"
    ],
    "title": "Policy Maintenance Proposal V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/policy-maintenance-view.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "digest": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "domain_version": {
        "const": 1
      },
      "influence": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/artifact-influence.schema.json"
      },
      "label": {
        "$ref": "https://chio.world/schemas/chio-wire/v1/security/information-label.schema.json"
      },
      "proposal": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/policy-maintenance-proposal.schema.json"
      }
    },
    "required": [
      "domain_version",
      "digest",
      "proposal",
      "label",
      "influence"
    ],
    "title": "Policy Maintenance View V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/policy-trajectory-ref.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "artifact": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/artifact-reference.schema.json"
      },
      "case_id": {
        "$ref": "#/$defs/opaqueId"
      }
    },
    "required": [
      "artifact",
      "case_id"
    ],
    "title": "Policy Trajectory Ref V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/recovery-setup-probe.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "benign_workflow": {
        "$ref": "#/$defs/opaqueId"
      },
      "denied_command": {
        "$ref": "#/$defs/opaqueId"
      },
      "deployment": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "domain_version": {
        "const": 1
      },
      "expires_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      },
      "issued_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      },
      "native_authority": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "probe_id": {
        "$ref": "#/$defs/opaqueId"
      },
      "required_coverage": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "scope": {
        "$ref": "#/$defs/scope"
      },
      "source_profile": {
        "$ref": "#/$defs/recoveryDigest32"
      }
    },
    "required": [
      "domain_version",
      "scope",
      "probe_id",
      "native_authority",
      "deployment",
      "source_profile",
      "required_coverage",
      "benign_workflow",
      "denied_command",
      "issued_at_unix_ms",
      "expires_at_unix_ms"
    ],
    "title": "Recovery Setup Probe V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/recovery-setup-report.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "benign_operation": {
        "$ref": "#/$defs/opaqueId"
      },
      "benign_receipt": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "current_serving_fence": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "denied_command_digest": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "domain_version": {
        "const": 1
      },
      "previous_serving_fence": {
        "$ref": "#/$defs/recoveryDigest32"
      },
      "probe": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/recovery-setup-probe.schema.json"
      },
      "qualified_at_unix_ms": {
        "$ref": "#/$defs/safeInteger"
      }
    },
    "required": [
      "domain_version",
      "probe",
      "benign_operation",
      "benign_receipt",
      "denied_command_digest",
      "previous_serving_fence",
      "current_serving_fence",
      "qualified_at_unix_ms"
    ],
    "title": "Recovery Setup Report V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "operation": {
        "additionalProperties": false,
        "properties": {
          "native_admission_digest": {
            "$ref": "#/$defs/recoveryDigest32"
          },
          "operation_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "operation_version": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          }
        },
        "required": [
          "operation_id",
          "native_admission_digest",
          "operation_version"
        ],
        "type": "object"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "recoveryEffectAdmissionUnresolvedV1": {
        "additionalProperties": false,
        "properties": {
          "admission_intent": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "admission_unresolved"
          }
        },
        "required": [
          "kind",
          "admission_intent"
        ],
        "title": "Recovery effect admission unresolved V1",
        "type": "object"
      },
      "recoveryEffectAwaitingApprovalV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_approval"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting approval V1",
        "type": "object"
      },
      "recoveryEffectAwaitingCallerReportV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_caller_report"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting caller report V1",
        "type": "object"
      },
      "recoveryEffectClosedBeforeEffectV1": {
        "additionalProperties": false,
        "properties": {
          "closure": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "closed_before_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "closure"
        ],
        "title": "Recovery effect closed before effect V1",
        "type": "object"
      },
      "recoveryEffectCompleteV1": {
        "additionalProperties": false,
        "properties": {
          "effect_count": {
            "$ref": "#/$defs/safeInteger"
          },
          "kind": {
            "const": "complete"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "effect_count"
        ],
        "title": "Recovery effect complete V1",
        "type": "object"
      },
      "recoveryEffectFailedAfterEffectV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "failed_after_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect failed after effect V1",
        "type": "object"
      },
      "recoveryEffectInFlightV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "in_flight"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect in flight V1",
        "type": "object"
      },
      "recoveryEffectNeverAdmittedV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "never_admitted"
          }
        },
        "required": [
          "kind"
        ],
        "title": "Recovery effect never admitted V1",
        "type": "object"
      },
      "recoveryEffectPartialV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "partial"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect partial V1",
        "type": "object"
      },
      "recoveryEffectUnknownV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "unknown"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect unknown V1",
        "type": "object"
      },
      "refusalCode": {
        "enum": [
          "invalid_evidence",
          "unsupported_profile",
          "stale_basis",
          "revoked",
          "expired",
          "budget_unavailable",
          "unknown_effect",
          "audience_denied",
          "resource_exhausted"
        ],
        "type": "string"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.world/schemas/chio-wire/v1/recovery/review-document.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "canonical_preview": {
        "maxLength": 32768,
        "minLength": 1,
        "type": "string",
        "x-maxUtf8Bytes": 32768
      },
      "intent": {
        "$ref": "https://chio.world/schemas/chio-wire/v1/recovery/approval-intent.schema.json"
      }
    },
    "required": [
      "intent",
      "canonical_preview"
    ],
    "title": "Recovery review document V1",
    "type": "object"
  },
  {
    "$defs": {
      "destinationId": {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        "type": "string",
        "x-maxUtf8Bytes": 256
      },
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "operation": {
        "additionalProperties": false,
        "properties": {
          "native_admission_digest": {
            "$ref": "#/$defs/recoveryDigest32"
          },
          "operation_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "operation_version": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          }
        },
        "required": [
          "operation_id",
          "native_admission_digest",
          "operation_version"
        ],
        "type": "object"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "recoveryEffectAdmissionUnresolvedV1": {
        "additionalProperties": false,
        "properties": {
          "admission_intent": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "admission_unresolved"
          }
        },
        "required": [
          "kind",
          "admission_intent"
        ],
        "title": "Recovery effect admission unresolved V1",
        "type": "object"
      },
      "recoveryEffectAwaitingApprovalV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_approval"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting approval V1",
        "type": "object"
      },
      "recoveryEffectAwaitingCallerReportV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "awaiting_caller_report"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect awaiting caller report V1",
        "type": "object"
      },
      "recoveryEffectClosedBeforeEffectV1": {
        "additionalProperties": false,
        "properties": {
          "closure": {
            "$ref": "#/$defs/opaqueId"
          },
          "kind": {
            "const": "closed_before_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "closure"
        ],
        "title": "Recovery effect closed before effect V1",
        "type": "object"
      },
      "recoveryEffectCompleteV1": {
        "additionalProperties": false,
        "properties": {
          "effect_count": {
            "$ref": "#/$defs/safeInteger"
          },
          "kind": {
            "const": "complete"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "effect_count"
        ],
        "title": "Recovery effect complete V1",
        "type": "object"
      },
      "recoveryEffectFailedAfterEffectV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "failed_after_effect"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect failed after effect V1",
        "type": "object"
      },
      "recoveryEffectInFlightV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "in_flight"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect in flight V1",
        "type": "object"
      },
      "recoveryEffectNeverAdmittedV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "never_admitted"
          }
        },
        "required": [
          "kind"
        ],
        "title": "Recovery effect never admitted V1",
        "type": "object"
      },
      "recoveryEffectPartialV1": {
        "additionalProperties": false,
        "properties": {
          "applied_effects": {
            "maximum": 9007199254740991,
            "minimum": 1,
            "type": "integer"
          },
          "kind": {
            "const": "partial"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation",
          "applied_effects"
        ],
        "title": "Recovery effect partial V1",
        "type": "object"
      },
      "recoveryEffectUnknownV1": {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "unknown"
          },
          "operation": {
            "$ref": "#/$defs/operation"
          }
        },
        "required": [
          "kind",
          "operation"
        ],
        "title": "Recovery effect unknown V1",
        "type": "object"
      },
      "refusalCode": {
        "enum": [
          "invalid_evidence",
          "unsupported_profile",
          "stale_basis",
          "revoked",
          "expired",
          "budget_unavailable",
          "unknown_effect",
          "audience_denied",
          "resource_exhausted"
        ],
        "type": "string"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/signed-explanation-view.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "algorithm": {
        "enum": [
          "ed25519",
          "p256",
          "p384",
          "hybrid"
        ],
        "type": "string"
      },
      "authority_key": {
        "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$",
        "type": "string"
      },
      "body": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/explanation-view.schema.json"
      },
      "signature": {
        "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$",
        "type": "string"
      }
    },
    "required": [
      "body",
      "authority_key",
      "algorithm",
      "signature"
    ],
    "title": "Recovery Signed Explanation View V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/signed-recovery-setup-probe.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "algorithm": {
        "enum": [
          "ed25519",
          "p256",
          "p384",
          "hybrid"
        ],
        "type": "string"
      },
      "authority_key": {
        "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$",
        "type": "string"
      },
      "body": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/recovery-setup-probe.schema.json"
      },
      "signature": {
        "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$",
        "type": "string"
      }
    },
    "required": [
      "body",
      "authority_key",
      "algorithm",
      "signature"
    ],
    "title": "Signed Recovery Setup Probe V1",
    "type": "object"
  },
  {
    "$defs": {
      "opaqueId": {
        "maxLength": 128,
        "minLength": 1,
        "not": {
          "pattern": "[\\r\\n]"
        },
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string"
      },
      "recoveryDigest32": {
        "items": {
          "maximum": 255,
          "minimum": 0,
          "title": "Recovery digest octet",
          "type": "integer"
        },
        "maxItems": 32,
        "minItems": 32,
        "title": "Recovery digest32",
        "type": "array"
      },
      "safeInteger": {
        "maximum": 9007199254740991,
        "minimum": 0,
        "type": "integer"
      },
      "scope": {
        "additionalProperties": false,
        "properties": {
          "authority_domain": {
            "$ref": "#/$defs/opaqueId"
          },
          "process_id": {
            "$ref": "#/$defs/opaqueId"
          },
          "tenant_id": {
            "$ref": "#/$defs/opaqueId"
          }
        },
        "required": [
          "authority_domain",
          "tenant_id",
          "process_id"
        ],
        "type": "object"
      }
    },
    "$id": "https://chio.computer/schemas/chio-wire/v1/recovery/signed-recovery-setup-report.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": false,
    "properties": {
      "algorithm": {
        "enum": [
          "ed25519",
          "p256",
          "p384",
          "hybrid"
        ],
        "type": "string"
      },
      "authority_key": {
        "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\\+mldsa65)$",
        "type": "string"
      },
      "body": {
        "$ref": "https://chio.computer/schemas/chio-wire/v1/recovery/recovery-setup-report.schema.json"
      },
      "signature": {
        "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\\+mldsa65)$",
        "type": "string"
      }
    },
    "required": [
      "body",
      "authority_key",
      "algorithm",
      "signature"
    ],
    "title": "Signed Recovery Setup Report V1",
    "type": "object"
  },
  {
    "$defs": {
      "flowIdentifier": {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[^\\s\\u0000-\\u001F\\u007F-\\u009F](?:[^\\u0000-\\u001F\\u007F-\\u009F]*[^\\s\\u0000-\\u001F\\u007F-\\u009F])?$",
        "type": "string",
        "x-maxUtf8Bytes": 256
      }
    },
    "$id": "https://chio.world/schemas/chio-wire/v1/security/information-label.schema.json",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "description": "Canonical portable DLM information label. Identifier maxLength is a structural Unicode-scalar bound; runtime validation additionally enforces the normative 256-byte UTF-8 ceiling and owner self readership.",
    "oneOf": [
      {
        "additionalProperties": false,
        "properties": {
          "compartments": {
            "items": {
              "$ref": "#/$defs/flowIdentifier"
            },
            "maxItems": 64,
            "type": "array",
            "uniqueItems": true
          },
          "kind": {
            "const": "known"
          },
          "owners": {
            "additionalProperties": {
              "items": {
                "$ref": "#/$defs/flowIdentifier"
              },
              "maxItems": 256,
              "type": "array",
              "uniqueItems": true
            },
            "maxProperties": 64,
            "propertyNames": {
              "$ref": "#/$defs/flowIdentifier"
            },
            "type": "object"
          }
        },
        "required": [
          "kind",
          "owners",
          "compartments"
        ],
        "type": "object"
      },
      {
        "additionalProperties": false,
        "properties": {
          "kind": {
            "const": "top"
          }
        },
        "required": [
          "kind"
        ],
        "type": "object"
      }
    ],
    "title": "Information Label"
  }
];
