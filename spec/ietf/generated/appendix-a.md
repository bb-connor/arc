The examples in this appendix are built from two cases of the Chio
binding vector corpus, `capability/v1.json` case
`valid_no_delegation_chain` and `receipt/v1.json` case `allow_receipt`,
so every key, hash, and signature in them is exact. Lines longer than 69
characters are folded as described in {{RFC8792}}, and each folded block
begins with the header line that document defines.

## Capability Token {#example-capability}

The following case is `capability/v1.json` case
`valid_no_delegation_chain` from the Chio binding vector corpus. It is a
directly issued token with no delegation chain and one tool grant,
pretty-printed here for reading. Capability tokens are defined in
{{capabilities}}.

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{
  "expires_at": 1710000800,
  "id": "cap-bindings-direct",
  "issued_at": 1710000200,
  "issuer": "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb\
      6810c473a",
  "schema": "chio.capability.v1",
  "scope": {
    "grants": [
      {
        "constraints": [
          {
            "type": "path_prefix",
            "value": "/workspace/"
          }
        ],
        "max_invocations": 3,
        "operations": [
          "invoke",
          "read_result"
        ],
        "server_id": "srv-files",
        "tool_name": "file_read"
      }
    ]
  },
  "signature": "423e1a5ce4c07d2ef4aa8c11c065b1d778dba80d4e91242ca59c\
      0a431529965bc6a332f9e431d4fd11c68b0431fde84b48991476dd5bea9137\
      d8c8c8471c6804",
  "subject": "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da\
      8eb6e39f2d"
}
~~~

The signing body of the token is its canonical form without the
`signature` member. The member `"schema":"chio.capability.v1"` sorts
between `issuer` and `scope`. The signing body is the
`capability_signing_body_canonical_json` value of the case:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"expires_at":1710000800,"id":"cap-bindings-direct","issued_at":\
1710000200,"issuer":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"schema":"chio.capability.v1","scope":{"grants":[{"constraints":\
[{"type":"path_prefix","value":"/workspace/"}],"max_invocations":3,\
"operations":["invoke","read_result"],"server_id":"srv-files",\
"tool_name":"file_read"}]},"subject":\
"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"}
~~~

The signing wrapper ({{signing-wrapper}}) of this body under the schema
id `chio.capability.v1` is these 88 octets, in hex:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

6368696f2e7369676e696e672d777261707065722e7631005d8d33c3d56ece64cca5\
a6fa61a763d04ce26ebfd9235ec1f75e81b28a6a535f89dfefe2ef217fd1b424ff7e\
d5825d3920ae3258f527b25fc9c573a994bbdba3
~~~

The `signature` member is an Ed25519 signature over the wrapper that
verifies under the key in `issuer`.

## Tool Call Request Frame {#example-frame}

The following request is built from `capability/v1.json` case
`valid_no_delegation_chain` and `receipt/v1.json` case `allow_receipt`
of the Chio binding vector corpus. Its `capability_token` is the token
of {{example-capability}}, and its `server_id`, `tool`, and `params` are
the `tool_server`, `tool_name`, and `action.parameters` members of the
receipt of {{example-receipt}}. Its `id` is illustrative. The request is
not a case of the corpus, and its canonical form is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"capability_token":{"expires_at":1710000800,"id":\
"cap-bindings-direct","issued_at":1710000200,"issuer":\
"66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",\
"schema":"chio.capability.v1","scope":{"grants":[{"constraints":\
[{"type":"path_prefix","value":"/workspace/"}],"max_invocations":3,\
"operations":["invoke","read_result"],"server_id":"srv-files",\
"tool_name":"file_read"}]},"signature":"423e1a5ce4c07d2ef4aa8c11c065\
b1d778dba80d4e91242ca59c0a431529965bc6a332f9e431d4fd11c68b0431fde84b\
48991476dd5bea9137d8c8c8471c6804","subject":\
"0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"},\
"id":"req-001","params":{"mode":"read","path":\
"/workspace/docs/roadmap.md"},"server_id":"srv-files","tool":\
"file_read","type":"tool_call_request"}
~~~

In the native transport ({{native-transport}}), a message is sent as a
frame: a four-octet length in big-endian order, followed by the
canonical form as the payload. The payload here is 758 octets long, so
the length prefix is:
{: keepWithNext="true"}

~~~
000002f6
~~~

The first 32 octets of the payload are the ASCII text
`{"capability_token":{"expires_at`. In hex they are:
{: keepWithNext="true"}

~~~
7b226361706162696c6974795f746f6b656e223a7b22657870697265735f6174
~~~

## Receipt {#example-receipt}

The following case is `receipt/v1.json` case `allow_receipt` from the
Chio binding vector corpus. It records an allow decision for a call with
the server, tool, and parameters of {{example-frame}}, and it is
pretty-printed here for reading. Its `capability_id` is
`cap-bindings-001`. The capability and receipt cases of the corpus are
independent, so that value is not the `id` of the token in
{{example-capability}}. Receipts are defined in {{receipts}}.

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{
  "action": {
    "parameter_hash": "035350b0e6a021a4c924a149111944945e94d12f6d8a5\
        e24e4461e7009ebf929",
    "parameters": {
      "mode": "read",
      "path": "/workspace/docs/roadmap.md"
    }
  },
  "boundary_class": "prevent",
  "capability_id": "cap-bindings-001",
  "content_hash": "4062edaf750fb8074e7e83e0c9028c94e32468a8b6f161477\
      4328ef045150f93",
  "decision": {
    "verdict": "allow"
  },
  "evidence": [
    {
      "details": "path allowed",
      "guard_name": "ForbiddenPathGuard",
      "verdict": true
    },
    {
      "details": "no secrets detected",
      "guard_name": "SecretLeakGuard",
      "verdict": true
    }
  ],
  "id": "c9909f733d5fb367922293f0167d06db715393be114f212096cf2866f29\
      433ea",
  "kernel_key": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421\
      eea691446d22c",
  "metadata": {
    "surface": "bindings-vectors",
    "version": 1
  },
  "policy_hash": "policy-bindings-v1",
  "receipt_kind": "mediated_decision",
  "redaction_mode": "none",
  "signature": "67e3bfef7a6f3da592811e088d396f3186fbc1533632b273fbd3\
      a2f6ce60eb099418d256853398661d802d179ea869acb584bed757681f501f\
      2c40fd4fde790a",
  "timestamp": 1710000200,
  "tool_name": "file_read",
  "tool_origin": "caller_executed",
  "tool_server": "srv-files",
  "trust_level": "mediated"
}
~~~

The signing body of the receipt is the canonical form of a JSON object
with two members: `body`, which is the receipt without its `id` and
`signature` members, and `id`, which is the SHA-256 digest of the
canonical form of `body`, in lowercase hex. The
`receipt_body_canonical_json` value of the case is the canonical form of
the receipt without its `signature` member. The signing body is:
{: keepWithNext="true"}

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ================

{"body":{"action":{"parameter_hash":\
"035350b0e6a021a4c924a149111944945e94d12f6d8a5e24e4461e7009ebf929",\
"parameters":{"mode":"read","path":"/workspace/docs/roadmap.md"}},\
"boundary_class":"prevent","capability_id":"cap-bindings-001",\
"content_hash":\
"4062edaf750fb8074e7e83e0c9028c94e32468a8b6f1614774328ef045150f93",\
"decision":{"verdict":"allow"},"evidence":[{"details":\
"path allowed","guard_name":"ForbiddenPathGuard","verdict":true},\
{"details":"no secrets detected","guard_name":"SecretLeakGuard",\
"verdict":true}],"kernel_key":\
"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",\
"metadata":{"surface":"bindings-vectors","version":1},"policy_hash":\
"policy-bindings-v1","receipt_kind":"mediated_decision",\
"redaction_mode":"none","timestamp":1710000200,"tool_name":\
"file_read","tool_origin":"caller_executed","tool_server":\
"srv-files","trust_level":"mediated"},"id":\
"c9909f733d5fb367922293f0167d06db715393be114f212096cf2866f29433ea"}
~~~

The signing wrapper ({{signing-wrapper}}) of this body under the schema
id `chio.receipt.v1` is these 88 octets, in hex:
{: keepWithNext="true"}

~~~
=============== NOTE: '\' line wrapping per RFC 8792 ================

6368696f2e7369676e696e672d777261707065722e76310030a0a0cb00102ac64808\
db450924b39544cc41b773e6d2b7f0d899021a6c2ae16d0752cbe80e4a4f8204063c\
d20e9a17bbcb5c5ce16d3ea122fd05cfe80365ee
~~~

The `signature` member is an Ed25519 signature over the wrapper that
verifies under the key in `kernel_key`. The `parameter_hash` member of
`action` is the SHA-256 digest of the canonical form of its `parameters`
member, in the same encoding.
