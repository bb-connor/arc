"""Finite initialize rejection reader witness proposal; no path-only exemption.

Integrate only after Source retains the bounded object/borrowed-method helper.
The mask is the existing Rust-noise lexer; raw source must be test-masked Source
for this one exact path. Literals are retained separately because the existing
masked API alone cannot distinguish object/method literal substitutions.
No arbitrary regex or hash is read from the inventory catalog.
"""
import hashlib
import re

MCP_HTTP = "crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs"
RAW_SUPPORT = MCP_HTTP + "::initialize-reject-source"
API = "bounded-reject-only::object+borrowed-method62+immediate-refusal+same-wire-admission"
# Fixed reviewer-owned pins. Whitespace/comments can change; every literal and
# source token in this finite helper and its pre-DOM route remains reviewable.
SHAPE_TOKENS_SHA256 = 'fbf7cfca7ad6bdf69df0caab2678abcf82d70f6680840928f165dece96ba7f02'
POST_ROUTE_TOKENS_SHA256 = '1d87cecb9bee58562f04f6fd446281261224259c0e4f4802f40e568a4434f1ac'


def tokens(raw, lexer):
    result = []
    cursor = 0
    while True:
        match = lexer.RUST_NOISE.search(raw, cursor)
        if match is None:
            result.append("".join(raw[cursor:].split()))
            return "".join(result)
        result.append("".join(raw[cursor:match.start()].split()))
        if match.group(0).startswith("//"):
            cursor = match.end()
            continue
        if match.group(0) == "/*":
            depth, cursor = 1, match.end()
            while depth and cursor < len(raw):
                opened, closed = raw.find("/*", cursor), raw.find("*/", cursor)
                if closed < 0:
                    return None
                if opened >= 0 and opened < closed:
                    depth, cursor = depth + 1, opened + 2
                else:
                    depth, cursor = depth - 1, closed + 2
            if depth:
                return None
            continue
        if match.group(1) is not None:
            terminator = '"' + match.group(1)
            end = raw.find(terminator, match.end())
            if end < 0:
                return None
            cursor = end + len(terminator)
            result.append(raw[match.start():cursor])
            continue
        result.append(match.group(0))
        cursor = match.end()


def one_function(source, name, lexer):
    syntax = lexer.blank_rust_noise(source)
    starts = list(re.finditer(r"\b(?:async\s+)?fn\s+" + re.escape(name) + r"\s*(?:<[^{};]*>)?\s*\(", syntax))
    if len(starts) != 1:
        return None
    start = starts[0].start()
    body = syntax.find("{", starts[0].end())
    if body < 0:
        return None
    depth, end = 1, body + 1
    while depth and end < len(syntax):
        depth += (syntax[end] == "{") - (syntax[end] == "}")
        end += 1
    return None if depth else source[start:end]


def apis(path, reader, source, lexer):
    # Called with the raw test-masked Source for exactly this registered owner.
    if path != MCP_HTTP or reader != "initialize_request_shape" or not source:
        return []
    syntax = lexer.blank_rust_noise(source)
    if not re.search(r"\bconst\s+MCP_MAX_POST_BODY_BYTES\s*:\s*usize\s*=\s*8\s*\*\s*1024\s*\*\s*1024\s*;", syntax):
        return []
    if len(re.findall(r"\binitialize_request_shape\s*\(", syntax)) != 2:
        return []
    shape = one_function(source, "initialize_request_shape", lexer)
    post = one_function(source, "handle_post", lexer)
    if shape is None or post is None:
        return []
    shape_tokens = tokens(shape, lexer)
    if shape_tokens is None or hashlib.sha256(shape_tokens.encode()).hexdigest() != SHAPE_TOKENS_SHA256:
        return []
    post_syntax = lexer.blank_rust_noise(post)
    body = re.search(r"\blet\s*\(headers,\s*body\)\s*=\s*match\s+read_limited_mcp_post_body\(request\)\.await", post_syntax)
    admitted = re.search(r"\bsender\.decode\(&body,\s*MCP_MAX_POST_BODY_BYTES\)", post_syntax)
    if body is None or admitted is None or body.start() >= admitted.start():
        return []
    # Auth and format refusal checks remain before even the bounded pre-parser.
    positions = [post_syntax.find(name) for name in (
        "validate_origin", "authenticate_request", "validate_post_accept_header",
        "validate_content_type", "read_limited_mcp_post_body", "initialize_request_shape",
    )]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        return []
    route_tokens = tokens(post[body.start():admitted.end()], lexer)
    if route_tokens is None or hashlib.sha256(route_tokens.encode()).hexdigest() != POST_ROUTE_TOKENS_SHA256:
        return []
    return [API]
