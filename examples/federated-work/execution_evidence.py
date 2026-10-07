#!/usr/bin/env python3
"""Verify the bounded, single-receipt pre-settlement public witness offline.

Pins come from a separate caller-controlled file. One checkpoint with one leaf
is the supported funded profile. This authenticates signed source commitments;
it does not reconstruct the private request/evaluation preimages or establish
payment, budget, settlement, public anchoring, or independent-operator trust.
The allocation identifier is independently pinned, not derived or chain-verified.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

import funded_wire
from python_buyer.protocol import canonical, digest, fields, hex_bytes, inclusion, integer, require
from python_buyer.protocol import verify_signature as ed25519_verify

MAX_BYTES = 256 * 1024
PROFILE = 'chio.pre_settlement_execution.v1'
FACETS = ['artifact_integrity', 'receipt_authenticity', 'checkpoint_membership', 'guarantee_consistency']
IDENTITIES = ['authority_uuid', 'operation_id', 'request_id', 'hold_id', 'authorization_id', 'outcome_id']
HASHES = ['request_binding_hash', 'request_sha256', 'raw_outcome_sha256', 'resolved_output_sha256',
          'post_return_evaluation_sha256', 'post_guard_decision_sha256', 'pricing_verdict_sha256']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def text(value, limit=512, *, nonblank=False):
    require(type(value) is str and 0 < len(value.encode()) <= limit and '\0' not in value
            and (not nonblank or bool(value.strip())),
            'invalid bounded text')
    return value


def key(value):
    raw = hex_bytes(value)
    require(int.from_bytes(raw, 'little') & (2**255 - 1) < 2**255 - 19, 'noncanonical Ed25519 point')
    funded_wire.ed25519_key(value, weak=True)
    return value


def signature(body, sig, pin):
    key(pin)
    raw = hex_bytes(sig, 64)
    key(raw[:32].hex())
    require(int.from_bytes(raw[32:], 'little') < 2**252 + 27742317777372353535851937790883648493,
            'noncanonical signature scalar')
    ed25519_verify(body, sig, pin)


def signed(value, pin):
    fields(value, ['body', 'signerKey', 'signature'])
    require(value['signerKey'] == pin, 'envelope signer differs from pinned authority')
    signature(value['body'], value['signature'], pin)
    return value['body']


def load(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'artifact byte bound')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=funded_wire.pairs,
                           parse_float=funded_wire.forbidden_number, parse_constant=funded_wire.forbidden_number)
        require(canonical(value) == raw, 'artifact must be exact canonical JSON')
        def safe(child, depth=0):
            require(depth <= 64, 'artifact nesting bound')
            if type(child) is int:
                integer(child)
            elif type(child) is dict:
                for item in child.values():
                    safe(item, depth + 1)
            elif type(child) is list:
                for item in child:
                    safe(item, depth + 1)
        safe(value)
        return value
    except (UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError('invalid bounded canonical JSON') from error


def authority(policy, at):
    fields(policy, ['authority_id', 'key', 'key_epoch', 'valid_from', 'valid_until',
                    'rotation_policy_ref', 'revocation_status_ref'])
    for name in ['authority_id', 'rotation_policy_ref', 'revocation_status_ref']:
        text(policy[name], nonblank=True)
    key(policy['key'])
    integer(policy['key_epoch'], 1)
    integer(policy['valid_from'], 1, at)
    integer(policy['valid_until'], at + 1)
    return policy


def standing(status, policy, action_at, trust, now):
    authority(policy, action_at)
    body = signed(status, trust['status_authority']['key'])
    fields(body, ['schema', 'status_ref', 'authority_id', 'key', 'key_epoch', 'revoked_from', 'observed_at'])
    require(body['schema'] == 'chio.finding.authority-status.v1', 'unsupported authority status')
    integer(body['key_epoch'], 1)
    for status_name, policy_name in [('status_ref', 'revocation_status_ref'), ('authority_id', 'authority_id'),
                                     ('key', 'key'), ('key_epoch', 'key_epoch')]:
        require(body[status_name] == policy[policy_name], 'status changes exact authority role or epoch')
    observed = integer(body['observed_at'], action_at, now)
    authority(trust['status_authority'], observed)
    require(now - observed <= trust['max_age_secs'], 'stale authority status')
    # A revoked key can backdate new signatures, so artifact time cannot restore its authority.
    require(body['revoked_from'] is None, 'authority status reports a revoked signer')


def context(value, pins, now):
    fields(value, ['schema', 'governanceAuthority', 'profile', 'governanceStanding',
                   'admittedKernelKey', 'collateralAuthority'])
    require(value['schema'] == 'chio.experimental.funded-finding-context.v2', 'unsupported context')
    p = signed(value['profile'], value['governanceAuthority']['key'])
    fields(p, ['schema', 'profile_id', 'governance_authority', 'operator', 'receipt_signers', 'checkpoint_logs',
               'bbs_projection_issuer', 'allowed_runner_manifests', 'required_receipt_semantics', 'resolver_policy_ref',
               'retention_policy_ref', 'resource_caps', 'predicate_engine', 'allowed_predicates', 'required_facets',
               'verifier_report_signer', 'purchase_authority', 'failed_delivery_authority', 'issued_at', 'expires_at'])
    require(p['schema'] == 'chio.finding.challenge-verifier-profile.v1' and
            p['profile_id'] == digest({**p, 'profile_id': ''}), 'profile schema or content address differs')
    require(p['governance_authority'] == value['governanceAuthority']['key'], 'profile governance changed')
    require(p['required_receipt_semantics'] == PROFILE and p['required_facets'] == FACETS,
            'profile changes execution semantics or required facets')
    integer(p['issued_at'], 1, now)
    integer(p['expires_at'], now + 1, p['issued_at'] + 86400)
    for name in ['operator', 'resolver_policy_ref', 'retention_policy_ref']:
        text(p[name], nonblank=True)
    require(p['predicate_engine'] == 'chio-replay-v1' and
            p['allowed_predicates'] == ['baseline_fails_candidate_passes_v1'], 'unsupported predicate engine')
    caps = fields(p['resource_caps'], ['max_recipe_bytes', 'max_evidence_receipts', 'max_runtime_secs', 'max_memory_bytes'])
    for count in caps.values():
        integer(count, 1)
    require(caps['max_evidence_receipts'] == 1, 'profile must bound one evidence receipt')
    manifests = p['allowed_runner_manifests']
    require(type(manifests) is list and 1 <= len(manifests) <= 64, 'runner manifest bound')
    for manifest in manifests:
        hex_bytes(manifest)
    require(len(set(manifests)) == len(manifests), 'duplicate runner manifest')
    bbs = fields(p['bbs_projection_issuer'], ['issuer_fingerprint', 'key_hex', 'registry_ref', 'key_epoch',
                                              'valid_from', 'valid_until', 'revocation_status_ref'])
    for name in ['issuer_fingerprint', 'key_hex', 'registry_ref', 'revocation_status_ref']:
        text(bbs[name], nonblank=True)
    integer(bbs['key_epoch'], 1)
    integer(bbs['valid_from'], 1)
    integer(bbs['valid_until'], bbs['valid_from'] + 1)
    for policy in [value['governanceAuthority'], value['collateralAuthority'], p['verifier_report_signer'],
                   p['purchase_authority'], p['failed_delivery_authority']]:
        authority(policy, now)
    require(p['verifier_report_signer']['key'] == pins['verifier'], 'verifier differs from external pin')
    roles = p['receipt_signers']
    require(type(roles) is list and len(roles) == 3, 'exact three receipt signer roles required')
    by_role = {}
    for role in roles:
        fields(role, ['role', 'policy'])
        require(type(role['role']) is str and role['role'] not in by_role, 'duplicate receipt signer role')
        by_role[role['role']] = authority(role['policy'], now)
    require(set(by_role) == {'production', 'delivery', 'replay'}, 'unknown receipt role')
    require(len({r['key'] for r in by_role.values()}) == 3, 'receipt signer role collision')
    require(by_role['production']['key'] == value['admittedKernelKey'], 'production kernel is not admitted')
    logs = p['checkpoint_logs']
    require(type(logs) is list and len(logs) == 1, 'exact one checkpoint log required')
    log = fields(logs[0], ['log_id', 'signer'])
    cp_policy = authority(log['signer'], now)
    require(log['log_id'] == 'local-log-' + sha(hex_bytes(cp_policy['key'])), 'checkpoint log alias')
    authority_keys = [p['governance_authority'], p['verifier_report_signer']['key'],
                      p['purchase_authority']['key'], p['failed_delivery_authority']['key']]
    require(len(set(authority_keys)) == len(authority_keys), 'profile authority role collision')
    require(all(policy['key'] not in authority_keys for policy in by_role.values()) and
            cp_policy['key'] not in authority_keys, 'artifact signer aliases profile authority')
    # Every role above covers now, so their validity windows overlap.
    require(all(policy['key'] != cp_policy['key'] for policy in by_role.values()),
            'receipt and checkpoint signer role collision')
    trust = fields(value['governanceStanding'], ['signed_statuses', 'status_authority', 'max_age_secs'])
    authority(trust['status_authority'], now)
    integer(trust['max_age_secs'], 1, 86400)
    require(type(trust['signed_statuses']) is list and len(trust['signed_statuses']) == 1,
            'bootstrap must retain exact governance status')
    distinct = [pins['buyer'], pins['provider'], pins['verifier'], cp_policy['key'],
                value['governanceAuthority']['key'], trust['status_authority']['key']]
    require(len(set(distinct)) == len(distinct), 'authority role collision')
    require(value['admittedKernelKey'] not in [k for k in distinct if k != pins['provider']],
            'kernel collides with unrelated authority role')
    standing(trust['signed_statuses'][0], value['governanceAuthority'], p['issued_at'], trust, now)
    return p, by_role['production'], cp_policy, trust


def receipt(value, agreement, submission, admitted, now):
    fields(value, ['id', 'timestamp', 'capability_id', 'tool_server', 'tool_name', 'action', 'decision',
                   'receipt_kind', 'boundary_class', 'tool_origin', 'redaction_mode', 'content_hash',
                   'policy_hash', 'metadata', 'trust_level', 'kernel_key', 'signature'],
           ['tenant_id'])
    require(value['kernel_key'] == admitted, 'receipt signer is not admitted')
    require(value['receipt_kind'] == 'mediated_decision' and value['boundary_class'] == 'prevent' and
            value['tool_origin'] == 'chio_internal' and value['redaction_mode'] == 'none' and
            value['trust_level'] == 'mediated' and value['decision'] == {'verdict': 'allow'},
            'receipt is not native execution-only allow evidence')
    require(value['tool_server'] == 'experimental-funded-w0' and value['tool_name'] == 'review', 'unsupported native tool')
    integer(value['timestamp'], 1, now)
    text(value['capability_id'])
    for name in ['id', 'content_hash', 'policy_hash']:
        hex_bytes(value[name])
    if 'tenant_id' in value:
        text(value['tenant_id'])
    action = fields(value['action'], ['parameters', 'parameter_hash'])
    parameters = fields(action['parameters'], ['input'], ['chio_capture_waiver_terms_digest'])
    waiver = agreement.get('captureWaiverTerms')
    require(('chio_capture_waiver_terms_digest' in parameters) == (waiver is not None),
            'native action differs from original waiver commitment')
    if waiver is not None:
        # Authenticate the action commitment covered by both agreement
        # signatures. Financial waiver authorization remains a native check.
        require(parameters['chio_capture_waiver_terms_digest'] == digest(waiver) and
                waiver['body']['requestId'] == agreement['requestId'] and
                waiver['body']['contractContextDigest'] == digest(dict(
                    schema='chio.experimental.native-funded-waiver-context.v1',
                    domain=agreement['domain'], work=agreement['work'])),
                'native action changes original waiver terms')
    require(type(parameters['input']) is str and len(parameters['input'].encode()) <= 65536, 'input byte bound')
    require(action['parameter_hash'] == digest(parameters) and
            submission['inputSha256'] == sha(parameters['input'].encode()), 'action or input digest differs')
    metadata = fields(value['metadata'], ['receipt_semantics', 'execution_evidence'],
                      ['chio_receipt_signing_nonce', 'receipt_context'])
    require(metadata['receipt_semantics'] == {'profile': PROFILE}, 'receipt changes execution profile')
    evidence = fields(metadata['execution_evidence'], ['schema', 'phase'] + IDENTITIES + HASHES)
    require(evidence['schema'] == 'chio.execution_evidence.v1' and evidence['phase'] == 'execution_confirmed',
            'execution schema or phase differs')
    for name in IDENTITIES:
        text(evidence[name])
    for name in HASHES + ['outcome_id']:
        hex_bytes(evidence[name])
    if 'chio_receipt_signing_nonce' in metadata:
        text(metadata['chio_receipt_signing_nonce'])
    if 'receipt_context' in metadata:
        require(type(metadata['receipt_context']) is dict, 'receipt context must be object')
        if 'request_id' in metadata['receipt_context']:
            require(metadata['receipt_context']['request_id'] == evidence['request_id'], 'receipt request context changed')
    binding = submission['binding']
    for snake, camel in [('authority_uuid', 'authorityUuid'), ('operation_id', 'operationId'), ('hold_id', 'holdId'),
                         ('authorization_id', 'authorizationId'), ('outcome_id', 'outcomeId'),
                         ('request_sha256', 'requestSha256'), ('raw_outcome_sha256', 'rawOutcomeSha256')]:
        require(evidence[snake] == binding[camel], 'receipt changes original native binding: ' + snake)
    require(evidence['request_id'] == agreement['requestId'] and
            evidence['request_sha256'] == agreement['requestSha256'], 'receipt changes agreed request')
    require(value['policy_hash'] == agreement['policySha256'], 'receipt changes agreed native policy')
    require(evidence['resolved_output_sha256'] == value['content_hash'], 'resolved output differs from receipt content')
    body = {k: v for k, v in value.items() if k not in ['id', 'signature']}
    require(value['id'] == digest(body), 'receipt content address differs')
    signature({'id': value['id'], 'body': body}, value['signature'], admitted)
    return evidence


def checkpoint(bundle, finding, cp_policy, trust, production_policy, now):
    cps = bundle['checkpoints']
    require(type(cps) is list and len(cps) == 1, 'single-checkpoint profile requires complete one-entry prefix')
    cp = fields(cps[0], ['body', 'signature'])
    body = fields(cp['body'], ['schema', 'checkpoint_seq', 'batch_start_seq', 'batch_end_seq', 'tree_size',
                              'merkle_root', 'chain_root', 'issued_at', 'kernel_key'])
    for name in ['checkpoint_seq', 'batch_start_seq', 'batch_end_seq', 'tree_size']:
        integer(body[name], 1, 1)
    integer(body['issued_at'], bundle['receipt']['timestamp'], finding['issued_at'])
    signature(body, cp['signature'], cp_policy['key'])
    inclusion(bundle['receipt'], cp, bundle['inclusion'], cp_policy['key'])
    leaf = {name: body[name] for name in ['checkpoint_seq', 'batch_start_seq', 'batch_end_seq', 'merkle_root']}
    require(body['chain_root'] == '0x' + sha(b'\0' + canonical(leaf)), 'checkpoint chain root differs')
    log_id = 'local-log-' + sha(hex_bytes(cp_policy['key']))
    require(finding['evidence_checkpoint_ref'] == log_id + '#1', 'Finding changes checkpoint reference')
    expected = dict(schema='chio.checkpoint_publication.v1', log_id='local-log-' + sha(hex_bytes(cp_policy['key'])),
                    checkpoint_seq=1, checkpoint_sha256=digest(body), merkle_root=body['merkle_root'],
                    published_at=body['issued_at'], kernel_key=body['kernel_key'], log_tree_size=1,
                    entry_start_seq=1, entry_end_seq=1)
    require(canonical(bundle['transparency']) == canonical(dict(publications=[expected], witnesses=[],
                                                              consistency_proofs=[], equivocations=[])),
            'transparency differs from independently derived complete prefix')
    statuses = bundle['signerStatuses']
    require(type(statuses) is list and len(statuses) == 2, 'exact production and checkpoint status required')
    standing(statuses[0], production_policy, bundle['receipt']['timestamp'], trust, now)
    standing(statuses[1], cp_policy, body['issued_at'], trust, now)
    return digest(body)


def verify(raw, pins, now):
    integer(now, 1)
    fields(pins, ['buyer', 'provider', 'verifier', 'authorityUuid', 'allocationId'])
    require(any(hex_bytes(pins['allocationId'], prefix='0x')), 'zero allocation pin')
    for name in ['buyer', 'provider', 'verifier']:
        key(pins[name])
    text(pins['authorityUuid'])
    value = fields(load(raw), ['agreement', 'submission', 'context', 'bundle', 'output'])
    a, s = value['agreement'], value['submission']
    funded_wire.parse(canonical(a))
    funded_wire.parse(canonical(s))
    agreement, submission = a['body'], s['body']
    require(agreement['buyerKey'] == pins['buyer'] and agreement['providerKey'] == pins['provider'] and
            agreement['authorityUuid'] == pins['authorityUuid'], 'agreement differs from external pins')
    signature(agreement, a['buyerSignature'], pins['buyer'])
    signature(agreement, a['providerSignature'], pins['provider'])
    signature(submission, s['signature'], pins['provider'])
    require(agreement['requiredFindingFacets'] == FACETS and agreement['work']['amount'] == '100',
            'agreement exceeds supported execution profile')
    require(agreement['findingContextSha256'] == digest(value['context']), 'original context pin differs')
    p, production, cp_policy, trust = context(value['context'], pins, now)
    binding = submission['binding']
    require(binding['agreementSha256'] == digest(agreement) and binding['requestSha256'] == agreement['requestSha256'] and
            binding['authorityUuid'] == pins['authorityUuid'] and binding['allocationId'] == pins['allocationId'] and
            binding['expiresAt'] == agreement['work']['refundAfter'],
            'submission changes original agreement or native authority')
    finding = submission['finding']
    signature({**finding, 'signature': ''}, finding['signature'], pins['provider'])
    require(finding['issuer'] == pins['provider'] and finding['descriptor'] == dict(
        context_sha256=digest(binding), topic='security:openapi:authentication-declarations', outcome_class='positive_result'),
        'Finding issuer or original Binding differs')
    integer(finding['issued_at'], p['issued_at'], now)
    require(finding['expires_at'] == binding['expiresAt'] and now < finding['expires_at'], 'Finding validity differs')
    require(finding['guarantee_class'] == 'asserted' and finding['evidence_class'] == 'asserted' and
            finding['bond_ref'] == 'unbacked:experimental-funded-w0' and
            finding['status_feed_ref'] == 'unavailable:experimental-funded-w0' and
            finding['evidence_cost'] == {'currency': 'XTS', 'units': 100} and
            not any(name in finding for name in ['runtime_assurance_tier', 'replay_recipe_sha256',
                                                 'intent_commitment_receipt_id', 'license_ref', 'price_hint_ref']),
            'Finding invents unsupported assurance')
    output = canonical(value['output'])
    require(submission['outputSha256'] == sha(output), 'submitted output digest differs')
    reveal = dict(media_type='application/json', payload_b64=base64.b64encode(output).decode())
    require(finding['payload_media_type'] == 'application/json' and finding['payload_sha256'] == digest(reveal),
            'Finding payload commitment differs')
    bundle = fields(value['bundle'], ['schema', 'receipt', 'checkpoints', 'inclusion', 'transparency', 'signerStatuses'])
    require(bundle['schema'] == 'chio.experimental.funded-execution-bundle.v1', 'unsupported bundle')
    metadata = receipt(bundle['receipt'], agreement, submission, value['context']['admittedKernelKey'], now)
    require(finding['evidence_receipt_ids'] == [bundle['receipt']['id']], 'Finding receipt reference differs')
    checkpoint_hash = checkpoint(bundle, finding, cp_policy, trust, production, now)
    return dict(schema='chio.experimental.funded-execution-verification.v1', authorityVerified=True,
                authorityUuid=pins['authorityUuid'], allocationId=pins['allocationId'], allocationPinVerified=True,
                evaluatedAt=now, profile=PROFILE,
                agreementSha256=digest(agreement), contextSha256=digest(value['context']), findingId=finding['finding_id'],
                receiptSha256=digest(bundle['receipt']), receiptId=bundle['receipt']['id'], checkpointSha256=checkpoint_hash,
                evidenceSha256=digest(bundle), executionMatchesSubmission=metadata['resolved_output_sha256'] == sha(output),
                financialBacking=False, meteredExposureBacking=False, settledSpendBacking=False,
                sourcePreimagesRecomputed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifact', type=Path)
    parser.add_argument('--pins', type=Path, required=True)
    parser.add_argument('--evaluated-at', type=int, required=True)
    args = parser.parse_args()
    try:
        with args.artifact.open('rb') as source:
            raw = source.read(MAX_BYTES + 1)
        with args.pins.open('rb') as source:
            pins = load(source.read(MAX_BYTES + 1))
        sys.stdout.buffer.write(canonical(verify(raw, pins, args.evaluated_at)) + b'\n')
        return 0
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, RuntimeError, OSError) as error:
        print(f'execution evidence rejected: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
