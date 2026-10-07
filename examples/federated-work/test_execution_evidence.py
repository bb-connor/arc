"""Independent execution checks with real Ed25519 signatures, no Rust process."""
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from python_buyer.protocol import canonical, digest, sign

HERE = Path(__file__).parent
NOW = 1800000010
FACETS = ['artifact_integrity', 'receipt_authenticity', 'checkpoint_membership', 'guarantee_consistency']
PROFILE = 'chio.pre_settlement_execution.v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    def __init__(self):
        self.keys = {name: Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32)
                     for i, name in enumerate(['buyer', 'provider', 'verifier', 'governance', 'status',
                                               'kernel', 'checkpoint', 'delivery', 'replay', 'collateral',
                                               'purchase', 'failed'], 1)}
        self.pins = {k: self.pub(k) for k in ['buyer', 'provider', 'verifier']}
        self.pins['authorityUuid'] = 'authority-original'
        agreement = json.loads((HERE / 'fixtures/registered-work/agreement.json').read_bytes())
        submission = json.loads((HERE / 'fixtures/registered-work/submission.json').read_bytes())
        a = agreement['body']
        a.update(authorityUuid=self.pins['authorityUuid'], buyerKey=self.pub('buyer'),
                 providerKey=self.pub('provider'), requiredFindingFacets=FACETS[:])
        a['work'].update(submitBy=NOW + 10, challengeUntil=NOW + 20, resolveBy=NOW + 30, refundAfter=NOW + 40)
        submission['body']['outputSha256'] = digest({'result': 'original output'})
        b = submission['body']['binding']
        self.pins['allocationId'] = b['allocationId']
        b.update(authorityUuid=a['authorityUuid'], requestSha256=a['requestSha256'], expiresAt=NOW + 40)
        p = dict(schema='chio.finding.challenge-verifier-profile.v1', profile_id='',
                 governance_authority=self.pub('governance'), operator='funded-w0-fixture',
                 receipt_signers=[dict(role=role, policy=self.authority(key))
                                 for role, key in [('production', 'kernel'), ('delivery', 'delivery'), ('replay', 'replay')]],
                 checkpoint_logs=[dict(log_id='local-log-' + sha(bytes.fromhex(self.pub('checkpoint'))),
                                       signer=self.authority('checkpoint'))],
                 bbs_projection_issuer=dict(issuer_fingerprint='unavailable:fixture', key_hex='00' * 32,
                                            registry_ref='unavailable:fixture', key_epoch=1, valid_from=NOW - 10,
                                            valid_until=NOW + 40, revocation_status_ref='unavailable:fixture'),
                 allowed_runner_manifests=[digest('no-runner')], required_receipt_semantics=PROFILE,
                 resolver_policy_ref='funded-w0-execution-evidence-v1', retention_policy_ref='funded-w0-journal-v1',
                 resource_caps=dict(max_recipe_bytes=262144, max_evidence_receipts=1,
                                    max_runtime_secs=60, max_memory_bytes=16777216),
                 predicate_engine='chio-replay-v1', allowed_predicates=['baseline_fails_candidate_passes_v1'],
                 required_facets=FACETS[:], verifier_report_signer=self.authority('verifier'),
                 purchase_authority=self.authority('purchase'), failed_delivery_authority=self.authority('failed'),
                 issued_at=NOW - 10, expires_at=NOW + 40)
        p['profile_id'] = digest(p)
        context = dict(schema='chio.experimental.funded-finding-context.v2',
                       governanceAuthority=self.authority('governance'), profile=sign(p, self.keys['governance']),
                       governanceStanding=dict(signed_statuses=[self.status('governance', NOW - 10)],
                                               status_authority=self.authority('status'), max_age_secs=50),
                       admittedKernelKey=self.pub('kernel'), collateralAuthority=self.authority('collateral'))
        r = dict(timestamp=NOW - 5, capability_id='cap-original', tool_server='experimental-funded-w0',
                 tool_name='review', action=dict(parameters=dict(input='original input'),
                                                parameter_hash=digest(dict(input='original input'))),
                 decision=dict(verdict='allow'), receipt_kind='mediated_decision', boundary_class='prevent',
                 tool_origin='chio_internal', redaction_mode='none', trust_level='mediated',
                 content_hash=submission['body']['outputSha256'], policy_hash=a['policySha256'], kernel_key=self.pub('kernel'),
                 metadata=dict(receipt_semantics=dict(profile=PROFILE), execution_evidence=dict(
                     schema='chio.execution_evidence.v1', phase='execution_confirmed', authority_uuid=b['authorityUuid'],
                     operation_id=b['operationId'], request_id=a['requestId'], request_binding_hash='cd' * 32,
                     request_sha256=a['requestSha256'], hold_id=b['holdId'], authorization_id=b['authorizationId'],
                     outcome_id=b['outcomeId'], raw_outcome_sha256=b['rawOutcomeSha256'],
                     resolved_output_sha256=submission['body']['outputSha256'], post_return_evaluation_sha256='dd' * 32,
                     post_guard_decision_sha256='ee' * 32, pricing_verdict_sha256='ff' * 32)))
        self.value = dict(agreement=agreement, submission=submission, context=context, output={'result': 'original output'},
                          bundle=dict(schema='chio.experimental.funded-execution-bundle.v1', receipt=r))
        submission['body']['inputSha256'] = sha(b'original input')
        submission['body']['finding'].update(issuer=self.pub('provider'), issued_at=NOW - 2, expires_at=b['expiresAt'])
        self.resign_context()
        self.resign_receipt()

    def add_waiver_argument(self):
        a = self.value['agreement']['body']
        body = dict(schema='chio.contractual-capture-waiver.v1', policyDigest='12' * 32,
                    contractContextDigest=digest(dict(schema='chio.experimental.native-funded-waiver-context.v1',
                                                     domain=a['domain'], work=a['work'])),
                    capabilityDigest='34' * 32, requestId=a['requestId'],
                    issuedAtUnixMs=(NOW - 8) * 1000, expiresAtUnixMs=(NOW + 40) * 1000)
        terms = dict(body=body, receiverSignature=self.keys['provider'].sign(canonical(body)).hex(),
                     counterpartySignature=self.keys['buyer'].sign(canonical(body)).hex())
        a['captureWaiverTerms'] = terms
        action = self.value['bundle']['receipt']['action']
        action['parameters']['chio_capture_waiver_terms_digest'] = digest(terms)
        action['parameter_hash'] = digest(action['parameters'])
        self.resign_context()
        self.resign_receipt()

    def pub(self, name):
        return self.keys[name].public_key().public_bytes_raw().hex()

    def authority(self, name):
        return dict(authority_id='fixture/' + name, key=self.pub(name), key_epoch=1, valid_from=NOW - 10,
                    valid_until=NOW + 40, rotation_policy_ref='rotation/' + name, revocation_status_ref='status/' + name)

    def status(self, name, observed):
        p = self.authority(name)
        return sign(dict(schema='chio.finding.authority-status.v1', status_ref=p['revocation_status_ref'],
                         authority_id=p['authority_id'], key=p['key'], key_epoch=1, revoked_from=None,
                         observed_at=observed), self.keys['status'])

    def resign_context(self):
        c = self.value['context']
        p = c['profile']['body']
        p['profile_id'] = digest({**p, 'profile_id': ''})
        c['profile'] = sign(p, self.keys['governance'])
        a = self.value['agreement']['body']
        a['findingContextSha256'] = digest(c)
        self.value['agreement'] = dict(body=a, buyerSignature=self.keys['buyer'].sign(canonical(a)).hex(),
                                       providerSignature=self.keys['provider'].sign(canonical(a)).hex())
        self.value['submission']['body']['binding']['agreementSha256'] = digest(a)
        self.resign_submission()

    def resign_submission(self):
        s = self.value['submission']['body']
        f = s['finding']
        f['descriptor']['context_sha256'] = digest(s['binding'])
        f['payload_sha256'] = digest(dict(media_type='application/json', payload_b64=base64.b64encode(canonical(self.value['output'])).decode()))
        f['finding_id'] = digest({**f, 'finding_id': '', 'signature': ''})
        f['signature'] = self.keys['provider'].sign(canonical({**f, 'signature': ''})).hex()
        self.value['submission'] = sign(s, self.keys['provider'], envelope=False)

    def resign_receipt(self):
        bundle = self.value['bundle']
        r = bundle['receipt']
        body = {k: v for k, v in r.items() if k not in ['id', 'signature']}
        r['id'] = digest(body)
        r['signature'] = self.keys['kernel'].sign(canonical(dict(id=r['id'], body=body))).hex()
        root = '0x' + sha(b'\0' + canonical(r))
        chain = dict(checkpoint_seq=1, batch_start_seq=1, batch_end_seq=1, merkle_root=root)
        cp = dict(schema='chio.checkpoint_statement.v2', **chain, tree_size=1, issued_at=NOW - 3,
                  kernel_key=self.pub('checkpoint'), chain_root='0x' + sha(b'\0' + canonical(chain)))
        bundle['checkpoints'] = [sign(cp, self.keys['checkpoint'], envelope=False)]
        bundle['inclusion'] = dict(checkpoint_seq=1, receipt_seq=1, leaf_index=0, merkle_root=root,
                                   proof=dict(audit_path=[], leaf_index=0, tree_size=1))
        publication = dict(schema='chio.checkpoint_publication.v1',
                           log_id='local-log-' + sha(bytes.fromhex(self.pub('checkpoint'))),
                           checkpoint_seq=1, checkpoint_sha256=digest(cp), merkle_root=root,
                           published_at=cp['issued_at'], kernel_key=cp['kernel_key'], log_tree_size=1,
                           entry_start_seq=1, entry_end_seq=1)
        bundle['transparency'] = dict(publications=[publication], witnesses=[], consistency_proofs=[], equivocations=[])
        bundle['signerStatuses'] = [self.status('kernel', NOW - 3), self.status('checkpoint', NOW - 3)]
        f = self.value['submission']['body']['finding']
        f['evidence_receipt_ids'] = [r['id']]
        f['evidence_checkpoint_ref'] = publication['log_id'] + '#1'
        self.resign_submission()


class ExecutionEvidenceTests(unittest.TestCase):
    def test_checkpoint_reference_requires_original_log_identity(self):
        f = self.fixture.value['submission']['body']['finding']
        f['evidence_checkpoint_ref'] = digest(self.fixture.value['bundle']['checkpoints'][0]['body'])
        self.fixture.resign_submission()
        with self.assertRaises(ValueError):
            self.verify()

    def test_signed_receipt_cannot_change_agreed_policy(self):
        self.fixture.value['bundle']['receipt']['policy_hash'] = 'dc' * 32
        self.fixture.resign_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def setUp(self):
        self.fixture = Fixture()
        self.assertIsNotNone(importlib.util.find_spec('execution_evidence'), 'independent verifier is not implemented')
        import execution_evidence
        self.verifier = execution_evidence

    def verify(self):
        return self.verifier.verify(canonical(self.fixture.value), self.fixture.pins, NOW)

    def test_valid_signed_evidence_has_no_financial_backing(self):
        result = self.verify()
        self.assertTrue(result['authorityVerified'])
        self.assertTrue(result['allocationPinVerified'])
        self.assertEqual(result['allocationId'], self.fixture.pins['allocationId'])
        self.assertFalse(result['financialBacking'])
        self.assertFalse(result['settledSpendBacking'])
        self.assertTrue(result['executionMatchesSubmission'])
        self.assertEqual(result['receiptSha256'], digest(self.fixture.value['bundle']['receipt']))

    def test_supported_provider_is_also_native_kernel(self):
        self.fixture.keys['kernel'] = self.fixture.keys['provider']
        c = self.fixture.value['context']
        c['admittedKernelKey'] = self.fixture.pub('provider')
        c['profile']['body']['receipt_signers'][0]['policy']['key'] = self.fixture.pub('provider')
        self.fixture.value['bundle']['receipt']['kernel_key'] = self.fixture.pub('provider')
        self.fixture.resign_context()
        self.fixture.resign_receipt()
        self.assertTrue(self.verify()['authorityVerified'])

    def test_authenticated_negative_output_is_reported_without_payment(self):
        self.fixture.value['output'] = {'result': 'different submitted output'}
        self.fixture.value['submission']['body']['outputSha256'] = digest(self.fixture.value['output'])
        self.fixture.resign_submission()
        result = self.verify()
        self.assertFalse(result['executionMatchesSubmission'])
        self.assertFalse(result['financialBacking'])

    def test_core_rejects_actor_chain_and_non_digest_outcome(self):
        self.fixture.value['bundle']['receipt']['actor_chain'] = [{'actor_id': 'caller'}]
        self.fixture.resign_receipt()
        with self.assertRaises(ValueError):
            self.verify()
        self.fixture = Fixture()
        self.fixture.value['submission']['body']['binding']['outcomeId'] = 'not-a-digest'
        self.fixture.value['bundle']['receipt']['metadata']['execution_evidence']['outcome_id'] = 'not-a-digest'
        self.fixture.resign_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def test_signed_checkpoint_chronology_and_forks(self):
        for name, value in [('checkpoint_seq', 2), ('tree_size', 2), ('batch_start_seq', 2),
                            ('chain_root', '0x' + '00' * 32), ('issued_at', NOW - 8),
                            ('previous_checkpoint_sha256', 'aa' * 32)]:
            self.fixture = Fixture()
            cp = self.fixture.value['bundle']['checkpoints'][0]
            cp['body'][name] = value
            cp['signature'] = self.fixture.keys['checkpoint'].sign(canonical(cp['body'])).hex()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()

    def test_output_and_finding_content_addresses(self):
        self.fixture.value['output'] = {'result': 'changed unsigned payload'}
        with self.assertRaises(ValueError):
            self.verify()
        self.fixture = Fixture()
        self.fixture.value['submission']['body']['finding']['finding_id'] = '00' * 32
        f = self.fixture.value['submission']['body']['finding']
        f['signature'] = self.fixture.keys['provider'].sign(canonical({**f, 'signature': ''})).hex()
        self.fixture.value['submission'] = sign(self.fixture.value['submission']['body'],
                                                self.fixture.keys['provider'], envelope=False)
        with self.assertRaises(ValueError):
            self.verify()

    def test_cli_requires_external_pins_and_emits_canonical_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / 'artifact.json'
            pins = Path(directory) / 'pins.json'
            artifact.write_bytes(canonical(self.fixture.value))
            pins.write_bytes(canonical(self.fixture.pins))
            command = [sys.executable, str(HERE / 'execution_evidence.py'), str(artifact),
                       '--pins', str(pins), '--evaluated-at', str(NOW)]
            result = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, canonical(self.verify()) + b'\n')
            self.fixture.pins['authorityUuid'] = 'substituted-pin'
            pins.write_bytes(canonical(self.fixture.pins))
            rejected = subprocess.run(command, capture_output=True, check=False)
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(rejected.stdout, b'')
            self.assertIn(b'execution evidence rejected', rejected.stderr)

    def test_status_authority_and_governance_validity_are_checked(self):
        for target in ['governanceAuthority', 'status_authority']:
            self.fixture = Fixture()
            c = self.fixture.value['context']
            policy = c[target] if target == 'governanceAuthority' else c['governanceStanding'][target]
            policy['valid_until'] = NOW - 4
            self.fixture.resign_context()
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.verify()
        self.fixture = Fixture()
        self.fixture.value['context']['governanceStanding']['max_age_secs'] = 1
        self.fixture.resign_context()
        with self.assertRaises(ValueError):
            self.verify()

    def test_unknown_nested_fields_and_null_optionals_are_rejected(self):
        mutations = [lambda v: v['context'].update(privateKey='secret'),
                     lambda v: v['bundle'].update(settled=True),
                     lambda v: v['bundle']['receipt'].update(tenant_id=None),
                     lambda v: v['bundle']['receipt'].update(evidence=[]),
                     lambda v: v['bundle']['receipt']['metadata'].update(chio_receipt_signing_nonce=''),
                     lambda v: v['bundle']['receipt']['metadata'].update(receipt_context=None)]
        for mutate in mutations:
            self.fixture = Fixture()
            mutate(self.fixture.value)
            self.fixture.resign_context()
            self.fixture.resign_receipt()
            with self.assertRaises(ValueError):
                self.verify()

    def test_any_revoked_signer_rejects_even_when_artifact_is_backdated(self):
        for role in ['governance', 'production', 'checkpoint']:
            self.fixture = Fixture()
            if role == 'governance':
                statuses = self.fixture.value['context']['governanceStanding']['signed_statuses']
                index = 0
            else:
                statuses = self.fixture.value['bundle']['signerStatuses']
                index = 0 if role == 'production' else 1
            body = statuses[index]['body']
            body.update(observed_at=NOW, revoked_from=NOW - 1)
            statuses[index] = sign(body, self.fixture.keys['status'])
            self.fixture.resign_context()
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, 'revoked'):
                self.verify()

    def test_rust_authority_role_separation_is_preserved(self):
        collisions = [('purchase_authority', 'governance'), ('failed_delivery_authority', 'verifier'),
                      ('delivery', 'governance'), ('replay', 'checkpoint'), ('purchase_authority', 'kernel')]
        for target, source in collisions:
            self.fixture = Fixture()
            p = self.fixture.value['context']['profile']['body']
            if target in ['delivery', 'replay']:
                policy = next(item['policy'] for item in p['receipt_signers'] if item['role'] == target)
            else:
                policy = p[target]
            policy['key'] = self.fixture.pub(source)
            self.fixture.resign_context()
            with self.subTest(target=target, source=source), self.assertRaises(ValueError):
                self.verify()

    def test_provider_cannot_substitute_original_allocation(self):
        self.fixture.value['submission']['body']['binding']['allocationId'] = '0x' + 'aa' * 32
        self.fixture.resign_submission()
        with self.assertRaises(ValueError):
            self.verify()

    def test_blank_signed_profile_identifiers_reject(self):
        self.fixture.value['context']['profile']['body']['operator'] = ' '
        self.fixture.resign_context()
        with self.assertRaises(ValueError):
            self.verify()

    def test_native_execution_does_not_carry_copied_guard_evidence(self):
        self.fixture.value['bundle']['receipt']['evidence'] = [
            {'guard_name': 'invented-copy', 'verdict': True, 'details': 'not source evaluation evidence'}]
        self.fixture.resign_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def test_allocation_pin_is_required_strict_nonzero_hex(self):
        for value in [None, '0x' + '00' * 32, '0x' + 'AA' * 32, 'aa' * 32, True]:
            self.fixture = Fixture()
            self.fixture.pins['allocationId'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verify()
        del self.fixture.pins['allocationId']
        with self.assertRaises(ValueError):
            self.verify()

    def test_original_waiver_argument_is_part_of_signed_native_action(self):
        self.fixture.add_waiver_argument()
        self.assertTrue(self.verify()['executionMatchesSubmission'])

    def test_waiver_argument_cannot_substitute_original_signed_terms(self):
        self.fixture.add_waiver_argument()
        action = self.fixture.value['bundle']['receipt']['action']
        action['parameters']['chio_capture_waiver_terms_digest'] = 'ab' * 32
        action['parameter_hash'] = digest(action['parameters'])
        self.fixture.resign_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def test_external_pins_cannot_be_self_authorized(self):
        for key in self.fixture.pins:
            f = Fixture()
            f.pins[key] = ('0x' + 'aa' * 32 if key == 'allocationId' else
                           'other-authority' if key == 'authorityUuid' else f.pub('delivery'))
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verifier.verify(canonical(f.value), f.pins, NOW)

    def test_raw_exact_typed_canonical_bounds(self):
        raw = canonical(self.fixture.value)
        variants = [raw + b'\n', b' ' + raw, raw.replace(b'"bundle":', b'"bundle":{},"bundle":', 1),
                    raw.replace(b'"bundle":', b'"bu\\u006edle":{},"bundle":', 1),
                    raw.replace(str(NOW - 5).encode(), b'1.0', 1), b'x' * 262145]
        for raw in variants:
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                self.verifier.verify(raw, self.fixture.pins, NOW)

    def test_signed_execution_semantic_substitutions(self):
        for key, value in [('phase', 'settled'), ('schema', 'unknown'), ('hold_id', 'other'),
                           ('operation_id', 'other'), ('authority_uuid', 'other'), ('request_id', 'other'),
                           ('request_sha256', 'ab' * 32), ('authorization_id', 'other'), ('outcome_id', 'other'),
                           ('raw_outcome_sha256', 'ab' * 32), ('resolved_output_sha256', 'ab' * 32),
                           ('post_return_evaluation_sha256', 'AB' * 32), ('pricing_verdict_sha256', None)]:
            self.fixture = Fixture()
            self.fixture.value['bundle']['receipt']['metadata']['execution_evidence'][key] = value
            self.fixture.resign_receipt()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()

    def test_signed_financial_metadata_is_never_execution_authority(self):
        for key in ['financial', 'budget_authority', 'execution_nonce', 'mediated_spend', 'spent', 'settled']:
            self.fixture = Fixture()
            self.fixture.value['bundle']['receipt']['metadata'][key] = {'claim': True}
            self.fixture.resign_receipt()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()

    def test_signed_caller_advisory_and_denial_are_rejected(self):
        for key, value in [('tool_origin', 'caller_executed'), ('receipt_kind', 'advisory_evaluation'),
                           ('decision', {'verdict': 'deny', 'reason': 'no', 'guard': 'test'}),
                           ('content_hash', 'aa' * 32), ('timestamp', NOW + 1)]:
            self.fixture = Fixture()
            self.fixture.value['bundle']['receipt'][key] = value
            self.fixture.resign_receipt()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()

    def test_signed_status_role_epoch_revocation_and_chronology(self):
        for field, value in [('key_epoch', 2), ('status_ref', 'other'), ('key', self.fixture.pub('delivery')),
                             ('authority_id', 'other'), ('observed_at', NOW - 8), ('observed_at', NOW + 1),
                             ('revoked_from', NOW - 6)]:
            self.fixture = Fixture()
            status = self.fixture.value['bundle']['signerStatuses'][0]
            status['body'][field] = value
            self.fixture.value['bundle']['signerStatuses'][0] = sign(status['body'], self.fixture.keys['status'])
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify()

    def test_signed_profile_downgrade(self):
        for field, value in [('required_receipt_semantics', 'chio.mediated_spend.v1'),
                             ('required_facets', ['artifact_integrity', 'guarantee_consistency'])]:
            self.fixture = Fixture()
            self.fixture.value['context']['profile']['body'][field] = value
            self.fixture.resign_context()
            with self.assertRaises(ValueError):
                self.verify()

    def test_checkpoint_proof_and_transparency_tampering(self):
        mutations = [lambda b: b['inclusion'].update(receipt_seq=2),
                     lambda b: b['inclusion']['proof'].update(leaf_index=True),
                     lambda b: b['inclusion']['proof'].update(audit_path=['0x' + 'aa' * 32]),
                     lambda b: b['transparency']['publications'][0].update(log_tree_size=2),
                     lambda b: b['transparency'].update(witnesses=[{}]),
                     lambda b: b.update(checkpoints=[]),
                     lambda b: b.update(signerStatuses=b['signerStatuses'][::-1])]
        for mutate in mutations:
            self.fixture = Fixture()
            mutate(self.fixture.value['bundle'])
            with self.assertRaises(ValueError):
                self.verify()

    def test_signatures_and_content_addresses(self):
        paths = [('agreement', 'buyerSignature'), ('agreement', 'providerSignature'),
                 ('submission', 'signature'), ('bundle', 'receipt', 'signature'),
                 ('submission', 'body', 'finding', 'signature')]
        for path in paths:
            self.fixture = Fixture()
            value = self.fixture.value
            for key in path[:-1]:
                value = value[key]
            value[path[-1]] = '00' * 64
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify()


if __name__ == '__main__':
    unittest.main()
