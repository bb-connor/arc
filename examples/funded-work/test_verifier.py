"""Acceptance must depend on exact authority, actual checker results and retrieval."""
import copy
import shutil
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import artifacts as p
from custody import Custody
from verifier import decide
from test_protocol import agreement, keys, INPUT, OUTPUT

ALLOCATION = '0x' + '70'*32


class VerifierFixture:
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'custody.sqlite'
        self.a, self.pins = agreement()

    def submit(self, output=OUTPUT, allocation=ALLOCATION):
        with Custody(self.path, self.pins['custodian']) as store:
            receipt = store.retain(self.a['body'], INPUT, p.canonical(output), keys()[3])
            return p.sign(p.submission_body(self.a['body'], allocation, receipt), keys()[1])

    def run_verifier(self, submission, allocation=ALLOCATION, key=None):
        with Custody(self.path, self.pins['custodian']) as store:
            return decide(self.a, self.pins, allocation, submission, store, key or keys()[2])


class VerifierTests(VerifierFixture, unittest.TestCase):
    def test_shadow_checker_module_cannot_satisfy_a_pin_for_different_source(self):
        shadow=Path(self.directory.name)/'shadow'
        shadow.mkdir()
        wrong=copy.deepcopy(OUTPUT)
        wrong['operations'][0]['authenticationRequired']=False
        (shadow/'review.py').write_text('raise RuntimeError("shadow checker executed")\n')
        (shadow/'subcontract.py').write_text('raise RuntimeError("shadow dependency executed")\n')
        submission=self.submit(wrong)
        request=Path(self.directory.name)/'request.json'
        request.write_bytes(p.canonical({'agreement':self.a,'pins':self.pins,'submission':submission}))
        script="""import sys
sys.path[:0]=[sys.argv[1],sys.argv[2]]
import artifacts as p
from custody import Custody
from verifier import decide
from test_protocol import keys
v=p.load(open(sys.argv[3],'rb').read())
with Custody(sys.argv[4],v['pins']['custodian']) as store:
    result=decide(v['agreement'],v['pins'],v['submission']['body']['allocationId'],v['submission'],store,keys()[2])
    print(result['body']['accepted'])
"""
        result=subprocess.run([sys.executable,'-B','-c',script,str(Path(__file__).parent),str(shadow),str(request),str(self.path)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'False\n','a shadow checker certified false output')

    def test_new_evidence_cannot_starve_an_already_retained_claim_decision(self):
        original = self.submit()
        with Custody(self.path, self.pins['custodian']) as store:
            store.bind_submission(ALLOCATION, original)
            sequence = 0
            # Fill with real custody requests, first large, then progressively small.
            for size in (65000, 32000, 16000, 8000, 4000, 2000, 1000, 100, 1):
                while True:
                    sequence += 1
                    data = str(sequence).encode() + b'x' * size
                    try:
                        store.retain(self.a['body'], INPUT, data, keys()[3])
                    except p.ProtocolError as error:
                        self.assertIn('capacity exhausted', str(error))
                        break
        result = self.run_verifier(original)
        self.assertTrue(result['body']['accepted'])
        self.assertEqual(self.run_verifier(original), result)

    def test_checker_source_substitution_cannot_issue_a_decision(self):
        submission = self.submit()
        original = p.BUYER
        changed = Path(self.directory.name) / 'substituted-checker'
        changed.mkdir()
        shutil.copyfile(original / 'protocol.py', changed / 'protocol.py')
        (changed / 'review.py').write_bytes((original / 'review.py').read_bytes() + b'\n# changed checker\n')
        try:
            p.BUYER = changed
            with self.assertRaises(p.ProtocolError):
                self.run_verifier(submission)
        finally:
            p.BUYER = original

    def test_claim_capacity_denies_new_work_without_evicting_earned_authority(self):
        original = self.submit()
        decision = self.run_verifier(original)
        with Custody(self.path, self.pins['custodian']) as store:
            for n in range(1, 64):
                allocation = '0x' + format(n, '064x')
                body = {**original['body'], 'allocationId': allocation}
                store.bind_submission(allocation, p.sign(body, keys()[1]))
            allocation = '0x' + format(64, '064x')
            with self.assertRaises(p.ProtocolError):
                store.bind_submission(allocation, p.sign({**original['body'], 'allocationId': allocation}, keys()[1]))
        self.assertEqual(self.run_verifier(original), decision)

    def test_real_predicate_accepts_and_decision_survives_reopen(self):
        submission = self.submit()
        decision = self.run_verifier(submission)
        body = p.verify_decision(decision, self.a['body'], submission)
        self.assertTrue(body['accepted'])
        self.assertEqual(body['predicate'], 'match')
        self.assertEqual(body['rail']['amount'], '100')
        self.assertEqual(body['assurance'], 'artifact-only-v1')
        self.assertEqual(self.run_verifier(submission), decision)
        with Custody(self.path, self.pins['custodian']) as store:
            self.assertEqual(store.get(p.digest(submission)), p.canonical(submission))
            self.assertEqual(store.get(p.digest(decision)), p.canonical(decision))

    def test_false_authentication_observation_is_signed_rejection(self):
        wrong = copy.deepcopy(OUTPUT)
        wrong['operations'][0]['authenticationRequired'] = False
        submission = self.submit(wrong)
        body = p.verify_decision(self.run_verifier(submission), self.a['body'], submission)
        self.assertFalse(body['accepted'])
        self.assertEqual(body['predicate'], 'mismatch')

    def test_malformed_output_is_rejection_and_not_success(self):
        for output in ({'schema':'future', 'operations':[]}, {'accepted':True},
                       {'schema': OUTPUT['schema'], 'operations': OUTPUT['operations'], 'extra':1}):
            # Each independent obligation needs its own non-replaceable commitment.
            allocation = '0x' + p.digest(output)
            submission = self.submit(output, allocation)
            self.assertFalse(self.run_verifier(submission, allocation)['body']['accepted'])

    def test_unavailable_custody_does_not_sign_a_financial_decision(self):
        submission = self.submit()
        with sqlite3.connect(self.path) as connection:
            connection.execute('DELETE FROM objects WHERE digest=?', (p.sha256(p.canonical(OUTPUT)),))
        with self.assertRaises(p.ProtocolError):
            self.run_verifier(submission)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM decisions').fetchone()[0], 0)

    def test_conflicting_submission_cannot_replace_retained_claim(self):
        original = self.submit()
        first = self.run_verifier(original)
        wrong = copy.deepcopy(OUTPUT)
        wrong['operations'][0]['authenticationRequired'] = False
        with self.assertRaises(p.ProtocolError):
            self.run_verifier(self.submit(wrong))
        self.assertEqual(self.run_verifier(original), first)

    def test_provider_custodian_verifier_and_allocation_substitutions_deny(self):
        submission = self.submit()
        candidates = []
        for key, value in [('inputSha256','ab'*32), ('outputSha256','ab'*32),
                           ('checkerSha256','ab'*32), ('agreementSha256','ab'*32),
                           ('allocationId','0x'+'ab'*32), ('schema','future')]:
            changed = copy.deepcopy(submission['body'])
            changed[key] = value
            candidates.append(p.sign(changed, keys()[1]))
        changed = copy.deepcopy(submission['body'])
        changed['custody'] = p.sign(changed['custody']['body'], keys()[2])
        candidates.extend([p.sign(changed, keys()[1]), p.sign(submission['body'], keys()[0])])
        for candidate in candidates:
            with self.subTest(candidate=candidate['body']['schema']), self.assertRaises(p.ProtocolError):
                self.run_verifier(candidate)
        with self.assertRaises(p.ProtocolError):
            self.run_verifier(submission, key=keys()[0])

    def test_validly_signed_decision_cannot_change_any_financial_or_work_binding(self):
        submission = self.submit()
        decision = self.run_verifier(submission)
        for field, val in [('commitment','0x'+'ab'*32), ('predicate','mismatch'), ('accepted',False),
                           ('outputSha256','ab'*32), ('retainUntil',1), ('assurance','native-v1')]:
            body = copy.deepcopy(decision['body'])
            body[field] = val
            with self.subTest(field=field), self.assertRaises(p.ProtocolError):
                p.verify_decision(p.sign(body, keys()[2]), self.a['body'], submission)
        for field in decision['body']['rail']:
            body = copy.deepcopy(decision['body'])
            body['rail'][field] = '101'
            with self.subTest(rail=field), self.assertRaises(p.ProtocolError):
                p.verify_decision(p.sign(body, keys()[2]), self.a['body'], submission)

class ObserverBindingTests(VerifierFixture, unittest.TestCase):
    def observation(self, submission):
        return {'allocationId': ALLOCATION, 'agreementDigest': '0x' + p.digest(self.a['body']),
                'commitment': '0x' + p.digest(submission), 'state': 'Submitted', 'chainTime': 111,
                'rail': self.a['body']['rail'], 'deadlines': self.a['body']['deadlines']}

    def test_authorization_requires_exact_observed_deployment_claim_and_window(self):
        from verifier import authorize
        submission = self.submit()
        observed = self.observation(submission)
        changes = [('allocationId', '0x'+'ab'*32), ('agreementDigest','0x'+'ab'*32),
                   ('commitment','0x'+'ab'*32), ('state','Funded'), ('chainTime',110), ('chainTime',121)]
        for field, value in changes:
            changed = copy.deepcopy(observed)
            changed[field] = value
            with Custody(self.path, self.pins['custodian']) as store:
                with self.subTest(field=field), self.assertRaises(p.ProtocolError):
                    authorize(self.a, self.pins, submission, changed, store, keys()[2])
        for field in observed['rail']:
            changed = copy.deepcopy(observed)
            changed['rail'][field] = '101'
            with Custody(self.path, self.pins['custodian']) as store:
                with self.subTest(rail=field), self.assertRaises(p.ProtocolError):
                    authorize(self.a, self.pins, submission, changed, store, keys()[2])
        with Custody(self.path, self.pins['custodian']) as store:
            result = authorize(self.a, self.pins, submission, observed, store, keys()[2])
        self.assertEqual(result['authorization']['amount'], '100')
        self.assertEqual(result['authorization']['commitment'], '0x' + p.digest(submission))
        self.assertEqual(result['decisionDigest'], '0x' + p.digest(result['decision']['body']))


if __name__ == '__main__':
    unittest.main()
