#!/usr/bin/env python3
"""Original native identities across Finding verification and real escrow effects."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('CHIO_FUNDED_BINARY', ROOT / 'target/debug/chio-federated-work'))


class FundedLifecycle(unittest.TestCase):
    def run_case(self, mode, fault=None):
        with tempfile.TemporaryDirectory(prefix='chio-claim-') as directory:
            command = [str(BINARY), 'experimental-funded-lifecycle', directory, mode]
            if fault:
                command.append(fault)
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=150)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            first, replay, chain = report['first'], report['replay'], report['chain']
            for field in ('allocationId', 'operationId', 'holdId', 'authorizationId', 'authorityUuid', 'requestId'):
                self.assertEqual(first[field], replay[field], field)
            executions = 0 if mode == 'undispatched' else 1
            self.assertEqual(replay['executions'], executions)
            paid = mode == 'pay'
            self.assertEqual(replay['paymentState'], 'paid' if paid else 'refunded')
            self.assertTrue(replay['externalFundsTransferred'])
            self.assertEqual(chain['state'], 'Paid' if paid else 'Refunded')
            self.assertEqual(chain['escrowBalance'], '0')
            self.assertEqual(chain['payerBalance'], '900' if paid else '1000')
            self.assertEqual(chain['beneficiaryBalance'], '100' if paid else '0')
            self.assertEqual(chain['paid'], '100' if paid else '0')
            self.assertEqual(chain['refunded'], '0' if paid else '100')
            self.assertEqual(chain['events']['Funded'], 1)
            self.assertEqual(chain['events']['Paid'] + chain['events']['Refunded'], 1)
            for count in chain['events'].values():
                self.assertLessEqual(count, 1)
            if paid:
                self.assertEqual(replay['nativeState'], 'Completed')
                self.assertEqual(replay['nativePaymentState'], 'Settled')
            elif mode == 'unknown':
                self.assertEqual(replay['nativeState'], 'OutcomeUnknownAfterDispatch')
                self.assertEqual(replay['nativePaymentState'], 'Authorized')
                self.assertEqual(report['after']['holdDisposition'], 'open')
            elif mode == 'undispatched':
                self.assertEqual(replay['nativeState'], 'CompensatedBeforeDispatch')
                self.assertEqual(replay['nativePaymentState'], 'Settled')
                self.assertEqual(report['after']['holdDisposition'], 'reversed')
            else:
                self.assertEqual(replay['nativeState'], 'Finalizing')
                self.assertEqual(replay['nativePaymentState'], 'Settling')
            with sqlite3.connect(f'file:{directory}/authority.sqlite?mode=ro', uri=True) as database:
                self.assertEqual(database.execute('SELECT count(*) FROM admission_operations').fetchone()[0], 1)
                self.assertEqual(database.execute('SELECT count(*) FROM budget_authorization_holds').fetchone()[0], 1)
                operation, hold, authorization = database.execute('SELECT operation_id,hold_id,authorization_id FROM payment_journal').fetchone()
                self.assertEqual((operation, hold, authorization), (first['operationId'], first['holdId'], first['authorizationId']))
                action = database.execute('SELECT settle_action FROM payment_journal').fetchone()[0]
                self.assertEqual(action, 'release' if mode == 'undispatched' else None if mode == 'unknown' else 'capture')
                self.assertEqual(replay['nativePaymentAction'], action)
            with sqlite3.connect(f'file:{directory}/funding.sqlite?mode=ro', uri=True) as database:
                self.assertEqual(database.execute('SELECT count(*) FROM executions').fetchone()[0], executions)
                records = {kind: json.loads(payload) for kind, payload in database.execute('SELECT kind,payload FROM records')}
                transactions = {kind: value['transactionHash'] for kind, value in records.items() if kind in ('submit', 'record', 'pay', 'refund')}
                self.assertEqual(len(set(transactions.values())), len(transactions))
                self.assertEqual(transactions['pay' if paid else 'refund'], replay['settlementTransaction'])
                for action, observed in chain['transactions'].items():
                    self.assertLessEqual(len(observed), 1, f'duplicate mined {action} transaction')
                    for tx in observed:
                        self.assertEqual(tx['status'], 1)
                        self.assertEqual(tx['hash'], transactions[action])
                self.assertEqual(len(chain['transactions']['pay' if paid else 'refund']), 1)
                self.assertEqual(len(chain['transactions']['submit']), chain['events']['ClaimSubmitted'])
                self.assertEqual(len(chain['transactions']['record']), chain['events']['DecisionRecorded'])
                if mode in ('absent', 'unavailable'):
                    self.assertNotIn('decision', records)
                if mode == 'reject':
                    self.assertFalse(records['decision']['body']['accepted'])
                report['retainedTransactions'] = transactions
            if fault:
                self.assertEqual(report['killedSignal'], 9)
                self.assertEqual(report['after']['operationCount'], 1)
                self.assertEqual(report['after']['holdCount'], 1)
            if destination := os.environ.get('CHIO_FUNDED_EVIDENCE_DIR'):
                path = Path(destination)
                path.mkdir(parents=True, exist_ok=True)
                (path / f'{mode}-{fault or "complete"}.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_payout_rejection_and_missing_work_timeouts(self):
        for mode in ('pay', 'reject', 'absent', 'unavailable', 'preexpired'):
            with self.subTest(mode=mode):
                self.run_case(mode)

    def test_sigkill_around_original_claim_decision_and_money(self):
        for mode, points in (
            ('pay', ('after-submission', 'claim-after-prepare', 'claim-after-broadcast', 'after-claim', 'after-decision',
                     'decision-after-prepare', 'decision-after-broadcast', 'after-recorded-decision',
                     'pay-after-prepare', 'pay-after-broadcast', 'pay-after-observation')),
            ('reject', ('refund-after-prepare', 'refund-after-broadcast', 'refund-after-observation')),
            ('absent', ('refund-after-broadcast',)),
        ):
            for point in points:
                with self.subTest(mode=mode, point=point):
                    self.run_case(mode, point)

    def test_deadline_loss_refunds_even_with_retained_unrecorded_artifacts(self):
        for mode, point in (('pay-expired', 'after-submission'), ('pay-expired', 'claim-after-prepare'),
                            ('pay-expired', 'after-decision'), ('pay-expired', 'decision-after-prepare'),
                            ('reject-expired', 'after-decision')):
            with self.subTest(mode=mode, point=point):
                    self.run_case(mode, point)

    def test_refund_preserves_unknown_execution_and_unwinds_undispatched_hold(self):
        for mode in ('unknown', 'undispatched'):
            with self.subTest(mode=mode):
                self.run_case(mode)


if __name__ == '__main__':
    unittest.main(verbosity=2)
