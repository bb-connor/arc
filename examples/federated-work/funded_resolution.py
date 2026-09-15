#!/usr/bin/env python3
"""Contractual refunds resolve native capture without undoing consumed work."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('CHIO_FUNDED_BINARY', ROOT / 'target/debug/chio-federated-work'))


class FundedResolution(unittest.TestCase):
    def run_case(self, mode, fault):
        with tempfile.TemporaryDirectory(prefix='chio-capture-waiver-') as directory:
            result = subprocess.run([str(BINARY), 'experimental-funded-resolution', directory, mode, fault],
                                    cwd=ROOT, capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            before, after = report['before'], report['after']
            self.assertEqual(before['nativeState'], 'Finalizing')
            self.assertEqual(after['nativeState'], 'Completed')
            self.assertEqual(after['nativePaymentState'], 'Resolved')
            self.assertEqual(after['nativePaymentAction'], 'capture')
            self.assertEqual(after['paymentState'], 'refunded')
            self.assertEqual(after['executions'], 1)
            for field in ('allocationId', 'operationId', 'holdId', 'authorizationId', 'authorityUuid'):
                self.assertEqual(before[field], after[field], field)
            self.assertEqual(report['chain']['paid'], '0')
            self.assertEqual(report['chain']['refunded'], '100')
            self.assertEqual(report['chain']['beneficiaryBalance'], '0')
            self.assertEqual(report['chain']['payerBalance'], '1000')
            self.assertEqual(report['killedSignal'], None if fault == 'none' else 9)
            self.assertEqual(report['financial']['cost_charged'], 0)
            self.assertEqual(report['financial']['settlement_status'], 'failed')
            self.assertEqual(report['financial']['cost_breakdown']['payment']['recorded_units'], 100)
            with sqlite3.connect(f'file:{directory}/authority.sqlite?mode=ro', uri=True) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM admission_operations').fetchone()[0], 1)
                self.assertEqual(db.execute('SELECT count(*) FROM budget_authorization_holds').fetchone()[0], 1)
                state, action, cost = db.execute('SELECT state,settle_action,settle_amount_units FROM payment_journal').fetchone()
                self.assertEqual((state, action, cost), ('settling', 'capture', 100))
                events = db.execute("SELECT realized_spend_units FROM budget_mutation_events WHERE kind='reconcile_spend'").fetchall()
                self.assertEqual(events, [(100,)])
            self.assertEqual(report['sourceBefore'], report['sourceAfter'])
            if destination := os.environ.get('CHIO_FUNDED_EVIDENCE_DIR'):
                path = Path(destination)
                path.mkdir(parents=True, exist_ok=True)
                (path / f'resolution-{mode}-{fault}.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_native_refund_resolution_preserves_positive_work_history(self):
        for mode in ('reject', 'absent', 'unavailable', 'preexpired'):
            with self.subTest(mode=mode):
                self.run_case(mode, 'none')

    def test_resolution_recovers_original_authority_after_worker_loss(self):
        for fault in ('after-resolution-retained', 'after-resolution-accepted', 'after-resolution-completed'):
            with self.subTest(fault=fault):
                self.run_case('reject', fault)


if __name__ == '__main__':
    unittest.main(verbosity=2)
