#!/usr/bin/env python3
"""An earned child's original payment survives loss of its native parent."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('CHIO_FUNDED_BINARY', ROOT / 'target/debug/chio-federated-work'))


class FundedChild(unittest.TestCase):
    def run_case(self, fault):
        with tempfile.TemporaryDirectory(prefix='chio-earned-child-') as directory:
            result = subprocess.run(
                [str(BINARY), 'experimental-funded-child', directory, fault],
                cwd=ROOT, capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['parentKilledSignal'], 9)
            self.assertEqual(report['earned']['state'], 'Payable')
            self.assertEqual(report['earned']['paid'], '0')
            self.assertEqual(report['afterParentRefund']['child']['state'], 'Payable')
            self.assertEqual(report['afterParentRefund']['child']['paid'], '0')
            self.assertEqual(report['parent']['nativeState'], 'OutcomeUnknownAfterDispatch')
            self.assertEqual(report['parent']['executions'], 1)
            self.assertEqual(report['parent']['paymentState'], 'refunded')
            self.assertEqual(report['child']['nativeState'], 'Completed')
            self.assertEqual(report['child']['executions'], 1)
            self.assertEqual(report['child']['paymentState'], 'paid')
            self.assertEqual(report['final']['balances'], {
                'buyer': '1000', 'intermediary': '900', 'child': '100', 'escrow': '0', 'supply': '2000'})
            self.assertEqual(report['retired'], {'parentActionsDisabled': True, 'verifierSigningDisabled': True})
            self.assertEqual(report['childPayKilledSignal'], None if fault == 'none' else 9)
            for role in ('parent', 'child'):
                with sqlite3.connect(f'file:{directory}/{role}/authority.sqlite?mode=ro', uri=True) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM admission_operations').fetchone()[0], 1)
                    self.assertEqual(db.execute('SELECT count(*) FROM budget_authorization_holds').fetchone()[0], 1)
                    operation, hold, authorization = db.execute('SELECT operation_id,hold_id,authorization_id FROM payment_journal').fetchone()
                    self.assertEqual(operation, report[role]['operationId'])
                    self.assertEqual(hold, report[role]['holdId'])
                    self.assertEqual(authorization, report[role]['authorizationId'])
                original = report['original'][role]
                for field in ('operationId', 'holdId', 'authorizationId', 'allocationId', 'authorityUuid'):
                    self.assertEqual(original[field], report[role][field], (role, field))
                for action, transactions in report['final'][role]['transactions'].items():
                    self.assertLessEqual(len(transactions), 1, (role, action))
                    for transaction in transactions:
                        self.assertEqual(transaction['status'], 1)
            self.assertNotEqual(report['parent']['authorityUuid'], report['child']['authorityUuid'])
            self.assertNotEqual(report['parent']['allocationId'], report['child']['allocationId'])
            self.assertEqual(len(report['final']['parent']['transactions']['refund']), 1)
            self.assertEqual(len(report['final']['child']['transactions']['pay']), 1)
            self.assertEqual(len(report['final']['parent']['transactions']['submit']), 0)
            self.assertEqual(len(report['final']['child']['transactions']['record']), 1)
            if destination := os.environ.get('CHIO_FUNDED_EVIDENCE_DIR'):
                path = Path(destination)
                path.mkdir(parents=True, exist_ok=True)
                (path / f'earned-child-{fault}.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_earned_child_collects_after_native_parent_loss(self):
        for fault in ('none', 'pay-after-prepare', 'pay-after-broadcast', 'pay-after-observation'):
            with self.subTest(fault=fault):
                self.run_case(fault)


if __name__ == '__main__':
    unittest.main(verbosity=2)
