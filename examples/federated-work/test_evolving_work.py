"""Observable acceptance for one native D1/S1/treaty/F1 execution."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get('CHIO_FUNDED_BINARY', ROOT / 'target/debug/chio-federated-work'))


class EvolvingWork(unittest.TestCase):
    def test_growth_preserves_original_work_and_earned_child_after_parent_loss(self):
        with tempfile.TemporaryDirectory(prefix='chio-evolving-') as directory:
            result = subprocess.run([str(BINARY), 'experimental-evolving-work', directory],
                                    cwd=ROOT, capture_output=True, text=True, timeout=240)
            self.assertEqual(result.returncode, 0, result.stderr)
            r = json.loads(result.stdout)
            self.assertEqual(r['parentKilledSignal'], 9)
            self.assertEqual(r['earned']['state'], 'Payable')
            self.assertEqual(r['earned']['paid'], '0')
            self.assertEqual(r['discoveredAfterScout'], True)
            self.assertEqual(r['originalScoutPreserved'], True)
            self.assertEqual(r['graphNodeCounts'], [3, 4])
            self.assertEqual(set(r['rejections']), {'receiver', 'allocation', 'continuation', 'treaty'})
            self.assertTrue(all(r['rejections'].values()))
            self.assertEqual(r['final']['balances'], {
                'buyer': '900', 'intermediary': '1000', 'child': '100', 'escrow': '0', 'supply': '2000'})
            for role in ('scout', 'parent', 'child'):
                self.assertEqual(r[role]['executions'], 1)
                for field in ('operationId', 'allocationId', 'holdId', 'authorizationId', 'authorityUuid', 'runtimeClaimHistory'):
                    self.assertEqual(r['original'][role][field], r[role][field], (role, field))
                with sqlite3.connect(f'file:{directory}/{role}/authority.sqlite?mode=ro', uri=True) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM runtime_replay_claim_episodes').fetchone()[0], 1)
                    self.assertEqual(db.execute('SELECT count(*) FROM runtime_replay_claim_resources').fetchone()[0], 2)
                    self.assertEqual({row[0] for row in db.execute('SELECT DISTINCT operation_id FROM runtime_replay_claim_resources')}, {r[role]['operationId']})
                    self.assertEqual({row[0] for row in db.execute('SELECT participant_kind FROM runtime_replay_claim_resources')}, {'treaty_continuation', 'swarm_continuation'})
                self.assertEqual(len(r[role]['runtimeClaimHistory']), 1)
                for action, transactions in r['final'][role]['transactions'].items():
                    self.assertLessEqual(len(transactions), 1, (role, action))
                    self.assertTrue(all(tx['status'] == 1 for tx in transactions))
            self.assertEqual(r['discovery']['sourceOperation'], r['scout']['operationId'])
            self.assertTrue(any(row['authenticationRequired'] is False for row in r['discovery']['output']))
            self.assertEqual(r['parent']['nativeState'], 'OutcomeUnknownAfterDispatch')
            self.assertEqual(r['parent']['paymentState'], 'refunded')
            self.assertEqual(r['child']['nativeState'], 'Completed')
            self.assertEqual(r['scout']['nativeState'], 'Completed')
            self.assertEqual(r['collection']['transactionHash'], r['collectionReplay']['transactionHash'])
            self.assertEqual(r['child']['paymentState'], 'paid')
            self.assertEqual(r['scout']['paymentState'], 'paid')
            if destination := os.environ.get('CHIO_FUNDED_EVIDENCE_DIR'):
                path = Path(destination)
                path.mkdir(parents=True, exist_ok=True)
                (path / 'qualified-evolving-funded-work.json').write_text(json.dumps(r, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
