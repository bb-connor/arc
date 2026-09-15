"""Real namespace isolation and original funded settlement through public consent."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
BINARY=Path(os.environ.get('CHIO_FUNDED_BINARY',ROOT/'target/debug/chio-federated-work'))

class IsolatedConsent(unittest.TestCase):
    def test_isolated_payout_and_refund(self):
        for mode in ('pay','reject'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='chio-isolated-') as tmp:
                p=subprocess.run([str(BINARY),'experimental-isolated-lifecycle',tmp,mode],cwd=ROOT,capture_output=True,text=True,timeout=240)
                self.assertEqual(p.returncode,0,p.stderr)
                report=json.loads(p.stdout)
                for field in ('authorityUuid','allocationId','operationId','holdId','authorizationId'):
                    self.assertEqual(report['first'][field],report['replay'][field])
                self.assertEqual(report['replay']['executions'],1)
                self.assertEqual(report['chain']['state'],'Paid' if mode=='pay' else 'Refunded')
                self.assertEqual(report['chain']['payerBalance'],'900' if mode=='pay' else '1000')
                self.assertEqual(report['chain']['beneficiaryBalance'],'100' if mode=='pay' else '0')
                self.assertEqual(report['chain']['escrowBalance'],'0')
                for event in ('Funded','ClaimSubmitted','DecisionRecorded'):
                    self.assertEqual(report['chain']['events'][event],1)
                self.assertEqual(report['chain']['events']['Paid']+report['chain']['events']['Refunded'],1)
                self.assertEqual(len(report['isolation']),5)
                for probe in report['isolation']:
                    self.assertEqual(probe['blockedPeerStates'],4)
                    self.assertTrue(probe['hostSentinelAbsent'])
                    self.assertTrue(probe['inputReadOnly'])
                    self.assertTrue(probe['hostNetworkUnreachable'])
                self.assertTrue(report['buyerConsentReplayWithoutKey'])
                self.assertTrue(report['decisionReplayWithoutDependencies'])
                self.assertTrue(report['tamperedConsentDenied'])
                self.assertFalse(report['independentAdministration'])
                public=subprocess.run([os.environ['CHIO_FUNDED_PYTHON'],'-B',str(ROOT/'examples/federated-work/execution_evidence.py'),
                    str(Path(tmp)/'public/witness.json'),'--pins',str(Path(tmp)/'public/pins.json'),'--evaluated-at',str(report['evaluatedAt'])],cwd=ROOT,capture_output=True,text=True,timeout=30)
                self.assertEqual(public.returncode,0,public.stderr)
                result=json.loads(public.stdout)
                self.assertTrue(result['authorityVerified'])
                self.assertEqual(result['executionMatchesSubmission'],mode=='pay')
                self.assertFalse(result['financialBacking'])
                if dest:=os.environ.get('CHIO_FUNDED_EVIDENCE_DIR'):
                    out=Path(dest)
                    (out/f'isolated-{mode}.json').write_text(json.dumps(report,indent=2)+'\n')
                    (out/f'isolated-python-{mode}.json').write_text(public.stdout)
                    for file in (Path(tmp)/'public').iterdir():
                        if file.is_file():
                            (out/f'isolated-{mode}-{file.name}').write_bytes(file.read_bytes())

if __name__=='__main__':unittest.main()
