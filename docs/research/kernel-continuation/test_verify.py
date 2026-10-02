import copy
import unittest
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch
import verify

class QualificationTests(unittest.TestCase):
    def test_added_changed_or_missing_inputs_and_outputs_invalidate_record(self):
        sources={'native.rs':'original'}
        outputs={f'{verify.PREFIX}/results/qualified-{name}.{ext}':'bytes'
                 for name,_,_ in verify.CHECKS for ext in ('stdout','stderr')}
        record={'schema':'chio.kernel-continuation.qualification.v1','complete':True,
                'sources':sources,'outputs':outputs,
                'checks':[{'name':name,'command':command,'exit_code':code} for name,command,code in verify.CHECKS]}
        verify.assert_record(record,sources,outputs)
        for changed in ({'native.rs':'changed'},{},{'native.rs':'original','new.rs':'unqualified'}):
            with self.assertRaises(ValueError):verify.assert_record(record,changed,outputs)
        for changed in ({},{**outputs,'extra-log':'unqualified'},dict(outputs,**{next(iter(outputs)):'changed'})):
            with self.assertRaises(ValueError):verify.assert_record(record,sources,changed)
        for mutation in ('incomplete','missing-step','nonzero'):
            changed=copy.deepcopy(record)
            if mutation=='incomplete':changed['complete']=False
            elif mutation=='missing-step':changed['checks'].pop()
            else:changed['checks'][0]['exit_code']=1
            with self.assertRaises(ValueError):verify.assert_record(changed,sources,outputs)

    def test_stale_native_files_cannot_qualify_a_new_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);results=root/verify.PREFIX/'results'
            (results/'native').mkdir(parents=True)
            for name in ('none-true','none-false','tool-return-recorded-true',
                         'post-return-evaluation-begun-true','post-return-resolved-true',
                         'security-release-acknowledged-true','security-release-checkpointed-true','terminal-projected-true'):
                (results/'native'/f'{name}.json').write_text('{"stale":true}')
            checks=[('native-tests',['success-with-no-artifacts'],0)]
            with patch.multiple(verify,ROOT=root,RESULTS=results,RECORD=results/'verification.json',CHECKS=checks), \
                 patch.object(verify,'sources',return_value={'source':'digest'}), \
                 patch.object(verify,'frozen_paper'), \
                 patch.object(verify.subprocess,'check_output',return_value='head'), \
                 patch.object(verify.subprocess,'run',return_value=CompletedProcess([],0)):
                with self.assertRaisesRegex(ValueError,'native trajectory evidence is incomplete'):
                    verify.run()

if __name__=='__main__':unittest.main()
