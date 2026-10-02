import copy
import unittest
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

if __name__=='__main__':unittest.main()
