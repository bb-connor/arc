"""Real SQLite outbox invariants: immutable bytes, nonce ownership and inclusion."""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest

import artifacts as p
from rail_journal import Journal

OWNER='0x'+'40'*20
DOMAIN={'chainId':'31337','escrow':'0x'+'10'*20,'runtimeKeccak256':'0x'+'20'*32,'genesisHash':'0x'+'30'*32}


def prepared(nonce='1', allocation='0x'+'50'*32, action='pay'):
    intent={'schema':'chio.experimental.rail-intent.v1','allocationId':allocation,
            'agreementDigest':'0x'+'60'*32,'action':action,'actor':OWNER,'domain':DOMAIN,
            'callData':'0x12345678','gasLimit':'1000000','maxFeePerGas':'2000000000','maxPriorityFeePerGas':'1000000000'}
    intent['operationId']='0x'+p.digest(intent)
    return {'intent':intent,'nonce':nonce,'rawTransaction':'0x01020304','transactionHash':'0x'+'70'*32}


def inclusion(record):
    return {'transactionHash':record['transactionHash'],'blockHash':'0x'+'80'*32,
            'blockNumber':12,'transactionIndex':0,'status':'Included'}


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'rail.sqlite'
        with Journal(self.path,OWNER,DOMAIN,create=True):
            pass

    def test_exact_preparation_and_inclusion_survive_reopen(self):
        value=prepared()
        op=value['intent']['operationId']
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
        with Journal(self.path,OWNER,DOMAIN) as journal:
            self.assertEqual(journal.read(op)['prepared'],value)
            self.assertEqual(journal.read(op)['state'],'Unknown')
            journal.observe(op,inclusion(value))
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
            self.assertEqual(journal.read(op)['state'],'Included')
            self.assertEqual(journal.read(op)['observation'],inclusion(value))

    def test_changed_bytes_nonce_and_same_obligation_cannot_replace_intent(self):
        value=prepared()
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
            for field,replacement in [('nonce','2'),('rawTransaction','0x04030201'),('transactionHash','0x'+'ab'*32)]:
                changed=copy.deepcopy(value)
                changed[field]=replacement
                with self.subTest(field=field), self.assertRaises(p.ProtocolError):
                    journal.prepare(changed)
            changed=prepared('2')
            changed['intent']['gasLimit']='999999'
            del changed['intent']['operationId']
            changed['intent']['operationId']='0x'+p.digest(changed['intent'])
            with self.assertRaises(p.ProtocolError):
                journal.prepare(changed)

    def test_occupied_nonce_is_not_reusable_after_inclusion_or_uncertainty(self):
        value=prepared()
        op=value['intent']['operationId']
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
            journal.observe(op,inclusion(value))
            journal.uncertain(op,'missing_inclusion')
            self.assertEqual(journal.read(op)['state'],'Unknown')
            self.assertEqual(journal.read(op)['observation'],inclusion(value))
            with self.assertRaises(p.ProtocolError):
                journal.prepare(prepared(allocation='0x'+'ab'*32))
            journal.observe(op,inclusion(value))
            self.assertEqual(journal.read(op)['state'],'Included')

    def test_conflicting_or_other_transaction_inclusion_is_denied(self):
        value=prepared()
        op=value['intent']['operationId']
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
            wrong={**inclusion(value),'transactionHash':'0x'+'ab'*32}
            with self.assertRaises(p.ProtocolError):
                journal.observe(op,wrong)
            journal.observe(op,inclusion(value))
            with self.assertRaises(p.ProtocolError):
                journal.observe(op,{**inclusion(value),'blockHash':'0x'+'ab'*32})
            self.assertEqual(journal.read(op)['observation'],inclusion(value))

    def test_scope_missing_store_modes_and_tampered_record_deny(self):
        with self.assertRaises((OSError,p.ProtocolError)):
            Journal(self.path.with_name('missing.sqlite'),OWNER,DOMAIN)
        self.assertFalse(self.path.with_name('missing.sqlite').exists())
        with self.assertRaises(p.ProtocolError):
            Journal(self.path,'0x'+'ab'*20,DOMAIN)
        with self.assertRaises(p.ProtocolError):
            Journal(self.path,OWNER,{**DOMAIN,'chainId':'1'})
        self.path.chmod(0o644)
        with self.assertRaises(p.ProtocolError):
            Journal(self.path,OWNER,DOMAIN)
        self.path.chmod(0o600)
        value=prepared()
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE operations SET prepared=?",(b'{}',))
        with Journal(self.path,OWNER,DOMAIN) as journal:
            with self.assertRaises(p.ProtocolError):
                journal.read(value['intent']['operationId'])

    def test_capacity_preserves_old_operations_and_reserves_their_observations(self):
        with Journal(self.path,OWNER,DOMAIN) as journal:
            for n in range(64):
                value=prepared(str(n),'0x'+format(n+1,'064x'))
                journal.prepare(value)
            with self.assertRaises(p.ProtocolError):
                journal.prepare(prepared('64','0x'+format(65,'064x')))
            first=prepared('0','0x'+format(1,'064x'))
            journal.observe(first['intent']['operationId'],inclusion(first))
            self.assertEqual(journal.read(first['intent']['operationId'])['state'],'Included')

    def test_nonce_index_corruption_is_not_trusted_over_original_signed_record(self):
        value=prepared()
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE operations SET nonce='2'")
        with Journal(self.path,OWNER,DOMAIN) as journal:
            with self.assertRaises(p.ProtocolError):
                journal.read(value['intent']['operationId'])

    def test_new_preparation_cannot_reuse_a_corrupted_nonce_index(self):
        value=prepared()
        with Journal(self.path,OWNER,DOMAIN) as journal:
            journal.prepare(value)
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE operations SET nonce='2'")
        with Journal(self.path,OWNER,DOMAIN) as journal:
            with self.assertRaises(p.ProtocolError):
                journal.prepare(prepared(allocation='0x'+'ab'*32))


if __name__=='__main__':
    unittest.main()
