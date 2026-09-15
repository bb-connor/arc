"""Bounded owner-local outbox. Inclusion observations are never finality proofs.

Only the rail worker validates Ethereum signatures and live chain observations.
This store enforces immutable bytes, operation slots and occupied signer nonces.
"""
import os
from pathlib import Path
import re
import sqlite3
import sys

import artifacts as p
from owned_sqlite import open_owned, sync_parent

MAX_PREPARED=16*1024
MAX_OBSERVATION=4096
MAX_OPERATIONS=64
SCHEMA={
    'identity':'CREATE TABLE identity (body BLOB NOT NULL)',
    'operations':'CREATE TABLE operations (id TEXT PRIMARY KEY, allocation TEXT NOT NULL, action TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, prepared BLOB NOT NULL, prepared_sha TEXT NOT NULL, observation BLOB, observation_sha TEXT, uncertainty TEXT, UNIQUE(allocation,action))',
}


def domain(value):
    p.fields(value,('chainId','escrow','runtimeKeccak256','genesisHash'))
    p.decimal(value['chainId'])
    p.address(value['escrow'])
    p.hash256(value['runtimeKeccak256'],'0x')
    p.hash256(value['genesisHash'],'0x')
    return value


def hex_data(value,limit):
    p.require(type(value) is str and re.fullmatch(r'0x(?:[0-9a-f]{2})+',value)
              and len(value)<=2+2*limit,'invalid or oversized transaction bytes')


class Journal:
    def __init__(self,path,owner,rail,*,create=False):
        p.address(owner)
        self.identity={'schema':'chio.experimental.rail-journal.v1','owner':owner,'domain':domain(rail)}
        self.path=Path(os.path.abspath(path))
        self.db,created=open_owned(self.path,create=create)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('BEGIN IMMEDIATE')
            if created:
                for sql in SCHEMA.values():self.db.execute(sql)
                self.db.execute('INSERT INTO identity VALUES (?)',(p.canonical(self.identity),))
                self.db.execute('PRAGMA user_version=1')
            p.require(self.db.execute('PRAGMA user_version').fetchone()[0]==1,'unsupported rail journal version')
            layout=dict(self.db.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
            p.require(layout==SCHEMA,'unknown rail journal schema')
            p.require(self.db.execute('SELECT body FROM identity').fetchall()==[(p.canonical(self.identity),)],'rail journal scope changed')
            self.db.commit()
            if created:sync_parent(self.path)
        except Exception:
            self.db.close()
            raise

    def __enter__(self):return self
    def __exit__(self,*args):self.db.close()

    def validate(self,value):
        p.require(len(p.canonical(value))<=MAX_PREPARED,'prepared transaction exceeds reserved slot')
        p.fields(value,('intent','nonce','rawTransaction','transactionHash'))
        intent=p.fields(value['intent'],('schema','operationId','allocationId','agreementDigest','action',
            'actor','domain','callData','gasLimit','maxFeePerGas','maxPriorityFeePerGas'))
        p.require(intent['schema']=='chio.experimental.rail-intent.v1','unsupported intent')
        p.require(intent['actor']==self.identity['owner'] and p.canonical(domain(intent['domain']))==p.canonical(self.identity['domain']),'intent changes rail scope')
        p.require(intent['action'] in ('submit','decision','pay','refund'),'unsupported rail action')
        for key in ('operationId','allocationId','agreementDigest'):p.hash256(intent[key],'0x')
        body={key:value for key,value in intent.items() if key!='operationId'}
        p.require(intent['operationId']=='0x'+p.digest(body),'operation id is not content addressed')
        p.decimal(value['nonce'],0)
        for name in ('gasLimit','maxFeePerGas','maxPriorityFeePerGas'):p.decimal(intent[name],0)
        p.require(0<int(intent['gasLimit'])<=1000000 and int(intent['maxPriorityFeePerGas'])<=int(intent['maxFeePerGas']),'invalid gas envelope')
        hex_data(intent['callData'],2048)
        p.require(len(intent['callData'])>=10,'missing contract selector')
        hex_data(value['rawTransaction'],4096)
        p.hash256(value['transactionHash'],'0x')
        return intent

    def prepare(self,value):
        intent=self.validate(value)
        encoded=p.canonical(value)
        op=intent['operationId']
        try:
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                row=self.db.execute('SELECT 1 FROM operations WHERE id=?',(op,)).fetchone()
                if row:
                    p.require(p.canonical(self.read(op)['prepared'])==encoded,'prepared transaction cannot be replaced')
                    return self.read(op)
                for (retained,) in self.db.execute('SELECT id FROM operations').fetchall():
                    self.read(retained)
                p.require(self.db.execute('SELECT COUNT(*) FROM operations').fetchone()[0]<MAX_OPERATIONS,'rail journal capacity exhausted')
                # Fixed slot bounds reserve observation space before any broadcast.
                self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,NULL,NULL,NULL)',
                    (op,intent['allocationId'],intent['action'],value['nonce'],encoded,p.sha256(encoded)))
        except sqlite3.IntegrityError as error:
            raise p.ProtocolError('operation or signer nonce is already occupied') from error
        return self.read(op)

    def read(self,op):
        p.hash256(op,'0x')
        sizes=self.db.execute('SELECT length(prepared),length(observation) FROM operations WHERE id=?',(op,)).fetchone()
        p.require(sizes is not None and sizes[0]<=MAX_PREPARED and (sizes[1] is None or sizes[1]<=MAX_OBSERVATION),'operation missing or oversized')
        raw,sha,observed,observed_sha,uncertainty=self.db.execute('SELECT prepared,prepared_sha,observation,observation_sha,uncertainty FROM operations WHERE id=?',(op,)).fetchone()
        p.require(type(raw) is bytes and p.sha256(raw)==sha,'prepared transaction hash mismatch')
        value=p.load(raw)
        self.validate(value)
        p.require(value['intent']['operationId']==op,'operation binding changed')
        index=self.db.execute('SELECT allocation,action,nonce FROM operations WHERE id=?',(op,)).fetchone()
        p.require(index==(value['intent']['allocationId'],value['intent']['action'],value['nonce']),'operation index differs from retained transaction')
        observation=None
        if observed is not None:
            p.require(type(observed) is bytes and p.sha256(observed)==observed_sha,'observation hash mismatch')
            observation=p.load(observed)
            self.validate_observation(observation,value)
        return {'prepared':value,'observation':observation,'uncertainty':uncertainty,
                'state':observation['status'] if observation is not None and uncertainty is None else 'Unknown'}

    def validate_observation(self,value,prepared):
        p.require(len(p.canonical(value))<=MAX_OBSERVATION,'observation exceeds reserved slot')
        p.fields(value,('transactionHash','blockHash','blockNumber','transactionIndex','status'))
        p.require(value['transactionHash']==prepared['transactionHash'],'observation names another transaction')
        p.hash256(value['blockHash'],'0x')
        p.integer(value['blockNumber'],1)
        p.integer(value['transactionIndex'])
        p.require(value['status'] in ('Included','Reverted'),'unsupported inclusion status')

    def observe(self,op,value):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            current=self.read(op)
            self.validate_observation(value,current['prepared'])
            p.require(current['observation'] is None or p.canonical(current['observation'])==p.canonical(value),'observed inclusion changed')
            data=p.canonical(value)
            self.db.execute('UPDATE operations SET observation=?,observation_sha=?,uncertainty=NULL WHERE id=?',(data,p.sha256(data),op))
        return self.read(op)

    def uncertain(self,op,reason):
        p.require(reason in ('observer_unavailable','missing_inclusion','mismatch','pending','nonce_occupied'),'unsupported uncertainty')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.read(op)
            self.db.execute('UPDATE operations SET uncertainty=? WHERE id=?',(reason,op))
        return self.read(op)


def main():
    request=p.load(sys.stdin.buffer.read(p.MAX_JSON+1))
    p.fields(request,('command','path','owner','domain'),('prepared','operationId','observation','reason'))
    command=request['command']
    p.require(command in ('init','prepare','read','observe','uncertain'),'unsupported journal command')
    with Journal(request['path'],request['owner'],request['domain'],create=command=='init') as journal:
        if command=='init':return journal.identity
        if command=='prepare':return journal.prepare(request['prepared'])
        if command=='read':return journal.read(request['operationId'])
        if command=='observe':return journal.observe(request['operationId'],request['observation'])
        return journal.uncertain(request['operationId'],request['reason'])


if __name__=='__main__':
    try:print(p.canonical(main()).decode())
    except (p.ProtocolError,OSError,sqlite3.Error,KeyError,ValueError) as error:
        print(str(error),file=sys.stderr)
        sys.exit(1)
