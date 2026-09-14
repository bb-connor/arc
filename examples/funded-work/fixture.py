"""Private single-host fixture commands. Keys are generated locally, never exported.

Use only fresh throwaway mock-token experiments. All five artifact keys are
owned by this one fixture; separate companies or custody operators are not tested.
"""
import json
import os
from pathlib import Path
import stat
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import artifacts as p
from custody import Custody
from verifier import authorize


def read(path, limit=p.MAX_JSON):
    with open(path, 'rb') as handle:
        data = handle.read(limit + 1)
    p.require(len(data) <= limit, 'fixture file exceeds bound')
    return data


def private_keys(state):
    info = (state / 'keys.json').stat(follow_symlinks=False)
    p.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_uid == os.getuid() and info.st_nlink == 1, 'unsafe fixture keys')
    values = p.load(read(state / 'keys.json'))
    p.fields(values, ('A', 'B', 'C', 'verifier', 'custodian'))
    keys = {role: Ed25519PrivateKey.from_private_bytes(p.hex_bytes(value)) for role, value in values.items()}
    pins = {role: key.public_key().public_bytes_raw().hex() for role, key in keys.items()}
    return keys, pins


def parties(keys, names):
    p.fields(names, ('buyer', 'provider'))
    p.require(names['buyer'] in ('A', 'B', 'C') and names['provider'] in ('A', 'B', 'C')
              and names['buyer'] != names['provider'], 'unsupported fixture parties')
    selected = {role: keys[names[role]] for role in ('buyer', 'provider')}
    selected.update({role: keys[role] for role in ('verifier', 'custodian')})
    return selected, {role: key.public_key().public_bytes_raw().hex() for role, key in selected.items()}


def approved(state, value, keys):
    original = p.load(read(state / ('agreement-' + p.digest(value['body']) + '.json')))
    p.require(p.canonical(original['agreement']) == p.canonical(value), 'agreement differs from local joint approval')
    selected, pins = parties(keys, original['parties'])
    return p.verify_agreement(value, pins), selected, pins


def run(args):
    p.require(len(args) in (2, 3), 'usage: fixture.py init STATE | prepare/submit/authorize STATE REQUEST')
    command, directory = args[:2]
    state = Path(directory)
    info = state.stat(follow_symlinks=False)
    p.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
              and info.st_uid == os.getuid(), 'fixture state must be owned mode 0700')
    if command == 'init':
        p.require(len(args) == 2, 'init does not take a request')
        keys = {role: Ed25519PrivateKey.generate().private_bytes_raw().hex()
                for role in ('A', 'B', 'C', 'verifier', 'custodian')}
        fd = os.open(state / 'keys.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(p.canonical(keys))
            handle.flush()
            os.fsync(handle.fileno())
        _, pins = private_keys(state)
        return {'pins': pins}
    p.require(len(args) == 3 and command in ('prepare', 'submit', 'authorize'), 'unsupported fixture command')
    keys, pins = private_keys(state)
    request = p.load(read(args[2]))
    if command == 'prepare':
        p.fields(request, ('workId', 'inputPath', 'rail', 'deadlines', 'parentAgreementSha256', 'parties'))
        keys, pins = parties(keys, request['parties'])
        source = read(request['inputPath'], p.MAX_OBJECT)
        p.load(source, p.MAX_OBJECT)
        p.check_implementation()
        body = {'schema': 'chio.experimental.funded-w0-agreement.v1', 'workId': request['workId'],
                **{role+'Key': pin for role, pin in pins.items()}, 'inputSha256': p.sha256(source),
                'checkerSha256': p.CHECKER_SHA256, 'assurance': 'artifact-only-v1',
                'parentAgreementSha256': request['parentAgreementSha256'], 'rail': request['rail'],
                'deadlines': request['deadlines'], 'custody': {'policy':'local-retain-indefinitely-v1',
                'retainUntil': request['deadlines']['refundAfter'] + p.RECOVERY_SECONDS}}
        agreement = {'body': body, 'buyerSignature': keys['buyer'].sign(p.canonical(body)).hex(),
                     'providerSignature': keys['provider'].sign(p.canonical(body)).hex()}
        p.verify_agreement(agreement, pins)
        destination = state / ('agreement-' + p.digest(body) + '.json')
        with destination.open('xb') as handle:
            handle.write(p.canonical({'agreement': agreement, 'parties': request['parties']}))
            handle.flush()
            os.fsync(handle.fileno())
        return {'agreement': agreement, 'agreementDigest': '0x' + p.digest(body), 'pins': pins}
    if command == 'submit':
        p.fields(request, ('agreement', 'allocationId', 'inputPath', 'output'))
        body, keys, pins = approved(state, request['agreement'], keys)
        source = read(request['inputPath'], p.MAX_OBJECT)
        with Custody(state / 'custody.sqlite', pins['custodian']) as store:
            receipt = store.retain(body, source, p.canonical(request['output']), keys['custodian'])
            submission = p.sign(p.submission_body(body, request['allocationId'], receipt), keys['provider'])
            p.verify_submission(submission, body, request['allocationId'])
            store.bind_submission(request['allocationId'], submission)
        return {'submission': submission, 'commitment': '0x' + p.digest(submission), 'output': request['output']}
    p.fields(request, ('agreement', 'submission', 'observed'))
    _, keys, pins = approved(state, request['agreement'], keys)
    p.require((state / 'custody.sqlite').exists(), 'custody missing: verifier cannot retrieve work')
    started = time.perf_counter_ns()
    with Custody(state / 'custody.sqlite', pins['custodian']) as store:
        result = authorize(request['agreement'], pins, request['submission'], request['observed'], store, keys['verifier'])
    result['verificationMicros'] = (time.perf_counter_ns() - started) // 1000
    return result


if __name__ == '__main__':
    try:
        print(p.canonical(run(sys.argv[1:])).decode('utf-8'))
    except (p.ProtocolError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
