"""Manuscript counts derived from authenticated terminal native test output."""
import hashlib
import json
import re

BOUNDARIES = {
    'NativeWorkflow': 'workflow-tests', 'NativeDelegation': 'native-tests',
    'NativeComposition': 'native-regression', 'NativeEvolution': 'evolution-tests',
    'NativeExecutionExport': 'execution-export-tests', 'NativeDurable': 'durable-regression',
    'NativeFunded': 'funded-tests',
}


def native_counts(root, record, boundaries=None):
    boundaries = BOUNDARIES if boundaries is None else boundaries
    commands = record['commands']
    if any(item.get('exit_code') != 0 for item in commands.values()):
        raise ValueError('native count source has a nonterminal or failed command')
    numbers = dict(NativeCommands=len(commands), NativeSources=len(record['source_files']),
                   NativeOutputs=len(record['outputs']))
    for macro, command in boundaries.items():
        item = commands[command]
        name = item['stdout']
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError('native count source outside repository')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != record['outputs'].get(name):
            raise ValueError('native count source hash mismatch: ' + name)
        summaries = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',
                               data.decode('utf-8'))
        if not summaries or any(int(failed) for _, failed, _ in summaries):
            raise ValueError('native count source lacks a passing terminal test summary: ' + name)
        numbers[macro] = sum(int(passed) for passed, _, _ in summaries)
        numbers[macro + 'Ignored'] = sum(int(ignored) for _, _, ignored in summaries)
    return numbers


def historical_chain_counts(root):
    record_path = root / 'docs/research/evolving-funded-work/evidence/chain-regressions.json'
    record = json.loads(record_path.read_text())
    if record.get('exit_code') != 0 or record.get('source_unchanged') is not True:
        raise ValueError('historical chain campaign is not terminal and unchanged')
    digest = record['source_inventory_sha256']
    if not re.fullmatch('[a-f0-9]{64}', digest):
        raise ValueError('invalid chain source inventory digest')
    history = root / 'docs/research/dynamic-delegation/evidence'
    inventories = [json.loads(path.read_text())['source_files']
                   for path in history.rglob('qualification.json')]
    if not any(hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
               == digest for files in inventories):
        raise ValueError('chain source inventory is not retained')
    stdout = next(name for name in record['outputs'] if name.endswith('.stdout'))
    for name, expected in record['outputs'].items():
        path = (root / name).resolve()
        if (not path.is_relative_to(root.resolve()) or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError('historical chain output hash mismatch')
    counts = native_counts(root, dict(source_files={}, outputs=record['outputs'],
                                     commands={'chain': dict(exit_code=0, stdout=stdout)}),
                           {'HistoricalChainTests': 'chain'})
    return counts['HistoricalChainTests'], digest
