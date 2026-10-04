"""Finite, function-scoped witnesses for reviewed retained-state readers.

These source tripwires supplement the shared JSON constructor checks. They do
not establish authentication or dataflow; the inventory records those reviewed
contracts and their owning runtime tests separately.
"""
import json
from pathlib import Path
import re

RULES = json.loads(Path(__file__).with_suffix('.json').read_text())['rules']
SUPPORT_PATHS = tuple(sorted({
    witness['path']
    for rule in RULES
    for witness in [*rule['required_owner_witnesses'], *rule['producer_relationships']]
}))


def matches(body, expressions):
    return bool(body) and all(re.search(expression, body) for expression in expressions)


def verified_apis(path, reader, body, supports, owners, declarations):
    apis = []
    for rule in RULES:
        if (path, reader.split('#')[0]) != (rule['path'], rule['reader']):
            continue
        if not matches(body, rule['required_source_expressions']):
            continue
        witnessed = True
        for witness in rule['required_owner_witnesses']:
            code = supports.get(witness['path'], '')
            owner = witness['owner']
            scoped = declarations(code) if owner == '@file' else owners(code).get(owner, '')
            if not matches(scoped, witness['required_source_expressions']):
                witnessed = False
                break
        if not witnessed:
            continue
        for relationship in rule['producer_relationships']:
            bodies = owners(supports.get(relationship['path'], ''))
            callee = relationship['callee']
            # A qualified call still consumes the same private helper. Count
            # these conservatively by final path component; methods on an
            # unrelated receiver do not satisfy the free-function relationship.
            invocation = re.compile(
                r'(?<![\w.])(?:\w+::)*' + re.escape(callee)
                + r'\s*(?:::<[^;{}]*?>\s*)?\('
            )
            callers = {name: text for name, text in bodies.items()
                       if name.split('#')[0] != callee and invocation.search(text)}
            if set(callers) != set(relationship['expected_callers']):
                witnessed = False
                break
            count = relationship.get('expected_call_count')
            if count is not None and sum(len(invocation.findall(text))
                    for text in callers.values()) != count:
                witnessed = False
                break
        if witnessed:
            apis.append(rule['api_label'])
    return apis
