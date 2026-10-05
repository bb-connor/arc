"""Evidence requirements for publication; status flags are never evidence."""
import hashlib
from pathlib import Path

REQUIRED_GATES = frozenset(('manuscript', 'artifact', 'funded-security-integration',
                          'closest-prior-art', 'independent-operation',
                          'useful-work-economics', 'integration-advantage',
                          'foundational-claim'))
CLAIM_REQUIREMENTS = {
    'funded-security-integration': {'E01': 'locally-tested', 'E02': 'locally-tested'},
    'closest-prior-art': {'C13': 'locally-tested'},
    'independent-operation': {'E01': 'independently-tested'},
    'useful-work-economics': {'H02': 'established', 'H04': 'established'},
    'integration-advantage': {'H03': 'established'},
    'foundational-claim': {'B01': 'established'},
}


def required_files(release, claims, *, root, paper):
    """Collect mandatory freeze inputs without granting publication authority."""
    root, paper = Path(root).resolve(), Path(paper).resolve()
    paths = {(paper / name).resolve() for name in ('PUBLICATION.json', 'CLAIMS.json')}
    by_id = {}
    for claim in claims.get('claims', []):
        name = claim.get('claim_id')
        if name in by_id:
            raise ValueError('duplicate publication claim: ' + str(name))
        by_id[name] = claim

    def include(names, base):
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list) or not names:
            raise ValueError('missing named publication evidence')
        for name in names:
            if not isinstance(name, str) or not name:
                raise ValueError('missing named publication evidence')
            paths.add((base / name).resolve())

    for gate in release.get('gates', []):
        if gate.get('status') != 'passed':
            continue
        include(gate.get('evidence'), paper)
        for claim_id in CLAIM_REQUIREMENTS.get(gate.get('id'), {}):
            include(by_id.get(claim_id, {}).get('evidence_paths'), root)
    for path in paths:
        if not path.is_relative_to(root):
            raise ValueError('publication evidence outside repository: ' + str(path))
        if not path.is_file():
            raise ValueError('missing publication evidence: ' + str(path))
    return sorted(paths)


def verify(release, claims, manifest, *, root, paper):
    errors, seen = [], set()
    files = manifest.get('files', {})
    root, paper = Path(root).resolve(), Path(paper).resolve()

    def evidence(name):
        if not isinstance(name, str) or not name:
            return ['missing named publication evidence']
        path = (paper / name).resolve()
        if not path.is_relative_to(root):
            return ['publication evidence outside repository: ' + name]
        key = path.relative_to(root).as_posix()
        if key not in files:
            return ['publication evidence absent from frozen manifest: ' + name]
        if not path.is_file():
            return ['missing publication evidence: ' + name]
        if hashlib.sha256(path.read_bytes()).hexdigest() != files[key]:
            return ['publication evidence hash mismatch: ' + name]
        return []

    for name in ('PUBLICATION.json', 'CLAIMS.json'):
        errors.extend(evidence(name))
    by_id = {}
    for claim in claims.get('claims', []):
        name = claim.get('claim_id')
        if name in by_id:
            errors.append('duplicate publication claim: ' + str(name))
        by_id[name] = claim
    for gate in release.get('gates', []):
        name = gate.get('id')
        if name in seen:
            errors.append(f'duplicate publication gate: {name}')
        seen.add(name)
        if name not in REQUIRED_GATES:
            errors.append(f'unknown publication gate: {name}')
        if gate.get('status') != 'passed':
            errors.append(f'publication gate open: {name}')
            continue
        if not gate.get('acceptance') or not gate.get('result'):
            errors.append(f'publication gate lacks acceptance or result: {name}')
        paths = gate.get('evidence')
        if isinstance(paths, str):
            paths = [paths]
        if not isinstance(paths, list) or not paths:
            errors.append(f'publication gate lacks evidence: {name}')
        else:
            for path in paths:
                errors.extend(evidence(path))
        for claim_id, required in CLAIM_REQUIREMENTS.get(name, {}).items():
            claim = by_id.get(claim_id, {})
            statuses = claim.get('status', [])
            if (not isinstance(statuses, list) or required not in statuses
                    or (required in ('established', 'independently-tested')
                        and 'hypothesis' in statuses)):
                errors.append(f'publication claim does not support {name}: {claim_id}')
            claim_paths = claim.get('evidence_paths', [])
            if not claim_paths:
                errors.append(f'publication claim lacks evidence: {claim_id}')
            for path in claim_paths:
                # Claim paths are repository-relative; gate paths are paper-relative.
                errors.extend(evidence(str(root / path)))
    errors.extend(f'missing publication gate: {name}' for name in sorted(REQUIRED_GATES - seen))
    for flag in ('publish_ready', 'breakthrough_established'):
        if release.get(flag) is not True:
            errors.append(f'{flag} is not true')
    return errors
