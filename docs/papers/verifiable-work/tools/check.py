"""Check the manuscript against retained results; never promote open research gates."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
from provenance import HISTORICAL_SOURCE, EVIDENCE, verify_revision_files, verify_qualification

PAPER = Path(__file__).resolve().parents[1]
ROOT = PAPER.parents[2]
REQUIRED_GATES = frozenset(('manuscript', 'artifact', 'funded-security-integration',
                          'closest-prior-art', 'independent-operation',
                          'useful-work-economics', 'integration-advantage',
                          'foundational-claim'))


def verify_publication(release):
    errors = []
    seen = set()
    for gate in release.get('gates', []):
        name = gate.get('id')
        if name in seen:
            errors.append(f'duplicate publication gate: {name}')
        seen.add(name)
        if gate.get('status') != 'passed':
            errors.append(f'publication gate open: {name}')
    errors.extend(f'missing publication gate: {name}' for name in sorted(REQUIRED_GATES-seen))
    for flag in ('publish_ready', 'breakthrough_established'):
        if release.get(flag) is not True:
            errors.append(f'{flag} is not true')
    return errors


def verify_files(root, hashes):
    root = root.resolve()
    errors = []
    for name, expected in hashes.items():
        file = (root/name).resolve()
        if not file.is_relative_to(root):
            errors.append(f'outside root: {name}')
        elif not file.is_file():
            errors.append(f'missing: {name}')
        elif hashlib.sha256(file.read_bytes()).hexdigest() != expected:
            errors.append(f'hash mismatch: {name}')
    return errors


def derived():
    model = json.loads((PAPER/'evidence/claim-traces.json').read_text())
    comparison = json.loads((PAPER/'evidence/comparison.json').read_text())
    contract = (PAPER/'evidence/contracts.log').read_text()
    if model['counterexample'] is not None or comparison['mismatches']:
        raise ValueError('positive result contains a counterexample or mismatch')
    match = re.search(r'(?:#|ℹ) pass (\d+)', contract)
    if not match or not re.search(r'(?:#|ℹ) fail 0\b', contract):
        raise ValueError('contract suite is not terminal and passing')
    if len(model['traces']) != comparison['traces']:
        raise ValueError('model/comparator trace count drift')
    neg = json.loads((PAPER/'evidence/expiry-counterexample.json').read_text())
    if neg['counterexample']['property'] != 'accepted claim was refunded':
        raise ValueError('negative model calibration missing')
    if 'Missing expected rejection' not in (PAPER/'evidence/contract-mutation.log').read_text():
        raise ValueError('negative bytecode calibration missing')
    lean = (PAPER/'evidence/lean.log').read_text()
    if 'sorryAx' in lean or 'error:' in lean or 'earned_never_refunded' not in lean:
        raise ValueError('Lean evidence invalid')
    proof = (PAPER/'formal/WorkClaims.lean').read_text()
    if re.search(r'\b(sorry|admit|axiom)\b', proof):
        raise ValueError('unchecked proof placeholder')
    numbers = dict(ModelStates=model['states'], ModelTransitions=model['transitions'],
                   TraceCount=len(model['traces']), MatchedSteps=comparison['checked_steps'],
                   ContractTests=int(match[1]), ProofCount=len(re.findall(r'^theorem ',proof,re.M)))
    upstream = PAPER/'evidence/erc8183'
    upstream_log = (upstream/'logs/verified-upstream.log').read_text()
    upstream_result = re.search(r': (\d+) tests passed, 0 failed, 0 skipped', upstream_log)
    tests = json.loads((upstream/'logs/verified-comparison-json.log').read_text())
    results = [result for suite in tests.values() for result in suite['test_results'].values()]
    if not upstream_result or not results or any(r['status'] != 'Success' for r in results):
        raise ValueError('upstream comparison is not terminal and passing')
    for name in ('verified-upstream', 'verified-comparison-traces', 'verified-comparison-json',
                 'portable-reproduction'):
        if json.loads((upstream/f'logs/{name}.command.json').read_text())['exit_status'] != 0:
            raise ValueError('upstream comparison command failed: '+name)
    numbers.update(UpstreamTests=int(upstream_result[1]), PairedTests=len(results))
    integration_path = PAPER/'evidence/integration-summary.json'
    summary = (json.loads(integration_path.read_text())['manuscript_summary'] if integration_path.exists()
               else 'Integration qualification is in progress; the manuscript does not treat the combined candidate as verified.')
    return ('% Generated from retained evidence; regenerate with tools/check.py --refresh.\n'
            + ''.join('\\newcommand{\\'+k+'}{'+format(v,',')+'}\n' for k,v in numbers.items())
            + '\\newcommand{\\IntegrationSummary}{'+summary+'}\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--refresh',action='store_true')
    parser.add_argument('--freeze',action='store_true')
    parser.add_argument('--publication',action='store_true')
    args = parser.parse_args()
    macros=derived()
    if args.refresh:
        (PAPER/'results.tex').write_text(macros)
        print('Derived result macros refreshed from retained evidence.')
        return
    errors=[]
    observations = json.loads((PAPER/'evidence/observations.json').read_text())
    for observed in observations['checks']:
        errors.extend(verify_files(PAPER/'evidence',
                                   {observed['log']: observed['log_sha256']}))
    integration = json.loads((PAPER/'evidence/integration-summary.json').read_text())
    raw_source_manifest = gzip.decompress((PAPER/'evidence'/integration['source_manifest']).read_bytes())
    if hashlib.sha256(raw_source_manifest).hexdigest() != integration['source_manifest_uncompressed_sha256']:
        errors.append('native source inventory hash mismatch')
    source_files = json.loads(raw_source_manifest)['sourceFiles']
    # The historical experiment's build inputs belong to its retained epoch.
    # Manuscript/tooling inputs are checked by the current artifact inventory.
    source_files = {k:v for k,v in source_files.items()
                    if not k.startswith('docs/papers/verifiable-work/')}
    # Historical native observations remain checked against the preserved tree.
    # New native code is qualified separately below; no old inventory is rewritten.
    errors.extend(verify_revision_files(ROOT, HISTORICAL_SOURCE, source_files))
    qualification = ROOT/EVIDENCE/'qualification.json'
    if not qualification.is_file():
        errors.append('missing current dynamic native qualification')
    else:
        errors.extend(verify_qualification(ROOT, json.loads(qualification.read_text())))
    trial = json.loads((PAPER/'trial/manifest.template.json').read_text())
    errors.extend(verify_revision_files(ROOT, HISTORICAL_SOURCE, trial['profile_inputs']))
    for check in integration['checks']:
        record = json.loads((PAPER/'evidence'/check['record']).read_text())
        if record['exitCode'] != 0 or not (PAPER/'evidence'/check['log']).is_file():
            errors.append('native evidence incomplete: '+check['id'])
    if (PAPER/'results.tex').read_text()!=macros:
        errors.append('result macros differ from evidence')
    sources = json.loads((PAPER/'sources.json').read_text())['sources']
    if any(s['status']!='retrieved' or not s.get('sha256') for s in sources):
        errors.append('source retrieval incomplete')
    texfiles=[PAPER/'paper.tex',*(PAPER/'sections').glob('*.tex')]
    tex='\n'.join(x.read_text() for x in texfiles)
    bib=(PAPER/'bib.bib').read_text()
    keys=set(re.findall(r'@\w+\{([^,]+),',bib))
    citations=set(k.strip() for group in re.findall(r'\\cite\w*\{([^}]+)\}',tex) for k in group.split(','))
    for key in sorted(citations-keys): errors.append('missing citation: '+key)
    if '\u2014' in tex or '\u2014' in bib: errors.append('em dash in manuscript')
    if re.search(r'\b(TODO|TBD|FIXME)\b',tex): errors.append('manuscript placeholder')
    log=(PAPER/'paper.log').read_text() if (PAPER/'paper.log').exists() else ''
    if not log: errors.append('missing LaTeX build log')
    for pattern in (r'Undefined control sequence',r'LaTeX Error',r'Citation .+ undefined',
                    r'Reference .+ undefined',r'undefined references',r'There were undefined'):
        if re.search(pattern,log): errors.append('LaTeX error: '+pattern)
    widths=re.findall(r'Overfull \\hbox \((\d+(?:\.\d+)?)pt too wide\)',log)
    if any(float(x)>2 for x in widths): errors.append('overfull line over 2pt: '+','.join(widths))
    blg=(PAPER/'paper.blg').read_text() if (PAPER/'paper.blg').exists() else ''
    if not blg or 'Warning--' in blg or '(There was' in blg: errors.append('bibliography missing or warnings')
    if (PAPER/'paper.pdf').exists():
        text=subprocess.check_output(['pdftotext',str(PAPER/'paper.pdf'),'-'],text=True)
        if 'A Peer-to-Peer Economy' not in text or 'Verifiable Work' not in text: errors.append('PDF title mismatch')
        for name in ('ModelStates','ModelTransitions','MatchedSteps','ContractTests'):
            value=re.search(r'\\'+name+r'\}\{([^}]+)\}',macros)[1]
            if value not in text: errors.append('PDF missing derived result '+name)
    else: errors.append('missing PDF')
    manifest=PAPER/'artifact-manifest.json'
    if args.freeze:
        candidates=[*PAPER.rglob('*'),* (ROOT/'examples/funded-work-model').glob('*.py'),
                    *(ROOT/'docs/research/dynamic-delegation').rglob('*'),
                    *(ROOT/'docs/research/swarm-evolution').rglob('*'),
                    *(ROOT/'docs/research/evolving-funded-work').rglob('*'),
                    ROOT/'docs/superpowers/specs/2026-10-02-evolving-funded-work-design.md',
                    ROOT/'docs/superpowers/plans/2026-10-02-evolving-funded-work.md',
                    ROOT/'docs/superpowers/specs/2026-10-02-dynamic-delegation-design.md',
                    ROOT/'docs/superpowers/plans/2026-10-02-dynamic-delegation.md',
                    ROOT/'docs/superpowers/specs/2026-10-02-sovereign-swarm-evolution-design.md',
                    ROOT/'docs/superpowers/plans/2026-10-02-sovereign-swarm-evolution.md',
                    ROOT/'docs/research/kernel-continuation/CAPITAL.md',
                    ROOT/'docs/research/kernel-continuation/capital.py',
                    ROOT/'docs/research/kernel-continuation/test_capital.py',
                    ROOT/'docs/research/kernel-continuation/results/capital.json',
                    ROOT/'examples/funded-work-model/claim-traces.json',
                    * (ROOT/'contracts/src').rglob('*.sol'),
                    * (ROOT/'contracts/scripts').glob('work-claim-*.mjs'),
                    * (ROOT/'contracts/scripts/fixtures').rglob('*'),
                    ROOT/'contracts/scripts/funded-work-fit.test.mjs',
                    ROOT/'contracts/scripts/test-utils.mjs',
                    ROOT/'contracts/package.json', ROOT/'contracts/pnpm-lock.yaml']
        files={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
               for f in candidates if f.is_file() and f!=manifest and f.name!='PROGRESS.md'
               and '__pycache__' not in f.parts and (f.suffix not in ('.aux','.blg','.bbl','.out','.log') or 'evidence' in f.parts)}
        manifest.write_text(json.dumps(dict(schema='chio.paper.artifact.v1',
             foundation_commit='7755d3762baa5e0fda0d171835a9000c26de9033',files=files),indent=2)+'\n')
    if manifest.exists():
        errors.extend(verify_files(ROOT,json.loads(manifest.read_text())['files']))
    elif not args.refresh: errors.append('missing artifact manifest (freeze after qualification)')
    if args.publication:
        release=json.loads((PAPER/'PUBLICATION.json').read_text())
        errors.extend(verify_publication(release))
    for error in errors: print('FAIL:',error)
    if errors: raise SystemExit(1)
    print('PASS: manuscript, bibliography, derived results, PDF and artifact hashes agree.')

if __name__=='__main__': main()
