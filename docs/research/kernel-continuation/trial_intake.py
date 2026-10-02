"""Validate six paired integration records; never certify operator independence."""
import argparse
import csv
from decimal import Decimal, InvalidOperation
import hashlib
import json
from fractions import Fraction
from pathlib import Path
import re
from statistics import median

SOURCE_TEMPLATE = Path(__file__).parent.parent / 'kernel-work/results/integration-records.csv'
FIELDS = SOURCE_TEMPLATE.read_text().splitlines()[0].split(',')
ARTIFACT_FIELDS = ('provider_source_sha','verifier_source_sha','task_corpus_sha',
                   'adapter_diff_sha','event_log_sha','operator_attestation','quality_adjudication')
COUNTS = ('manual_approvals','model_tokens','state_bytes','physical_effects','failed_attempts',
          'recoverable_incidents','recovered_without_repair','database_edits','bespoke_repairs')
NUMBERS = tuple(FIELDS[10:24]) + tuple(FIELDS[25:30])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, label, integer=False):
    try:
        require(isinstance(value, str) and len(value) <= 80, f'{label}: invalid number')
        result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f'{label}: invalid number') from error
    require(result.is_finite() and result >= 0 and result <= Decimal('1e18'),
            f'{label}: expected finite nonnegative value <= 1e18')
    if result == 0:
        return Decimal(0)
    digits = list(result.as_tuple().digits)
    exponent = result.as_tuple().exponent
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    require(len(digits) <= 18 and -24 <= exponent <= 18,
            f'{label}: exceeds supported precision (18 significant digits, resolution 1e-24)')
    require(not integer or result == result.to_integral_value(), f'{label}: expected integer')
    return result


def decimal_display(value):
    return str(Decimal(value.numerator) / Decimal(value.denominator))


def exact_ratio(value):
    return {'numerator':str(value.numerator),'denominator':str(value.denominator)}


def confined(root, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute(), 'artifact path must be relative')
    path = (root / name).resolve()
    require(path.is_relative_to(root) and path.is_file(), f'missing or escaping file: {name}')
    return path


def analyze(package):
    package = Path(package).resolve()
    root = package.parent
    manifest = json.loads(package.read_text())
    require(manifest.get('schema') == 'chio.integration-intake.v1', 'wrong manifest schema')
    require(manifest.get('mode') in ('synthetic','independent'), 'mode is required')
    artifacts = manifest.get('artifacts')
    require(isinstance(artifacts, dict) and artifacts, 'no artifact inventory')
    files = {}
    for sha, name in artifacts.items():
        require(re.fullmatch('[0-9a-f]{64}', sha) is not None, 'invalid artifact digest')
        path = confined(root, name)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == sha, f'artifact hash mismatch: {name}')
        files[sha] = path
    with confined(root, manifest.get('records')).open(newline='') as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == FIELDS, 'CSV header differs from preregistration')
        rows = list(reader)
    require(len(rows) == 12, 'six complete pairs required')
    operators = manifest.get('operators')
    require(isinstance(operators, dict) and operators, 'operators are unregistered')
    schedule = manifest.get('scheduled_incidents')
    require(isinstance(schedule,dict) and set(schedule) ==
            {f'I{i}/{arm}' for i in range(1,7) for arm in ('Chio','B1')},
            'frozen incident schedule required for all pair members')
    indexed = {}
    seen_attempts = set()
    seen_incidents = set()
    for row in rows:
        require(set(row) == set(FIELDS) and all(isinstance(v,str) and v.strip() for v in row.values()),
                'blank, extra or truncated CSV field')
        exercise, arm = row['exercise'], row['arm']
        require(exercise in {f'I{i}' for i in range(1,7)} and arm in ('Chio','B1'), 'unknown arm or exercise')
        require((exercise,arm) not in indexed, 'duplicate pair member')
        indexed[exercise,arm] = row
        expected_order = '1' if (arm == 'Chio') == (int(exercise[1]) % 2 == 1) else '2'
        require(row['order'] == expected_order, 'counterbalanced order changed')
        require(row['operator_id'] in operators, 'unregistered operator')
        for field in ARTIFACT_FIELDS:
            require(row[field] in files, f'{exercise}/{arm}: unbound {field}')
        for field in NUMBERS:
            number(row[field], field, field in COUNTS)
        events = [json.loads(line) for line in files[row['event_log_sha']].read_text().splitlines()]
        require(events, 'empty attempt log')
        total = Fraction(0)
        counts = dict.fromkeys(('failed_attempts','recoverable_incidents','recovered_without_repair',
                                'database_edits','bespoke_repairs'),0)
        incidents = {}
        for event in events:
            require(isinstance(event,dict), 'attempt must be an object')
            identity = event.get('attempt_id')
            require(isinstance(identity,str) and identity and identity not in seen_attempts, 'missing or reused attempt ID')
            seen_attempts.add(identity)
            require(event.get('status') in ('succeeded','failed','cancelled'), 'unknown attempt outcome')
            counts['failed_attempts'] += event['status'] != 'succeeded'
            total += Fraction(number(event.get('hands_on_hours'), 'attempt effort'))
            for key in ('recoverable_incident','recovered_without_repair'):
                require(type(event.get(key)) is bool, f'{key} must be boolean')
            require('incident_id' in event, 'missing incident identity')
            incident = event['incident_id']
            require(incident is None or (isinstance(incident,str) and 0 < len(incident) <= 128),
                    'invalid incident identity')
            require(event['recoverable_incident'] == (incident is not None),
                    'incident identity disagrees with recovery classification')
            for key in ('database_edits','bespoke_repairs'):
                require(type(event.get(key)) is int and event[key] >= 0, f'invalid {key}')
                require(event[key] == 0 or incident is not None, 'repair has no incident identity')
                counts[key] += event[key]
            recovered = event['recovered_without_repair']
            require(not recovered or (event['recoverable_incident'] and event['status'] == 'succeeded'
                    and event['database_edits'] == 0 and event['bespoke_repairs'] == 0),
                    'repaired or failed attempt counted as unassisted recovery')
            if incident is not None:
                history = incidents.setdefault(incident,[])
                require(not history or history[-1]['status'] != 'succeeded',
                        'completed incident reused for another attempt')
                history.append(event)
        require(not seen_incidents.intersection(incidents), 'incident identity reused across pair members')
        scheduled = schedule[f'{exercise}/{arm}']
        require(isinstance(scheduled,list) and all(isinstance(s,str) for s in scheduled)
                and len(scheduled) == len(set(scheduled)) and set(scheduled) == set(incidents),
                'raw attempts do not cover the frozen incident schedule')
        seen_incidents.update(incidents)
        counts['recoverable_incidents'] = len(incidents)
        for history in incidents.values():
            recovered = history[-1]['recovered_without_repair']
            repairs = sum(event['database_edits'] + event['bespoke_repairs'] for event in history)
            require(not recovered or repairs == 0, 'earlier repair invalidates unassisted recovery')
            counts['recovered_without_repair'] += recovered
        require(total == Fraction(Decimal(row['repeated_hands_on_hours'])), 'omitted or conflicting hands-on effort')
        for key, count in counts.items():
            require(count == Decimal(row[key]), f'raw attempts disagree with {key}')
        require(counts['recoverable_incidents'] > 0, 'scheduled recovery incidents missing')
    pairs = []
    ratios = []
    matched = True
    adjudications = manifest.get('adjudications')
    require(isinstance(adjudications,dict) and set(adjudications) == {f'I{i}' for i in range(1,7)},
            'six adjudications required')
    for i in range(1,7):
        exercise = f'I{i}'
        require((exercise,'Chio') in indexed and (exercise,'B1') in indexed, 'incomplete pair')
        candidate, baseline = indexed[exercise,'Chio'], indexed[exercise,'B1']
        for field in ('operator_id','task_corpus_sha','model_pin','trust_profile','budget_profile'):
            require(candidate[field] == baseline[field], f'unmatched pair pin: {field}')
        adjudication = adjudications[exercise]
        require(isinstance(adjudication,dict) and adjudication.get('artifact_sha') in files, 'missing adjudication evidence')
        require(candidate['quality_adjudication'] == baseline['quality_adjudication']
                == adjudication['artifact_sha'], 'unbound pair adjudication')
        committed = json.loads(files[adjudication['artifact_sha']].read_text())
        require(isinstance(committed,dict) and isinstance(committed.get('exercises'),dict),
                'invalid committed adjudication')
        evidence = committed['exercises'].get(exercise)
        require(isinstance(evidence,dict), 'missing committed pair judgment')
        for field in ('safety_matched','progress_matched','quality_matched'):
            require(type(adjudication.get(field)) is bool, f'missing {field}')
            require(type(evidence.get(field)) is bool and evidence[field] == adjudication[field],
                    'adjudication disagrees with committed evidence')
            matched &= adjudication[field]
        denominator = Decimal(baseline['repeated_hands_on_hours'])
        require(denominator > 0, 'zero B1 denominator is unresolved')
        ratio = Fraction(Decimal(candidate['repeated_hands_on_hours'])) / Fraction(denominator)
        ratios.append(ratio)
        pairs.append({'exercise':exercise,'ratio':decimal_display(ratio),'exact_ratio':exact_ratio(ratio)})
    recovery = {}
    recovery_counts = {}
    for arm in ('Chio','B1'):
        arm_rows = [r for r in rows if r['arm'] == arm]
        recovered = sum(int(Decimal(r['recovered_without_repair'])) for r in arm_rows)
        scheduled = sum(int(Decimal(r['recoverable_incidents'])) for r in arm_rows)
        recovery_counts[arm] = {'scheduled_incidents':scheduled,'recovered_without_repair':recovered}
        recovery[arm] = Fraction(recovered,scheduled)
    median_ratio = median(ratios)
    thresholds = median_ratio <= Fraction(1,2) and matched and recovery['Chio'] >= Fraction(19,20)
    return {'schema':'chio.integration-intake-result.v1','mode':manifest['mode'],
            'record_complete':True,'pairs':pairs,'median_paired_ratio':decimal_display(median_ratio),
            'median_paired_ratio_exact':exact_ratio(median_ratio),
            'recovery_fractions':{arm:decimal_display(value) for arm,value in recovery.items()},
            'recovery_counts':recovery_counts,
            'matched_safety_progress_quality':matched,'numerical_thresholds_met':thresholds,
            'independence':'not_established','empirical_acceptance':False,
            'limitation':'Mechanical validation cannot establish authentic effort, independence, completeness of supplied logs or adjudicator truth. Independent audit remains required.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest',type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.manifest)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({'record_complete':False,'empirical_acceptance':False,'error':str(error)},indent=2))
        return 2
    print(json.dumps(result,indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
