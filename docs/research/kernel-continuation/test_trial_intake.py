import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from trial_fixture import make_package, FIELDS
from trial_intake import analyze

class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.package=make_package(Path(self.temp.name)/'package')
        self.root=self.package.parent
    def rows(self):
        with (self.root/'records.csv').open() as f:return list(csv.DictReader(f))
    def put_rows(self,rows):
        with (self.root/'records.csv').open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=FIELDS);writer.writeheader();writer.writerows(rows)
    def manifest(self):return json.loads(self.package.read_text())
    def put_manifest(self,value):self.package.write_text(json.dumps(value))
    def test_complete_synthetic_package_cannot_pass_empirical_gate(self):
        result=analyze(self.package)
        self.assertEqual(result['median_paired_ratio'],'0.5')
        self.assertEqual(len(result['pairs']),6)
        self.assertTrue(result['record_complete'])
        self.assertTrue(result['numerical_thresholds_met'])
        self.assertFalse(result['empirical_acceptance'])
        self.assertEqual(result['independence'],'not_established')
    def test_missing_duplicate_or_out_of_order_pair_is_rejected(self):
        original=self.rows()
        for rows in (original[:-1],original+[original[0]], [dict(r,order='1') for r in original]):
            self.put_rows(rows)
            with self.assertRaises(ValueError):analyze(self.package)
    def test_negative_nonfinite_fractional_counts_and_zero_denominator(self):
        original=self.rows()
        for field,value in [('model_cost','-1'),('model_cost','NaN'),('model_cost','Infinity'),
                            ('failed_attempts','1.5'),('repeated_hands_on_hours','0')]:
            rows=[r.copy() for r in original];rows[1][field]=value;self.put_rows(rows)
            with self.assertRaises(ValueError):analyze(self.package)
    def test_tampered_missing_or_escaping_artifacts(self):
        manifest=self.manifest();sha=next(iter(manifest['artifacts']))
        original=manifest['artifacts'][sha]
        for name in ('missing','../outside'):
            manifest['artifacts'][sha]=name;self.put_manifest(manifest)
            with self.assertRaises(ValueError):analyze(self.package)
        manifest['artifacts'][sha]=original;self.put_manifest(manifest)
        (self.root/original).write_text('tampered')
        with self.assertRaises(ValueError):analyze(self.package)
    def test_missing_matching_constraints_or_changed_pair_pins(self):
        manifest=self.manifest();manifest['adjudications']['I1'].pop('safety_matched');self.put_manifest(manifest)
        with self.assertRaises(ValueError):analyze(self.package)
        manifest['adjudications']['I1']['safety_matched']=False;self.put_manifest(manifest)
        with self.assertRaises(ValueError):analyze(self.package)
        rows=self.rows();rows[1]['trust_profile']='easier';self.put_rows(rows)
        with self.assertRaises(ValueError):analyze(self.package)
    def test_omitted_failure_or_repair_is_rejected(self):
        rows=self.rows();rows[0]['failed_attempts']='0';self.put_rows(rows)
        with self.assertRaises(ValueError):analyze(self.package)
    def test_repaired_success_cannot_be_counted_as_unassisted(self):
        manifest=self.manifest();rows=self.rows();old=rows[0]['event_log_sha']
        path=self.root/manifest['artifacts'][old];events=[json.loads(l) for l in path.read_text().splitlines()]
        events[1]['database_edits']=1
        data=''.join(json.dumps(e)+'\n' for e in events).encode();path.write_bytes(data)
        new=hashlib.sha256(data).hexdigest();manifest['artifacts'][new]=manifest['artifacts'].pop(old)
        rows[0]['event_log_sha']=new;rows[0]['database_edits']='1'
        self.put_rows(rows);self.put_manifest(manifest)
        with self.assertRaises(ValueError):analyze(self.package)
    def test_unregistered_operator_and_claimed_independence_are_not_accepted(self):
        rows=self.rows();rows[0]['operator_id']='invented';self.put_rows(rows)
        with self.assertRaises(ValueError):analyze(self.package)

    def test_adjudication_cannot_disagree_with_committed_artifact(self):
        manifest=self.manifest();manifest['adjudications']['I1']['quality_matched']=False
        self.put_manifest(manifest)
        with self.assertRaises(ValueError):analyze(self.package)
    def test_median_is_of_six_ratios_and_failed_effort_is_included(self):
        manifest=self.manifest();rows=self.rows()
        for i,row in enumerate(rows):
            pair=i//2
            total=([1,1,1,3,3,1000] if row['arm']=='Chio' else [4,4,4,4,4,100])[pair]
            old=row['event_log_sha'];path=self.root/manifest['artifacts'][old]
            events=[json.loads(line) for line in path.read_text().splitlines()]
            events[0]['hands_on_hours']='0.5';events[1]['hands_on_hours']=str(total-.5)
            data=''.join(json.dumps(e)+'\n' for e in events).encode();path.write_bytes(data)
            new=hashlib.sha256(data).hexdigest();manifest['artifacts'][new]=manifest['artifacts'].pop(old)
            row['event_log_sha']=new;row['repeated_hands_on_hours']=str(total)
        self.put_rows(rows);self.put_manifest(manifest)
        self.assertEqual(analyze(self.package)['median_paired_ratio'],'0.5')

    def change_events(self, index, mutate, **totals):
        manifest=self.manifest();rows=self.rows();old=rows[index]['event_log_sha']
        path=self.root/manifest['artifacts'][old]
        events=[json.loads(line) for line in path.read_text().splitlines()]
        mutate(events)
        data=''.join(json.dumps(e)+'\n' for e in events).encode();path.write_bytes(data)
        new=hashlib.sha256(data).hexdigest();manifest['artifacts'][new]=manifest['artifacts'].pop(old)
        rows[index].update(event_log_sha=new,**totals)
        self.put_rows(rows);self.put_manifest(manifest)
    def test_retry_counts_one_incident_and_retains_failed_effort(self):
        def retry(events):
            events[0]['incident_id']=events[1]['incident_id']
            events[0]['recoverable_incident']=True
        self.change_events(0,retry)
        result=analyze(self.package)
        self.assertEqual(result['recovery_fractions']['Chio'],'1')
        self.assertEqual(result['median_paired_ratio'],'0.5')
    def test_prior_repair_cannot_be_hidden_by_a_clean_final_attempt(self):
        def repair(events):
            events[0]['incident_id']=events[1]['incident_id']
            events[0]['database_edits']=1
        self.change_events(0,repair,database_edits='1')
        with self.assertRaises(ValueError):analyze(self.package)
    def test_repaired_incident_is_counted_once_and_retained(self):
        def repair(events):
            events[0].update(incident_id=events[1]['incident_id'],recoverable_incident=True,database_edits=1)
            events[1]['recovered_without_repair']=False
        self.change_events(0,repair,database_edits='1',recovered_without_repair='0')
        result=analyze(self.package)
        self.assertFalse(result['numerical_thresholds_met'])
        self.assertLess(float(result['recovery_fractions']['Chio']),.95)
    def test_missing_incident_identity_is_unresolved(self):
        self.change_events(0,lambda events:events[1].pop('incident_id'))
        with self.assertRaises(ValueError):analyze(self.package)
    def test_extreme_decimal_exponent_is_a_structured_input_error(self):
        from trial_intake import number
        with self.assertRaises(ValueError):number('1e-1000000','hours')
    def test_primary_threshold_comparison_does_not_round_a_failure_to_a_pass(self):
        n=10**17-1
        amounts=[(1,10),(1,10),(n-1,2*n),(n,2*(n-1)),(9,10),(9,10)]
        for i,(candidate,baseline) in enumerate(amounts):
            for offset,total in enumerate((candidate,baseline)):
                def costs(events,total=total):
                    events[0]['hands_on_hours']='0'
                    events[1]['hands_on_hours']=str(total)
                self.change_events(2*i+offset,costs,repeated_hands_on_hours=str(total))
        self.assertFalse(analyze(self.package)['numerical_thresholds_met'])

    def test_scheduled_incident_missing_from_logs_cannot_disappear(self):
        manifest=self.manifest()
        manifest['scheduled_incidents']['I1/Chio'].append('missing-incident')
        self.put_manifest(manifest)
        with self.assertRaises(ValueError):analyze(self.package)

if __name__=='__main__':unittest.main()
