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
        self.assertEqual(analyze(self.package)['median_paired_ratio'],'0.50')

if __name__=='__main__':unittest.main()
