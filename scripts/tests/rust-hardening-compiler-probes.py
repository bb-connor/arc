#!/usr/bin/env python3
"""Compile deliberate violations using the repository's actual policy attributes.

No workspace dependency build is needed. Cargo integration is qualified by the
workspace Clippy run and mirror gate; this calibrates each compiler rule itself.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('hardening', ROOT / 'scripts/check-rust-hardening.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
manifest = tomllib.loads((ROOT / 'Cargo.toml').read_text())
flags = []
for namespace in ['rust', 'clippy']:
    for lint, level in manifest['workspace']['lints'][namespace].items():
        if level == 'deny':
            flags += ['-D', ('clippy::' if namespace == 'clippy' else '') + lint]
root_source = (ROOT / 'crates/core/chio-bounded/src/lib.rs').read_text()
policy = '\n'.join('#![' + original + ']' for _, original in gate.root_attributes(root_source)
                   if 'clippy::' in original and 'deny(' in original)
forbid = '\n'.join('#![' + original + ']' for code, original in gate.root_attributes(root_source) if 'forbid' in code and 'unsafe_code' in code)
catalog = json.loads((ROOT / gate.CATALOG).read_text())
accounting_source = (ROOT / catalog['accounting_modules'][0]).read_text()
accounting_policy = '\n'.join('#![' + original + ']' for code, original in gate.root_attributes(accounting_source) if 'arithmetic_side_effects' in code)
probes = {
    'indexing_slicing': 'pub fn probe(v: &[u8], index: usize) -> u8 { v[index] }',
    'as_conversions': 'pub fn probe(v: u64) -> u8 { v as u8 }',
    'panic': 'pub fn probe() { panic!("fixture") }',
    'todo': 'pub fn probe() { todo!() }',
    'unimplemented': 'pub fn probe() { unimplemented!() }',
    'unreachable': 'pub fn probe() { unreachable!() }',
    'dbg_macro': 'pub fn probe() { dbg!(1); }',
    'print_stdout': 'pub fn probe() { println!("fixture"); }',
    'print_stderr': 'pub fn probe() { eprintln!("fixture"); }',
    'undocumented_unsafe_blocks': 'pub fn probe(p: &u8) -> u8 { unsafe { *(p as *const u8) } }',
    'multiple_unsafe_ops_per_block': 'pub fn probe(a: &u8, b: &u8) -> u8 {\n// SAFETY: both references are live for the call.\nunsafe { *(a as *const u8) + *(b as *const u8) } }',
    'E0133': 'pub unsafe fn probe(p: *const u8) -> u8 { *p }',
    'unsafe_code': '#[allow(unsafe_code)] pub fn probe(p: &u8) -> u8 {\n// SAFETY: p is live.\nunsafe { *(p as *const u8) } }',
    'arithmetic_side_effects': 'pub fn probe(a: u64, b: u64) -> u64 { a - b }',
}
driver = subprocess.check_output(['rustup', 'which', 'clippy-driver'], text=True).strip()
with tempfile.TemporaryDirectory(prefix='chio-hardening-compiler-') as temporary:
    directory = Path(temporary)
    for name, body in [('positive', 'pub fn probe(v: &[u8], index: usize) -> Option<u8> { v.get(index).copied() }'), *probes.items()]:
        unsafe_probe = name in {'undocumented_unsafe_blocks', 'multiple_unsafe_ops_per_block', 'E0133'}
        attributes = '' if unsafe_probe else policy
        if name == 'arithmetic_side_effects':
            attributes += '\n' + accounting_policy
        if name == 'unsafe_code':
            attributes += '\n' + forbid
        path = directory / 'probe.rs'
        path.write_text(attributes + '\n' + body)
        result = subprocess.run([driver, '--edition=2021', '--crate-type=lib', '--crate-name=probe',
                                 '--emit=metadata', '--error-format=json', '-o', str(directory / 'probe.rmeta'),
                                 *flags, str(path)], text=True, capture_output=True)
        codes = set()
        for line in result.stderr.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('level') == 'error':
                codes.add((item.get('code') or {}).get('code'))
        expected = name if name == 'E0133' else ('E0453' if name == 'unsafe_code' else 'clippy::' + name)
        if name == 'positive':
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0 and expected in codes, (name, codes, result.stderr)
        print(f'{name}: expected compiler outcome observed')
