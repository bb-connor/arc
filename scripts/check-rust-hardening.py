#!/usr/bin/env python3
"""Enforce the declared Rust policy; compiler probes establish lint behavior.

This is a lexical tripwire, not Rust name resolution. The compiler enforces
unsafe/TCB rules; these checks prevent removal or unjustified local relaxation.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CATALOG = 'docs/security/toolchain/rust-hardening.json'
TCB_LINTS = ('indexing_slicing', 'panic', 'todo', 'unimplemented', 'unreachable',
             'dbg_macro', 'print_stdout', 'print_stderr', 'as_conversions')
_spec = importlib.util.spec_from_file_location('hardening_lexer', ROOT / 'scripts/check-accounting-arithmetic.py')
lexer = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lexer
_spec.loader.exec_module(lexer)


def attributes(text):
    code = lexer.blank_rust_noise(text)
    for match in re.finditer(r'#!?\s*\[', code):
        start = code.index('[', match.start())
        end = lexer.attribute_end(code, start)
        yield code[start + 1:end - 1], text[start + 1:end - 1]


def root_attributes(text):
    code = lexer.blank_rust_noise(text)
    cursor = 0
    while match := re.match(r'\s*#!\s*\[', code[cursor:]):
        start = cursor + match.end() - 1
        end = lexer.attribute_end(code, start)
        yield code[start + 1:end - 1], text[start + 1:end - 1]
        cursor = end


def has_deny(text, lint):
    for code, _ in root_attributes(text):
        # Accept the declared production policy, never a test-only or otherwise
        # inactive cfg. Unknown predicates cannot establish a production floor.
        conditional = re.fullmatch(
            r'\s*cfg_attr\s*\(\s*not\s*\(\s*test\s*\)\s*,\s*(deny\s*\([^()]*\))\s*,?\s*\)\s*',
            code, re.S)
        policy = conditional.group(1) if conditional else code
        unconditional = re.fullmatch(r'\s*deny\s*\(([^()]*)\)\s*', policy, re.S)
        if unconditional and lint in {entry.strip() for entry in unconditional.group(1).split(',')}:
            return True
    return False


def library_errors(path, text, exceptions):
    if any(re.fullmatch(r'\s*forbid\s*\(\s*unsafe_code\s*\)\s*', code)
           for code, _ in root_attributes(text)):
        return []
    if exceptions.get(path, '').strip():
        return []
    return [f'{path}: library must forbid unsafe or name its unsafe boundary']


def exception_errors(text):
    errors = []
    for code, original in attributes(text):
        if not re.search(r'\b(?:allow|expect)\s*\([^)]*clippy::', code):
            continue
        # The token must exist outside comments and strings; then inspect its value.
        reason = re.search(r'\breason\s*=', code)
        if reason is None or not re.match(r'"[^"\n]*\S[^"\n]*"', original[reason.end():].lstrip()):
            errors.append('Clippy exception requires a nonempty reason')
    return errors


def secret_errors(text):
    code = lexer.blank_rust_noise(text)
    errors = []
    # Capture all adjacent attributes, then scan the entire balanced body.
    # Array types contain semicolons, and tuples/const generics may contain
    # nested delimiters. This remains lexical: type aliases are not resolved.
    pattern = r'((?:#\s*\[[^]]*\]\s*)+)(?:pub(?:\([^)]*\))?\s+)?struct\s+\w+[^;{(]*[({]'
    for match in re.finditer(pattern, code, re.S):
        traits = ",".join(re.findall(r"\bderive\s*\(([^)]*)\)", match.group(1)))
        start = match.end() - 1
        stack = []
        end = start
        closing = {'(': ')', '[': ']', '{': '}'}
        for end in range(start, len(code)):
            char = code[end]
            if char in closing:
                stack.append(closing[char])
            elif stack and char == stack[-1]:
                stack.pop()
                if not stack:
                    break
        body = code[start:end + 1]
        raw = bool(re.search(r'\bZeroizing\s*<', body))
        wrapped = bool(re.search(r'\bSecret(?:Box|String|Slice)\b', body))
        if raw and re.search(r'\b(?:Debug|Serialize)\b', traits):
            errors.append('raw zeroizing secret must not derive Debug or Serialize')
        if wrapped and re.search(r'\bSerialize\b', traits):
            errors.append('secret owner must use explicit custody export, not derive Serialize')
    return errors


def accounting_include_errors(root, includes):
    errors = []
    for child, parent in includes.items():
        owner = root / parent
        included = root / child
        if not included.is_file() or not owner.is_file():
            errors.append(f'{child}: missing accounting include or owner')
            continue
        source = owner.read_text()
        targets = { (owner.parent / match).resolve() for match in
                    re.findall(r'include!\(\s*"([^"\n]+)"\s*\)', source) }
        if included.resolve() not in targets:
            errors.append(f'{child}: not included by its arithmetic owner {parent}')
        if not has_deny(source, 'clippy::arithmetic_side_effects'):
            errors.append(f'{child}: accounting include owner lacks arithmetic deny')
    return errors


def check(root):
    catalog = json.loads((root / CATALOG).read_text())
    result = subprocess.run(['cargo', 'metadata', '--offline', '--no-deps', '--format-version', '1'],
                            cwd=root, text=True, capture_output=True, check=True)
    metadata = json.loads(result.stdout)
    errors = []
    libraries = set()
    for package in metadata['packages']:
        if package['id'] not in metadata['workspace_members']:
            continue
        for target in package['targets']:
            if not set(target['kind']) & {'lib', 'proc-macro', 'cdylib', 'rlib', 'staticlib'}:
                continue
            path = Path(target['src_path']).relative_to(root).as_posix()
            libraries.add(path)
            errors.extend(library_errors(path, (root / path).read_text(), catalog['unsafe_libraries']))
            if (path.startswith(('crates/security/', 'crates/kernel/'))
                    or package['name'] in {'chio-core-types', 'chio-bounded', 'chio-supervisor',
                                          'chio-store-sqlite', 'chio-control-plane'}):
                if catalog['tcb_libraries'].get(package['name']) != path:
                    errors.append(f'{path}: security library missing from TCB policy')
    for path in set(catalog['unsafe_libraries']) - libraries:
        errors.append(f'{path}: stale unsafe library exception')
    roots = set()
    for path in catalog['tcb_libraries'].values():
        text = (root / path).read_text()
        roots.add(Path(path).parent)
        for lint in TCB_LINTS:
            if not has_deny(text, 'clippy::' + lint):
                errors.append(f'{path}: missing production deny for {lint}')
    for path in catalog['accounting_modules']:
        if not has_deny((root / path).read_text(), 'clippy::arithmetic_side_effects'):
            errors.append(f'{path}: missing accounting arithmetic deny')
    errors.extend(accounting_include_errors(root, catalog.get('accounting_includes', {})))
    for directory in roots:
        for path in (root / directory).rglob('*'):
            if path.suffix not in {'.rs', '.inc'}:
                continue
            text = path.read_text()
            for error in exception_errors(text):
                errors.append(f'{path.relative_to(root)}: {error}')
    secret_roots = roots | {Path('crates/guards/chio-external-guards/src'),
                            Path('crates/trust/chio-federation-authority/src'),
                            Path('crates/economy/chio-settle/src')}
    for directory in secret_roots:
        for path in (root / directory).rglob('*'):
            if path.suffix in {'.rs', '.inc'}:
                for error in secret_errors(path.read_text()):
                    errors.append(f'{path.relative_to(root)}: {error}')
    return errors, len(libraries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    errors, libraries = check(args.root.resolve())
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print(f'Rust hardening policy: {libraries} library roots, TCB, accounting and secret checks passed')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
