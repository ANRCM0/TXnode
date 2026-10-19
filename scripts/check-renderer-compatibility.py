#!/usr/bin/env python3
"""Check candidate renderer integrity and the pinned Core's declared surface."""
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    'internal/credentialdelivery/render.go',
    'internal/credentialdelivery/render_formats.go',
    'internal/credentialprovider/render_clients.go',
    'internal/credentialprovider/render_surge.go',
    'internal/credentialprovider/render_http.go',
    'internal/credentialprovider/render_cors.go',
}
SURFACE = ('execution', 'input', 'formats', 'profiles', 'transports', 'compatibility')


def main():
    candidate = json.loads((ROOT / 'compatibility/renderers.v1.json').read_text(encoding='utf-8'))
    core_root = ROOT / '.compat/core'
    core = json.loads((core_root / 'contracts/renderers/builtin.v1.json').read_text(encoding='utf-8'))
    if candidate.get('schema') != 'txnode-builtin-renderers/v1':
        raise ValueError('Unexpected Node renderer declaration schema')
    if not re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', candidate.get('version', '')):
        raise ValueError('Invalid independently versioned Node renderer package')
    actual = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(SOURCES)}
    if candidate.get('source_files') != actual:
        raise ValueError('Review and version the Node renderer package after source changes')
    for key in SURFACE:
        if key not in candidate or candidate[key] != core.get(key):
            raise ValueError('Candidate renderer interface differs from supported Core: ' + key)
    # Core retains integrity over its own implementation. Node source hashes
    # belong to the candidate, so a compatible Node release need not modify Core.
    for name, expected in core['source_files'].items():
        if name.startswith('api/') and hashlib.sha256((core_root / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned Core renderer source changed: ' + name)
    print('Candidate Node renderer integrity and pinned Core interface match; runtime acceptance is separate')


if __name__ == '__main__':
    main()
