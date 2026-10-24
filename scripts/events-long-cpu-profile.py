#!/usr/bin/env python3
"""Finite, instrumented events/long stack collection from archived binaries in Actions."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
from types import SimpleNamespace


CANDIDATE = '90508592b4c0b433eb9a71f367694a981aa958e1'
REFERENCE_REPORT = '7af59ce203b043e734aeaaf27ef6d5d65e308835ca483ca5d5a13cd04c7c12fa'
GROUPS, WARMUP, SECONDS, CONCURRENCY = 6, 2, 55, 4
MIN_PROFILE_CPU_NANOS = 2_000_000_000


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def varint(data, offset):
    result = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError('truncated profile varint')
        value, offset = data[offset], offset + 1
        result |= (value & 127) << shift
        if value < 128:
            return result, offset
    raise ValueError('oversized profile varint')


def fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number <= 0:
            raise ValueError('invalid profile field')
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire in (1, 2, 5):
            length = 8 if wire == 1 else 4
            if wire == 2:
                length, offset = varint(data, offset)
            if offset + length > len(data):
                raise ValueError('truncated profile field')
            value, offset = data[offset:offset + length], offset + length
        else:
            raise ValueError('unsupported profile wire type')
        yield number, wire, value


def profile_stats(path):
    """Read standard pprof weights; stack decoding stays with the pinned Go tool."""
    entries = list(fields(gzip.decompress(path.read_bytes())))
    strings = [value.decode('utf-8') for number, wire, value in entries if (number, wire) == (6, 2)]
    def value_type(message):
        indexes = {n: v for n, w, v in fields(message) if w == 0}
        return [strings[indexes.get(1, 0)], strings[indexes.get(2, 0)]]
    types = [value_type(value) for number, wire, value in entries if (number, wire) == (1, 2)]
    period_types = [value_type(value) for number, wire, value in entries if (number, wire) == (11, 2)]
    scalar = {number: value for number, wire, value in entries if wire == 0}
    if types != [['samples', 'count'], ['cpu', 'nanoseconds']] or period_types != [['cpu', 'nanoseconds']]:
        raise ValueError('unexpected profile measurement types')
    count, cpu = 0, 0
    for number, wire, message in entries:
        if (number, wire) != (2, 2):
            continue
        values = []
        for field, kind, value in fields(message):
            if field == 2 and kind == 0:
                values.append(value)
            elif field == 2 and kind == 2:
                offset = 0
                while offset < len(value):
                    item, offset = varint(value, offset)
                    values.append(item)
        if len(values) != 2 or any(v >= 1 << 63 for v in values):
            raise ValueError('invalid profile sample values')
        count += values[0]
        cpu += values[1]
    period, duration = scalar[12], scalar[10]
    if period != 10_000_000 or count <= 0 or cpu != count * period or duration <= 0:
        raise ValueError('invalid profile CPU weights or duration')
    return {'sample_count': count, 'cpu_nanos': cpu, 'period_nanos': period,
            'duration_nanos': duration, 'sample_types': types}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference-directory', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('profile execution belongs to Linux Actions')
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError('fresh output required')
    output.mkdir(parents=True)
    root = Path(__file__).resolve().parent.parent
    reference = args.reference_directory.resolve() / 'native-long-cpu'
    if digest(reference / 'report.json') != REFERENCE_REPORT:
        raise RuntimeError('reference report changed')
    original = json.loads((reference / 'report.json').read_text())
    first_plan = json.loads((reference / 'plan.json').read_text())
    if original['candidate'] != CANDIDATE or original['accepted'] is not False:
        raise RuntimeError('reference identity changed')
    def git(*parts):
        return subprocess.check_output(['git', *parts], cwd=root)
    for path, expected in first_plan['source_sha256'].items():
        if digest(root / path) != expected or (root / path).read_bytes() != git('show', CANDIDATE + ':' + path):
            raise RuntimeError('original sampling source changed')
    for side in ('legacy', 'candidate'):
        for prefix, field in (('server-', 'harness_sha256'), ('tx-node-', 'binary_sha256')):
            binary = reference / (prefix + side)
            if digest(binary) != original['builds'][side][field]:
                raise RuntimeError('frozen binary hash mismatch')
            binary.chmod(0o700)
    go = subprocess.check_output(['go', 'version'], text=True).strip()
    if go != original['go']:
        raise RuntimeError('profile toolchain differs from frozen build')
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    plan = {'schema': 'txnode-events-long-profile/v1', 'candidate': CANDIDATE,
            'baseline': original['baseline'], 'workflow_source': git('rev-parse', 'HEAD').decode().strip(),
            'reference_run': 40059251852, 'reference_artifact': 12547191583,
            'reference_report_sha256': REFERENCE_REPORT, 'builds': original['builds'], 'go': go,
            'source_sha256': first_plan['source_sha256'], 'driver_sha256': digest(Path(__file__)),
            'original_affinity': allowed, 'driver_affinity': sorted(os.sched_getaffinity(0)),
            'settings': {'groups': GROUPS, 'warmup_seconds': WARMUP, 'sample_seconds': SECONDS,
                         'concurrency': CONCURRENCY, 'mode': 'events', 'workload': 'long',
                         'cpu_profiler': True, 'persistence_observer': False},
            'minimum_profile_cpu_nanos_per_side': MIN_PROFILE_CPU_NANOS,
            'scope': 'Six alternating profiled pairs, startup/warmup/55s-transfer/shutdown. '
                     'Stack diagnostics only; no formal comparison or acceptance. Original binaries and byte proofs retained.',
            'full_S3_accepted': False}
    write(output / 'plan.json', plan)
    report = {'schema': plan['schema'], 'candidate': CANDIDATE, 'baseline': original['baseline'],
              'accepted': False, 'full_S3_accepted': False, 'samples': [], 'aggregates': {},
              'scope': plan['scope'], 'collection_complete': False, 'hotspot_sample_budget_met': False}
    write(output / 'report.json', report)
    bench = load('frozen_original_bench', root / 'scripts/native-acceptance.py')
    validator = load('frozen_cpu_validator', root / 'scripts/native-s3-summary.py')
    settings = SimpleNamespace(warmup=WARMUP, seconds=SECONDS, concurrency=CONCURRENCY)
    origin = bench.Origin()
    try:
        for group in range(1, GROUPS + 1):
            sides = ('legacy', 'candidate') if group % 2 else ('candidate', 'legacy')
            for side in sides:
                state = output / ('g%d-%s' % (group, side))
                profile = state / 'cpu.pprof'
                item = {'group': group, 'side': side, 'acceptance_sample': False,
                        'profile_scope': 'startup, warmup, transfer and graceful shutdown'}
                item['sample'] = bench.sample(reference / ('server-' + side), state, 'events', 'long',
                                             settings, origin, cpu_profile=profile, persistence_diagnostics=False)
                try:
                    item.update(profile_sha256=digest(profile), profile=profile_stats(profile),
                                valid_process_cpu_window=validator.valid_cpu(item['sample']))
                except Exception as error:
                    item['collection_error'] = type(error).__name__
                report['samples'].append(item)
                write(output / 'report.json', report)
                print('profile group=%d side=%s status=%s stats=%s' % (
                    group, side, item['sample']['status'], item.get('profile')), flush=True)
    finally:
        origin.close()
    complete = (len(report['samples']) == GROUPS * 2 and all(
        item['sample']['status'] == 'measured' and item.get('valid_process_cpu_window') is True
        and 'collection_error' not in item for item in report['samples']))
    if complete:
        for side in ('legacy', 'candidate'):
            items = [item for item in report['samples'] if item['side'] == side]
            profiles = [str(output / ('g%d-%s/cpu.pprof' % (item['group'], side))) for item in items]
            target = output / ('aggregate-' + side + '.pprof')
            command = ['go', 'tool', 'pprof', '-proto', '-output', str(target),
                       str(reference / ('server-' + side)), *profiles]
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            stats = profile_stats(target)
            if any(stats[key] != sum(item['profile'][key] for item in items) for key in ('sample_count', 'cpu_nanos')):
                raise RuntimeError('aggregate profile CPU weights differ from raw profiles')
            files = {}
            for label, flags in [('flat', []), ('cumulative', ['-cum'])]:
                path = output / ('top-%s-%s.txt' % (side, label))
                value = subprocess.check_output(['go', 'tool', 'pprof', '-top', '-nodecount=80',
                                                 *flags, str(reference / ('server-' + side)), str(target)],
                                                stderr=subprocess.PIPE, timeout=60)
                path.write_bytes(value)
                files[path.name] = digest(path)
            report['aggregates'][side] = {'profile': stats, 'profile_sha256': digest(target), 'top_sha256': files}
    report['collection_complete'] = complete and len(report['aggregates']) == 2
    report['hotspot_sample_budget_met'] = report['collection_complete'] and all(
        value['profile']['cpu_nanos'] >= MIN_PROFILE_CPU_NANOS for value in report['aggregates'].values())
    write(output / 'report.json', report)
    print(json.dumps({'collection_complete': report['collection_complete'],
                      'hotspot_sample_budget_met': report['hotspot_sample_budget_met'],
                      'aggregates': report['aggregates'], 'full_S3_accepted': False}), flush=True)
    if not report['collection_complete'] or not report['hotspot_sample_budget_met']:
        raise SystemExit('extended profile collection or predeclared stack budget incomplete')


if __name__ == '__main__':
    main()
