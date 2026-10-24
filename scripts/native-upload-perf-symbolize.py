"""Resolve Go PCs in retained upload perf stacks without new recording or builds."""
import argparse
import collections
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import urllib.error
import urllib.request
import zipfile


ARTIFACT = 12575080077
ZIP_SHA = '4a958c966aad5945011c1b3c6fb6afe22dbfe714074ee174d3dfcb4ec7798574'
RECORDER = '1ab2d8c8a85db903e5c54dfefadffff0b3dc154e'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def read(path):
    return json.loads(path.read_text())


def fetch():
    token = os.environ['GH_TOKEN']
    request = urllib.request.Request(
        'https://api.github.com/repos/ANRCM0/TXnode/actions/artifacts/%d/zip' % ARTIFACT,
        headers={'Authorization': 'Bearer ' + token})
    try:
        urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
        raise RuntimeError('artifact redirect required')
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise RuntimeError('artifact API refused the request') from None
        url = error.headers['Location']
    del request, token
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
    except Exception:
        raise RuntimeError('retained stack transport failed') from None
    del url
    if hashlib.sha256(data).hexdigest() != ZIP_SHA:
        raise ValueError('retained perf ZIP changed')
    return zipfile.ZipFile(io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('symbol decoding belongs to Linux Actions')
    if args.output.exists() or args.reference.exists():
        raise RuntimeError('fresh private decoding directories required')
    args.output.mkdir(parents=True)
    with fetch() as archive:
        for name in ['plan.json', 'report.json'] + ['sample-g%d-%s/perf-script.txt' % (group, side)
                                                   for group in range(1, 4) for side in ('legacy', 'candidate')]:
            path = args.output / 'input' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read('native-upload-perf/' + name))
    root = Path(__file__).resolve().parent.parent
    reader = module('frozen_symbol_reference', root / 'scripts/native-cpu-latency-follow-up.py')
    reference = reader.download_reference(args.reference)
    perf = module('frozen_stack_parser', root / 'scripts/native-perf-window.py')
    if (root / 'scripts/native-perf-window.py').read_bytes() != subprocess.check_output(
            ['git', 'show', RECORDER + ':scripts/native-perf-window.py']):
        raise ValueError('retained stack parser changed')
    original, original_plan = read(args.output / 'input/report.json'), read(args.output / 'input/plan.json')
    if (original['collection_complete'] is not True or original['candidate'] != reference['candidate']
            or original['candidate'] != reader.CANDIDATE or original_plan['workflow_source'] != RECORDER
            or original['full_S3_accepted'] is not False or original['accepted'] is not False
            or len(original['samples']) != 6):
        raise ValueError('retained stack identity changed')
    if subprocess.check_output(['go', 'version'], text=True).strip() != 'go version go1.26.0 linux/amd64':
        raise ValueError('pinned Go decoder required')
    binaries = {}
    for side in ('legacy', 'candidate'):
        path = args.reference / ('server-' + side)
        if perf.sha(path) != reference['builds'][side]['harness_sha256']:
            raise ValueError('original Go executable changed')
        binaries[path.name] = perf.sha(path)
    plan = {'schema': 'txnode-upload-perf-symbol-plan/v1',
            'workflow_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'candidate': reader.CANDIDATE, 'perf_run': 40130295695, 'perf_artifact': ARTIFACT,
            'perf_zip_sha256': ZIP_SHA, 'reference_artifact': reader.REFERENCE_ARTIFACT,
            'reference_zip_sha256': reader.REFERENCE_ZIP, 'binary_sha256': binaries,
            'go': 'go version go1.26.0 linux/amd64', 'recording_executed': False,
            'binaries_recompiled': False, 'full_S3_accepted': False,
            'scope': 'static Go addr2line of exact retained PCs; no new stacks, build, Node workload or acceptance ratio'}
    perf.write(args.output / 'plan.json', plan)
    captured = {}
    maps = {}
    for side in ('legacy', 'candidate'):
        addresses = set()
        for entry in original['samples']:
            if entry['side'] != side:
                continue
            script = args.output / ('input/sample-g%d-%s/perf-script.txt' % (entry['group'], side))
            if perf.sha(script) != entry['perf_window']['script_sha256']:
                raise ValueError('retained script digest changed')
            points = perf.parse_samples(script, entry['sample']['cpu_measurement']['start']['pid'])
            captured[(entry['group'], side)] = points
            for point in points:
                addresses.update(frame['address'] for frame in point['frames']
                                 if frame['symbol'] == '[unknown]' and frame['dso'].endswith('/server-' + side))
        ordered = sorted(addresses, key=lambda value: int(value, 16))
        decoded = subprocess.check_output(['go', 'tool', 'addr2line', str(args.reference / ('server-' + side))],
                                          input=''.join('0x' + value + '\n' for value in ordered), text=True,
                                          stderr=subprocess.PIPE, timeout=30)
        (args.output / ('addr2line-' + side + '.txt')).write_text(decoded)
        lines = decoded.splitlines()
        if len(lines) != 2 * len(ordered):
            raise ValueError('Go address decoder row count differs')
        maps[side] = {address: {'function': lines[2 * i], 'source': lines[2 * i + 1]}
                      for i, address in enumerate(ordered)}
        perf.write(args.output / ('address-map-' + side + '.json'), maps[side])
    aggregates = {side: {'samples': 0, 'period_ns': 0, 'process_cpu_ns': 0, 'business_bytes': 0,
                         'flat': collections.Counter(), 'cumulative': collections.Counter(),
                         'leaf_domains': collections.Counter()} for side in ('legacy', 'candidate')}
    rows = []
    for entry in original['samples']:
        side = entry['side']
        cpu = entry['sample']['cpu_measurement']
        points = [point for point in captured[(entry['group'], side)]
                  if cpu['start']['monotonic_after_nanos'] <= point['time_ns'] <= cpu['end']['monotonic_before_nanos']]
        row = {'group': entry['group'], 'side': side, 'samples': len(points),
               'period_ns': sum(p['period_ns'] for p in points), 'flat': collections.Counter(),
               'cumulative': collections.Counter(), 'leaf_domains': collections.Counter()}
        if row['samples'] != entry['inner']['samples'] or row['period_ns'] != entry['inner']['period_ns']:
            raise ValueError('retained original CPU window changed')
        for point in points:
            resolved = []
            for frame in point['frames']:
                name = frame['symbol']
                if name == '[unknown]' and frame['dso'].endswith('/server-' + side):
                    translated = maps[side][frame['address']]['function']
                    if translated != '?':
                        name = translated
                resolved.append(name)
            leaf = point['frames'][0]
            if leaf['dso'].endswith('/server-' + side):
                domain = 'go-unresolved' if resolved[0] == '[unknown]' else 'go'
            elif leaf['dso'].startswith('[') and leaf['dso'] not in ('[unknown]', '[vdso]'):
                domain = 'kernel'
            else:
                domain = leaf['dso']
            row['flat'][resolved[0]] += point['period_ns']
            row['leaf_domains'][domain] += point['period_ns']
            for name in set(resolved):
                row['cumulative'][name] += point['period_ns']
        aggregate = aggregates[side]
        for key in ('samples', 'period_ns'):
            aggregate[key] += row[key]
        aggregate['process_cpu_ns'] += cpu['delta_nanos']
        aggregate['business_bytes'] += entry['sample']['bytes']
        for key in ('flat', 'cumulative', 'leaf_domains'):
            aggregate[key].update(row[key])
            row[key] = dict(row[key].most_common())
        rows.append(row)
    for value in aggregates.values():
        for key in ('flat', 'cumulative', 'leaf_domains'):
            value[key] = dict(value[key].most_common())
    if not all(perf.sha(args.reference / name) == expected for name, expected in binaries.items()):
        raise ValueError('original executable changed while decoding')
    result = {'schema': 'txnode-upload-perf-symbols/v1', 'candidate': reader.CANDIDATE,
              'plan_sha256': perf.sha(args.output / 'plan.json'), 'rows': rows, 'aggregates': aggregates,
              'address_map_sha256': {side: perf.sha(args.output / ('address-map-' + side + '.json'))
                                    for side in ('legacy', 'candidate')},
              'decoded': True, 'recording_executed': False, 'binaries_recompiled': False,
              'accepted': False, 'full_S3_accepted': False}
    perf.write(args.output / 'report.json', result)
    print(json.dumps({'decoded': True, 'recording_executed': False, 'binaries_recompiled': False,
                      'samples': {side: value['samples'] for side, value in aggregates.items()},
                      'leaf_domains': {side: value['leaf_domains'] for side, value in aggregates.items()},
                      'full_S3_accepted': False}), flush=True)


if __name__ == '__main__':
    main()
