"""Read this Actions runner's hardware CPU counter capability on a finite fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


PERF_SHA = '2d0953085bf720a25efbe24f853e97d27b1f12f18a398255ff82cbafde254dad'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('capability check belongs to Linux Actions')
    if args.output.exists():
        raise RuntimeError('fresh output required')
    args.output.mkdir(parents=True)
    perf = Path('/usr/bin/perf')
    if hashlib.sha256(perf.read_bytes()).hexdigest() != PERF_SHA:
        raise ValueError('perf differs from the verified software decoder')
    os.environ.pop('GH_TOKEN', None)
    fixture = ('import time\nend=time.monotonic()+2\nvalue=1\n'
               'while time.monotonic()<end:\n value=(value*13+7)%10000019\n')
    environment = dict(os.environ, LC_ALL='C')
    command = ['sudo', '-n', str(perf), 'stat', '-x', ';', '-e', 'cycles,instructions',
               '--', sys.executable, '-c', fixture]
    with (args.output / 'stat.stdout').open('wb') as out, (args.output / 'stat.stderr').open('wb') as err:
        completed = subprocess.run(command, stdout=out, stderr=err, env=environment, timeout=15)
    text = (args.output / 'stat.stderr').read_text()
    counters = {}
    for line in text.splitlines():
        fields = line.split(';')
        if len(fields) >= 3 and fields[2].strip() in ('cycles', 'instructions'):
            try:
                count = int(fields[0].replace(',', '').strip())
            except ValueError:
                count = None
            counters[fields[2].strip()] = {'count': count, 'raw': line}
    supported = (completed.returncode == 0 and set(counters) == {'cycles', 'instructions'}
                 and all(item['count'] is not None and item['count'] > 0 for item in counters.values()))
    result = {'schema': 'txnode-hardware-perf-capability/v1',
              'tool_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              'perf_sha256': PERF_SHA, 'events': ['cycles', 'instructions'], 'fixture_wall_seconds': 2,
              'probe_exit_code': completed.returncode, 'counters': counters,
              'hardware_counters_supported_on_this_runner': supported,
              'collected': True, 'node_workload_executed': False, 'accepted': False, 'full_S3_accepted': False,
              'stderr_sha256': hashlib.sha256((args.output / 'stat.stderr').read_bytes()).hexdigest(),
              'scope': 'finite CPU-only fixture; capability is scoped to this runner, not all hosted environments'}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
