"""Finite Actions probe for software CPU sampling; never Node acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('capability probe belongs to Linux Actions')
    if args.output.exists():
        raise RuntimeError('fresh output required')
    args.output.mkdir(parents=True)
    result = {'schema': 'txnode-native-perf-probe/v1',
              'tool_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
              'event': 'cpu-clock', 'frequency': 997, 'call_graph': 'dwarf,16384',
              'probe_wall_seconds': 2, 'available': False, 'accepted': False, 'full_S3_accepted': False,
              'scope': 'finite CPU-only fixture and read-only perf capabilities; no Node workload or acceptance'}
    try:
        candidates = [Path('/usr/bin/perf')] + sorted(Path('/usr/lib/linux-tools').glob('*/perf'), reverse=True)
        perf = None
        for candidate in candidates:
            if not candidate.is_file():
                continue
            check = subprocess.run([str(candidate), '--version'], capture_output=True, text=True, timeout=5)
            if check.returncode == 0:
                perf = candidate.resolve()
                result.update(perf=str(perf), perf_version=check.stdout.strip(),
                              perf_sha256=hashlib.sha256(perf.read_bytes()).hexdigest())
                break
        if perf is None:
            raise RuntimeError('no working perf binary in installed tool directories')
        for name, command in [('record-help.txt', ['record', '-h']), ('report-help.txt', ['report', '-h']),
                              ('script-help.txt', ['script', '-h'])]:
            reply = subprocess.run([str(perf), *command], capture_output=True, text=True, timeout=5)
            (args.output / name).write_text(reply.stdout + reply.stderr, encoding='utf-8')
        fixture = ('import time\nend=time.monotonic()+2\nvalue=1\n'
                   'while time.monotonic()<end:\n value=(value*13+7)%10000019\n')
        command = ['sudo', '-n', str(perf), 'record', '-F', '997', '-e', 'cpu-clock',
                   '--call-graph', 'dwarf,16384', '-o', str(args.output / 'probe.data'), '--', sys.executable,
                   '-c', fixture]
        with (args.output / 'record.stdout').open('wb') as out, (args.output / 'record.stderr').open('wb') as err:
            recorded = subprocess.run(command, stdout=out, stderr=err, timeout=20)
        result['record_exit_code'] = recorded.returncode
        data = args.output / 'probe.data'
        if data.exists():
            subprocess.run(['sudo', '-n', 'chown', '%d:%d' % (os.getuid(), os.getgid()), str(data)],
                           check=True, timeout=5)
        if recorded.returncode != 0:
            raise RuntimeError('software CPU event recording unavailable; see record.stderr')
        if not data.is_file() or not data.stat().st_size:
            raise RuntimeError('perf did not retain probe data')
        result.update(data_bytes=data.stat().st_size, data_sha256=hashlib.sha256(data.read_bytes()).hexdigest())
        for name, options in [('report.txt', ['report', '--stdio']), ('script.txt', ['script'])]:
            with (args.output / name).open('wb') as out, (args.output / (name + '.stderr')).open('wb') as err:
                decoded = subprocess.run(['sudo', '-n', str(perf), *options, '-i', str(data)],
                                         stdout=out, stderr=err, timeout=20)
            result[name + '_exit_code'] = decoded.returncode
            if decoded.returncode != 0 or not (args.output / name).stat().st_size:
                raise RuntimeError('perf probe decode unavailable')
        result['available'] = True
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result), flush=True)
    if result['available'] is not True:
        raise SystemExit('software perf capability unavailable')


if __name__ == '__main__':
    main()
