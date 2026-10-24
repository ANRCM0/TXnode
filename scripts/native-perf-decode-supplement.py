"""Decode the exact retained perf probe; never repeat its recording."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import urllib.error
import urllib.request
import zipfile


ARTIFACT = 12574041411
ZIP_SHA = '9901551ca9a3299fb8111e118a4977d908786ea9108fc0006b1c63b8f8998e0c'
DATA_SHA = '9b36da264d0bb4e65577dc24ba7059fe7a55d8a666c5caf6a58961755319a40a'
PERF_SHA = '2d0953085bf720a25efbe24f853e97d27b1f12f18a398255ff82cbafde254dad'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('decoder belongs to Linux Actions')
    if args.output.exists():
        raise RuntimeError('fresh output required')
    args.output.mkdir(parents=True)
    token = os.environ.pop('GH_TOKEN')
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
    del token, request
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
    except Exception:
        raise RuntimeError('artifact transport failed') from None
    del url
    if hashlib.sha256(data).hexdigest() != ZIP_SHA:
        raise ValueError('original probe ZIP changed')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        payload = archive.read('native-perf-probe/probe.data')
        reference = json.loads(archive.read('native-perf-probe/result.json'))
    if (hashlib.sha256(payload).hexdigest() != DATA_SHA or reference['record_exit_code'] != 0
            or reference['report.txt_exit_code'] != 255 or reference['available'] is not False):
        raise ValueError('original recording or failed decode identity changed')
    path = args.output / 'original-probe.data'
    path.write_bytes(payload)
    (args.output / 'original-result.json').write_text(json.dumps(reference, indent=2) + '\n', encoding='utf-8')
    perf = Path('/usr/bin/perf')
    if sha(perf) != PERF_SHA:
        raise ValueError('decoder binary differs from the original probe')
    plan = {'schema': 'txnode-perf-decode-supplement-plan/v1',
            'workflow_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'reference_run': 40128772350, 'reference_artifact': ARTIFACT,
            'reference_zip_sha256': ZIP_SHA, 'reference_data_sha256': DATA_SHA, 'perf_sha256': PERF_SHA,
            'recording_executed': False, 'accepted': False, 'full_S3_accepted': False,
            'scope': 'read-only decode of exact prior probe; -f is limited to SHA-verified private data ownership'}
    (args.output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    result = {'schema': 'txnode-perf-decode-supplement/v1', 'recording_executed': False,
              'decoded': False, 'accepted': False, 'full_S3_accepted': False, 'commands': []}
    try:
        for name, options in [('report.txt', ['report', '--stdio', '-f']),
                              ('script.txt', ['script', '-f', '--ns', '--show-lost-events', '-F',
                                              'comm,pid,tid,time,period,event,ip,sym,dso'])]:
            with (args.output / name).open('wb') as out, (args.output / (name + '.stderr')).open('wb') as err:
                reply = subprocess.run(['sudo', '-n', str(perf), *options, '-i', str(path)],
                                       stdout=out, stderr=err, timeout=40)
            result['commands'].append({'output': name, 'exit_code': reply.returncode})
            if reply.returncode != 0 or not (args.output / name).stat().st_size:
                raise RuntimeError('original probe decode incomplete')
        headers = sum('cpu-clock:' in line for line in (args.output / 'script.txt').read_text().splitlines())
        if headers != 2012:
            raise ValueError('decoded sample count differs from the original record log')
        result.update(decoded=True, cpu_clock_samples=headers,
                      report_sha256=sha(args.output / 'report.txt'), script_sha256=sha(args.output / 'script.txt'))
    finally:
        assert sha(path) == DATA_SHA
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
