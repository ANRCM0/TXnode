"""Actions-only taskstats TGID capability probe; no Node workload or acceptance."""
import argparse
import errno
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def attributes(payload):
    result, offset = [], 0
    while offset < len(payload):
        if len(payload) - offset < 4:
            raise ValueError('truncated netlink attribute header')
        length, kind = struct.unpack_from('=HH', payload, offset)
        if length < 4 or offset + length > len(payload):
            raise ValueError('invalid netlink attribute length')
        result.append((kind & 0x3fff, payload[offset + 4:offset + length]))
        offset += (length + 3) & ~3
    if offset != len(payload):
        raise ValueError('missing netlink attribute alignment')
    return result


def attribute(kind, payload):
    result = struct.pack('=HH', len(payload) + 4, kind) + payload
    return result + b'\0' * (-len(result) % 4)


class Taskstats:
    def __init__(self, output, layout):
        self.output, self.layout, self.sequence = output, layout, 0
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
        self.socket.settimeout(3)
        self.socket.bind((0, 0))
        self.port = self.socket.getsockname()[0]
        family = self.request(16, 3, 2, b'TASKSTATS\0', 'family')
        ids = [value for kind, value in family if kind == 1]
        if len(ids) != 1 or len(ids[0]) != 2:
            raise ValueError('ambiguous taskstats family identity')
        self.family = struct.unpack('=H', ids[0])[0]
        if self.family < 16:
            raise ValueError('invalid generic netlink family')

    def request(self, family, command, kind, value, label):
        self.sequence += 1
        body = struct.pack('=BBH', command, 1, 0) + attribute(kind, value)
        request = struct.pack('=IHHII', 16 + len(body), family, 1,
                              self.sequence, self.port) + body
        (self.output / (label + '-request.bin')).write_bytes(request)
        self.socket.sendto(request, (0, 0))
        response, address = self.socket.recvfrom(65536)
        (self.output / (label + '-response.bin')).write_bytes(response)
        if address != (0, 0) or len(response) < 16:
            raise ValueError('untrusted or truncated netlink response')
        length, kind, flags, sequence, port = struct.unpack_from('=IHHII', response)
        if sequence != self.sequence or port != self.port or length != len(response):
            raise ValueError('netlink response identity or length mismatch')
        if kind == 2:
            if len(response) < 20:
                raise ValueError('truncated netlink error')
            error = struct.unpack_from('=i', response, 16)[0]
            if error >= 0:
                raise ValueError('unexpected acknowledgement instead of statistics')
            raise OSError(-error, os.strerror(-error))
        if kind != family or flags & 2 or len(response) < 20:
            raise ValueError('unexpected multipart or generic netlink response')
        return attributes(response[20:])

    def snapshot(self, pid, label):
        before = time.monotonic_ns()
        values = self.request(self.family, self.layout['command_get'],
                              self.layout['command_attr_tgid'], struct.pack('=I', pid), label)
        after = time.monotonic_ns()
        aggregates = [value for kind, value in values if kind == self.layout['type_aggr_tgid']]
        if len(aggregates) != 1:
            raise ValueError('one TGID aggregate required')
        children = attributes(aggregates[0])
        identities = [value for kind, value in children if kind == self.layout['type_tgid']]
        stats = [value for kind, value in children if kind == self.layout['type_stats']]
        if (identities != [struct.pack('=I', pid)] or len(stats) != 1
                or len(stats[0]) < self.layout['stime_offset'] + 8):
            raise ValueError('TGID or taskstats payload mismatch')
        version = struct.unpack_from('=H', stats[0], self.layout['version_offset'])[0]
        if version < 1:
            raise ValueError('invalid taskstats version')
        return {'pid': pid, 'taskstats_version': version, 'payload_bytes': len(stats[0]),
                'user_microseconds': struct.unpack_from('=Q', stats[0], self.layout['utime_offset'])[0],
                'system_microseconds': struct.unpack_from('=Q', stats[0], self.layout['stime_offset'])[0],
                'request_before_monotonic_nanos': before,
                'response_after_monotonic_nanos': after}


FIXTURE = r'''
import json, os, resource, sys, threading, time
def usage(stage):
    value = resource.getrusage(resource.RUSAGE_SELF)
    print(json.dumps({'stage': stage, 'pid': os.getpid(),
                      'user_microseconds': round(value.ru_utime * 1e6),
                      'system_microseconds': round(value.ru_stime * 1e6)}), flush=True)
def work(kernel):
    deadline = time.monotonic() + 1
    if kernel:
        fd = os.open('/dev/zero', os.O_RDONLY)
        try:
            while time.monotonic() < deadline:
                os.read(fd, 1024 * 1024)
        finally:
            os.close(fd)
    else:
        value = 1
        while time.monotonic() < deadline:
            for _ in range(10000):
                value = (value * 17 + 13) % 1000000007
usage('baseline')
for stage in ('user', 'system'):
    if sys.stdin.readline().strip() != stage:
        raise SystemExit('fixture command mismatch')
    worker = threading.Thread(target=work, args=(stage == 'system',))
    worker.start()
    worker.join()
    usage(stage)
if sys.stdin.readline().strip() != 'stop':
    raise SystemExit('fixture stop command missing')
'''


def layout(output):
    source = r'''
#include <linux/taskstats.h>
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("{\"version_offset\":%zu,\"utime_offset\":%zu,\"stime_offset\":%zu,\"size\":%zu,"
           "\"command_get\":%d,\"command_attr_tgid\":%d,\"type_aggr_tgid\":%d,\"type_tgid\":%d,\"type_stats\":%d}\n",
        offsetof(struct taskstats, version), offsetof(struct taskstats, ac_utime),
        offsetof(struct taskstats, ac_stime), sizeof(struct taskstats),
        TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_TGID, TASKSTATS_TYPE_AGGR_TGID,
        TASKSTATS_TYPE_TGID, TASKSTATS_TYPE_STATS);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='taskstats-layout-') as directory:
        root = Path(directory)
        (root / 'layout.c').write_text(source, encoding='ascii')
        subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-o', str(root / 'layout'),
                        str(root / 'layout.c')], check=True)
        result = json.loads(subprocess.check_output([str(root / 'layout')]))
    write(output / 'layout.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('probe execution belongs to Linux Actions')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    plan = {'schema': 'txnode-taskstats-capability-plan/v1', 'fixture_seconds': 2,
            'fixture_phases': ['baseline', 'user', 'system'], 'node_samples': 0,
            'query': 'TASKSTATS_CMD_ATTR_TGID', 'units': 'microseconds',
            'maximum_rusage_delta_error_microseconds': 5000,
            'minimum_user_phase_microseconds': 300000,
            'minimum_system_phase_microseconds': 100000,
            'purpose': 'check TGID counters including joined threads, not S3 acceptance',
            'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'kernel': platform.release(), 'machine': platform.machine(),
            'uid': os.geteuid(), 'full_S3_accepted': False}
    write(output / 'plan.json', plan)
    result = {'schema': 'txnode-taskstats-capability/v1', 'supported': False,
              'collection_complete': False, 'node_samples': 0, 'full_S3_accepted': False}
    child = None
    try:
        collector = Taskstats(output, layout(output))
        result['self'] = collector.snapshot(os.getpid(), 'self')
        child = subprocess.Popen([sys.executable, '-c', FIXTURE], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stages = []
        for stage in ('baseline', 'user', 'system'):
            if stage != 'baseline':
                child.stdin.write(stage + '\n')
                child.stdin.flush()
            observed = json.loads(child.stdout.readline())
            if observed['stage'] != stage or observed['pid'] != child.pid:
                raise ValueError('fixture stage or process mismatch')
            time.sleep(0.02)
            snapshot = collector.snapshot(child.pid, stage)
            stages.append({'stage': stage, 'rusage': observed, 'taskstats': snapshot})
            write(output / 'stages.json', stages)
        child.stdin.write('stop\n')
        child.stdin.flush()
        _, errors = child.communicate(timeout=5)
        if child.returncode != 0 or errors:
            raise ValueError('fixture failed to stop cleanly')
        differences = []
        for start, end in zip(stages, stages[1:]):
            row = {'stage': end['stage']}
            for field in ('user_microseconds', 'system_microseconds'):
                expected = end['rusage'][field] - start['rusage'][field]
                actual = end['taskstats'][field] - start['taskstats'][field]
                if actual < 0 or abs(actual - expected) > 5000:
                    raise ValueError('TGID counter differs from joined-thread rusage')
                row[field] = {'rusage_delta': expected, 'taskstats_delta': actual,
                              'absolute_error': abs(actual - expected)}
            differences.append(row)
        if (differences[0]['user_microseconds']['taskstats_delta'] < 300000
                or differences[1]['system_microseconds']['taskstats_delta'] < 100000):
            raise ValueError('fixture did not distinguish user and system CPU')
        result.update(supported=True, collection_complete=True, comparisons=differences,
                      includes_joined_threads=True, family=collector.family)
    except OSError as error:
        if error.errno not in (errno.ENOENT, errno.EPERM, errno.EACCES, errno.EOPNOTSUPP):
            raise
        result.update(collection_complete=True, unavailable_errno=error.errno,
                      unavailable_reason=errno.errorcode[error.errno])
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        write(output / 'result.json', result)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
