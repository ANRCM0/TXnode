"""Bound software perf sampling around an existing process, retaining control proofs."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time


PERF = Path('/usr/bin/perf')
PERF_SHA = '2d0953085bf720a25efbe24f853e97d27b1f12f18a398255ff82cbafde254dad'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def proc(pid):
    values = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
    name = Path('/proc/%d/comm' % pid).read_text().strip()
    return {'name': name, 'parent': int(values[1]), 'start': int(values[19])}


def descendant(pid, ancestor):
    for _ in range(12):
        if pid == ancestor:
            return True
        if pid <= 1:
            return False
        pid = proc(pid)['parent']
    return False


def parse_samples(path, pid):
    headers = re.compile(r'^(.+?)\s+(\d+)/(\d+)\s+(\d+)\.(\d{9}):\s+(\d+)\s+cpu-clock:\s*$')
    frames = re.compile(r'^\s*([0-9a-f]+)\s+(.+?)\s+\((.+)\)\s*$')
    samples = []
    current = None
    for line in path.read_text().splitlines():
        head = headers.fullmatch(line)
        if head:
            _, process, thread, seconds, nanos, period = head.groups()
            if int(process) != pid or int(period) <= 0:
                raise ValueError('sample PID or CPU period differs from the private target')
            current = {'pid': int(process), 'tid': int(thread), 'time_ns': int(seconds) * 10**9 + int(nanos),
                       'period_ns': int(period), 'frames': []}
            samples.append(current)
        elif line.strip() and current is not None:
            frame = frames.fullmatch(line)
            if not frame:
                raise ValueError('unexpected perf sample frame')
            current['frames'].append({'address': frame[1], 'symbol': frame[2], 'dso': frame[3]})
    if not samples or not all(item['frames'] for item in samples):
        raise ValueError('empty software CPU stacks')
    return samples


class PerfWindow:
    def __init__(self, process, state):
        self.process, self.state = process, state
        self.handle = None
        self.perf_pid = self.perf_start = None
        self.control = self.ack = None
        self.stdout = self.stderr = None
        self.enabled = False
        self.finished = False
        self.result = {'complete': False, 'tracee_pid': process.pid, 'controls': [],
                       'scope': 'enable before first CPU request; disable after second CPU acknowledgement'}

    def command(self, value):
        sent = time.monotonic_ns()
        os.write(self.control, value.encode() + b'\n')
        data = b''
        deadline = time.monotonic() + 5
        while b'\n' not in data:
            if self.handle.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('perf control acknowledgement missing')
            ready, _, _ = select.select([self.ack], [], [], .05)
            if ready:
                data += os.read(self.ack, 1024)
        if data != b'ack\n':
            raise ValueError('unexpected perf control acknowledgement')
        self.result['controls'].append({'command': value, 'sent_ns': sent, 'ack_ns': time.monotonic_ns()})

    def identify(self):
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal():
                continue
            try:
                identity = proc(int(path.name))
                if identity['name'] in ('perf', 'perf-record') and descendant(int(path.name), self.handle.pid):
                    self.perf_pid, self.perf_start = int(path.name), identity['start']
                    return
            except (OSError, ValueError, IndexError):
                continue
        raise RuntimeError('private perf child identity unavailable')

    def start(self):
        if sha(PERF) != PERF_SHA:
            raise ValueError('perf binary differs from the verified capability probe')
        for name in ('perf-control', 'perf-ack'):
            os.mkfifo(self.state / name, 0o600)
        self.control = os.open(self.state / 'perf-control', os.O_RDWR | os.O_NONBLOCK)
        self.ack = os.open(self.state / 'perf-ack', os.O_RDWR | os.O_NONBLOCK)
        self.stdout = (self.state / 'perf-record.stdout').open('wb')
        self.stderr = (self.state / 'perf-record.stderr').open('wb')
        command = ['sudo', '-n', str(PERF), 'record', '-F', '997', '-e', 'cpu-clock', '-k', 'CLOCK_MONOTONIC',
                   '--call-graph', 'dwarf,16384', '--max-size', '128M', '-D', '-1',
                   '--control=fifo:%s,%s' % (self.state / 'perf-control', self.state / 'perf-ack'),
                   '-o', str(self.state / 'perf.data'), '-p', str(self.process.pid)]
        self.handle = subprocess.Popen(command, stdout=self.stdout, stderr=self.stderr, start_new_session=True)
        self.command('enable')
        self.enabled = True
        self.identify()
        self.result.update(perf_pid=self.perf_pid, perf_start=self.perf_start, perf_sha256=PERF_SHA)
        write(self.state / 'perf-window.json', self.result)

    def stop(self):
        if self.finished:
            return
        try:
            if self.handle is None:
                raise RuntimeError('perf was not started')
            if self.handle.poll() is None:
                if self.enabled:
                    self.command('disable')
                    self.enabled = False
                if self.perf_pid is None:
                    self.identify()
                identity = proc(self.perf_pid)
                if (identity['name'] not in ('perf', 'perf-record') or identity['start'] != self.perf_start
                        or not descendant(self.perf_pid, self.handle.pid)):
                    raise RuntimeError('private perf identity changed before stopping')
                self.result['stop_requested_ns'] = time.monotonic_ns()
                subprocess.run(['sudo', '-n', 'kill', '-INT', str(self.perf_pid)], check=True, timeout=5)
            code = self.handle.wait(timeout=10)
            self.result.update(perf_exit_code=code, stopped_ns=time.monotonic_ns(),
                               tracee_alive_after_stop=self.process.poll() is None)
            if code not in (0, -2, 130) or self.process.poll() is not None:
                raise RuntimeError('perf did not stop independently of its target')
            self.stdout.close()
            self.stderr.close()
            self.stdout = self.stderr = None
            path = self.state / 'perf.data'
            subprocess.run(['sudo', '-n', 'chown', '%d:%d' % (os.getuid(), os.getgid()), str(path)],
                           check=True, timeout=5)
            self.result.update(data_bytes=path.stat().st_size, data_sha256=sha(path))
            for name, arguments in [('perf-report.txt', ['report', '--stdio', '-f']),
                                     ('perf-script.txt', ['script', '-f', '--ns', '--show-lost-events', '-F',
                                                          'comm,pid,tid,time,period,event,ip,sym,dso'])]:
                with (self.state / name).open('wb') as out, (self.state / (name + '.stderr')).open('wb') as err:
                    decoded = subprocess.run(['sudo', '-n', str(PERF), *arguments, '-i', str(path)],
                                             stdout=out, stderr=err, timeout=40)
                if decoded.returncode != 0:
                    raise RuntimeError('private perf decode failed')
            lost = re.findall(r'^# Total Lost Samples: (\d+)$', (self.state / 'perf-report.txt').read_text(), re.MULTILINE)
            if lost != ['0']:
                raise ValueError('software sample loss is present or unknown')
            samples = parse_samples(self.state / 'perf-script.txt', self.process.pid)
            declared = re.findall(r'\((\d+) samples\)', (self.state / 'perf-record.stderr').read_text())
            if declared != [str(len(samples))]:
                raise ValueError('record log and decoded sample count differ')
            self.result.update(complete=True, samples=len(samples), lost_samples=0,
                               period_total_ns=sum(item['period_ns'] for item in samples),
                               report_sha256=sha(self.state / 'perf-report.txt'),
                               script_sha256=sha(self.state / 'perf-script.txt'))
        except Exception as error:
            self.result.update(error_type=type(error).__name__, error=str(error))
            raise
        finally:
            self.finished = True
            for stream in (self.stdout, self.stderr):
                if stream:
                    stream.close()
            for descriptor in (self.control, self.ack):
                if descriptor is not None:
                    os.close(descriptor)
            for name in ('perf-control', 'perf-ack'):
                (self.state / name).unlink(missing_ok=True)
            write(self.state / 'perf-window.json', self.result)
