"""Bounded trace helpers preserved from diagnostic source 119064c6 (strace -I 2)."""
import json
from pathlib import Path
import re
import signal
import subprocess
import time


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def proc_field(pid, name):
    for line in Path('/proc/%d/status' % pid).read_text().splitlines():
        if line.startswith(name + ':'):
            return line.split(':', 1)[1].strip()
    raise ValueError('missing process identity field')


def descendant(pid, ancestor):
    for _ in range(12):
        if pid == ancestor:
            return True
        if pid <= 1:
            return False
        pid = int(proc_field(pid, 'PPid'))
    return False


def syscall_summary(path):
    rows, total = [], None
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r'\d+\.\d+', fields[0]):
            continue
        if len(fields) not in (5, 6):
            raise ValueError('unexpected syscall summary columns')
        item = {'name': fields[-1], 'percent': float(fields[0]), 'system_seconds': float(fields[1]),
                'usecs_per_call': int(fields[2]), 'calls': int(fields[3]),
                'errors': int(fields[4]) if len(fields) == 6 else 0}
        if item['name'] == 'total':
            total = item
        else:
            rows.append(item)
    if not rows or total is None or sum(item['calls'] for item in rows) != total['calls']:
        raise ValueError('syscall summary is not complete')
    if sum(item['errors'] for item in rows) != total['errors']:
        raise ValueError('syscall summary error total mismatch')
    return {'rows': rows, 'total': total}


class TraceWindow:
    def __init__(self, process, state, interruptible=2):
        self.process, self.state = process, state
        self.interruptible = interruptible
        self.handle = None
        self.tracer_pid = None
        self.log = None
        self.result = {'scope': 'attach before first CPU request; detach after second CPU acknowledgement',
                       'summary_only': True, 'complete': False, 'interruptible': interruptible}

    def start(self):
        self.log = (self.state / 'trace-attach.log').open('wb')
        command = ['sudo', '-n', 'strace', '-f', '-c', '-I', str(self.interruptible), '-o',
                   str(self.state / 'syscalls.txt'), '-p', str(self.process.pid)]
        self.handle = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=self.log,
                                       start_new_session=True)
        deadline = time.monotonic() + 5
        while True:
            tracer = int(proc_field(self.process.pid, 'TracerPid'))
            if tracer:
                if proc_field(tracer, 'Name') != 'strace' or not descendant(tracer, self.handle.pid):
                    raise RuntimeError('unexpected tracer identity')
                self.tracer_pid = tracer
                self.result.update(tracee_pid=self.process.pid, tracer_pid=tracer,
                                   sigint_caught=bool(int(proc_field(tracer, 'SigCgt'), 16)
                                                     & (1 << (signal.SIGINT - 1))),
                                   attached_monotonic_nanos=time.monotonic_ns())
                return
            if self.handle.poll() is not None:
                raise RuntimeError('tracer exited before attachment')
            if time.monotonic() >= deadline:
                raise RuntimeError('tracer attachment deadline')
            time.sleep(.01)

    def stop(self):
        if self.handle is None:
            return
        if self.handle.poll() is None:
            tracer = self.tracer_pid or int(proc_field(self.process.pid, 'TracerPid'))
            if tracer:
                if proc_field(tracer, 'Name') != 'strace' or not descendant(tracer, self.handle.pid):
                    raise RuntimeError('tracer identity changed before detach')
                subprocess.run(['sudo', '-n', 'kill', '-INT', str(tracer)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
            else:
                self.handle.terminate()
        self.result['tracer_exit_code'] = self.handle.wait(timeout=10)
        self.log.close()
        self.log = None
        alive = self.process.poll() is None
        tasks = list(Path('/proc/%d/task' % self.process.pid).glob('*/status')) if alive else []
        detached = alive and bool(tasks) and all(
            next(line.split(':', 1)[1].strip() for line in path.read_text().splitlines()
                 if line.startswith('TracerPid:')) == '0' for path in tasks)
        self.result.update(detached_monotonic_nanos=time.monotonic_ns(),
                           tracee_alive_after_detach=alive, detached=detached,
                           detached_thread_count=len(tasks))
        self.handle = None
        if not detached:
            raise RuntimeError('tracee did not continue after detach')
        if self.result['tracer_exit_code'] not in (0, -signal.SIGINT, 128 + signal.SIGINT):
            raise RuntimeError('unexpected tracer exit status')
        summary = syscall_summary(self.state / 'syscalls.txt')
        self.result.update(summary=summary, complete=True)
        write(self.state / 'syscall-window.json', self.result)
