import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time


def bounded(argv, cwd, timeout=10, cap=65536):
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    blocks = queue.Queue(maxsize=4)
    closed = threading.Event()

    def read():
        try:
            while not closed.is_set():
                data = process.stdout.read(4096)
                while not closed.is_set():
                    try:
                        blocks.put(data, timeout=.05)
                        break
                    except queue.Full:
                        continue
                if not data:
                    return
        finally:
            process.stdout.close()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    output = bytearray()
    deadline = time.monotonic() + timeout
    state = 'CAPTURED'
    eof = False
    try:
        while not eof:
            if time.monotonic() >= deadline:
                state = 'HOLD_DEADLINE'
                break
            try:
                block = blocks.get(timeout=min(.05, max(.001, deadline-time.monotonic())))
            except queue.Empty:
                continue
            room = cap-len(output)
            output.extend(block[:room])
            if len(block) > room:
                state = 'HOLD_OUTPUT_CAP'
                break
            eof = not block
    finally:
        closed.set()
        if process.poll() is None and state != 'CAPTURED':
            process.kill()
        try:
            code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait(timeout=2)
            state = 'HOLD_CLOSURE'
        reader.join(timeout=2)
        if reader.is_alive():
            state = 'HOLD_READER_CLOSURE'
    return {'argv': list(argv), 'pid': process.pid, 'exit': code, 'state': state,
            'bytes': len(output), 'output': output.decode('utf8', 'replace'),
            'sha256': hashlib.sha256(output).hexdigest(), 'direct_child_reaped': process.poll() is not None}


def checked_event(policy, env, actual):
    if (env['GITHUB_EVENT_NAME'] != policy['event_name'] or env['GITHUB_REF'] != policy['branch_ref']
            or len(actual) != 2 or actual[0] != env['GITHUB_SHA']
            or not all(re.fullmatch('[0-9a-f]{40}', value) for value in actual)):
        raise ValueError('event identity mismatch')
    return dict(event_sha=actual[0], event_tree=actual[1], event_name=env['GITHUB_EVENT_NAME'], branch_ref=env['GITHUB_REF'])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def storage_record(free, total):
    required = 25*1024**3 + 12*1024**3 + 64*1024**2
    return dict(free=free,total=total,target_growth=25*1024**3,reserve=12*1024**3,
                compact_copy=64*1024**2,required_free=required,capacity_admitted=free>=required)


def main():
    parser = argparse.ArgumentParser()
    for name in ['repo', 'root-policy', 'plan', 'operator', 'source-manifest', 'context', 'target']:
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    context = args.context.resolve()
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if os.name != 'posix' or repo != Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True):
        raise ValueError('hosted Linux workspace required')
    if not context.is_relative_to(temp) or not args.target.resolve().is_relative_to(temp):
        raise ValueError('job-owned paths required')
    context.mkdir(parents=True, exist_ok=False)
    record = {'state': 'HOLD', 'observations': {}, 'error': None}
    try:
        policy = json.loads(args.root_policy.read_bytes())
        if policy['state'] != 'ROOT_REVIEWED_POLICY_RUNTIME_UNOBSERVED':
            raise ValueError('reviewed static policy required')
        for path, expected in policy['published_files'].items():
            subject = repo / path
            if subject.is_symlink() or not subject.resolve(strict=True).is_relative_to(repo) or digest(subject) != expected:
                raise ValueError('published file drift: '+path)
        for path, key in [(args.plan,'plan_sha256'),(args.operator,'operator_sha256'),(args.source_manifest,'source_manifest_sha256')]:
            if digest(path) != policy[key]:
                raise ValueError('policy source join: '+key)
        for path, name in [(args.root_policy,'root-policy.json'),(args.plan,'plan.json'),
                           (args.operator,'runner.py'),(args.source_manifest,'source-manifest.json'),
                           (Path(__file__),'bind-runtime.py')]:
            data=path.read_bytes()
            if len(data)>4*1024**2:
                raise ValueError('context source cap')
            (context/name).write_bytes(data)
        usage = shutil.disk_usage(args.target.parent)
        record['storage'] = storage_record(usage.free, usage.total)
        record['actor'] = dict(uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),uname=list(os.uname()),
                               proc_status=[s for s in Path('/proc/self/status').read_text().splitlines() if s.startswith(('Uid:','Gid:','Cap','NoNewPrivs:'))],
                               namespaces={n:os.readlink('/proc/self/ns/'+n) for n in ['mnt','net','pid','user']})

        def observe(name, argv):
            row = bounded(argv, repo)
            record['observations'][name] = row
            if row['exit'] != 0 or row['state'] != 'CAPTURED':
                raise ValueError('metadata command refused: '+name)
            return row['output'].strip()

        actual = observe('checkout',['git','rev-parse','HEAD','HEAD^{tree}']).splitlines()
        binding = checked_event(policy, os.environ, actual)
        if not record['storage']['capacity_admitted']:
            raise ValueError('insufficient measured postsetup space')
        for name in ['cargo','rustc']:
            path = Path(observe(name+'_path',['rustup','which','--toolchain','1.95.0',name])).resolve(strict=True)
            binding[name+'_path'] = str(path)
            binding[name+'_sha256'] = digest(path)
            observe(name+'_version',[str(path),'-vV' if name=='rustc' else '--version'])
        observe('active_toolchain',['rustup','show','active-toolchain'])
        observe('libalpm',['pkg-config','--modversion','libalpm'])
        observe('pacman',['pacman','-Q','pacman'])
        binding.update(state='RUNTIME_BOUND_UNOBSERVED_SUBJECT_PENDING_ROOT_REVIEW',
                       policy_sha256=digest(args.root_policy),exclusive_checkout_and_target=True)
        (context/'binding.json').write_text(json.dumps(binding,indent=2)+'\n')
        record['state']='RUNTIME_BOUND_UNOBSERVED_SUBJECT_PENDING_ROOT_REVIEW'
        record['context_sources']={p.name:dict(bytes=p.stat().st_size,sha256=digest(p)) for p in context.iterdir() if p.is_file()}
    except Exception as exc:
        record['error']=str(exc)
    finally:
        (context/'setup-preflight.json').write_text(json.dumps(record,indent=2)+'\n')
    if record['state']=='HOLD':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
