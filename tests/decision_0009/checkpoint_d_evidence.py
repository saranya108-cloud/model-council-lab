"""Single-use D capture and read-only verification, through authorized V4/V5.

The V4 foreground process is also the unittest Harness for its three suites.
It never starts a second runner process alongside the four proof children.
Archived data is evidence, never a means to recreate operational authority.
"""

import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time
import unittest
import zipfile

from tools.decision_0009.acer_adapter.journal_persistence import (
    ARTIFACT_ROOT, REPOSITORY, LIMITS, CASE_JOURNAL_LIMIT, CASE_WITNESS_LIMIT,
    OBJECT_LIMIT, _open_directory, check_budget, create_directory, preserve_file,
)
from tools.decision_0009.acer_adapter.process_services import (
    PINNED_PYTHON, PINNED_SHA256, verify_interpreter,
)

BASELINE = 'eb27da7a56c2c01e673173a1d9bc8cacdf6c721a'
BRANCH = 'm1-live-adapter-dev'
ACCEPTED_C = '7a2b3147ebec8441d3197be072bb384bb309d3692fb8416b54614e969acdc97f'
PARTIAL_D = 'd8bf7bcd0bc091b3cae544a869016b568129cdc66256433685d86a4c1986c1ab'
CANDIDATE = ARTIFACT_ROOT / 'evidence/final-candidate-01'
MODIFIED = tuple('tools/decision_0009/acer_adapter/' + n for n in
                 ('README.md', 'custody.py', 'evidence.py', 'supervisor.py'))
NEW = (
    'tools/decision_0009/acer_adapter/local_ipc.py',
    'tools/decision_0009/acer_adapter/journal_persistence.py',
    'tools/decision_0009/acer_adapter/process_services.py',
    'tests/decision_0009/acer_adapter_process_support.py',
    'tests/decision_0009/test_acer_adapter_process.py',
    'tests/decision_0009/checkpoint_d_evidence.py',
)
PATTERNS = {
    'focused': 'test_acer_adapter_process.py',
    'adapter': 'test_acer_adapter*.py',
    'startup': 'test_startup_characterization_*.py',
}
COMMANDS = {name: "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests python3 -B -m unittest "
    "discover -s tests/decision_0009 -p '%s' -v" % pattern for name, pattern in PATTERNS.items()}
PRIOR = {
    'u04-checkpoint-a-repair-20261004': (255, '358046b69276aab5346283d6f77ee7eaf8a7b2e95839bf756101820681fcc141'),
    'u04-checkpoint-b-corrective-20261005': (126, '373c19c597c76973cf827061e98956dcde7fc3daa657d41fa0951ff4cd5d1584'),
    'u04-checkpoint-c-20261007': (826, '9b8e3d1b492ce62c135fc5f5c3d2cd21a7fff72ed177e3c59e15400602743f90'),
}
PRIOR_SEALS = {
    'u04-checkpoint-a-repair-20261004/opus-re-review-package/PACKAGE-SHA256SUMS':
        'fe0c7d427009e5ab64c30eb204908cc3780398ad2a43e407304e36ceebe9dbf7',
    'u04-checkpoint-b-corrective-20261005/checkpoint-b-review-99d87c7fa547/package-seal.json':
        'b8547fdb11e456445d299da1ac895ddaa60202882dea0eba002d12857278fc55',
    'u04-checkpoint-c-20261007/candidate-08-sol-final-corrective/seal-manifest.json':
        '074ad4fdef6fca367f0b18fd2f1273a7ad8d634e005bca5061944e08d5b2f38b',
}
REQUIREMENTS = {
    'D01': 'Harness-only faults; exact owned direct children, closed roles and authorized artifact roots.',
    'D02': 'Original enrolled authorization/store/campaign/actor/operation/subject/source/target; copied data confers no authority.',
    'D03': 'Accepted frozen frame/reservation, sole original JPS, file/directory barriers, independent readback, original W commitment/confirmation, then current C initiation.',
    'D04': 'Actual accepted PersistentSupervisor/Controller-local store, reducer and capabilities die; replacement reconstructs accepted history and newly authorized non-executing bindings.',
    'D05': 'Original W serializes revocation/frontier/admission; stale channels deny; immutable ORIGIN/RECOVERY_RECONCILE provenance.',
    'D06': 'Original independent C observations establish at most one initiation per accepted logical operation.',
    'D07': 'Missing registry state is UNKNOWN, not NOT_STARTED; acceptance/possible initiation/claims/results prevent false freshness.',
    'D08': 'Quarantine denies append/RP/reconciliation; exact accepted W-only pending completion creates no frame/object/effect grant; denial is irreversible.',
    'D09': 'Separate original JPS persistence/readback, original W facts, original C claims/results, actual wait exit/reap and bounded quiescence observations.',
    'D10': 'Final frozen source, exact scope/enrollment, fresh complete suites, test identities, preserved artifacts and prior A/B/C evidence.',
    'D11': 'Same original W/C/JPS required through private bootstrap endpoints and owned observed lifetime; copied IDs/files/PIDs/transcripts do not authenticate continuity.',
}
FAULTS = {
    'F01': 'Owned Controller abrupt loss', 'F02': 'One response suppressed, operation retained',
    'F03': 'Existing original-channel delay/replay/reorder', 'F04': 'Original W loss',
    'F05': 'Original C loss', 'F06': 'Original JPS loss',
    'F07': 'Seven-byte fault-case journal prefix',
    'F08': 'Fault-case complete-frame rollback with pre/postimages',
    'F09': 'Fault-case conflicting predecessor with pre/postimages',
    'F10': 'Identity/root/endpoint substitution rejection', 'F11': 'Rejected process impostors, no signal',
    'F12': 'Exact reconciliation interruption', 'F13': 'Withheld observation, UNKNOWN/incomplete',
    'F14': 'Selected actual simulated C registry loss with retained facts',
    'F15': 'Closed shutdown, TERM/KILL only if required, actual owned wait/reap',
    'F16': 'W acknowledgement loss with retained fact', 'F17': 'Quarantine/fencing public and lower denial',
}
CUTS = (
    'before_reservation', 'after_reservation_before_frame', 'partial_frame',
    'bytes_written_before_barrier', 'barrier_complete_before_readback', 'readback_before_commit',
    'commit_before_ack', 'acceptance_before_claim', 'claimed_before_initiation',
    'initiated_before_result', 'result_frame_before_commit', 'result_commit_before_ack',
)
SCOPE = {
    'authority': 'Human Chair session-provided Decision 0009 Checkpoint D implementation authorization, preflight clarification and corrective authorization; DISPOSITION A.',
    'authority_representation': 'Normalized scope binding; the supplied council session remains normative. Exact fixture enrollments and canonical authorization bytes are separately archived.',
    'accepted_architecture': 'D01-D11 unchanged; accepted A/B/C application owners across process adapters; no parallel D application policy.',
    'baseline_head': BASELINE, 'branch': BRANCH, 'accepted_c_snapshot': ACCEPTED_C,
    'partial_development_snapshot_not_final': PARTIAL_D,
    'modified': list(MODIFIED), 'new': list(NEW),
    'artifact_roots': {k: str(ARTIFACT_ROOT / k) for k in LIMITS},
    'cumulative_limits_bytes': LIMITS, 'case_journal_bytes': CASE_JOURNAL_LIMIT,
    'case_witness_bytes': CASE_WITNESS_LIMIT, 'application_object_bytes': OBJECT_LIMIT,
    'wire_bytes': 16 * 1024**2, 'final_candidate': str(CANDIDATE),
    'roles': ['foreground H/unittest', 'one Controller at a time', 'original JPS', 'original W', 'original C'],
    'process_bound': 5, 'controller_lifetimes_per_case': 4, 'service_replacement': False,
    'transport': 'anonymous AF_UNIX SOCK_STREAM socket pairs; fixed bootstrap peers; no listener/discovery/network/pickle/generic RPC',
    'ownership': 'pinned Popen, shell=False, close_fds=True, exact pass_fds, allowlisted child environment; one live nonserializable owner; sole thread waitpid; tombstones; no numeric-PID fallback',
    'requirements': REQUIREMENTS, 'fault_allowlist': FAULTS, 'cut_points': list(CUTS),
    'validation_commands': COMMANDS,
    'capture_command': 'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests:tests/decision_0009 python3 -B -m unittest checkpoint_d_evidence.CheckpointDEvidenceTests.test_capture_final_candidate -v',
    'verification_command': 'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests:tests/decision_0009 python3 -B -m unittest checkpoint_d_evidence.CheckpointDEvidenceTests.test_verify_final_candidate -v',
    'scope_commands': ['git diff --check', 'git diff --cached --name-status',
        'git status --porcelain=v1 --untracked-files=all', 'git diff --name-status ' + BASELINE + ' --'],
    'stop_boundary': 'Any envelope/baseline/interpreter/identity/ordering/ownership/barrier/continuity/UNKNOWN/duplicate/suite/source/evidence/limit conflict returns to Human Chair; final-candidate-01 is single-use.',
    'prohibitions': ['other source paths', 'dependencies/installations', 'Git mutation/publication',
        'subagents', 'persistent daemons', 'credentials/providers/network/GPU',
        'real workloads/custody/publication', 'host configuration', 'prior evidence mutation/deletion'],
    'limitations': ['trusted macOS arm64 fixture', 'simulated custody/workload/destination',
        'no W/C/JPS replacement recovery', 'no whole runtime/host/reboot/power-loss recovery',
        'no protected provisioning or hostile same-user containment', 'no deployment/production readiness',
        'host ps unavailable; bounded owned-child quiescence only'],
    'review_boundary': 'Claude Opus 5.5 independent technical/adversarial review pending; no Opus/Nova/Human Chair acceptance or Git publication authority.',
}


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _relative(path):
    path = Path(path)
    if not path.is_absolute():
        path = REPOSITORY / path
    value = path.relative_to(REPOSITORY)
    _require('..' not in value.parts, 'closed repository path required')
    return value.as_posix()


def _read(path):
    path = REPOSITORY / _relative(path)
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode), 'regular evidence/source file required')
            _require(before.st_size <= 256 * 1024**2, 'bounded evidence read required')
            blocks, remaining = [], before.st_size
            while remaining:
                block = os.read(fd, min(1024**2, remaining))
                _require(block, 'short evidence read')
                blocks.append(block)
                remaining -= len(block)
            after = os.fstat(fd)
            _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                     (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                     'evidence identity changed during read')
            return b''.join(blocks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _entry(path):
    path = REPOSITORY / _relative(path)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raw, kind = os.readlink(path).encode(), 'SYMLINK_RECEIPT'
    else:
        _require(stat.S_ISREG(st.st_mode), 'unexpected artifact type')
        raw, kind = _read(path), 'REGULAR'
    return dict(kind=kind, bytes=len(raw), sha256=_sha(raw),
                identity=[st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)],
                mtime_ns=st.st_mtime_ns, nlink=st.st_nlink)


def _members(root, *, exclude_candidate=False):
    result = {}
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs.sort()
        files.sort()
        for name in list(subdirs):
            path = Path(directory) / name
            if exclude_candidate and path == CANDIDATE:
                subdirs.remove(name)
            elif path.is_symlink():
                result[_relative(path)] = _entry(path)
                subdirs.remove(name)
        for name in files:
            path = Path(directory) / name
            result[_relative(path)] = _entry(path)
    return result


def _outside():
    result = {}
    for category in LIMITS:
        check_budget(category)
        result.update(_members(ARTIFACT_ROOT / category, exclude_candidate=True))
    return result


def _git(*arguments):
    result = subprocess.run(['/usr/bin/git', *arguments], cwd=REPOSITORY, shell=False,
        close_fds=True, pass_fds=(), env=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C',
            GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null'),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    _require(result.returncode == 0, 'read-only Git check failed: ' + repr(arguments))
    return result.stdout


def _source():
    verify_interpreter()
    _require(platform.system() == 'Darwin' and platform.machine() == 'arm64' and
             platform.python_version() == '3.14.7', 'approved platform differs')
    _require(REPOSITORY == Path.cwd().resolve(), 'repository path differs')
    _require(_git('rev-parse', 'HEAD').decode().strip() == BASELINE, 'HEAD differs')
    _require(_git('rev-parse', '--abbrev-ref', 'HEAD').decode().strip() == BRANCH, 'branch differs')
    _require(not _git('diff', '--cached', '--name-status'), 'staged state differs')
    _git('diff', '--check')
    changed = _git('diff', '--name-status', BASELINE, '--').decode().splitlines()
    _require(sorted(changed) == sorted('M\t' + p for p in MODIFIED), 'tracked scope differs')
    status = _git('status', '--porcelain=v1', '--untracked-files=all').decode().splitlines()
    _require(sorted(status) == sorted([' M ' + p for p in MODIFIED] + ['?? ' + p for p in NEW]),
             'worktree or new-path scope differs')
    tracked = _git('ls-files', '-z').decode().rstrip('\0').split('\0')
    files, identities, baseline = {}, {}, {}
    for name in sorted(set(tracked) | set(NEW)):
        entry = _entry(REPOSITORY / name)
        _require(entry['kind'] == 'REGULAR', 'source alias rejected')
        files[name], identities[name] = entry['sha256'], entry
        if name in tracked:
            baseline[name] = _sha(_git('show', BASELINE + ':' + name))
            if name not in MODIFIED:
                _require(files[name] == baseline[name], 'protected source differs: ' + name)
    return dict(files=files, snapshot_sha256=_sha(_json(files)), source_identities=identities,
        baseline_files=baseline, baseline_head=BASELINE, branch=BRANCH, accepted_c_snapshot=ACCEPTED_C,
        modified=list(MODIFIED), new=list(NEW), scope_sha256=_sha(_json(SCOPE)),
        interpreter=str(PINNED_PYTHON), interpreter_sha256=PINNED_SHA256,
        platform='macOS arm64', python_version=platform.python_version(),
        git_scope=dict(diff=changed, status=status, staged=[]))


def _prior():
    result = {}
    for name, (count, expected) in PRIOR.items():
        entries = _members(REPOSITORY / 'logs' / name)
        hashes = {str(Path(p).relative_to(Path('logs') / name)): e['sha256'] for p, e in entries.items()}
        _require(len(hashes) == count and _sha(_json(hashes)) == expected,
                 'prior A/B/C evidence changed: ' + name)
        result[name] = dict(files=entries, membership_sha256=expected)
    for name, expected in PRIOR_SEALS.items():
        _require(_sha(_read(REPOSITORY / 'logs' / name)) == expected, 'accepted seal differs')
    manifest = json.loads(_read(REPOSITORY / 'logs/u04-checkpoint-c-20261007/candidate-08-sol-final-corrective/source-manifest.json'))
    _require(manifest['snapshot_sha256'] == ACCEPTED_C, 'accepted C source binding differs')
    return result


def _audit_case(report, read, names):
    """Recompute closure from original service/OS observations, never Controller status."""
    roots = {k: _relative(v) for k, v in report['artifact_roots'].items()}
    case = report['case_id']
    _require(all(Path(v).name == case for v in roots.values()), 'case/root membership differs')
    _require(not report['cleanup_errors'] and report['quiescence']['all_reaped'] and
             not report['quiescence']['uncertain'], 'owned-child closure incomplete')
    active, popped, exits, kills, peak = set(), {}, 0, 0, 1
    last_time = 0
    for event in report['processes']:
        _require(event['monotonic_ns'] >= last_time, 'process lifetime order differs')
        last_time = event['monotonic_ns']
        role, kind = event.get('role'), event['event']
        if kind == 'POPEN':
            _require(role not in active and role in ('CONTROLLER', 'W', 'C', 'JPS'), 'role ownership overlaps')
            popped[role] = popped.get(role, 0) + 1
            _require(popped[role] <= (4 if role == 'CONTROLLER' else 1), 'original service restarted')
            active.add(role)
            peak = max(peak, len(active) + 1)
            _require(event['operating_processes_including_h'] == len(active) + 1 <= 5, 'process bound differs')
            _require(event['interpreter'] == str(PINNED_PYTHON) and
                     event['interpreter_sha256'] == PINNED_SHA256, 'child interpreter differs')
            _require(event['environment_keys'] == sorted(['D_PROOF_CHILD', 'LANG', 'LC_ALL',
                'PYTHONDONTWRITEBYTECODE', 'PYTHONNOUSERSITE']), 'child environment differs')
            _require(len(event['pass_fds']) == len(set(event['pass_fds'])), 'inherited descriptors duplicate')
        elif kind == 'SIGNAL':
            _require(role in active and event['capability_valid'] and event['signal'] in (9, 15),
                     'unowned signal observation')
            kills += int(role == 'CONTROLLER' and event['signal'] == 9)
        elif kind == 'EXIT_REAP':
            _require(role in active and event['mechanism'] == 'sole-owner-waitpid-WNOHANG' and
                     os.waitstatus_to_exitcode(event['wait_status']) == event['returncode'],
                     'actual exit/wait/reap observation differs')
            active.remove(role)
            exits += 1
        else:
            _require(kind in ('CLOSED_SHUTDOWN_ACK', 'CLOSED_SHUTDOWN_UNCONFIRMED', 'QUIESCENCE'),
                     'uncertain process observation')
    _require(not active and exits == sum(popped.values()) == report['quiescence']['owned_children'] and
             peak == report['quiescence']['peak_operating_processes_including_h'] <= 5, 'quiescence differs')
    _require(all(popped.get(r) == 1 for r in ('W', 'C', 'JPS')), 'missing original service lifetime')
    bootstrap = json.loads(read(roots['evidence'] + '/bootstrap.json'))
    for role in ('W', 'C', 'JPS'):
        _require(bootstrap['original_instances'][role] == report['original_instances'][role], 'bootstrap continuity differs')
    audits = [json.loads(read(p)) for p in sorted(names) if p.startswith(roots['evidence'] + '/persistence-')]
    audit = [event for block in audits for event in block['observations']]
    _require([e['sequence'] for e in audit] == list(range(1, len(audit) + 1)) and
             len(audit) == report['persistence_observations'], 'persistence observations incomplete')
    _require(all(a['instance'] == report['original_instances']['JPS'] for a in audits), 'JPS observer changed')
    facts = [json.loads(read(p)) for p in sorted(names) if p.startswith(roots['witness'] + '/')]
    reserves = {f['value']['transaction_id']: f for f in facts if f['kind'] == 'reservation'}
    _require(all(r['value']['store_identity'] == bootstrap['store_identity'] and
                 r['value']['authorization_digest'] == bootstrap['authorization']['authorization_digest'] and
                 r['value']['campaign_id'] == bootstrap['authorization']['campaign_id']
                 for r in reserves.values()), 'original enrollment/store/campaign binding differs')
    ordered, unavailable = 0, 0
    for fact in facts:
        if fact['kind'] != 'commitment':
            continue
        value = fact['value']
        reservation = value['reservation']
        original = reserves[reservation['transaction_id']]
        _require(value['completion_mode'] == 'ORIGIN' and original['value'] == reservation,
                 'original commitment provenance differs')
        begin, end = original['monotonic_ns'], fact['monotonic_ns']
        wanted = [('BYTES_WRITTEN', 'CONTROLLER'), ('BARRIER_COMPLETE', 'CONTROLLER'),
                  ('READBACK', 'CONTROLLER'), ('READBACK', 'W')]
        position, barrier_sha = 0, None
        for event in audit:
            if event['revision'] != reservation['revision'] or not begin < event['monotonic_ns'] < end:
                continue
            if position < len(wanted) and (event['kind'], event['peer']) == wanted[position]:
                if position == 1:
                    _require(event['barrier'] is True, 'persistence barrier incomplete')
                    barrier_sha = event['sha256']
                if position >= 2:
                    _require(event['barrier'] is True and event['sha256'] == barrier_sha,
                             'independent readback differs')
                position += 1
        if position == len(wanted):
            ordered += 1
        else:
            _require(not audit and any(f['fault'] == 'F06' for f in report['faults']),
                     'commit lacks independently ordered persistence/readback')
            unavailable += 1
    for fact in facts:
        if fact['kind'] == 'acceptance-confirmed':
            tx = fact['value']['transaction']
            matching = [f for f in facts if f['kind'] == 'commitment' and f['value']['reservation']['transaction_id'] == tx]
            _require(len(matching) == 1 and matching[0]['monotonic_ns'] < fact['monotonic_ns'],
                     'acceptance confirmation lacks original commitment')
    observations = [json.loads(read(p)) for p in sorted(names)
                    if re.fullmatch(re.escape(roots['evidence']) + r'/observation-\d{4}\.json', p)]
    _require(len(observations) == report['independent_observations'], 'independent observation membership differs')
    grant_operations, grant_transactions, counts, authentic_results = {}, {}, {}, set()
    for observation in observations:
        for role, field in (('W', 'w'), ('C', 'c'), ('JPS', 'jps')):
            data = observation[field]
            instance = data.get('instance', data.get('service_instance'))
            _require(instance == observation['continuity'][role] == report['original_instances'][role],
                     'original observer endpoint/lifetime binding differs')
        _require(observation['jps']['root_identity'] == bootstrap['root_identity'], 'original JS root differs')
        for frame in observation['jps']['records']:
            event = frame['payload']
            if event.get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED':
                grant_operations[event['grant_id']] = event['logical_operation_id']
                grant_transactions[event['grant_id']] = frame['transaction_id']
        registry = observation['c']['registries']
        for grant, count in registry['counts'].items():
            _require(type(count) is int and 0 <= count <= 1, 'duplicate original C initiation')
            counts[grant] = max(counts.get(grant, 0), count)
        for result in registry['grant_results'].values():
            authentic_results.add(_sha(bytes.fromhex(result[0]['$bytes'])))
    logical = {}
    for grant, operation in grant_operations.items():
        if grant in counts:
            logical[operation] = logical.get(operation, 0) + counts[grant]
            if counts[grant]:
                _require(any(f['kind'] == 'acceptance-confirmed' and
                             f['value']['transaction'] == grant_transactions[grant] for f in facts),
                         'independent C initiation lacks original W acceptance confirmation')
    _require(all(count <= 1 for count in logical.values()), 'duplicate logical initiation')
    if case.startswith('accepted-positive-chain-'):
        _require(kills and len(observations) == 2 and observations[0]['c']['original_source_owned'],
                 'positive accepted original/death chain absent')
        original = [f for f in observations[0]['jps']['records'] if
                    f['payload'].get('record_type') == 'PUBLICATION' and
                    f['payload'].get('operation') == 'intent' and
                    f['authority_facts'].get('publication_grant', {}).get('phase') == 'INTENT']
        _require(len(original) == 1 and observations[1]['jps']['records'][:len(observations[0]['jps']['records'])] ==
                 observations[0]['jps']['records'], 'original history provenance changed')
        source = observations[0]['c']['registries']['subjects']['evidence/proof']
        _require(source['original_intent_ref']['event_id'] == original[0]['transaction_id'] and
                 source['original_create_ref'] is not None, 'actual original reservation/source absent')
        last = observations[-1]
        obj = last['c']['registries']['objects']['evidence/proof']
        raw = bytes.fromhex(obj['bytes']['$bytes'])
        _require(_sha(raw) == bootstrap['subject']['source_digest'] and
                 obj['object_durable'] and obj['namespace_durable'], 'accepted continuation/durability absent')
        results = [f['payload'] for f in last['jps']['records'] if
                   f['payload'].get('record_type') == 'RECOVERY_PUBLICATION_RESULT']
        _require(any(f['outcome'] == 'VERIFIED' for f in results), 'accepted verification absent')
        for event in results:
            proof = event['destination_receipt']
            key = roots['journal'] + '/object-' + _sha(proof['object_id'].encode())
            raw = read(key)
            _require(_sha(raw) == proof['sha256'] in authentic_results and len(raw) == proof['length'],
                     'result not linked to independent original C receipt/JPS proof')
    if case.startswith(('accepted-pending-reconciliation-', 'accepted-reconcile-ack-loss-',
                        'accepted-before-reconciliation-loss-')):
        _require(len(observations) >= 2 and observations[0]['jps'] == observations[1]['jps'] and
                 observations[0]['c'] == observations[1]['c'], 'W-only interval changed JS or C')
    if case.startswith('accepted-quarantine-reconciliation-'):
        before, after = observations[-2:]
        _require(before['w']['health'] == after['w']['health'] == 'QUARANTINED' and
                 before['w']['pending'] == after['w']['pending'] and
                 before['jps'] == after['jps'] and before['c'] == after['c'],
                 'quarantine permitted checkpoint reconciliation/effect')
    if case.startswith('accepted-stable-conflict-'):
        _require(observations[0]['w']['denials'] and
                 observations[0]['w']['denials'] == observations[-1]['w']['denials'],
                 'accepted irreversible denial changed')
    journal_bytes = sum(len(read(p)) for p in names if p.startswith(roots['journal'] + '/'))
    witness_bytes = sum(len(read(p)) for p in names if p.startswith(roots['witness'] + '/'))
    _require(journal_bytes < CASE_JOURNAL_LIMIT and witness_bytes < CASE_WITNESS_LIMIT,
             'per-case artifact limit reached')
    for path in names:
        if path.startswith(roots['journal'] + '/object-'):
            _require(len(read(path)) <= OBJECT_LIMIT, 'application object limit exceeded')
    return dict(case_id=case, owned_children=exits, actual_controller_sigkills=kills,
        peak_processes=peak, ordered_origin_commits=ordered,
        unavailable_jps_observations_expected_negative=unavailable,
        known_logical_initiations=logical, authentic_result_digests=sorted(authentic_results),
        bootstrap_authorization_sha256=_sha(_json(bootstrap['authorization'])),
        facts=len(facts), persistence_observations=len(audit), all_reaped=True)


def _coverage(reports):
    faults = {name: [] for name in FAULTS}
    cuts = {name: [] for name in CUTS}
    reservation_loss = []
    for report in reports:
        for fault in report['faults']:
            _require(fault['fault'] in faults, 'unapproved fault')
            faults[fault['fault']].append(report['case_id'])
            stage = fault.get('stage')
            if stage in cuts:
                cuts[stage].append(report['case_id'])
            if fault.get('operation') == 'RESERVE_FRAME' and fault['fault'] == 'F16':
                reservation_loss.append(report['case_id'])
    _require(all(faults.values()) and all(cuts.values()) and reservation_loss, 'fault/cut coverage incomplete')
    return dict(faults={k: sorted(set(v)) for k, v in faults.items()},
                cut_points={k: sorted(set(v)) for k, v in cuts.items()},
                reservation_response_loss=sorted(set(reservation_loss)))


def _enrollments(reports, read):
    from tools.decision_0009.acer_adapter.contracts import (
        authorization_from_record, authorization_digest, canonical_authorization_bytes,
    )
    result = {}
    for report in reports:
        path = _relative(report['artifact_roots']['evidence']) + '/bootstrap.json'
        bootstrap = json.loads(read(path))
        auth = authorization_from_record(bootstrap['authorization'])
        raw = canonical_authorization_bytes(auth)
        _require(authorization_digest(auth) == auth.authorization_digest, 'fixture authorization digest differs')
        result[report['case_id']] = dict(store_identity=bootstrap['store_identity'],
            campaign_id=auth.campaign_id, authorization_id=auth.authorization_id,
            authorization_digest=auth.authorization_digest, canonical_bytes_hex=raw.hex(),
            canonical_bytes_sha256=_sha(raw), bootstrap_artifact=path,
            original_w_instance=bootstrap['original_instances']['W'], subject=bootstrap['subject'],
            limit='Historical enrolled data; operational authentication required original private channels and original W verifier.')
    return result


class _Transcript(io.StringIO):
    def __init__(self):
        super().__init__()
        self.external = sys.stderr
        self.length = 0

    def write(self, value):
        self.length += len(value.encode())
        _require(self.length < 8 * 1024**2, 'bounded raw suite output exhausted')
        self.external.write(value)
        self.external.flush()
        return super().write(value)


class _Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started, self.finished, self.subcases = [], [], []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished.append(test.id())
        super().stopTest(test)

    def addSubTest(self, test, subtest, err):
        self.subcases.append(dict(id=subtest.id(), parent=test.id(),
            outcome='PASS' if err is None else 'FAIL_OR_ERROR',
            detail=None if err is None else self._exc_info_to_string(err, test)))
        super().addSubTest(test, subtest, err)


def _tests(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _tests(test)
        else:
            yield test


def _run_suite(name, source):
    from decision_0009.acer_adapter_process_support import CASE_OBSERVATIONS
    offset = len(CASE_OBSERVATIONS)
    suite = unittest.TestLoader().discover(str(REPOSITORY / 'tests/decision_0009'), PATTERNS[name])
    identities = []
    for test in _tests(suite):
        module = sys.modules[type(test).__module__]
        path = _relative(Path(module.__file__).resolve())
        _require(path in source['files'], 'test outside source binding')
        identities.append(dict(id=test.id(), source=path, sha256=source['files'][path]))
    transcript = _Transcript()
    start = time.monotonic_ns()
    with contextlib.redirect_stdout(transcript), contextlib.redirect_stderr(transcript):
        result = unittest.TextTestRunner(stream=transcript, verbosity=2, resultclass=_Result,
                                        failfast=True).run(suite)
    end = time.monotonic_ns()
    complete = len(identities) == result.testsRun == len(result.finished) == len(result.started)
    success = complete and result.wasSuccessful() and not result.skipped and not result.expectedFailures
    report = dict(name=name, equivalent_command=COMMANDS[name], source_snapshot=source['snapshot_sha256'],
        execution='Same foreground V4 unittest Harness; TestLoader.discover/TextTestRunner; no secondary runner process',
        exit_state=dict(kind='in-process unittest completion', equivalent_unittest_exit_status=0 if success else 1),
        started_ns=start, completed_ns=end, elapsed_ns=end-start, complete=complete,
        tests=result.testsRun, planned_tests=len(identities), failures=len(result.failures),
        errors=len(result.errors), skips=len(result.skipped), expected_failures=len(result.expectedFailures),
        unexpected_successes=len(result.unexpectedSuccesses), test_identities=identities,
        started=result.started, finished=result.finished, subcase_count=len(result.subcases),
        subcases=result.subcases, failure_details=result.failures, error_details=result.errors,
        cases=CASE_OBSERVATIONS[offset:])
    # Only strings, not TestCase/exception/callable instances, enter evidence.
    report['failure_details'] = [[test.id(), detail] for test, detail in result.failures]
    report['error_details'] = [[test.id(), detail] for test, detail in result.errors]
    return report, transcript.getvalue().encode(), success


def _put(name, value, *, raw=False):
    preserve_file(CANDIDATE / name, value if raw else _json(value))


def _case_members(reports):
    members = {}
    for report in reports:
        for root in report['artifact_roots'].values():
            members.update(_members(Path(root)))
        for fault in report['faults']:
            for path in fault.get('artifacts', []):
                _require(Path(path).parent == ARTIFACT_ROOT / 'faults', 'fault artifact escaped root')
                members[_relative(path)] = _entry(Path(path))
    return members


def _archive(members):
    estimated = sum(e['bytes'] + len(p.encode()) * 2 + 256 for p, e in members.items())
    _require(estimated < 256 * 1024**2, 'bounded final artifact archive exhausted')
    check_budget('evidence', estimated)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for path, entry in sorted(members.items()):
            if entry['kind'] == 'SYMLINK_RECEIPT':
                continue
            _require(_entry(REPOSITORY / path) == entry, 'artifact changed before archival copy')
            archive.writestr(zipfile.ZipInfo(path), _read(REPOSITORY / path))
    _put('artifacts.zip', stream.getvalue(), raw=True)


def _package_files():
    prefix = _relative(CANDIDATE)
    return {str(Path(p).relative_to(prefix)): dict(bytes=e['bytes'], sha256=e['sha256'])
            for p, e in _members(CANDIDATE).items() if Path(p).name != 'seal.json'}


def _verify():
    """Strictly read-only: no services, suites, faults, repair or writes."""
    source = json.loads(_read(CANDIDATE / 'source-manifest.json'))
    _require(_source() == source, 'final source/identity/scope changed')
    seal = json.loads(_read(CANDIDATE / 'seal.json'))
    files = _package_files()
    _require(files == seal['files'] and _sha(_json({p: e['sha256'] for p, e in files.items()})) ==
             seal['package_content_sha256'], 'package seal or membership differs')
    _require(seal['source_snapshot'] == source['snapshot_sha256'] and
             seal['schema'] == 'decision-0009-checkpoint-d-seal/v1' and
             seal['status'] == 'REVIEW_CANDIDATE', 'seal source/status differs')
    _require(json.loads(_read(CANDIDATE / 'authority-scope.json')) == SCOPE, 'authorization scope differs')
    _require(json.loads(_read(CANDIDATE / 'prior-evidence.json')) == _prior(), 'prior evidence changed')
    outside = json.loads(_read(CANDIDATE / 'retained-artifacts-after.json'))
    _require(_outside() == outside, 'retained artifact membership/identity changed')
    before = json.loads(_read(CANDIDATE / 'historical-development-before.json'))
    _require(all(outside.get(p) == e for p, e in before['files'].items()), 'historical evidence changed')
    for path, expected in source['files'].items():
        _require(_sha(_read(CANDIDATE / 'source' / path)) == expected, 'archived source differs')
    reports, ids, validation = [], {}, {}
    for name in PATTERNS:
        result = json.loads(_read(CANDIDATE / ('validation/' + name + '.json')))
        raw = _read(CANDIDATE / ('validation/' + name + '.log')).decode()
        _require(result['source_snapshot'] == source['snapshot_sha256'] and result['complete'] and
                 result['tests'] == result['planned_tests'] == len(result['started']) == len(result['finished']) and
                 not any(result[k] for k in ('failures', 'errors', 'skips', 'expected_failures', 'unexpected_successes')) and
                 result['exit_state']['equivalent_unittest_exit_status'] == 0, 'suite closure incomplete')
        _require(re.search(r'Ran %d tests? in ' % result['tests'], raw) and raw.rstrip().endswith('OK'),
                 'raw suite result differs')
        _require(result['subcase_count'] == len(result['subcases']) and
                 all(c['outcome'] == 'PASS' for c in result['subcases']), 'subcase closure differs')
        for test in result['test_identities']:
            _require(source['files'][test['source']] == test['sha256'], 'test source identity differs')
        ids[name] = {t['id'] for t in result['test_identities']}
        _require(set(result['started']) == set(result['finished']) == ids[name], 'test identity membership differs')
        reports.extend(result['cases'])
        validation[name] = {k: result[k] for k in
            ('tests', 'subcase_count', 'failures', 'errors', 'skips', 'exit_state')}
    _require(ids['focused'] < ids['adapter'] and not ids['startup'] & ids['adapter'], 'suite population differs')
    _require(len({r['case_id'] for r in reports}) == len(reports), 'final case reused')
    members = json.loads(_read(CANDIDATE / 'artifact-membership.json'))
    _require(all(outside.get(p) == e for p, e in members.items()), 'final original artifacts changed')
    with zipfile.ZipFile(io.BytesIO(_read(CANDIDATE / 'artifacts.zip')), 'r') as archive:
        names = archive.namelist()
        regular = {p for p, e in members.items() if e['kind'] == 'REGULAR'}
        _require(len(names) == len(set(names)) and set(names) == regular, 'archive membership differs')
        for path in names:
            _require(_relative(path) == path and archive.getinfo(path).compress_type == zipfile.ZIP_STORED,
                     'archive path/type differs')
            raw = archive.read(path)
            _require(len(raw) == members[path]['bytes'] and _sha(raw) == members[path]['sha256'],
                     'archived artifact bytes differ')
        audits = []
        for report in reports:
            path = _relative(report['artifact_roots']['evidence']) + '/process-observations.json'
            _require(json.loads(archive.read(path)) == report, 'case report changed after closure')
            audits.append(_audit_case(report, archive.read, set(names)))
        _require(_enrollments(reports, archive.read) ==
                 json.loads(_read(CANDIDATE / 'enrollment-manifest.json')), 'exact enrollment binding differs')
    _require(audits == json.loads(_read(CANDIDATE / 'independent-closure.json')), 'independent closure differs')
    _require(_coverage(reports) == json.loads(_read(CANDIDATE / 'fault-coverage.json')), 'fault coverage differs')
    closure = json.loads(_read(CANDIDATE / 'closure.json'))
    _require(closure['source_snapshot'] == source['snapshot_sha256'] and
             closure['status'] == 'IMPLEMENTATION_VALIDATION_COMPLETE_REVIEW_PENDING' and
             closure['cases'] == len(reports) and closure['owned_children_reaped'] ==
             sum(a['owned_children'] for a in audits) and
             closure['actual_controller_sigkills'] == sum(a['actual_controller_sigkills'] for a in audits) and
             closure['peak_processes'] == max(a['peak_processes'] for a in audits) and
             closure['validation'] == validation, 'final closure differs')
    return dict(source_snapshot=source['snapshot_sha256'], package_content_sha256=seal['package_content_sha256'],
        seal_sha256=_sha(_read(CANDIDATE / 'seal.json')), cases=len(reports),
        owned_children_reaped=closure['owned_children_reaped'], verification='READ_ONLY_PASS')


class CheckpointDEvidenceTests(unittest.TestCase):
    def test_capture_final_candidate(self):
        _require(not CANDIDATE.exists() and not CANDIDATE.is_symlink(), 'final-candidate-01 already exists: STOP')
        source, prior, historical = _source(), _prior(), _outside()
        # Validate the archival checker on closed current-format development
        # observations before consuming the single-use candidate. These remain
        # historical; only the fresh suites below supply final case evidence.
        threshold = max((REPOSITORY / p).stat().st_mtime_ns for p in MODIFIED + NEW
                        if p not in ('tools/decision_0009/acer_adapter/README.md', NEW[-1]))
        examples = {}
        for path in (ARTIFACT_ROOT / 'evidence/development').glob('accepted-*/process-observations.json'):
            if path.stat().st_mtime_ns >= threshold:
                report = json.loads(_read(path))
                examples[report['case_id'].rsplit('-', 1)[0]] = report
        _require(examples, 'closed corrective development observations absent')
        for report in examples.values():
            members = _case_members([report])
            _audit_case(report, lambda p: _read(REPOSITORY / p), set(members))
        _coverage(list(examples.values()))
        create_directory(CANDIDATE.parent)
        fd = _open_directory(CANDIDATE.parent)
        try:
            os.mkdir(CANDIDATE.name, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)
        _put('CAPTURE_STARTED.json', dict(status='INCOMPLETE_UNLESS_VALID_FINAL_SEAL',
            bound_utc=datetime.now(timezone.utc).isoformat(), harness_pid_diagnostic=os.getpid(),
            source_snapshot=source['snapshot_sha256'], argv=sys.argv))
        _put('source-manifest.json', source)
        _put('authority-scope.json', SCOPE)
        _put('prior-evidence.json', prior)
        _put('historical-development-before.json', dict(status='HISTORICAL_NOT_FINAL', files=historical))
        for path in source['files']:
            _put('source/' + path, _read(REPOSITORY / path), raw=True)
        reports, results = [], {}
        for name in PATTERNS:
            _require(_source() == source, 'source changed before final suite: STOP')
            result, raw, success = _run_suite(name, source)
            _put('validation/' + name + '.log', raw, raw=True)
            _put('validation/' + name + '.json', result)
            _require(success, 'required final suite incomplete/failed: preserve candidate and STOP')
            _require(_source() == source, 'source changed during final validation: STOP')
            reports.extend(result['cases'])
            results[name] = {k: result[k] for k in ('tests', 'subcase_count', 'failures', 'errors', 'skips', 'exit_state')}
        _require(_prior() == prior, 'prior evidence changed during validation')
        outside = _outside()
        _require(all(outside.get(p) == e for p, e in historical.items()), 'historical artifacts changed')
        members = _case_members(reports)
        audits = [_audit_case(r, lambda p: _read(REPOSITORY / p), set(members)) for r in reports]
        coverage = _coverage(reports)
        _put('artifact-membership.json', members)
        _put('enrollment-manifest.json', _enrollments(reports, lambda p: _read(REPOSITORY / p)))
        _archive(members)
        _put('retained-artifacts-after.json', outside)
        _put('independent-closure.json', audits)
        _put('fault-coverage.json', coverage)
        _put('closure.json', dict(status='IMPLEMENTATION_VALIDATION_COMPLETE_REVIEW_PENDING',
            source_snapshot=source['snapshot_sha256'], cases=len(reports),
            owned_children_reaped=sum(a['owned_children'] for a in audits),
            actual_controller_sigkills=sum(a['actual_controller_sigkills'] for a in audits),
            peak_processes=max(a['peak_processes'] for a in audits), validation=results,
            requirements=REQUIREMENTS, review=SCOPE['review_boundary'],
            limits=SCOPE['limitations'], completed_utc=datetime.now(timezone.utc).isoformat(),
            host_process_table='sandbox ps denial is environmental, not daemon-presence/absence evidence'))
        _require(_source() == source, 'source changed before final seal: STOP')
        files = _package_files()
        _put('seal.json', dict(schema='decision-0009-checkpoint-d-seal/v1', files=files,
            package_content_sha256=_sha(_json({p: e['sha256'] for p, e in files.items()})),
            source_snapshot=source['snapshot_sha256'], status='REVIEW_CANDIDATE'))
        # Every package/service writer is closed before this read-only check.
        print(json.dumps(_verify(), sort_keys=True))

    def test_verify_final_candidate(self):
        print(json.dumps(_verify(), sort_keys=True))
