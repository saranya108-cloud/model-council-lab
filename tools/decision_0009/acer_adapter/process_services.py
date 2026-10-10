"""Foreground D child services and single-owner direct-child lifecycle.

Only the Harness constructs ProcessOwner. Children never construct it or spawn
children. No numeric-PID signaling interface, listener, daemon or discovery.
"""

import hashlib
import json
import os
from pathlib import Path
import selectors
import select
import signal
import socket
import subprocess
import sys
import time
import traceback
import threading
import uuid

from .journal_persistence import (
    ARTIFACT_ROOT, REPOSITORY, JournalPersistence, check_budget, create_directory,
)
from .local_ipc import Channel, ProtocolError, failure_record

PINNED_PYTHON = Path('/opt/homebrew/Cellar/python@3.14/3.14.7/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PINNED_SHA256 = '87d4df53fd91304be5bac391fb204643c36b7df2023c04a0953bcbc7d4fdf634'
ROLES = frozenset(('CONTROLLER', 'JPS', 'W', 'C'))


def _log_failure():
    raw = traceback.format_exc().encode('utf-8')[:64 * 1024]
    if os.fstat(2).st_size + len(raw) >= 1024 * 1024:
        raise OwnershipError('bounded child diagnostic artifact limit reached')
    os.write(2, raw)


class OwnershipError(RuntimeError):
    pass


def verify_interpreter():
    if (Path(sys.executable).resolve() != PINNED_PYTHON or
            hashlib.sha256(PINNED_PYTHON.read_bytes()).hexdigest() != PINNED_SHA256):
        raise OwnershipError('approved interpreter identity changed')


class _OwnedChild:
    __slots__ = ('_owner', '_process', 'role', 'state', 'returncode', 'control', 'log_path')

    def __init__(self, owner, process, role, control, log_path):
        self._owner, self._process = owner, process
        self.role, self.control, self.log_path = role, control, log_path
        self.state, self.returncode = 'OWNED', None

    def __reduce__(self):
        raise TypeError('owned process capability cannot be serialized')

    def __copy__(self):
        raise TypeError('owned process capability cannot be copied')


class ProcessOwner:
    """The sole poll/signal/wait/reap owner; a reaped handle is a tombstone."""

    def __init__(self, evidence_root):
        if os.environ.get('D_PROOF_CHILD') == '1':
            raise OwnershipError('a proof child may not own or spawn a child')
        verify_interpreter()
        self.evidence_root = Path(evidence_root)
        if self.evidence_root.relative_to(ARTIFACT_ROOT).parts[0] != 'evidence':
            raise OwnershipError('approved proof evidence root required')
        create_directory(self.evidence_root)
        self._children = []
        self.observations = []
        self.signal_syscalls = 0
        self._owner_thread = threading.get_ident()
        self._launched_roles = set()
        self._controller_count = 0
        self._peak_owned = 0

    def _record(self, child, event, **facts):
        self.observations.append(dict(role=child.role, event=event,
                                      monotonic_ns=time.monotonic_ns(), **facts))

    def _require(self, child, *, live=True):
        if (threading.get_ident() != self._owner_thread or
                type(child) is not _OwnedChild or child._owner is not self or
                not any(c is child for c in self._children) or
                child.state == 'UNCERTAIN' or live and child.state != 'OWNED'):
            raise OwnershipError('exact live owned-child capability required')
        return child._process

    def launch(self, role, channels, child_ends):
        if (threading.get_ident() != self._owner_thread or
                any(c.state == 'UNCERTAIN' for c in self._children) or
                role != 'CONTROLLER' and role in self._launched_roles or
                role == 'CONTROLLER' and self._controller_count >= 4):
            raise OwnershipError('sole owner, original nonrestartable services and bounded Controller lifetimes required')
        if role not in ROLES or any(c.state == 'OWNED' and c.role == role for c in self._children):
            raise OwnershipError('one owned process per role at a time')
        if sum(c.state == 'OWNED' for c in self._children) >= 4:
            raise OwnershipError('five-process proof bound including Harness')
        verify_interpreter()
        descriptors = tuple(sorted({s.fileno() for s in child_ends}))
        if any(fd < 0 for fd in descriptors) or len(descriptors) != len(child_ends):
            raise OwnershipError('exact unique inherited endpoints required')
        # Every inherited fd is named in the closed bootstrap topology.
        if {entry['fd'] for entry in channels} != set(descriptors):
            raise OwnershipError('pass_fds differs from bootstrap topology')
        log = self.evidence_root / ('child-%d-%s.log' % (len(self._children), role.lower()))
        # Reserve headroom for all four concurrently owned bounded logs.
        check_budget('evidence', 4 * 1024 * 1024)
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        environment = dict(PYTHONDONTWRITEBYTECODE='1', D_PROOF_CHILD='1',
                           LANG='C', LC_ALL='C', PYTHONNOUSERSITE='1')
        try:
            process = subprocess.Popen(
                [str(PINNED_PYTHON), '-B', '-s', '-m',
                 'tools.decision_0009.acer_adapter.process_services', role,
                 json.dumps(channels, sort_keys=True, separators=(',', ':'))],
                shell=False, close_fds=True, pass_fds=descriptors, env=environment,
                cwd=REPOSITORY, stdin=subprocess.DEVNULL, stdout=fd, stderr=fd,
            )
        finally:
            os.close(fd)
        child = _OwnedChild(self, process, role, None, str(log))
        self._children.append(child)
        self._peak_owned = max(self._peak_owned, sum(c.state == 'OWNED' for c in self._children))
        self._launched_roles.add(role)
        if role == 'CONTROLLER':
            self._controller_count += 1
        self._record(child, 'POPEN', pid_diagnostic=process.pid,
                     operating_processes_including_h=sum(c.state == 'OWNED' for c in self._children) + 1,
                     pass_fds=list(descriptors), environment_keys=sorted(environment),
                     interpreter=str(PINNED_PYTHON), interpreter_sha256=PINNED_SHA256)
        for sock in child_ends:
            sock.close()
        return child

    def set_control(self, child, control):
        self._require(child)
        if child.control is not None or type(control) is not Channel:
            raise OwnershipError('single retained bootstrap control endpoint required')
        child.control = control

    def poll(self, child):
        process = self._require(child, live=False)
        if child.state == 'REAPED':
            return child.returncode
        try:
            if process.returncode is not None:
                raise OwnershipError('Popen lifecycle changed outside the sole wait owner')
            waited, status = os.waitpid(process.pid, os.WNOHANG)
            if waited == 0:
                return None
            if waited != process.pid:
                raise OwnershipError('direct-child wait ownership uncertain')
            code = os.waitstatus_to_exitcode(status)
        except BaseException:
            child.state = 'UNCERTAIN'
            self._record(child, 'WAIT_OWNERSHIP_UNCERTAIN')
            raise
        if code is not None:
            process.returncode = code
            child.state, child.returncode = 'REAPED', code
            self._record(child, 'EXIT_REAP', returncode=code, wait_status=status,
                         mechanism='sole-owner-waitpid-WNOHANG')
        return code

    def signal(self, child, sig):
        if sig not in (signal.SIGTERM, signal.SIGKILL):
            raise OwnershipError('closed proof signal allowlist')
        process = self._require(child)
        if self.poll(child) is not None:
            raise OwnershipError('reaped process capability is permanently invalid')
        try:
            # Sole owner; no other thread or component can wait/reap this child.
            # The exact owned, unreaped direct-child capability was checked
            # above. Its PID cannot be reused before this sole owner reaps it.
            os.kill(process.pid, sig)
            self.signal_syscalls += 1
            self._record(child, 'SIGNAL', signal=int(sig), capability_valid=True)
        except BaseException:
            child.state = 'UNCERTAIN'
            self._record(child, 'SIGNAL_OWNERSHIP_UNCERTAIN')
            raise

    def wait(self, child, timeout=5):
        process = self._require(child, live=False)
        if child.state == 'REAPED':
            return self.result(child)
        deadline = time.monotonic() + timeout
        while self.poll(child) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, timeout)
            time.sleep(min(0.01, remaining))
        return self.result(child)

    def result(self, child):
        self._require(child, live=False)
        return dict(role=child.role, returncode=child.returncode,
                    reaped=child.state == 'REAPED', state=child.state)

    def cleanup(self, child):
        from .supervisor import TransactionPending
        self._require(child, live=False)
        if self.poll(child) is not None:
            return self.result(child)
        if child.control is not None:
            try:
                child.control.request('SHUTDOWN', {})
                self._record(child, 'CLOSED_SHUTDOWN_ACK')
            except (OSError, ProtocolError, TransactionPending):
                self._record(child, 'CLOSED_SHUTDOWN_UNCONFIRMED')
        try:
            return self.wait(child, timeout=1)
        except subprocess.TimeoutExpired:
            self.signal(child, signal.SIGTERM)
        try:
            return self.wait(child, timeout=1)
        except subprocess.TimeoutExpired:
            self.signal(child, signal.SIGKILL)
        return self.wait(child, timeout=5)

    def quiescence(self):
        for child in self._children:
            self.poll(child)
        result = dict(owned_children=len(self._children),
                      peak_operating_processes_including_h=self._peak_owned + 1,
                      all_reaped=all(c.state == 'REAPED' for c in self._children),
                      uncertain=any(c.state == 'UNCERTAIN' for c in self._children),
                      scope='D proof-owned direct children only; host ps unavailable')
        self.observations.append(dict(event='QUIESCENCE', monotonic_ns=time.monotonic_ns(), **result))
        return result


class _JournalService:
    def __init__(self, configuration, channels):
        if set(configuration) != {'root', 'root_identity', 'fault_case'}:
            raise ProtocolError('closed JPS bootstrap')
        self.persistence = JournalPersistence(configuration['root'], configuration['root_identity'],
                                              fault_case=configuration['fault_case'])
        self.channels = channels
        self.objects = {}
        self.persistence_observations = []

    def _observe(self, kind, channel, result):
        if len(self.persistence_observations) >= 16384:
            raise ProtocolError('bounded independent persistence observation queue exhausted')
        name = next(n for n, c in self.channels.items() if c is channel)
        self.persistence_observations.append(dict(sequence=len(self.persistence_observations) + 1,
            kind=kind, peer=channel.peer_role, endpoint=name, monotonic_ns=time.monotonic_ns(),
            bytes=result.get('bytes', result.get('written')), revision=result.get('revision', result.get('frames')),
            sha256=result.get('sha256'), barrier=result.get('barrier')))

    def handle(self, channel, operation, body):
        if operation == 'READ_JOURNAL':
            observed = self.persistence.read()
            self._observe('READBACK', channel, observed)
            return dict(observed, service_instance=self.instance)
        if operation == 'READ_PERSISTENCE_OBSERVATIONS' and channel.peer_role == 'OBSERVER':
            if not 0 <= body['since'] <= len(self.persistence_observations):
                raise ProtocolError('bounded original observation cursor required')
            return dict(instance=self.instance, observations=self.persistence_observations[body['since']:])
        if operation == 'WRITE_FRAME':
            names = [name for name, registered in self.channels.items() if registered is channel]
            if len(names) != 1 or not names[0].startswith('controller-'):
                raise ProtocolError('fixed Controller/JPS peer required')
            slot = int(names[0].split('-')[1])
            permitted = self.channels['w'].request('PERSIST_PERMISSION',
                {'controller_slot': slot, 'frame': body['frame'], 'actor_handle': body['actor_handle']})
            if permitted != {'permitted': True, 'transaction': body['frame']['transaction_id']}:
                raise ProtocolError('exact original W persistence permission required')
            result = self.persistence.write_frame(body['frame'])
            self._observe('BYTES_WRITTEN', channel, result)
            self.channels['w'].request('PERSISTED', {'transaction': body['frame']['transaction_id']})
            return result
        if operation == 'BARRIER':
            frame = body['frame']
            names = [name for name, registered in self.channels.items() if registered is channel]
            if len(names) != 1 or not names[0].startswith('controller-'):
                raise ProtocolError('original captured Controller barrier endpoint required')
            slot = int(names[0].split('-')[1])
            self.channels['w'].request('PERSIST_PERMISSION', {'controller_slot': slot,
                'frame': frame, 'actor_handle': body['actor_handle']})
            observed = self.persistence.read()
            if not observed['records'] or observed['records'][-1] != frame:
                raise ProtocolError('barrier requires the exact written frame')
            result = self.persistence.barrier(frame['revision'])
            self._observe('BARRIER_COMPLETE', channel, result)
            self.channels['w'].request('PERSISTED', {'transaction': frame['transaction_id']})
            return result
        if operation == 'COMPLETE_PERSISTENCE' and channel is self.channels['w']:
            return self.persistence.complete_persistence(body['frame'])
        if operation == 'PUT_OBJECT':
            from .journal_persistence import OBJECT_LIMIT, preserve_file, identity
            names = [name for name, registered in self.channels.items() if registered is channel]
            if len(names) != 1 or not names[0].startswith('controller-'):
                raise ProtocolError('original captured Controller object endpoint required')
            slot = int(names[0].split('-')[1])
            raw = bytes.fromhex(body['bytes_hex'])
            if len(raw) > OBJECT_LIMIT or not body['object_id']:
                raise ProtocolError('bounded immutable application object required')
            permitted = self.channels['w'].request('OBJECT_PERMISSION', dict(controller_slot=slot,
                producer=body['producer'], boundary=body['boundary'], actor_handle=body['actor_handle'],
                object_id=body['object_id'], sha256=hashlib.sha256(raw).hexdigest(), length=len(raw)))
            old = self.objects.get(body['object_id'])
            if old is not None:
                if self._read_object(body['object_id']) != raw:
                    raise ProtocolError('immutable application object collision')
            else:
                self.persistence._check_identity()
                from .journal_persistence import CASE_JOURNAL_LIMIT
                used = sum(p.lstat().st_size for p in self.persistence.root.iterdir()
                           if p.is_file() and not p.is_symlink())
                if used + len(raw) >= CASE_JOURNAL_LIMIT:
                    raise ProtocolError('per-case journal/object artifact limit reached')
                path = self.persistence.root / ('object-' + hashlib.sha256(body['object_id'].encode()).hexdigest())
                preserve_file(path, raw)
                self.objects[body['object_id']] = (path.name, identity(path.lstat()))
            if self._read_object(body['object_id']) != raw:
                raise ProtocolError('independent exact object readback mismatch')
            self.channels['w'].request('OBJECT_PERSISTED', {'lease': permitted['lease']})
            return {'digest': hashlib.sha256(raw).hexdigest()}
        if operation == 'READ_OBJECT':
            return {'bytes_hex': self._read_object(body['object_id']).hex()}
        if operation == 'READ_OBJECTS':
            return {'objects': {key: self._read_object(key).hex() for key in self.objects}}
        if channel.peer_role == 'H':
            if operation == 'FAULT_PREFIX':
                return self.persistence.fault_prefix(body['length'])
            if operation == 'FAULT_ROLLBACK':
                return self.persistence.fault_rewrite(length=body['length'])
            if operation == 'FAULT_CONFLICT':
                return self.persistence.fault_rewrite(frame=body['frame'])
        raise ProtocolError('unsupported closed JPS operation')

    def _read_object(self, object_id):
        from .journal_persistence import identity, _regular, OBJECT_LIMIT
        self.persistence._check_identity()
        if object_id not in self.objects:
            raise ProtocolError('original immutable application object unavailable')
        name, expected = self.objects[object_id]
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.persistence._rootfd)
        try:
            observed = os.fstat(fd)
            _regular(observed)
            if identity(observed) != expected or observed.st_size > OBJECT_LIMIT:
                raise ProtocolError('immutable object identity changed')
            raw = os.pread(fd, observed.st_size + 1, 0)
            if len(raw) != observed.st_size or identity(os.fstat(fd)) != expected:
                raise ProtocolError('immutable object readback changed')
            return raw
        finally:
            os.close(fd)

    def close(self):
        self.persistence.close()


class _ServicePump:
    """Bounded duplex service calls over the existing bootstrap endpoints.

    C/W/JPS callbacks can cross different original endpoints. A call stack
    must service those endpoints without creating threads, children, listeners
    or an unrelated local lock. Nested Harness mutations fail pending; W's C
    lease additionally excludes fencing for the complete accepted C call.
    """
    def __init__(self, channels, service, selector):
        self.channels, self.service, self.selector = channels, service, selector
        self.depth = 0
        self.replies = {}

    def drop(self, channel):
        try:
            self.selector.unregister(channel.fileno())
        except (KeyError, ValueError):
            pass
        channel.close()

    def wait(self, expected):
        from .supervisor import TransactionPending
        if expected in self.replies:
            return self.replies.pop(expected)
        while True:
            active = [c for c in self.channels.values() if not c._closed]
            ready, _, _ = select.select([c.fileno() for c in active], [], [], 5)
            if not ready:
                raise TransactionPending('transport', 'required-service-response', 'UNKNOWN')
            channel = next(c for c in active if c.fileno() == ready[0])
            try:
                message = channel.receive()
            except (OSError, ProtocolError):
                self.drop(channel)
                if channel is expected:
                    raise
                continue
            if message['kind'] == 'RESPONSE':
                if channel is expected:
                    return message
                if channel in self.replies or len(self.replies) >= 8:
                    raise ProtocolError('bounded correlated response queue exhausted')
                self.replies[channel] = message
                continue
            try:
                if channel.peer_role == 'H' or self.depth >= 8:
                    raise TransactionPending('transport', 'occupied-accepted-call', 'UNKNOWN')
                # W nested callbacks may check an existing authority. They
                # cannot recursively start another W application transition.
                if (channel.local_role == 'W' and channel.peer_role == 'CONTROLLER' and
                        message['operation'] not in ('SNAPSHOT', 'QUERY_TRANSACTION',
                            'AUTHENTICATE_ACTOR', 'ACK_CURRENT', 'VERIFY_ENROLLMENT')):
                    raise TransactionPending('transport', 'nested-W-mutation', 'UNKNOWN')
                self.depth += 1
                try:
                    result = self.service.handle(channel, message['operation'], message['body'])
                finally:
                    self.depth -= 1
            except Exception as exc:
                _log_failure()
                try:
                    channel.answer(error=failure_record(exc))
                except (OSError, ProtocolError):
                    self.drop(channel)
            else:
                try:
                    channel.answer(result)
                except (OSError, ProtocolError):
                    self.drop(channel)


def _child_main(role, topology):
    verify_interpreter()
    if role not in ROLES or os.environ.get('D_PROOF_CHILD') != '1':
        raise ProtocolError('proof bootstrap required')
    channels = {}
    for entry in topology:
        if set(entry) != {'name', 'fd', 'peer'} or entry['name'] in channels:
            raise ProtocolError('closed unique bootstrap endpoint')
        sock = socket.socket(fileno=entry['fd'])
        sock.settimeout(5)
        channels[entry['name']] = Channel(sock, role, entry['peer'])
    control = channels['h']
    setup = control.receive()
    if setup['operation'] != 'SETUP':
        raise ProtocolError('setup before service admission')
    configuration = setup['body']['configuration']
    instance = uuid.uuid4().hex
    if role == 'JPS':
        service = _JournalService(configuration, channels)
    elif role == 'W':
        from .supervisor import ProcessWitnessAuthority
        service = ProcessWitnessAuthority(configuration, channels, instance)
    elif role == 'C':
        from .custody import ProcessRetainedHost
        service = ProcessRetainedHost(configuration, channels, instance)
    else:
        from .supervisor import ProcessController
        service = ProcessController(configuration, channels)
    service.instance = instance
    for channel in channels.values():
        channel.handler = service.handle
    control.answer(dict(instance=instance, role=role, interpreter_sha256=PINNED_SHA256))
    delay_operation, delayed = None, None
    selector = selectors.DefaultSelector()
    for name, channel in channels.items():
        # Outgoing-only service paths are consumed synchronously, not by loop.
        if role == 'CONTROLLER' and name in ('jps', 'w', 'c'):
            continue
        selector.register(channel.fileno(), selectors.EVENT_READ, channel)
    pump = _ServicePump(channels, service, selector)
    for channel in channels.values():
        channel.waiter = pump.wait
    try:
        running = True
        while running:
            if role == 'C':
                service.tick()
            ready = selector.select(timeout=0.005 if role == 'C' else 0.5)
            for key, _ in ready[:1]:
                channel = key.data
                try:
                    msg = channel.receive()
                except (ProtocolError, OSError):
                    selector.unregister(key.fd)
                    channel.close()
                    if channel is control:
                        running = False
                    continue
                if msg['kind'] != 'REQUEST':
                    raise ProtocolError('unsolicited response')
                operation, body = msg['operation'], msg['body']
                if channel is control and operation == 'SETUP':
                    channel.answer(error=failure_record(ProtocolError('original bootstrap is sealed; service replacement denied')))
                    continue
                if channel is control and operation == 'DELAY':
                    allowed = {'JPS': ('WRITE_FRAME', 'BARRIER'), 'C': ('RP_INITIATE', 'ORIGINAL_PUBLICATION')}
                    if body['operation'] not in allowed.get(role, ()) or delayed is not None:
                        channel.answer(error='closed bounded delay selection required')
                    else:
                        delay_operation = body['operation']
                        channel.answer({'armed': True})
                    continue
                if channel is control and operation == 'RELEASE':
                    if delayed is None:
                        channel.answer(error='no exact delayed message')
                    else:
                        old_channel, old_operation, old_body = delayed
                        delayed = None
                        try:
                            old_result = service.handle(old_channel, old_operation, old_body)
                        except Exception as exc:
                            denial = type(exc).__name__ + ': ' + str(exc)
                            try:
                                old_channel.answer(error=denial)
                            except (OSError, ProtocolError):
                                pass
                            channel.answer({'released': True, 'denied': True, 'reason': denial})
                        else:
                            try:
                                old_channel.answer(old_result)
                            except (OSError, ProtocolError):
                                pass
                            channel.answer({'released': True, 'denied': False})
                    continue
                if operation == delay_operation and channel.peer_role == 'CONTROLLER':
                    if delayed is not None:
                        channel.answer(error='bounded delay slot occupied')
                    else:
                        delayed = (channel, operation, body)
                        delay_operation = None
                        control.request('DELAYED', {'operation': operation})
                    continue
                if operation == 'SHUTDOWN' and channel is control:
                    channel.answer({'shutdown': True})
                    running = False
                elif operation == 'PING' and channel is control:
                    channel.answer({'instance': instance, 'role': role})
                else:
                    try:
                        result = service.handle(channel, operation, body)
                    except Exception as exc:
                        _log_failure()
                        try:
                            channel.answer(error=failure_record(exc))
                        except (OSError, ProtocolError):
                            pump.drop(channel)
                    else:
                        matches = getattr(service, 'suppress_matches', None)
                        if (matches(operation, body) if matches is not None else
                                getattr(service, 'suppress', None) == operation):
                            service.suppress = None
                            transaction = body.get('transaction', '')
                            if operation in ('RESERVE_FRAME', 'COMMIT_FRAME'):
                                transaction = body['frame']['transaction_id']
                            # F02/F16 drops exactly this reply. The operation
                            # has completed and its original retained fact stays.
                            if channel is control:
                                control.request('DROPPED', {'operation': operation, 'transaction': transaction})
                                from .supervisor import TransactionPending
                                channel.answer(error=failure_record(TransactionPending(
                                    transaction or operation, 'acknowledgement-suppressed', 'UNKNOWN')))
                            else:
                                channel._incoming.pop()
                                control.request('DROPPED', {'operation': operation, 'transaction': transaction})
                        else:
                            try:
                                channel.answer(result)
                            except (OSError, ProtocolError):
                                pump.drop(channel)
    finally:
        selector.close()
        service.close()
        for channel in channels.values():
            channel.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('closed role/topology bootstrap required')
    _child_main(sys.argv[1], json.loads(sys.argv[2]))
