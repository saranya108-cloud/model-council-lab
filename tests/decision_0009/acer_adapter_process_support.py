"""Bounded foreground Harness. No fixture cleanup deletes retained artifacts."""

from dataclasses import asdict, replace
import copy
import hashlib
import json
import os
import signal
import socket
import time
import uuid

from tools.decision_0009.acer_adapter.contracts import (
    DestinationRule, ObjectRule, SupplementRule, authorization_digest,
)
from tools.decision_0009.acer_adapter.journal_persistence import (
    ARTIFACT_ROOT, create_directory, identity, preserve_file,
)
from tools.decision_0009.acer_adapter.local_ipc import Channel, ProtocolError, canonical
from tools.decision_0009.acer_adapter.process_services import ProcessOwner, OwnershipError
from decision_0009.acer_adapter_fakes import u04_authorization, MutableArtifacts
from tools.decision_0009.acer_adapter.supervisor import _process_data, TransactionPending

CASE_OBSERVATIONS = []


class ProofWorld:
    """Owns four direct children, fixed peer topology and read-only Observer."""

    def __init__(self, label, *, fault_case=False):
        self.case_id = label + '-' + uuid.uuid4().hex
        self.fault_case = fault_case
        self.evidence = ARTIFACT_ROOT / 'evidence/development' / self.case_id
        self.journal = ARTIFACT_ROOT / ('faults' if fault_case else 'journal') / self.case_id
        self.witness_root = ARTIFACT_ROOT / 'witness' / self.case_id
        for root in (self.evidence, self.journal, self.witness_root):
            create_directory(root)
        self.owner = ProcessOwner(self.evidence)
        self._channels = {}
        # One original and three bounded successive Controller lifetimes;
        # F12 needs a replacement after interrupting reconciliation itself.
        self._topology = {r: [] for r in ('JPS', 'W', 'C', 'CONTROLLER-0', 'CONTROLLER-1', 'CONTROLLER-2', 'CONTROLLER-3')}
        self._ends = {r: [] for r in self._topology}
        self._sockets = []
        self.children = {}
        self.instances = {}
        self.controller_slot = 0
        self.quiescent = False
        self.faults = []
        self._closed = False
        self._observation_sequence = 0
        self._persistence_sequence = self._persistence_capture = 0
        self._source = b'Checkpoint D original independently retained simulated evidence.\n'
        auth = u04_authorization()
        auth = replace(auth, destination_rules=(DestinationRule('d-rule', 'd-destination',
            'd-port', 'evidence', 'OBJECT_AND_NAMESPACE', 'ALL_LOWER_WRITERS'),),
            object_rules=(ObjectRule('d-object-rule', auth.campaign_id, 'FAILURE_EVIDENCE',
                                    'd-destination', 'evidence/proof'),),
            supplement_rules=(SupplementRule('d-supplement-rule', 'd-destination', 'evidence',
                ('FAILURE_EVIDENCE',), ('PUBLICATION_READBACK',), 'RECOVERY_SUPPLEMENT_V1'),))
        auth = replace(auth, authorization_digest=authorization_digest(auth))
        self.authorization = json.loads(json.dumps(asdict(auth)))
        self.store_identity = 'd-store-' + self.case_id[-32:]
        self.subject = dict(subject_id=auth.campaign_id, source_id='normalizer-1',
            source_digest=hashlib.sha256(self._source).hexdigest(), source_length=len(self._source),
            destination_id='d-destination', object_key='evidence/proof')
        self._wire('JPS', 'w', 'W', 'jps')
        self._wire('C', 'w', 'W', 'c')
        for slot in range(4):
            controller = 'CONTROLLER-%d' % slot
            for role in ('JPS', 'W', 'C'):
                self._wire(controller, role.lower(), role, 'controller-%d' % slot)
            self._h_wire(controller)
        for role in ('JPS', 'W', 'C'):
            self._h_wire(role)
            self._observer_wire(role)
        self._controller_configuration = dict(store_identity=self.store_identity,
            authorization=self.authorization, subject=self.subject, replacement=False,
            artifacts=_process_data(MutableArtifacts().read()), source_hex=self._source.hex())
        try:
            rootfd = os.open(self.journal, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                root_identity = list(identity(os.fstat(rootfd)))
            finally:
                os.close(rootfd)
            self._launch('JPS', dict(root=str(self.journal), root_identity=root_identity, fault_case=fault_case))
            self._launch('C', dict(store_identity=self.store_identity, authorization=self.authorization,
                subject=self.subject, source_hex=self._source.hex()))
            self._launch('W', dict(store_identity=self.store_identity, authorization=self.authorization,
                subject=self.subject, jps_instance=self.instances['JPS'], c_instance=self.instances['C'],
                witness_root=str(self.witness_root)))
            self._launch('CONTROLLER-0', self._controller_configuration)
            preserve_file(self.evidence / 'bootstrap.json', canonical(dict(
                authorization=self.authorization, store_identity=self.store_identity,
                subject=self.subject, original_instances=self.instances,
                root_identity=root_identity, channel_roles={name: [dict(name=c['name'], peer=c['peer'])
                    for c in entries] for name, entries in self._topology.items()})))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _role(name):
        return 'CONTROLLER' if name.startswith('CONTROLLER-') else name

    def _pair(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        a.settimeout(30)
        b.settimeout(30)
        self._sockets.extend((a, b))
        return a, b

    def _wire(self, left, left_name, right, right_name):
        a, b = self._pair()
        self._topology[left].append(dict(name=left_name, fd=a.fileno(), peer=self._role(right)))
        self._topology[right].append(dict(name=right_name, fd=b.fileno(), peer=self._role(left)))
        self._ends[left].append(a)
        self._ends[right].append(b)

    def _h_wire(self, role):
        a, b = self._pair()
        self._channels[role] = Channel(a, 'H', self._role(role))
        self._topology[role].append(dict(name='h', fd=b.fileno(), peer='H'))
        self._ends[role].append(b)

    def _observer_wire(self, role):
        a, b = self._pair()
        self._channels['observer-' + role] = Channel(a, 'OBSERVER', role)
        self._topology[role].append(dict(name='observer', fd=b.fileno(), peer='OBSERVER'))
        self._ends[role].append(b)

    def _launch(self, name, configuration):
        child = self.owner.launch(self._role(name), self._topology[name], self._ends[name])
        self.children[name] = child
        control = self._channels[name]
        self.owner.set_control(child, control)
        admitted = control.request('SETUP', {'configuration': configuration})
        if admitted['role'] != self._role(name):
            raise AssertionError('bootstrap role substitution')
        self.instances[name] = admitted['instance']

    @property
    def controller(self):
        return self.children['CONTROLLER-%d' % self.controller_slot]

    @property
    def control(self):
        return self._channels['CONTROLLER-%d' % self.controller_slot]

    def command(self, action, *, cut=''):
        if self.owner.poll(self.controller) is not None:
            raise OwnershipError('Controller has actually exited/reaped')
        return self.control.request('RUN', {'action': action, 'cut': cut})

    def crash_at(self, stage, *, action='continue'):
        self.control.begin('RUN', {'action': action, 'cut': stage})
        msg = self.control.receive()
        if stage == 'partial_frame':
            if not self.fault_case or msg.get('operation') != 'STAGE' or msg['body']['stage'] != 'partial_frame_prepare':
                raise AssertionError('partial writes require the exact accepted reservation and fault-case journal')
            self._channels['JPS'].request('FAULT_PREFIX', {'length': 7})
            self.faults.append({'fault': 'F07', 'prefix': 7, 'target': str(self.journal / 'journal.frames')})
            self.control.answer({'observed': True})
            msg = self.control.receive()
        if msg['kind'] != 'REQUEST' or msg['operation'] != 'STAGE' or msg['body']['stage'] != stage:
            raise AssertionError('required real loss cut point not independently reached: ' + repr(msg))
        self.faults.append(dict(fault='F01', stage=stage, transaction=msg['body']['transaction']))
        self.owner.signal(self.controller, signal.SIGKILL)
        result = self.owner.wait(self.controller)
        # Never resume this Controller stack, invoke crash(), or copy its objects.
        self.control.close()
        return dict(result, cut=stage, transaction=msg['body']['transaction'])

    def _replacement(self):
        if self.owner.poll(self.controller) is None:
            raise OwnershipError('original Controller must actually exit and be reaped first')
        for role in ('W', 'JPS', 'C'):
            if self.owner.poll(self.children[role]) is not None:
                raise OwnershipError('positive recovery requires original surviving ' + role)
        deadline = time.monotonic() + 5
        while True:
            try:
                self._channels['W'].request('FENCE', {'channel': self.controller_slot})
                break
            except TransactionPending:
                if time.monotonic() >= deadline:
                    raise OwnershipError('original cross-process exclusion unresolved')
                time.sleep(0.01)
        self.controller_slot += 1
        if self.controller_slot > 3:
            raise OwnershipError('closed four-lifetime Controller bootstrap capacity exhausted')
        self._launch('CONTROLLER-%d' % self.controller_slot,
                     dict(self._controller_configuration, replacement=True))

    def recover(self, *, cut=''):
        self._replacement()
        return self.command('recover', cut=cut)

    def terminate_controller(self):
        self.faults.append({'fault': 'F01', 'stage': 'accepted-original-history-complete'})
        self.owner.signal(self.controller, signal.SIGKILL)
        result = self.owner.wait(self.controller)
        self.control.close()
        return result

    def recover_and_crash(self, stage):
        self._replacement()
        self.faults.append({'fault': 'F12', 'stage': stage})
        return self.crash_at(stage, action='recover')

    def response_loss(self, role, operation, *, action='continue'):
        if role not in ('W', 'C'):
            raise AssertionError('closed response-loss service')
        control = self._channels[role]
        control.request('SUPPRESS', {'operation': operation})
        self.control.begin('RUN', {'action': action, 'cut': ''})
        dropped = control.receive()
        if (dropped['kind'] != 'REQUEST' or dropped['operation'] != 'DROPPED' or
                dropped['body']['operation'] != operation):
            raise AssertionError('identified response loss not independently observed')
        self.owner.signal(self.controller, signal.SIGKILL)
        result = self.owner.wait(self.controller)
        self.control.close()
        control.answer({'observed': True})
        self.faults.append(dict(fault='F16' if role == 'W' else 'F02',
            role=role, operation=operation, transaction=dropped['body']['transaction'],
            underlying_fact_preserved=True))
        return result

    def delay_then_crash(self, role, operation):
        if role not in ('C', 'JPS'):
            raise AssertionError('closed delayed service')
        control = self._channels[role]
        control.request('DELAY', {'operation': operation})
        self.control.begin('RUN', {'action': 'continue', 'cut': ''})
        delayed = control.receive()
        if delayed['operation'] != 'DELAYED' or delayed['body']['operation'] != operation:
            raise AssertionError('exact original peer message was not delayed')
        self.owner.signal(self.controller, signal.SIGKILL)
        result = self.owner.wait(self.controller)
        self.control.close()
        control.answer({'observed': True})
        self.faults.append(dict(fault='F03', role=role, operation=operation,
                               provenance='retained original channel and original message'))
        return result

    def crash_at_c(self, stage):
        control = self._channels['C']
        control.request('ARM_STAGE', {'stage': stage})
        self.control.begin('RUN', {'action': 'continue', 'cut': ''})
        msg = control.receive()
        if msg['operation'] != 'C_STAGE' or msg['body']['stage'] != stage:
            raise AssertionError('original accepted C cut not observed')
        observed = self._channels['observer-C'].request('SNAPSHOT', {})
        self.c_cut_observation = observed
        preserve_file(self.evidence / ('c-cut-' + stage + '.json'), canonical(observed))
        self.owner.signal(self.controller, signal.SIGKILL)
        result = self.owner.wait(self.controller)
        self.control.close()
        control.answer({'observed': True})
        self.faults.append(dict(fault='F01', stage=stage, operation_id=msg['body']['operation_id']))
        return result

    def release(self, role):
        return self._channels[role].request('RELEASE', {})

    def kill_service(self, role):
        if role not in ('W', 'C', 'JPS'):
            raise AssertionError('closed original-service loss role')
        self.owner.signal(self.children[role], signal.SIGKILL)
        result = self.owner.wait(self.children[role])
        self.faults.append(dict(fault={'W': 'F04', 'C': 'F05', 'JPS': 'F06'}[role], result=result))
        return result

    def forget(self, facts):
        result = self._channels['C'].request('FORGET', {'facts': facts})
        self.faults.append(dict(fault='F13' if facts == ['result_observation'] else 'F14',
                               removed_facts=list(facts), retained='claims/counts/results/source'))
        return result

    def destination_ack_loss(self, fault):
        result = self._channels['C'].request('ARM_DESTINATION_FAULT', {'fault': fault})
        self.faults.append(dict(fault='F02', service='original-C', cut=fault,
                               underlying_operation='accepted OfflinePublicationDestination.initiate_recovery'))
        return result

    def quarantine(self):
        self.faults.append({'fault': 'F17', 'condition': 'quarantine'})
        return self._channels['W'].request('QUARANTINE', {})

    def corrupt(self, fault):
        if not self.fault_case:
            raise AssertionError('only enumerated fault-case journal may be mutated')
        observed = self._channels['observer-JPS'].request('READ_JOURNAL', {})
        if fault == 'F08':
            length = observed['boundaries'][-2]
            result = self._channels['JPS'].request('FAULT_ROLLBACK', {'length': length})
        elif fault == 'F09':
            frame = dict(observed['records'][-1], predecessor_hash='f' * 64)
            result = self._channels['JPS'].request('FAULT_CONFLICT', {'frame': frame})
        else:
            raise AssertionError('closed F08/F09 variant')
        self.faults.append(dict(fault=fault, target=str(self.journal / 'journal.frames'), **result))
        return result

    def observe(self):
        jps = self._channels['observer-JPS'].request('READ_JOURNAL', {})
        w = self._channels['observer-W'].request('SNAPSHOT', {})
        c = self._channels['observer-C'].request('SNAPSHOT', {})
        # A read-only cross-check of original C counts against actual accepted
        # logical operation identities. Absence is never converted to zero.
        counts = c['registries']['counts']
        logical_counts = {}
        for frame in jps['records']:
            event = frame['payload']
            if event.get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED' and event['grant_id'] in counts:
                key = event['logical_operation_id']
                logical_counts[key] = logical_counts.get(key, 0) + counts[event['grant_id']]
        if any(n > 1 for n in logical_counts.values()):
            raise AssertionError('independent original C observations show duplicate logical initiation')
        continuity = {}
        for role, observation in (('JPS', jps), ('W', w), ('C', c)):
            if self.owner.poll(self.children[role]) is not None:
                raise OwnershipError('original service exited: ' + role)
            actual = observation.get('instance', observation.get('service_instance'))
            if actual != self.instances[role]:
                raise AssertionError('original private-channel service lifetime mismatch')
            continuity[role] = actual
        result = dict(jps=jps, w=w, c=c, continuity=continuity)
        self._observation_sequence += 1
        preserve_file(self.evidence / ('observation-%04d.json' % self._observation_sequence), canonical(result))
        self._observe_persistence()
        return result

    def _observe_persistence(self):
        if self.owner.poll(self.children['JPS']) is not None:
            return
        audit = self._channels['observer-JPS'].request('READ_PERSISTENCE_OBSERVATIONS',
            {'since': self._persistence_sequence})
        if audit['instance'] != self.instances['JPS']:
            raise OwnershipError('original JPS observation endpoint continuity unproven')
        for event in audit['observations']:
            self._persistence_sequence += 1
            if event['sequence'] != self._persistence_sequence:
                raise AssertionError('independent persistence observation gap')
        self._persistence_capture += 1
        preserve_file(self.evidence / ('persistence-%04d.json' % self._persistence_capture), canonical(audit))

    def suppress_fence_ack(self):
        control = self._channels['W']
        def observed(channel, operation, body):
            if operation != 'DROPPED' or body['operation'] != 'FENCE':
                raise AssertionError('exact original W fencing acknowledgement required')
            observation = self._channels['observer-W'].request('SNAPSHOT', {})
            preserve_file(self.evidence / 'fence-ack-lost.json', canonical(observation))
            self.faults.append(dict(fault='F16', operation='FENCE', fact='independently retained frontier/revocation'))
            return {'observed': True}
        control.handler = observed
        control.request('SUPPRESS', {'operation': 'FENCE'})

    def reject_impostors(self):
        before = self.owner.signal_syscalls
        rejected = 0
        try:
            self.owner.signal(self.controller._process.pid, signal.SIGKILL)
        except OwnershipError:
            rejected += 1
        # A structurally copied wrapper has no membership in the owner registry.
        from tools.decision_0009.acer_adapter.process_services import _OwnedChild
        impostor = object.__new__(_OwnedChild)
        for field in _OwnedChild.__slots__:
            setattr(impostor, field, getattr(self.controller, field))
        try:
            self.owner.signal(impostor, signal.SIGKILL)
        except OwnershipError:
            rejected += 1
        self.owner.cleanup(self.controller)
        try:
            self.owner.signal(self.controller, signal.SIGKILL)
        except OwnershipError:
            rejected += 1
        self.faults.append(dict(fault='F11', rejected=rejected,
                               signal_syscalls=self.owner.signal_syscalls - before))
        return {'rejected': rejected, 'signal_syscalls': self.owner.signal_syscalls - before}

    def close(self):
        if self._closed:
            return
        self._closed = True
        errors = []
        names = [n for n in self.children if n.startswith('CONTROLLER-')]
        names += [r for r in ('C', 'W', 'JPS') if r in self.children]
        for name in names:
            try:
                if name == 'JPS':
                    self._observe_persistence()
                self.owner.cleanup(self.children[name])
            except BaseException as exc:
                errors.append(type(exc).__name__ + ': ' + str(exc))
        self.faults.append(dict(fault='F15', operation='bounded-owned-child-cleanup', errors=list(errors)))
        quiescence = self.owner.quiescence()
        self.quiescent = quiescence['all_reaped'] and not quiescence['uncertain'] and not errors
        for channel in self._channels.values():
            channel.close()
        for sock in self._sockets:
            sock.close()
        report = dict(case_id=self.case_id, faults=copy.deepcopy(self.faults), independent_observations=self._observation_sequence,
            persistence_observations=self._persistence_sequence,
            processes=copy.deepcopy(self.owner.observations), quiescence=copy.deepcopy(quiescence), cleanup_errors=list(errors),
            original_instances=copy.deepcopy(self.instances), artifact_roots=dict(journal=str(self.journal),
            witness=str(self.witness_root), evidence=str(self.evidence)),
            limit='trusted host, simulated workload/custody/destination; no host process-table proof')
        preserve_file(self.evidence / 'process-observations.json', canonical(report))
        CASE_OBSERVATIONS.append(report)
        if errors:
            raise OwnershipError('owned-child cleanup incomplete: ' + repr(errors))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
