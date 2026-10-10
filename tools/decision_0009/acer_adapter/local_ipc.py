"""Closed Checkpoint D messages on bootstrap-owned anonymous socket pairs.

This is a fixed proof protocol, not a method invocation or object transport.
At most eight nested correlated requests per direction may be outstanding.
Serialized fields are data;
the retained endpoint and its fixed peer binding determine who sent them.
"""

import json
import socket
import struct

MAX_MESSAGE = 16 * 1024 * 1024
MAX_DEPTH = 64
MAX_CALL_DEPTH = 8


class ProtocolError(RuntimeError):
    pass


def failure_record(exc):
    """Closed transport of failure distinctions; never transport capabilities."""
    from .supervisor import TransactionPending, LostAcknowledgement
    result = {'kind': type(exc).__name__, 'message': str(exc)}
    if isinstance(exc, TransactionPending):
        result.update(transaction=exc.transaction_id, stage=exc.stage, status=exc.status)
    if isinstance(exc, LostAcknowledgement):
        from dataclasses import asdict
        result['receipt'] = asdict(exc.receipt)
    from .evidence import PublicationAcknowledgementLost
    if isinstance(exc, PublicationAcknowledgementLost):
        result['receipt'] = exc.receipt
    return result


def raise_failure(record):
    from .supervisor import (AuthorizationDenied, Quarantined, TransactionPending,
                             LostAcknowledgement, AppendReceipt, StoreError)
    if type(record) is not dict or not {'kind', 'message'} <= set(record):
        raise ProtocolError('closed typed service failure required')
    kind = record['kind']
    if kind == 'TransactionPending' and set(record) == {'kind', 'message', 'transaction', 'stage', 'status'}:
        raise TransactionPending(record['transaction'], record['stage'], record['status'])
    if kind == 'LostAcknowledgement' and set(record) == {'kind', 'message', 'receipt'}:
        raise LostAcknowledgement(AppendReceipt(**record['receipt']))
    if kind == 'PublicationAcknowledgementLost' and set(record) == {'kind', 'message', 'receipt'}:
        from .evidence import PublicationAcknowledgementLost
        raise PublicationAcknowledgementLost(record['receipt'])
    if set(record) != {'kind', 'message'}:
        raise ProtocolError('unexpected service failure fields')
    if kind == 'AuthorizationDenied':
        raise AuthorizationDenied(record['message'])
    if kind == 'Quarantined':
        raise Quarantined(record['message'])
    if kind == 'StoreError':
        raise StoreError(record['message'])
    from .evidence import PublicationAuthorityDenied, EvidenceError
    from .custody import CustodyError, ContainmentUnavailable
    from .contracts import ContractError
    from .authorization import OfflineChairAuthenticationError
    from .supervisor import CASMismatch, DuplicateEvent, StaleRead, DispatchUncertain
    from .evidence import AttributionUnavailable
    from .journal_persistence import PersistenceError
    failures = {'PublicationAuthorityDenied': PublicationAuthorityDenied,
                'EvidenceError': EvidenceError, 'CustodyError': CustodyError,
                'ContainmentUnavailable': ContainmentUnavailable, 'ContractError': ContractError,
                'OfflineChairAuthenticationError': OfflineChairAuthenticationError,
                'CASMismatch': CASMismatch, 'DuplicateEvent': DuplicateEvent,
                'StaleRead': StaleRead, 'DispatchUncertain': DispatchUncertain,
                'AttributionUnavailable': AttributionUnavailable, 'PersistenceError': PersistenceError}
    if kind in failures:
        raise failures[kind](record['message'])
    raise ProtocolError(kind + ': ' + record['message'])


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError('duplicate key')
        result[key] = value
    return result


def _shape(value, depth=0):
    if depth > MAX_DEPTH:
        raise ProtocolError('message depth limit')
    if value is None or type(value) in (str, bool, int):
        if type(value) is int and value.bit_length() > 128:
            raise ProtocolError('integer limit')
        return
    if type(value) is list:
        for item in value:
            _shape(item, depth + 1)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for item in value.values():
            _shape(item, depth + 1)
        return
    raise ProtocolError('closed JSON value required')


def canonical(value):
    _shape(value)
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_MESSAGE:
        raise ProtocolError('message size')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError('constant')))
        if type(value) is not dict or canonical(value) != raw:
            raise ProtocolError('canonical object required')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError('invalid canonical message') from exc


def _read_exact(sock, length):
    parts = bytearray()
    while len(parts) < length:
        part = sock.recv(length - len(parts))
        if not part:
            raise ProtocolError('peer closed before complete frame')
        parts.extend(part)
    return bytes(parts)


def read_message(sock):
    length, = struct.unpack('!I', _read_exact(sock, 4))
    if not 0 < length <= MAX_MESSAGE:
        raise ProtocolError('wire message limit')
    return decode(_read_exact(sock, length))


def write_message(sock, value):
    raw = canonical(value)
    if not 0 < len(raw) <= MAX_MESSAGE:
        raise ProtocolError('wire message limit')
    sock.sendall(struct.pack('!I', len(raw)) + raw)


# Exact top-level fields. Each service additionally checks the closed nested
# transaction schema before any mutation. No service resolves a method name.
_JPS = {
    'WRITE_FRAME': {'frame': dict}, 'BARRIER': {'frame': dict},
    'READ_JOURNAL': {}, 'READ_OBJECT': {'object_id': str}, 'READ_OBJECTS': {},
    'PUT_OBJECT': {'object_id': str, 'bytes_hex': str, 'producer': dict, 'boundary': str},
}
_W = {'RECONCILE': {'transaction': str}, 'SNAPSHOT': {}}
_C = {'SNAPSHOT': {}}
_CONTROL = {
    'SETUP': {'configuration': dict}, 'SHUTDOWN': {}, 'PING': {},
}

# Dedicated accepted-kernel ports. Each opcode has a closed carrier; there is
# deliberately no CALL/method/target opcode and no serialized live object.
_KERNEL_W = {
    'ALLOCATE_GENERATION': {'store_identity': str},
    'ACQUIRE_FENCE': {'owner': str},
    'REGISTER_ACTOR': {'producer': dict},
    'CHANGE_MODE': {'producer': dict, 'mode': str, 'boundary': str, 'session': dict},
    'AUTHENTICATE_ACTOR': {'producer': dict, 'boundary': str},
    'FREEZE_ACTOR': {'producer': dict},
    'RESERVE_FRAME': {'frame': dict},
    'COMMIT_FRAME': {'frame': dict},
    'ACK_FRAME': {'transaction': str},
    'QUERY_TRANSACTION': {'transaction': str},
    'ACK_CURRENT': {'producer': dict, 'transaction': str},
    'DENY_CAMPAIGN': {'producer': dict, 'code': str},
    'DENY_FROZEN_CAMPAIGN': {'producer': dict, 'code': str},
    'VERIFY_ENROLLMENT': {'authorization': dict},
    'VERIFY_SERVICE_CONTINUITY': {},
}
_KERNEL_CALLBACKS = {
    'VALIDATE_RP_ENVELOPE': {'frame': dict},
    'VALIDATE_RW_ENVELOPE': {'frame': dict},
    'VALIDATE_ACTOR_REGISTRATION': {'producer': dict, 'store_identity': str,
        'authorization_digest': str, 'campaign_id': str},
    'VALIDATE_ENTRY_ALLOCATION': {'store_identity': str, 'authorization_digest': str, 'campaign_id': str},
    'VALIDATE_ENTRY_FENCE': {'owner': str, 'authorization_digest': str, 'campaign_id': str},
    'VALIDATE_MODE_TRANSITION': {'producer': dict, 'mode': str, 'boundary': str, 'session': dict},
    'VALIDATE_CAPTURED_RESERVATION': {'frame': dict},
    'VALIDATE_CAPTURED_COMMITMENT': {'frame': dict},
    'VALIDATE_CAPTURED_ACKNOWLEDGEMENT': {'transaction': str},
    'VALIDATE_CAPTURED_OBJECT': {'object_id': str, 'sha256': str, 'length': int},
    'VALIDATE_RETAINED_CONFLICT': {'event': dict},
}
ACTOR_W_OPERATIONS = frozenset(('CHANGE_MODE', 'AUTHENTICATE_ACTOR', 'FREEZE_ACTOR',
    'RESERVE_FRAME', 'COMMIT_FRAME', 'ACK_FRAME', 'ACK_CURRENT', 'DENY_CAMPAIGN'))
for _opcode in ACTOR_W_OPERATIONS:
    _KERNEL_W[_opcode]['actor_handle'] = str
SCHEMAS = {
    ('CONTROLLER', 'JPS'): _JPS,
    ('W', 'JPS'): dict({k: _JPS[k] for k in ('READ_JOURNAL', 'READ_OBJECT')},
                     COMPLETE_PERSISTENCE={'frame': dict}),
    ('OBSERVER', 'JPS'): {'READ_JOURNAL': {}, 'READ_PERSISTENCE_OBSERVATIONS': {'since': int}},
    ('CONTROLLER', 'W'): _W,
    ('C', 'W'): {'SNAPSHOT': {}},
    ('JPS', 'W'): {'PERSIST_PERMISSION': {'controller_slot': int, 'frame': dict},
                   'PERSISTED': {'transaction': str},
                   'OBJECT_PERMISSION': {'controller_slot': int, 'producer': dict, 'boundary': str}},
    ('OBSERVER', 'W'): {'SNAPSHOT': {}},
    ('CONTROLLER', 'C'): _C,
    ('OBSERVER', 'C'): {'SNAPSHOT': {}},
    ('W', 'C'): {'CONTINUITY': {'challenge': str},
                 'CONFIRMS_PUBLICATION_CONFLICT': {'intended': dict},
                 'CONFIRMS_CUSTODY_LOSS': {'record': dict}},
    ('H', 'JPS'): dict(_CONTROL, FAULT_PREFIX={'length': int},
                       FAULT_ROLLBACK={'length': int}, FAULT_CONFLICT={'frame': dict},
                       DELAY={'operation': str}, RELEASE={}),
    ('H', 'W'): dict(_CONTROL, FENCE={'channel': int},
                     SUPPRESS={'operation': str}, QUARANTINE={}),
    ('H', 'C'): dict(_CONTROL, FORGET={'facts': list}, SUPPRESS={'operation': str},
                    ARM_STAGE={'stage': str}, ARM_DESTINATION_FAULT={'fault': str},
                    DELAY={'operation': str}, RELEASE={}),
    ('H', 'CONTROLLER'): dict(_CONTROL, RUN={'action': str, 'cut': str}),
    ('CONTROLLER', 'H'): {'STAGE': {'stage': str, 'transaction': str}},
    ('W', 'H'): {'DROPPED': {'operation': str, 'transaction': str}},
    ('C', 'H'): {'DROPPED': {'operation': str, 'transaction': str},
                 'DELAYED': {'operation': str}, 'C_STAGE': {'stage': str, 'operation_id': str}},
    ('JPS', 'H'): {'DELAYED': {'operation': str}},
}
SCHEMAS[('CONTROLLER', 'W')].update(_KERNEL_W)
SCHEMAS[('W', 'CONTROLLER')] = _KERNEL_CALLBACKS
SCHEMAS[('CONTROLLER', 'C')].update({
    'BIND_SOURCE': {'intent': dict},
    'ORIGINAL_PUBLICATION': {'grant_handle': str, 'planned': dict, 'payload_hex': str, 'payload_present': bool},
    'SOURCE': {'original_ref': dict, 'object_key': str},
    'RP_PRECONDITION': {'subject': dict, 'operation': str},
    'RP_EXCLUDE': {'subject': dict}, 'RP_OBSERVE': {'subject': dict},
    'RP_ARM': {'grant_handle': str},
    'RP_INITIATE': {'grant_handle': str, 'fault': str},
    'RP_REGISTER_SUPPLEMENT': {'subject': dict, 'intent_ref': dict},
    'AUTHENTICATE_RECEIPT': {'raw_hex': str}, 'OBSERVATION_REASON': {'raw_hex': str},
    'PUBLICATION_RESULT': {'effect_id': str},
    'VALIDATE_PUBLICATION_RESULT': {'effect_id': str, 'raw_hex': str, 'verifier_id': str},
    'EFFECT_PORT_RECEIPT': {'effect_id': str},
    'VALIDATE_EFFECT_PORT_RECEIPT': {'effect_id': str, 'raw_hex': str, 'verifier_id': str},
    'PORT_OBSERVATION': {'receipt_hex': str},
    'CONFIRMS_PUBLICATION_CONFLICT': {'intended': dict},
    'CONFIRMS_CUSTODY_LOSS': {'record': dict},
    'BOOT_CUSTODY_ATTESTATION': {'attestation_id': str},
})
SCHEMAS[('C', 'CONTROLLER')] = {
    'VALIDATE_CURRENT_ACTOR': {'producer': dict, 'boundary': str},
    'VALIDATE_HEALTH': {}, 'READ_ACCEPTED_FRAMES': {},
    'VALIDATE_ORIGINAL_INITIATION': {'grant_handle': str, 'planned': dict},
    'VALIDATE_ORIGINAL_SOURCE_BINDING': {'intent': dict},
    'VALIDATE_RP_INITIATION': {'grant_handle': str},
    'VALIDATE_RP_SUBJECT': {'subject': dict, 'operation': str},
    'READ_ACCEPTED_OBJECT': {'object_id': str, 'sha256': str},
    'PUT_ACCEPTED_OBJECT': {'object_id': str, 'bytes_hex': str},
    'PUBLICATION_PROVENANCED': {'event_id': str, 'phase': str},
    'FRAME_PROVENANCED': {'event_id': str},
    'WINDOW_PROVENANCED': {'event_id': str},
    'VALIDATE_RP_BINDING': {}, 'ACK_ACCEPTED_TRANSACTION': {'transaction': str},
}
SCHEMAS[('C', 'W')].update({
    'BEGIN_C_OPERATION': {'controller_slot': int, 'boundary': str, 'actor_handle': str},
    'END_C_OPERATION': {'lease': str},
})
ACTOR_C_OPERATIONS = frozenset(('BIND_SOURCE', 'ORIGINAL_PUBLICATION', 'RP_PRECONDITION',
    'RP_EXCLUDE', 'RP_OBSERVE', 'RP_ARM', 'RP_INITIATE', 'RP_REGISTER_SUPPLEMENT'))
for _opcode in ACTOR_C_OPERATIONS:
    SCHEMAS[('CONTROLLER', 'C')][_opcode]['actor_handle'] = str
for _opcode in ('WRITE_FRAME', 'BARRIER', 'PUT_OBJECT'):
    SCHEMAS[('CONTROLLER', 'JPS')][_opcode]['actor_handle'] = str
SCHEMAS[('JPS', 'W')]['PERSIST_PERMISSION']['actor_handle'] = str
SCHEMAS[('JPS', 'W')]['OBJECT_PERMISSION'].update(
    actor_handle=str, object_id=str, sha256=str, length=int)
SCHEMAS[('JPS', 'W')]['OBJECT_PERSISTED'] = {'lease': str}
SCHEMAS[('W', 'C')]['REVOKE_CONTROLLER'] = {'controller_slot': int}


def validate_request(sender, receiver, operation, body):
    spec = SCHEMAS.get((sender, receiver), {}).get(operation)
    if spec is None or type(body) is not dict or set(body) != set(spec):
        raise ProtocolError('operation or fields outside fixed peer protocol')
    if any(type(body[k]) is not t for k, t in spec.items()):
        raise ProtocolError('closed request field type')
    _shape(body)


class Channel:
    """Private runtime endpoint: copying its data cannot mint a peer channel."""

    def __init__(self, sock, local_role, peer_role):
        if (type(sock) is not socket.socket or sock.family != socket.AF_UNIX or
                sock.type != socket.SOCK_STREAM or sock.getsockname() not in ('', b'') or
                sock.getpeername() not in ('', b'') or
                not ((local_role, peer_role) in SCHEMAS or (peer_role, local_role) in SCHEMAS)):
            raise ProtocolError('bootstrap anonymous Unix stream endpoint required')
        self._socket = sock
        self.local_role, self.peer_role = local_role, peer_role
        self._sequence = self._received = 0
        self._pending = []
        self._incoming = []
        self.handler = None
        self.waiter = None
        self._closed = False

    def __reduce__(self):
        raise TypeError('live channel cannot be serialized')

    def __copy__(self):
        raise TypeError('live channel cannot be copied')

    def fileno(self):
        return self._socket.fileno()

    def begin(self, operation, body):
        validate_request(self.local_role, self.peer_role, operation, body)
        if self._closed or len(self._pending) >= MAX_CALL_DEPTH:
            raise ProtocolError('closed channel or bounded request slot occupied')
        self._sequence += 1
        self._pending.append(self._sequence)
        write_message(self._socket, dict(version=1, sender=self.local_role,
            receiver=self.peer_role, kind='REQUEST', id=self._sequence,
            operation=operation, body=body))

    def receive(self):
        msg = read_message(self._socket)
        if (set(msg) != {'version', 'sender', 'receiver', 'kind', 'id', 'operation', 'body'} or
                type(msg['version']) is not int or msg['version'] != 1 or
                msg['sender'] != self.peer_role or msg['receiver'] != self.local_role or
                type(msg['id']) is not int or msg['id'] < 1):
            raise ProtocolError('fixed peer and closed frame required')
        if msg['kind'] == 'REQUEST':
            validate_request(self.peer_role, self.local_role, msg['operation'], msg['body'])
            if msg['id'] <= self._received or len(self._incoming) >= MAX_CALL_DEPTH:
                raise ProtocolError('replayed request or bounded receive slot occupied')
            self._received = msg['id']
            self._incoming.append((msg['id'], msg['operation']))
        elif msg['kind'] == 'RESPONSE':
            if (not self._pending or msg['id'] != self._pending[-1] or msg['operation'] != 'REPLY' or
                    type(msg['body']) is not dict or
                    set(msg['body']) != {'ok', 'result', 'error'} or
                    type(msg['body']['ok']) is not bool or
                    type(msg['body']['result']) is not dict or
                    type(msg['body']['error']) not in (str, dict, type(None))):
                raise ProtocolError('exact response correlation required')
            self._pending.pop()
        else:
            raise ProtocolError('closed message kind required')
        return msg

    def answer(self, result=None, *, error=None):
        if not self._incoming:
            raise ProtocolError('no captured request to answer')
        identifier, _ = self._incoming[-1]
        write_message(self._socket, dict(version=1, sender=self.local_role,
            receiver=self.peer_role, kind='RESPONSE', id=identifier, operation='REPLY',
            body=dict(ok=error is None, result={} if result is None else result, error=error)))
        self._incoming.pop()

    def request(self, operation, body):
        self.begin(operation, body)
        while True:
            msg = self.receive() if self.waiter is None else self.waiter(self)
            if msg['kind'] == 'RESPONSE':
                break
            if self.handler is None:
                raise ProtocolError('unexpected request during synchronous service transaction')
            # The handler is local bootstrap code for closed protocol operations.
            # No method name, callable or target object arrives on the wire.
            try:
                result = self.handler(self, msg['operation'], msg['body'])
            except Exception as exc:
                self.answer(error=failure_record(exc))
            else:
                self.answer(result)
        if not msg['body']['ok']:
            if type(msg['body']['error']) is dict:
                raise_failure(msg['body']['error'])
            raise ProtocolError(msg['body']['error'])
        return msg['body']['result']

    def close(self):
        self._closed = True
        self._socket.close()
