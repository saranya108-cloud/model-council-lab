"""V2-2A deterministic simulated operations, with no filesystem implementation.

Case names and steps are internal test plans, not platform contracts. No step
performs the named operation: each consumes exactly one supplied result. Real
setup/acquisition, platform schemas and independent oracles remain unavailable.
"""
from dataclasses import dataclass
from types import MappingProxyType

from tools.decision_0009.retention_v2.qualification import SimulatedObservations


# Every supported synthetic experiment has an explicit source-to-case mapping.
CASES = MappingProxyType({
    'exclusive_creation': ('r2 §§13–14; Amendment 1a §3', ('create', 'exclusive_check')),
    'allocation': ('r2 §13; Amendment 1a §§3–4', ('create', 'allocate', 'size', 'zero')),
    'resource_limit': ('r2 §13', ('set_limit', 'read_limit', 'acquire_descriptor', 'bounded_write')),
    'descriptor_exclusion': ('r2 §14; Amendment 1a §3', ('self_descriptors', 'acquire_descriptor', 'exclude_inheritance', 'close')),
    'synchronization': ('r2 §15; Amendment 1a §6', ('bounded_write', 'sync', 'readback', 'close')),
    'short_write_stop': ('r2 §15; Amendment 1a §8', ('bounded_write', 'sync', 'readback')),
})


@dataclass(frozen=True, slots=True)
class ExecutionScope:
    case: str
    synthetic: bool = True


@dataclass(frozen=True, slots=True)
class EffectResult:
    status: str
    original_status: int | None


class SimulatedEffectBackend:
    """Finite script with an ordered call trace; never invokes a callback."""
    def __init__(self, results):
        if type(results) is not tuple or len(results) > 8:
            raise ValueError('bounded immutable result script required')
        if any(type(v) is not EffectResult or v.status not in ('ok', 'short', 'error', 'uncertain')
               or (v.original_status is not None and type(v.original_status) is not int)
               for v in results):
            raise ValueError('invalid simulated effect result')
        self.results = results
        self.calls = []

    def take(self, operation):
        index = len(self.calls)
        self.calls.append(operation)
        return self.results[index] if index < len(self.results) else EffectResult('uncertain', None)


@dataclass(frozen=True, slots=True)
class DisposableTrace:
    source: str
    entries: tuple[tuple[str, EffectResult], ...]
    stopped: bool
    synthetic: bool = True


def observation_backend(responses):
    return SimulatedObservations(responses)


def exercise_disposable_case(case, backend, execution_scope):
    """Replay a finite synthetic plan; stop on first non-ok original result.

    Missing scope, a reused backend, or an unknown case blocks all invocation.
    No suffix completion, reassignment, replacement, retry or cleanup exists.
    """
    if (type(case) is not str or case not in CASES
            or type(backend) is not SimulatedEffectBackend
            or type(execution_scope) is not ExecutionScope
            or execution_scope.case != case or execution_scope.synthetic is not True
            or backend.calls):
        raise ValueError('fresh simulated backend and exact model scope required')
    source, operations = CASES[case]
    entries = []
    for operation in operations:
        result = backend.take(operation)
        entries.append((operation, result))
        if result.status != 'ok':
            return DisposableTrace(source, tuple(entries), True)
    return DisposableTrace(source, tuple(entries), False)
