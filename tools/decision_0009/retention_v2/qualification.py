"""Decision 0009 V2-2A: in-memory qualification preparation only.

Criteria cite r2 and final Amendment 1a; the accepted plan §D2 supplies
required evidence levels. Python data classes below are internal diagnostics,
NOT adopted wire formats, authority records, or the closed F/Q verifier result.

No platform interpretation/acquisition contract is implemented. The sole
parser contract is explicitly synthetic. Even complete synthetic predicates
produce only level-1 model evidence and never operational qualification.
TrustedContext is externally selected context, not authentication machinery.
No backend callback, host path, or live acquisition is accepted here.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from . import spec


@dataclass(frozen=True, slots=True)
class Criterion:
    name: str
    source: str
    levels: tuple[int, ...]
    requirement: str


@dataclass(frozen=True, slots=True)
class Criteria:
    subject: str
    size: int
    clauses: tuple[Criterion, ...]
    support_limits: tuple[int, int, int]
    revalidation_points: tuple[str, ...]


_COMMON = (
    Criterion('exclusive_creation', 'r2 §§13–14; Amendment 1a §3', (2, 5),
              'Exclusive creation at the externally bound identity; ambiguity stops, no replacement.'),
    Criterion('exact_size', 'r2 §§2, 13; Amendment 1a §3', (2, 5),
              'Exact fixed size, regular file, link count one; no post-activation resizing.'),
    Criterion('allocation', 'r2 §13; Amendment 1a §§3–4', (2, 5),
              'Creation-only allocation; preallocation does not guarantee future persistence.'),
    Criterion('zero_state', 'r2 §§2–3, 15; Amendment 1a §§4, 6', (2, 5),
              'Validate full target zero state and permanently unused regions, never borrow space.'),
    Criterion('synchronization', 'r2 §15; Amendment 1a §6', (2, 4, 5),
              'Original successful synchronization and exact readback; bytes alone are insufficient.'),
    Criterion('descriptor_exclusion', 'r2 §14; Amendment 1a §3', (2, 4, 5),
              'One writer; bounded self-inspection, no descriptor transfer/inheritance, mmap or async writes.'),
    Criterion('writer_closure', 'r2 §14; Amendment 1a §§3, 7', (4, 5),
              'Descriptor closure, writer termination and external custody evidence; no byte inference.'),
    Criterion('identity_parent', 'r2 §14; Amendment 1a §3', (5,),
              'Same bound device/inode/FILEID, link count, size and parent relationship.'),
    Criterion('custody_interval', 'r2 §14; Amendment 1a §3', (5,),
              'Full custody checks bracket setup, writes, security transitions and final closure.'),
    Criterion('short_write_stop', 'r2 §15; Amendment 1a §§6–8', (2, 4),
              'Short/error/uncertain write stops; no suffix fill, replacement or retry.'),
)
_F = (
    Criterion('resource_limit', 'r2 §13', (2, 4),
              'Read back soft = hard = 16777216 before writable capability; no alternate write path.'),
    Criterion('write_bounds', 'r2 §§2–3, 13–15', (1, 4),
              'Checked ranges, fixed regions, historical immutability and independent semantic budgets.'),
)
_Q = (
    Criterion('parent_protection', 'Amendment 1a §3', (5,),
              'Existing parent outside P/I/O; ancestors/ACL/flags prevent non-root entry replacement.'),
    Criterion('parent_persistence', 'Amendment 1a §3', (5,),
              'Preservation across reboot and ordinary cleanup; current boot alone is insufficient.'),
    Criterion('root_transition', 'Amendment 1a §3', (5,),
              'Same operator-created object transitions to root custody under separate authority.'),
    Criterion('capture_ranges', 'Amendment 1a §§4–6', (1, 4),
              'Fixed immutable capture extents, 128 cells/108 assigned, no unassigned use or reassignment.'),
    Criterion('freeze_no_retry', 'Amendment 1a §§6–8', (1, 4),
              'Permanent whole-Q freeze on uncertainty; independent stopping authority stays separate.'),
    Criterion('retention_read_closure', 'Amendment 1a §§3, 7, 12', (5,),
              'Q closed to writing for F retention/comparison; completeness and closure remain distinct.'),
)


def qualification_criteria(subject_kind: str) -> Criteria:
    """Return immutable clause-linked criteria, never a qualification decision."""
    if subject_kind not in ('F', 'Q'):
        raise ValueError('subject must be F or Q')
    return Criteria(subject_kind, spec.F_SIZE if subject_kind == 'F' else spec.Q_SIZE,
                    _COMMON + (_F if subject_kind == 'F' else _Q),
                    (spec.SUPPORT_OBJECTS_MAX, spec.SUPPORT_OBJECT_BYTES_MAX,
                     spec.SUPPORT_AGGREGATE_BYTES_MAX),
                    ('creation_binding', 'every_open', 'root_transition',
                     'f_retention_read', 'final_sealing') if subject_kind == 'Q' else
                    ('creation_allocation', 'writable_phase', 'security_transition', 'final_closure'))


@dataclass(frozen=True, slots=True)
class SyntheticContract:
    """Internal model vocabulary only; no platform schema or acquisition authority."""
    identity: str = 'v2-2a-internal-synthetic-only'


MODEL_CONTRACT = SyntheticContract()


@dataclass(frozen=True, slots=True)
class Observation:
    criterion: str
    subject: str
    binding: str
    parent: str
    interval: str
    authority: str
    modeled_level: int
    holds: bool


@dataclass(frozen=True, slots=True)
class ParsedObservation:
    raw: bytes | None
    observation: Observation | None
    diagnostics: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()


def _model_contract(contract):
    return type(contract) is SyntheticContract and contract == MODEL_CONTRACT


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def parse_observation(raw_bytes, contract) -> ParsedObservation:
    """Parse supplied synthetic bytes strictly, retaining the exact response.

    This grammar is an internal test transport, not a platform interpretation.
    A missing/different contract is unsupported, regardless of valid JSON.
    """
    raw = raw_bytes if type(raw_bytes) is bytes else None
    if not _model_contract(contract):
        return ParsedObservation(raw, None, ('no applicable interpretation contract',),
                                 ('normative schema/acquisition contract unavailable',))
    if raw is None or len(raw) > spec.SUPPORT_OBJECT_BYTES_MAX:
        return ParsedObservation(raw, None, ('expected bounded exact bytes',))
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
        fields = ('criterion', 'subject', 'binding', 'parent', 'interval', 'authority',
                  'modeled_level', 'holds')
        if type(value) is not dict or set(value) != set(fields):
            raise ValueError('closed internal observation fields required')
        for field in fields[:6]:
            item = value[field]
            if type(item) is not str or not item or len(item) > 256:
                raise ValueError('invalid string: ' + field)
            item.encode('utf-8')  # Reject escaped surrogates, too.
            if any(ord(char) < 32 for char in item):
                raise ValueError('control character: ' + field)
        criteria = qualification_criteria(value['subject'])
        if value['criterion'] not in {c.name for c in criteria.clauses}:
            raise ValueError('unknown criterion')
        if type(value['modeled_level']) is not int or not 1 <= value['modeled_level'] <= 5:
            raise ValueError('invalid modeled level')
        if type(value['holds']) is not bool:
            raise ValueError('holds must be boolean')
        return ParsedObservation(raw, Observation(**value))
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return ParsedObservation(raw, None, ('malformed synthetic observation',))


@dataclass(frozen=True, slots=True)
class TrustedContext:
    subject: str
    binding: str
    parent: str
    interval: str
    authority: str
    current_authority: str
    contract: SyntheticContract | None


@dataclass(frozen=True, slots=True)
class QualificationReport:
    model_satisfied: bool
    violations: tuple[str, ...]
    missing: tuple[str, ...]
    diagnostics: tuple[str, ...]
    unsupported: tuple[str, ...]
    # Not constructor inputs: synthetic reports cannot request promotion.
    @property
    def qualified(self):
        return False

    @property
    def synthetic(self):
        return True

    @property
    def evidence_level(self):
        return 1


@dataclass(frozen=True, slots=True, eq=False)
class SupportObject:
    """One internal modeled object; payload equality never establishes identity.

    This wrapper is not a wire schema, operational identifier or authority.
    """
    data: bytes


def support_diagnostics(inventory) -> tuple[str, ...]:
    """r2 §9: count each explicitly modeled support object once; no path reads.

    Repeated wrapper references count once. Distinct wrappers remain distinct
    even when they share the very same immutable payload. Raw bytes are not
    interpreted as object references. The caller supplies the complete inventory;
    no operational support inventory or reservation authority is created here.
    """
    if (type(inventory) not in (tuple, list)
            or any(type(v) is not SupportObject or type(getattr(v, 'data', None)) is not bytes
                   for v in inventory)):
        return ('invalid_support_inventory',)
    # eq=False retains object equality/hash: only wrapper identity is a key.
    unique = set(inventory)
    diagnostics = []
    if len(unique) > spec.SUPPORT_OBJECTS_MAX:
        diagnostics.append('support_count')
    if any(len(v.data) > spec.SUPPORT_OBJECT_BYTES_MAX for v in unique):
        diagnostics.append('support_object_size')
    if sum(len(v.data) for v in unique) > spec.SUPPORT_AGGREGATE_BYTES_MAX:
        diagnostics.append('support_aggregate')
    return tuple(diagnostics)


def evaluate_qualification(subject, observations, trusted_context, support_inventory) -> QualificationReport:
    """Conjunctive synthetic evaluation; no operational positive path exists.

    Binding/currentness are comparisons to externally supplied context. No
    response can authorize itself. Conflicting or inadmissible responses block
    the model result; an admissible violation remains visible alongside gaps.
    """
    criteria = qualification_criteria(subject)
    if type(trusted_context) is not TrustedContext:
        raise ValueError('explicit trusted context required')
    ctx = trusted_context
    diagnostics = list(support_diagnostics(support_inventory))
    if (ctx.subject != subject or not all(type(v) is str and v for v in
            (ctx.binding, ctx.parent, ctx.interval, ctx.authority, ctx.current_authority))
            or ctx.authority != ctx.current_authority):
        diagnostics.append('missing/stale/mismatched trusted binding or authority')
    if not _model_contract(ctx.contract):
        diagnostics.append('unsupported context contract')
    if type(observations) not in (tuple, list):
        raise ValueError('bounded supplied observations required')
    facts = {}
    # 17 clauses * 5 levels fits beneath the existing independent support count.
    if len(observations) > spec.SUPPORT_OBJECTS_MAX:
        diagnostics.append('observation count exceeds support ceiling')
    else:
        for supplied in observations:
            if type(supplied) is not ParsedObservation or type(supplied.raw) is not bytes:
                diagnostics.append('invalid parsed observation')
                continue
            # Reparse exact bytes under the selected context; reject forged
            # dataclasses and do not trust a caller-filled parsed fact.
            parsed = parse_observation(supplied.raw, ctx.contract)
            if parsed != supplied or parsed.observation is None:
                diagnostics.append('malformed, unsupported or inconsistent observation')
                continue
            obs = parsed.observation
            if (obs.subject, obs.binding, obs.parent, obs.interval, obs.authority) != (
                    subject, ctx.binding, ctx.parent, ctx.interval, ctx.authority):
                diagnostics.append('observation binding/currentness conflict')
                continue
            key = (obs.criterion, obs.modeled_level)
            facts.setdefault(key, set()).add(obs.holds)
    violations, missing = [], []
    for criterion in criteria.clauses:
        # Admissible negative evidence blocks at every modeled level; required
        # levels still exclusively govern affirmative evidence and missing facts.
        for level in range(1, 6):
            key = (criterion.name, level)
            label = criterion.name + '@' + str(level)
            values = facts.get(key, set())
            if False in values:
                violations.append(label)
            if len(values) > 1:
                diagnostics.append('conflicting facts: ' + label)
        for level in criterion.levels:
            if not facts.get((criterion.name, level), set()):
                missing.append(criterion.name + '@' + str(level))
    return QualificationReport(not (violations or missing or diagnostics), tuple(violations),
                               tuple(missing), tuple(diagnostics),
                               ('operational acquisition contracts unavailable',))


def inspect_layout(subject, image, *, initial=False, ranges=()) -> tuple[str, ...]:
    """Check supplied in-memory size, zero state and nonoverlapping ranges.

    Ranges are proposed synthetic target bounds, not write permission. Q bounds
    must fit one assigned receipt cell or one fixed payload extent. This is not
    another F/Q verifier; identity, history, checksums, lifecycle and authority
    are intentionally not inferred from these byte checks.
    """
    criteria = qualification_criteria(subject)
    if type(image) is not bytes or len(image) != criteria.size:
        return ('size',)
    diagnostics = []
    if initial and any(image):
        diagnostics.append('initial_zero')
    zero_regions = ((spec.F_REGION_BY_NAME['headroom'],) if subject == 'F' else spec.Q_ZERO_REGIONS)
    if any(any(image[r.start:r.end]) for r in zero_regions):
        diagnostics.append('reserved_zero')
    allowed = (tuple((r.start, r.end) for r in spec.F_REGIONS if r.name != 'headroom')
               if subject == 'F' else
               tuple((n * spec.Q_CELL_SIZE, (n + 1) * spec.Q_CELL_SIZE)
                     for n in range(spec.Q_ASSIGNED_COUNT)
                     if n not in spec.Q_UNDISPATCHED) +
               tuple((c.offset, c.offset + c.capacity) for c in spec.Q_CAPTURES
                     if c.number not in spec.Q_UNDISPATCHED))
    if type(ranges) not in (tuple, list):
        return tuple(diagnostics) + ('ranges',)
    seen = []
    for interval in ranges:
        if (type(interval) is not tuple or len(interval) != 2
                or any(type(v) is not int for v in interval)):
            diagnostics.append('range_shape')
            continue
        start, end = interval
        if not (0 <= start < end <= criteria.size) or not any(a <= start < end <= b for a, b in allowed):
            diagnostics.append('range_bounds')
        if any(start < b and a < end for a, b in seen):
            diagnostics.append('range_overlap')
        if 0 <= start < end <= criteria.size and any(image[start:end]):
            diagnostics.append('target_nonzero')
        seen.append(interval)
    return tuple(diagnostics)


@dataclass(frozen=True, slots=True)
class ObservationRequest:
    subject: str
    criteria: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SimulatedObservations:
    """Inert response table. No callbacks or host backend implementation seam."""
    responses: tuple[tuple[str, str, bytes], ...]


def observe_subject(request, backend) -> tuple[ParsedObservation, ...]:
    """Replay exactly scoped supplied responses once, with no discovery/retry.

    Deliberately accepts only this inert concrete backend data type. A future
    live backend would require new authority and code; duck-typed callables,
    simulation flags and ambient/default backends cannot execute here.
    """
    if type(request) is not ObservationRequest or type(backend) is not SimulatedObservations:
        raise ValueError('explicit request and inert simulated backend required')
    names = {c.name for c in qualification_criteria(request.subject).clauses}
    if (type(request.criteria) is not tuple or not request.criteria
            or any(type(v) is not str or v not in names for v in request.criteria)
            or len(set(request.criteria)) != len(request.criteria)):
        raise ValueError('explicit unique bounded criteria required')
    if type(backend.responses) is not tuple or len(backend.responses) > spec.SUPPORT_OBJECTS_MAX:
        raise ValueError('bounded response table required')
    table = {}
    for row in backend.responses:
        if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str
                or type(row[1]) is not str or type(row[2]) is not bytes):
            raise ValueError('malformed response table')
        key = row[:2]
        if key in table:
            raise ValueError('duplicate simulated response')
        table[key] = row[2]
    results = []
    for name in request.criteria:
        raw = table.get((request.subject, name))
        parsed = parse_observation(raw, MODEL_CONTRACT)
        if parsed.observation is not None and (parsed.observation.subject != request.subject
                                               or parsed.observation.criterion != name):
            parsed = ParsedObservation(raw, None, ('response outside requested scope',))
        results.append(parsed)
    return tuple(results)
