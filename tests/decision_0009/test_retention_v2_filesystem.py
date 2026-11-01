"""V2-2A model-only tests. Platform scenarios below are inert declarations.

Literal expectations derive from r2 §§2, 9, 13–15 and Amendment 1a
§§3–8, 13, not from verifier internals or production-generated oracles.
"""
from dataclasses import FrozenInstanceError, replace
from copy import deepcopy
import ast
import inspect
import json
import unittest

from tools.decision_0009.retention_v2 import qualification as q
import retention_v2_filesystem_support as support


# Required levels are independent literals from the accepted plan §D2.
COMMON = {
    'exclusive_creation': (2, 5), 'exact_size': (2, 5),
    'allocation': (2, 5), 'zero_state': (2, 5),
    'synchronization': (2, 4, 5), 'descriptor_exclusion': (2, 4, 5),
    'writer_closure': (4, 5), 'identity_parent': (5,),
    'custody_interval': (5,),
    'short_write_stop': (2, 4),
}
F_LEVELS = dict(COMMON, resource_limit=(2, 4), write_bounds=(1, 4),
                short_write_stop=(2, 4))
Q_LEVELS = dict(COMMON, parent_protection=(5,), parent_persistence=(5,),
                root_transition=(5,), capture_ranges=(1, 4),
                freeze_no_retry=(1, 4), retention_read_closure=(5,))


def context(subject='F'):
    return q.TrustedContext(subject, 'object-1', 'parent-1', 'interval-1',
                            'authority-1', 'authority-1', q.MODEL_CONTRACT)


def raw(criterion='exact_size', level=2, subject='F', holds=True, **changes):
    value = dict(criterion=criterion, subject=subject, binding='object-1',
                 parent='parent-1', interval='interval-1', authority='authority-1',
                 modeled_level=level, holds=holds)
    value.update(changes)
    return json.dumps(value, separators=(',', ':')).encode()


def observations(subject='F'):
    levels = F_LEVELS if subject == 'F' else Q_LEVELS
    return tuple(q.parse_observation(raw(name, level, subject), q.MODEL_CONTRACT)
                 for name, required in levels.items() for level in required)


# No runnable platform test classes or discovery hooks.
PROSPECTIVE_PLATFORM_CASES = (
    ('exclusive_creation', 'r2 §§13–14; Amendment 1a §3'),
    ('allocation', 'r2 §13; Amendment 1a §§3–4'),
    ('resource_limit', 'r2 §13'),
    ('descriptor_exclusion', 'r2 §14; Amendment 1a §3'),
    ('synchronization', 'r2 §15; Amendment 1a §6'),
    ('short_write_stop', 'r2 §15; Amendment 1a §8'),
)


class OfflineQualificationTests(unittest.TestCase):
    def evaluate(self, obs=None, ctx=None, inventory=()):
        return q.evaluate_qualification('F', observations() if obs is None else obs,
                                        context() if ctx is None else ctx, inventory)

    def test_criteria_match_adopted_literals(self):
        for subject, size, levels in [('F', 16777216, F_LEVELS), ('Q', 3145728, Q_LEVELS)]:
            criteria = q.qualification_criteria(subject)
            self.assertEqual(criteria.size, size)
            self.assertEqual(criteria.support_limits, (128, 65536, 4194304))
            self.assertEqual({c.name: c.levels for c in criteria.clauses}, levels)
            self.assertTrue(all(c.source for c in criteria.clauses))
            with self.assertRaises(FrozenInstanceError):
                criteria.size = 1
        self.assertEqual(q.qualification_criteria('Q').revalidation_points,
                         ('creation_binding', 'every_open', 'root_transition',
                          'f_retention_read', 'final_sealing'))
        with self.assertRaises(ValueError):
            q.qualification_criteria('unknown')

    def test_complete_synthetic_evidence(self):
        for subject in ('F', 'Q'):
            result = q.evaluate_qualification(subject, observations(subject), context(subject), ())
            self.assertTrue(result.model_satisfied)
            self.assertFalse(result.qualified)
            self.assertEqual(result.evidence_level, 1)
            self.assertTrue(result.synthetic)
            self.assertIn('operational acquisition contracts unavailable', result.unsupported)
            self.assertFalse(result.violations)

    def test_proven_violation(self):
        bad = q.parse_observation(raw(holds=False), q.MODEL_CONTRACT)
        result = self.evaluate((bad,))
        self.assertIn('exact_size@2', result.violations)
        self.assertFalse(result.model_satisfied)
        self.assertTrue(result.missing)

    def test_malformed_observation(self):
        for data in [None, '', b'\xff', b'{}', b'[]', b'{',
                     raw(extra=True), raw(modeled_level=True), raw(modeled_level=6),
                     raw(holds=1), raw(binding=''), raw(criterion='unknown'),
                     raw(subject='X'), b'{"subject":"F","subject":"Q"}',
                     raw(binding='\ud800'), b'x' * 65537]:
            with self.subTest(data=repr(data)[:70]):
                result = q.parse_observation(data, q.MODEL_CONTRACT)
                self.assertIsNone(result.observation)
                self.assertTrue(result.diagnostics)
        self.assertFalse(self.evaluate((q.parse_observation(b'{}', q.MODEL_CONTRACT),)).model_satisfied)

    def test_missing_contract_or_evidence(self):
        for contract in (None, 'host-json', replace(q.MODEL_CONTRACT, identity='other')):
            result = q.parse_observation(raw(), contract)
            self.assertTrue(result.unsupported)
            self.assertIsNone(result.observation)
        for changes in ({'contract': None}, {'binding': ''}, {'parent': ''}, {'interval': ''}):
            self.assertFalse(self.evaluate(ctx=replace(context(), **changes)).model_satisfied)
        self.assertFalse(self.evaluate(()).model_satisfied)
        self.assertFalse(self.evaluate(observations()[:-1]).model_satisfied)

    def test_conflicting_evidence(self):
        for changes in ({'holds': False}, {'binding': 'other'}, {'parent': 'other'},
                        {'interval': 'other'}, {'subject': 'Q'}):
            result = self.evaluate(observations() + (q.parse_observation(raw(**changes), q.MODEL_CONTRACT),))
            self.assertFalse(result.model_satisfied)
            self.assertTrue(result.diagnostics)

    def test_authority_currentness_and_binding(self):
        for changes in ({'authority': ''}, {'current_authority': 'old'}, {'subject': 'Q'}):
            self.assertFalse(self.evaluate(ctx=replace(context(), **changes)).model_satisfied)
        self.assertFalse(self.evaluate((q.parse_observation(raw(authorized=True), q.MODEL_CONTRACT),)).model_satisfied)
        stale = q.parse_observation(raw(authority='old'), q.MODEL_CONTRACT)
        self.assertFalse(self.evaluate(observations() + (stale,)).model_satisfied)
        self.assertFalse(self.evaluate(ctx=None).qualified)

    def test_evidence_levels_do_not_promote(self):
        low = tuple(q.parse_observation(raw(name, 1), q.MODEL_CONTRACT) for name in F_LEVELS)
        self.assertFalse(self.evaluate(low).model_satisfied)
        generic = tuple(o for o in observations() if o.observation.modeled_level == 2)
        self.assertFalse(self.evaluate(generic).model_satisfied)
        result = self.evaluate()
        self.assertTrue(result.model_satisfied)
        self.assertEqual(result.evidence_level, 1)
        self.assertFalse(result.qualified)

    def test_exact_size_ranges_and_zero_state(self):
        for subject, size in [('F', 16777216), ('Q', 3145728)]:
            image = bytes(size)
            self.assertFalse(q.inspect_layout(subject, image, initial=True))
            for data in (image[:-1], image + b'\0'):
                self.assertIn('size', q.inspect_layout(subject, data, initial=True))
            self.assertIn('initial_zero', q.inspect_layout(subject, b'\1' + image[1:], initial=True))
        image = bytearray(3145728)
        for offset in (110592, 524288, 2883584, 3145727):
            image[offset] = 1
            self.assertIn('reserved_zero', q.inspect_layout('Q', bytes(image)))
            image[offset] = 0
        self.assertFalse(q.inspect_layout('Q', bytes(image), ranges=((131072, 131073),)))
        for ranges in [((110592, 110593),), ((524288, 524289),), ((2883584, 2883585),),
                       ((131072, 131074), (131073, 131075)), ((-1, 0),), ((3145727, 3145729),),
                       ((131072, 163841),), ((2807808, 2807809),), ((102400, 102401),)]:
            self.assertTrue(q.inspect_layout('Q', bytes(image), ranges=ranges))
        self.assertTrue(q.inspect_layout('F', bytes(16777216), ranges=((12582912, 12582913),)))

    def test_support_capacity_boundaries(self):
        # Independent wrapper count, per-object, aggregate and repeated references.
        self.assertFalse(q.support_diagnostics(tuple(q.SupportObject(i.to_bytes(2, 'big')) for i in range(128))))
        self.assertIn('support_count', q.support_diagnostics(tuple(q.SupportObject(i.to_bytes(2, 'big')) for i in range(129))))
        self.assertFalse(q.support_diagnostics((q.SupportObject(bytes(65536)),)))
        self.assertIn('support_object_size', q.support_diagnostics((q.SupportObject(bytes(65537)),)))
        at = tuple(q.SupportObject(bytes([i]) * 65536) for i in range(64))
        self.assertFalse(q.support_diagnostics(at))
        self.assertIn('support_aggregate', q.support_diagnostics(at + (q.SupportObject(b'x'),)))
        one = q.SupportObject(b'x')
        self.assertFalse(q.support_diagnostics((one,) * 129))
        self.assertTrue(q.support_diagnostics((65536,)))
        self.assertFalse(self.evaluate(inventory=(q.SupportObject(bytes(65537)),)).model_satisfied)

    def test_bytes_do_not_prove_sync_or_closure(self):
        for omitted in ('synchronization', 'writer_closure', 'custody_interval'):
            filtered = tuple(o for o in observations() if o.observation.criterion != omitted)
            self.assertFalse(self.evaluate(filtered).model_satisfied)
        self.assertFalse(q.inspect_layout('F', bytes(16777216), initial=True))
        self.assertFalse(self.evaluate(()).qualified)

    def test_short_error_uncertain_no_retry(self):
        for status in ('short', 'error', 'uncertain'):
            backend = support.SimulatedEffectBackend((support.EffectResult('ok', 0),
                                                      support.EffectResult(status, 17),
                                                      support.EffectResult('ok', 0)))
            trace = support.exercise_disposable_case('allocation', backend, support.ExecutionScope('allocation'))
            self.assertTrue(trace.stopped)
            self.assertEqual(len(trace.entries), 2)
            self.assertEqual(trace.entries[-1][1], support.EffectResult(status, 17))
            self.assertEqual(backend.calls, ['create', 'allocate'])

    def test_observation_scope_is_explicit(self):
        request = q.ObservationRequest('F', ('exact_size',))
        backend = support.observation_backend((('F', 'exact_size', raw()),))
        self.assertEqual(q.observe_subject(request, backend)[0].observation.criterion, 'exact_size')
        for req, back in ((None, backend), (request, None),
                          (q.ObservationRequest('F', ()), backend),
                          (q.ObservationRequest('F', ('discover',)), backend),
                          (q.ObservationRequest('/tmp/F', ('exact_size',)), backend)):
            with self.assertRaises(ValueError):
                q.observe_subject(req, back)
        self.assertTrue(q.observe_subject(q.ObservationRequest('Q', ('exact_size',)), backend)[0].diagnostics)

    def test_disposable_trace_uses_fake_backend_only(self):
        for case, source in PROSPECTIVE_PLATFORM_CASES:
            backend = support.SimulatedEffectBackend(tuple(support.EffectResult('ok', 0) for _ in range(8)))
            trace = support.exercise_disposable_case(case, backend, support.ExecutionScope(case))
            self.assertFalse(trace.stopped)
            self.assertTrue(trace.synthetic)
            self.assertEqual(trace.source, source)
        backend = support.SimulatedEffectBackend(())
        for scope in (None, support.ExecutionScope('other'), support.ExecutionScope('allocation', False)):
            with self.assertRaises(ValueError):
                support.exercise_disposable_case('allocation', backend, scope)
        self.assertEqual(backend.calls, [])
        with self.assertRaises(ValueError):
            support.exercise_disposable_case('allocation', object(), support.ExecutionScope('allocation'))
        trace = support.exercise_disposable_case('allocation', backend, support.ExecutionScope('allocation'))
        self.assertTrue(trace.stopped)
        self.assertEqual(len(trace.entries), 1)

    def test_import_discovery_and_reporting_have_no_effects(self):
        # Inspect exact module source, without executing a subprocess or reloading.
        for module in (q, support):
            tree = ast.parse(inspect.getsource(module))
            imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
            names = [node.module if isinstance(node, ast.ImportFrom) else node.names[0].name for node in imports]
            self.assertFalse(set(names) & {'os', 'subprocess', 'socket', 'resource', 'pathlib', 'shutil'})
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
            self.assertFalse({node.func.id for node in calls} & {'open', 'exec', 'eval', '__import__'})
        self.assertFalse(self.evaluate().qualified)
        self.assertIsInstance(PROSPECTIVE_PLATFORM_CASES, tuple)

    def test_inputs_and_oracles_remain_independent(self):
        obs = observations()
        before = repr(obs)
        inventory = [q.SupportObject(b'a'), q.SupportObject(b'a')]
        original_references = tuple(inventory)
        self.evaluate(obs, inventory=inventory)
        self.assertEqual(repr(obs), before)
        self.assertEqual(inventory, list(original_references))
        self.assertTrue(all(current is original for current, original in zip(inventory, original_references)))
        self.assertEqual(q.qualification_criteria('F').size, 16777216)
        with self.assertRaises(ValueError):
            q.evaluate_qualification('F', (), None, ())

    def test_forged_parsed_facts_cannot_replace_exact_bytes(self):
        parsed = q.parse_observation(raw(holds=False), q.MODEL_CONTRACT)
        forged = replace(parsed, observation=replace(parsed.observation, holds=True))
        result = self.evaluate(observations() + (forged,))
        self.assertFalse(result.model_satisfied)
        self.assertTrue(result.diagnostics)

    def test_scope_and_script_cannot_expand_or_replay(self):
        request = q.ObservationRequest('F', ('exact_size',))
        for responses in ((('F', 'exact_size', raw()),) * 2,
                          (('F', 'exact_size', 'not bytes'),)):
            with self.assertRaises(ValueError):
                q.observe_subject(request, support.observation_backend(responses))
        mismatch = support.observation_backend((('F', 'exact_size', raw('allocation')),))
        self.assertIsNone(q.observe_subject(request, mismatch)[0].observation)
        backend = support.SimulatedEffectBackend((support.EffectResult('error', 73),))
        scope = support.ExecutionScope('allocation')
        trace = support.exercise_disposable_case('allocation', backend, scope)
        self.assertEqual(trace.entries, (('create', support.EffectResult('error', 73)),))
        with self.assertRaises(ValueError):
            support.exercise_disposable_case('allocation', backend, scope)
        self.assertEqual(backend.calls, ['create'])


    def test_non_required_level_violations_remain_visible(self):
        for subject, criterion, required in (
                ('F', 'exclusive_creation', (2, 5)),
                ('Q', 'parent_protection', (5,))):
            complete = observations(subject)
            self.assertTrue(q.evaluate_qualification(subject, complete, context(subject), ()).model_satisfied)
            for level in range(1, 6):
                if level in required:
                    continue
                with self.subTest(subject=subject, level=level):
                    failed = q.parse_observation(raw(criterion, level, subject, holds=False), q.MODEL_CONTRACT)
                    self.assertIsNotNone(failed.observation)
                    result = q.evaluate_qualification(subject, complete + (failed,), context(subject), ())
                    self.assertEqual(result.violations, (criterion + '@' + str(level),))
                    self.assertFalse(result.model_satisfied)
                    self.assertEqual(result.missing, ())
                    self.assertEqual(result.evidence_level, 1)
                    self.assertFalse(result.qualified)

    def test_non_required_levels_never_fill_positive_evidence_gaps(self):
        for subject, criterion, required, level in (
                ('F', 'exclusive_creation', (2, 5), 4),
                ('Q', 'parent_protection', (5,), 1)):
            incomplete = tuple(o for o in observations(subject) if o.observation.criterion != criterion)
            expected_missing = tuple(criterion + '@' + str(n) for n in required)
            for holds in (True, False):
                with self.subTest(subject=subject, holds=holds):
                    extra = q.parse_observation(raw(criterion, level, subject, holds=holds), q.MODEL_CONTRACT)
                    result = q.evaluate_qualification(subject, incomplete + (extra,), context(subject), ())
                    self.assertEqual(result.missing, expected_missing)
                    self.assertEqual(result.violations, () if holds else (criterion + '@' + str(level),))
                    self.assertFalse(result.model_satisfied)
                    self.assertEqual(result.evidence_level, 1)
                    self.assertFalse(result.qualified)

    def test_non_required_level_conflicts_remain_blocking(self):
        for subject, criterion, level in (('F', 'exclusive_creation', 4), ('Q', 'parent_protection', 1)):
            reports = []
            for order in ((True, False), (False, True)):
                conflicting = tuple(q.parse_observation(raw(criterion, level, subject, holds=holds),
                                    q.MODEL_CONTRACT) for holds in order)
                result = q.evaluate_qualification(subject, observations(subject) + conflicting, context(subject), ())
                label = criterion + '@' + str(level)
                self.assertEqual(result.violations, (label,))
                self.assertIn('conflicting facts: ' + label, result.diagnostics)
                self.assertFalse(result.model_satisfied)
                self.assertEqual(result.missing, ())
                reports.append(result)
            self.assertEqual(reports[0], reports[1])

    def test_support_same_object_references_count_once(self):
        one = q.SupportObject(bytes(65536))
        with self.assertRaises(FrozenInstanceError):
            one.data = b''
        inventory = (one,) * 129
        self.assertEqual(len(inventory), 129)
        self.assertTrue(all(value is one for value in inventory))
        self.assertEqual(q.support_diagnostics(inventory), ())
        self.assertTrue(self.evaluate(inventory=inventory).model_satisfied)

    def test_support_distinct_equal_objects_exceed_count(self):
        shared = b'support-object'
        inventory = tuple(q.SupportObject(shared) for _ in range(129))
        self.assertTrue(all(value.data is shared for value in inventory))
        self.assertTrue(all(value is not earlier for index, value in enumerate(inventory)
                            for earlier in inventory[:index]))
        self.assertEqual(q.support_diagnostics(inventory), ('support_count',))
        result = self.evaluate(inventory=inventory)
        self.assertFalse(result.model_satisfied)
        self.assertIn('support_count', result.diagnostics)

    def test_support_distinct_equal_aggregate_boundary(self):
        shared = bytes(65536)
        inventory = tuple(q.SupportObject(shared) for _ in range(65))
        self.assertTrue(all(value.data is shared for value in inventory))
        self.assertTrue(all(value is not earlier for index, value in enumerate(inventory)
                            for earlier in inventory[:index]))
        self.assertEqual(sum(len(value.data) for value in inventory[:64]), 4194304)
        self.assertEqual(q.support_diagnostics(inventory[:64]), ())
        self.assertEqual(sum(len(value.data) for value in inventory), 4259840)
        self.assertEqual(q.support_diagnostics(inventory), ('support_aggregate',))
        result = self.evaluate(inventory=inventory)
        self.assertFalse(result.model_satisfied)
        self.assertIn('support_aggregate', result.diagnostics)


    def test_support_payload_reuse_forms_do_not_change_object_counting(self):
        src = b'shared-support-payload'
        forms = (
            ('bytes', lambda: bytes(src)),
            ('deepcopy', lambda: deepcopy(src)),
            ('empty', lambda: b''),
            ('one_byte', lambda: bytes((7,))),
            ('equal_literal', lambda: b'equal-literal'),
        )
        for name, produce in forms:
            with self.subTest(form=name):
                inventory = tuple(q.SupportObject(produce()) for _ in range(129))
                self.assertTrue(all(value.data == inventory[0].data for value in inventory))
                self.assertTrue(all(value is not earlier for index, value in enumerate(inventory)
                                    for earlier in inventory[:index]))
                self.assertEqual(q.support_diagnostics(inventory), ('support_count',))
                self.assertEqual(q.support_diagnostics((inventory[0],) * 129), ())

    def test_support_same_wrapper_pair_differs_from_two_wrappers(self):
        shared = b'same-data'
        first, second = q.SupportObject(shared), q.SupportObject(shared)
        self.assertIsNot(first, second)
        self.assertIs(first.data, second.data)
        self.assertNotEqual(first, second)
        others = tuple(q.SupportObject(b'') for _ in range(127))
        # The same-wrapper pair contributes one object: 1 + 127 = 128.
        self.assertEqual(q.support_diagnostics((first, first) + others), ())
        # Distinct wrappers contribute two objects: 2 + 127 = 129.
        self.assertEqual(q.support_diagnostics((first, second) + others), ('support_count',))

    def test_support_raw_or_nonexact_model_inputs_fail_closed(self):
        class DerivedSupportObject(q.SupportObject):
            pass
        for inventory in (
                (b'',), (b'raw',), [b'raw'], (q.SupportObject(b'ok'), b'raw'),
                (DerivedSupportObject(b'data'),), (q.SupportObject(None),),
                (q.SupportObject('text'),), (q.SupportObject(bytearray(b'data')),),
                (object.__new__(q.SupportObject),)):
            self.assertEqual(q.support_diagnostics(inventory), ('invalid_support_inventory',))
            result = self.evaluate(inventory=inventory)
            self.assertFalse(result.model_satisfied)
            self.assertIn('invalid_support_inventory', result.diagnostics)
            self.assertFalse(result.qualified)
