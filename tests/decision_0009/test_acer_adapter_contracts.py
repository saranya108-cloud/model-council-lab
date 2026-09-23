import dataclasses
import unittest

from tools.decision_0009.acer_adapter.contracts import (
    ATTEMPT_STATES, BOOT_STATES, CAMPAIGN_STATES, LOCAL_EVIDENCE_STATES,
    PUBLICATION_STATES, SAFETY_MARKERS, ContractError, ProcessIdentity,
    parse_state,
)
from acer_adapter_fakes import authorization, identity, matrix


class ContractTests(unittest.TestCase):
    def test_closed_revision_4_vocabulary_rejects_removed_and_unknown_names(self):
        self.assertEqual(parse_state("attempt", "SLOT_SPAWN_ELIGIBLE"), "SLOT_SPAWN_ELIGIBLE")
        for removed in ("LOCAL_ATTEMPT_FINALIZED", "LOCAL_READBACK_VERIFIED",
                        "VALID_ADAPTER_ATTEMPT_COMPLETE", "EXCLUSIVE_WRITE",
                        "DURABLE_EXTERNAL_BYTES", "INDEPENDENT_READBACK",
                        "EXTERNAL_READBACK_VERIFIED", "MADE_UP"):
            with self.subTest(removed=removed), self.assertRaises(ContractError):
                parse_state("attempt", removed)
        with self.assertRaises(ContractError):
            parse_state("boot", "ATTEMPT_COMPLETE")

    def test_vocabulary_is_partitioned_into_closed_domains(self):
        all_states = (ATTEMPT_STATES | BOOT_STATES | CAMPAIGN_STATES |
                      LOCAL_EVIDENCE_STATES | PUBLICATION_STATES | SAFETY_MARKERS)
        self.assertEqual(len(all_states), sum(map(len, (ATTEMPT_STATES, BOOT_STATES,
                         CAMPAIGN_STATES, LOCAL_EVIDENCE_STATES,
                         PUBLICATION_STATES, SAFETY_MARKERS))))

    def test_records_are_frozen_and_enforce_bool_integer_distinction(self):
        record = identity()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.host_pid = 9
        values = {field.name: getattr(record, field.name) for field in dataclasses.fields(record)}
        values["host_pid"] = True
        with self.assertRaises(ContractError):
            ProcessIdentity(**values)

    def test_authorization_is_offline_closed_and_binds_execution_commit(self):
        auth = authorization()
        self.assertEqual(auth.core_commit, "de04b26c14f7e7d60173f463e9d79f9b7134a700")
        self.assertTrue(auth.offline_only)
        self.assertFalse(auth.retry_authorized)
        self.assertFalse(auth.tranche_b_authorized)
        with self.assertRaises(ContractError):
            dataclasses.replace(auth, core_commit="724700217f8d7183757768fb2a856872b64a3cf3")

    def test_matrix_requires_exact_ids_labels_and_bl_lb_order(self):
        slots = list(matrix())
        mutations = (
            dataclasses.replace(slots[0], slot_id="slot-altered"),
            dataclasses.replace(slots[0], attempt_id=slots[1].attempt_id),
            dataclasses.replace(slots[0], thermal_state="same-boot-warm"),
            dataclasses.replace(slots[0], handle_order="LB"),
        )
        for altered in mutations:
            candidate = list(slots)
            candidate[0] = altered
            with self.subTest(altered=altered), self.assertRaises(ContractError):
                dataclasses.replace(authorization(), slots=tuple(candidate))
