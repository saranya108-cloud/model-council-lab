"""M0-1 Level-1 tests. All Q images, histories and schemas are synthetic bytes.

No operational map/schema adoption, filesystem objects, provider calls,
process execution, synchronization, capture, cleanup or release occurs here.
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import unittest

import retention_v2_fixtures as fixtures
from tools.decision_0009.retention_v2 import cjson2, spec, verify


class M0QTests(unittest.TestCase):
    maxDiff = None

    def evaluate(self, image, evidence):
        result = verify.verify_q(image, evidence)
        self.assertFalse(result["authorizes_action"])
        self.assertFalse(result["release"]["deletion_authorized"])
        self.assertFalse(result["j_reopen_allowed"])
        return result

    def proof(self, evidence, capture=0):
        return evidence["references"][evidence["captures"][capture]["reference"]]

    def test_q_geometry_literals(self):
        self.assertEqual(3145728, spec.Q_SIZE)
        self.assertEqual(128, spec.Q_CELL_COUNT)
        self.assertEqual(1024, spec.Q_CELL_SIZE)
        self.assertEqual(108, spec.Q_ASSIGNED_COUNT)
        self.assertEqual(20, spec.Q_CELL_COUNT - spec.Q_ASSIGNED_COUNT)
        self.assertEqual(((0,131072),(131072,655360),(655360,2228224),
                          (2228224,2752512),(2752512,2883584),(2883584,3145728)),
                         tuple((r.start,r.end) for r in spec.Q_REGIONS))
        self.assertEqual(((110592,131072),(524288,655360),(2883584,3145728)),
                         tuple((r.start,r.end) for r in spec.Q_ZERO_REGIONS))
        self.assertEqual(2621440, sum(c.capacity for c in spec.Q_CAPTURES))
        with self.assertRaises(FrozenInstanceError):
            spec.Q_CAPTURES[0].capacity = 1
        with self.assertRaises(TypeError):
            spec.Q_GENERATION_BOUNDS["cleanup"] = (1, 1, 1)
        self.assertEqual((29,60,751432), spec.Q_GENERATION_BOUNDS["a2"])
        self.assertEqual((32,70,1609536), spec.Q_GENERATION_BOUNDS["provisioning"])
        self.assertEqual((39,81,992568), spec.Q_GENERATION_BOUNDS["process"])
        self.assertEqual((124,250,265248), spec.Q_GENERATION_BOUNDS["cleanup"])
        self.assertEqual({"a2_evidence":720896,"gate_b_ordinary_evidence":2654208,
                          "review_correction":110592,"descriptors_control_framing_padding":926208},
                         dict(spec.Q_ACCOUNT_RESERVATIONS))

    def test_q_capture_assignment_table_literal(self):
        self.assertEqual(fixtures.Q_EXTENTS_LITERAL,
                         tuple((c.number,c.offset,c.capacity) for c in spec.Q_CAPTURES))
        self.assertEqual(fixtures.Q_ROLES_LITERAL, spec.Q_CAPTURE_ROLES)
        self.assertEqual(tuple(range(108)), tuple(c.number for c in spec.Q_CAPTURES))
        self.assertEqual((100,101,102), spec.Q_UNDISPATCHED)
        intervals = sorted((c.offset,c.offset+c.capacity) for c in spec.Q_CAPTURES)
        self.assertTrue(all(left[1] <= right[0] for left,right in zip(intervals,intervals[1:])))
        image,evidence = fixtures.build_m0_q_fixture(())
        result = self.evaluate(image,evidence)
        self.assertEqual(108, len(result["captures"]))
        self.assertTrue(all(s["physical_state"] == "EMPTY" for s in result["captures"].values()))
        self.assertFalse(result["progression_blocked"])
        self.assertFalse(result["q_frozen"])

    def test_q_receipt_checksum_literal_vectors(self):
        for vector in fixtures.Q_CHECKSUM_LITERAL_VECTORS:
            with self.subTest(capture=vector["capture"]):
                digest = verify.compute_q_checksum(vector["capture"],vector["offset"],vector["capacity"],
                    bytes.fromhex(vector["cell_hex"]),bytes.fromhex(vector["payload_hex"]),
                    vector["map"],vector["binding"],vector["lifecycle"])
                self.assertEqual(vector["sha256"], digest.hex())
                for field in ("map","binding","lifecycle"):
                    args = dict(vector)
                    args[field] = "a" * len(vector[field])
                    changed = verify.compute_q_checksum(args["capture"],args["offset"],args["capacity"],
                        bytes.fromhex(args["cell_hex"]),bytes.fromhex(args["payload_hex"]),
                        args["map"],args["binding"],args["lifecycle"])
                    self.assertNotEqual(digest,changed)
                changed = verify.compute_q_checksum(vector["capture"],vector["offset"]+8,vector["capacity"],
                    bytes.fromhex(vector["cell_hex"]),bytes.fromhex(vector["payload_hex"]),
                    vector["map"],vector["binding"],vector["lifecycle"])
                self.assertNotEqual(digest, changed)

    def test_q_receipt_layout_and_schema(self):
        self.assertEqual(fixtures.Q_RECEIPT_FIELDS_LITERAL, spec.Q_RECEIPT_FIELDS)
        self.assertEqual(b"D9M0CAP\0", spec.Q_MAGIC)
        self.assertEqual(b"MCL-D0009-M0-CAPTURE-1A\0", spec.Q_CHECKSUM_DOMAIN)
        for changes in ({"extra":"forbidden"},{"format":"wrong"},{"length":"01"},
                        {"length":"32769"},{"completeness":"success"},{"schema":"bad"},
                        {"encoding":"bytes"},{"lifecycle":"A"*32},{"producer":"f"*64},
                        {"authorization":"f"*64},{"writer":"f"*64},{"map":"f"*64},{"binding":"f"*64}):
            with self.subTest(changes=changes):
                image,evidence = fixtures.build_m0_q_fixture()
                data = b"synthetic-evidence"
                cell = fixtures.m0_receipt_cell(0,data,evidence,changes=changes)
                mutated = bytearray(image);mutated[:1024] = cell
                self.assertEqual("INVALID",self.evaluate(bytes(mutated),evidence)["captures"][0]["physical_state"])

    def test_q_receipt_header_padding_and_suffix_defects(self):
        image,evidence = fixtures.build_m0_q_fixture()
        for offset in (0,8,12,16,1023,131072+len(b"synthetic-evidence")):
            with self.subTest(offset=offset):
                data = bytearray(image);data[offset] ^= 1
                result = self.evaluate(bytes(data),evidence)
                self.assertEqual("INVALID",result["captures"][0]["physical_state"])
                self.assertTrue(result["q_frozen"])
        for length in (0,977,0xffffffff):
            data=bytearray(image);data[12:16]=length.to_bytes(4,"little")
            self.assertEqual("INVALID",self.evaluate(bytes(data),evidence)["captures"][0]["physical_state"])

    def test_q_duplicate_and_noncanonical_receipt_rejected(self):
        image,evidence = fixtures.build_m0_q_fixture()
        size=int.from_bytes(image[12:16],"little")
        raw=image[48:48+size]
        for bad in (raw[:-1]+b',"length":"18"}',b' '+raw,raw.replace(b'"length":"18"',b'"length":18')):
            data=bytearray(image);data[12:16]=len(bad).to_bytes(4,"little")
            data[48:1024]=bad+bytes(976-len(bad))
            self.assertEqual("INVALID",self.evaluate(bytes(data),evidence)["captures"][0]["physical_state"])

    def test_q_payload_boundaries(self):
        for payload in (b"", bytes(32768), b"x"*32768):
            image,evidence=fixtures.build_m0_q_fixture(payloads={0:payload})
            self.assertEqual("RECEIPTED_COMPLETE",self.evaluate(image,evidence)["captures"][0]["physical_state"])
        with self.assertRaises(ValueError):
            fixtures.build_m0_q_fixture(payloads={0:b"x"*32769})

    def test_q_physical_state_matrix(self):
        observed=set()
        image,evidence=fixtures.build_m0_q_fixture(())
        observed.add(self.evaluate(image,evidence)["captures"][0]["physical_state"])
        for completeness in ("complete","partial","unresolved"):
            image,evidence=fixtures.build_m0_q_fixture(completeness={0:completeness})
            result=self.evaluate(image,evidence)
            observed.add(result["captures"][0]["physical_state"])
            self.assertEqual(completeness=="complete",result["captures"][0]["usable"])
        data=bytearray(image);data[:1024]=bytes(1024)
        observed.add(self.evaluate(bytes(data),evidence)["captures"][0]["physical_state"])
        data[0]=1
        result=self.evaluate(bytes(data),evidence)
        observed.add(result["captures"][0]["physical_state"])
        self.assertEqual("INVALID",result["captures"][0]["physical_state"])
        self.assertEqual(set(fixtures.Q_STATES_LITERAL),observed)
        self.assertEqual(fixtures.Q_STATES_LITERAL,spec.Q_PHYSICAL_STATES)

    def test_q_empty_dispatch_interpretation(self):
        image,evidence=fixtures.build_m0_q_fixture(())
        for dispatch,blocked in (("not_dispatched",False),("dispatched",True),("uncertain",True)):
            case=deepcopy(evidence);self.proof(case)["dispatch"]=dispatch
            result=self.evaluate(image,case)
            self.assertEqual("EMPTY",result["captures"][0]["physical_state"])
            self.assertEqual(dispatch,result["captures"][0]["dispatch"])
            self.assertEqual(blocked,result["progression_blocked"])
        result=self.evaluate(image,{})
        self.assertTrue(result["progression_blocked"])
        self.assertEqual("uncertain",result["captures"][0]["dispatch"])

    def test_q_unreadable_bytes_are_never_zero_or_complete(self):
        _,evidence=fixtures.build_m0_q_fixture()
        for image in (None,b"",bytes(3145727),bytes(3145729),bytearray(3145728)):
            result=self.evaluate(image,evidence)
            self.assertTrue(result["q_frozen"])
            self.assertTrue(all(s["physical_state"]=="INVALID" for s in result["captures"].values()))

    def test_q_zero_allowances_are_nonborrowable(self):
        image,evidence=fixtures.build_m0_q_fixture(())
        for offset in (110592,131071,524288,655359,2883584,3145727):
            data=bytearray(image);data[offset]=1
            result=self.evaluate(bytes(data),evidence)
            self.assertTrue(result["q_frozen"])
            self.assertIn("nonzero unassigned/nonborrowable space",result["errors"])

    def test_q_map_and_object_bindings(self):
        image,evidence=fixtures.build_m0_q_fixture()
        for field,value in (("map_bytes",b"wrong"),("lifecycle","a"*32),("binding","b"*64),
                            ("object","another-q"),("map_bytes",b"x"*65537)):
            case=deepcopy(evidence);case[field]=value
            self.assertTrue(self.evaluate(image,case)["progression_blocked"])
        case=deepcopy(evidence);case["map_view"][0]["capacity"]="32769"
        fixtures.m0_rebind_map(case)
        self.assertTrue(self.evaluate(image,case)["progression_blocked"])
        case=deepcopy(evidence);case["references"][case["map_attestation"]]["immutable"]=False
        self.assertTrue(self.evaluate(image,case)["progression_blocked"])

    def test_q_external_schema_is_required_and_closed(self):
        schema=fixtures._v2_1_cjson({"type":"object","fields":{"value":{"type":"string","max":"3"}}})
        for payload,valid in ((b'{"value":"ok"}',True),(b'{"value":"long"}',False),
                              (b'{"value":"ok","extra":null}',False)):
            image,evidence=fixtures.build_m0_q_fixture(payloads={0:payload},structured={0:schema})
            result=self.evaluate(image,evidence)
            self.assertEqual("RECEIPTED_COMPLETE" if valid else "INVALID",result["captures"][0]["physical_state"])
        image,evidence=fixtures.build_m0_q_fixture(payloads={0:b'{"value":"ok"}'},structured={0:schema})
        evidence["schemas"]={}
        self.assertEqual("INVALID",self.evaluate(image,evidence)["captures"][0]["physical_state"])

    def test_q_complete_without_closure_freezes(self):
        image,evidence=fixtures.build_m0_q_fixture()
        for step in ("payload_fsync","receipt_fsync","readback","close"):
            case=deepcopy(evidence);self.proof(case)["trace"].remove(step)
            result=self.evaluate(image,case)
            self.assertEqual("RECEIPTED_COMPLETE",result["captures"][0]["physical_state"])
            self.assertEqual("closure_unproven",result["captures"][0]["closure"])
            self.assertTrue(result["q_frozen"])
            self.assertTrue(result["progression_blocked"])

    def test_q_preconditions_and_original_references(self):
        image,evidence=fixtures.build_m0_q_fixture()
        for key in ("authority","identity","custody","map","reservations","f_closed"):
            case=deepcopy(evidence);self.proof(case)["checks"][key]=False
            self.assertTrue(self.evaluate(image,case)["q_frozen"])
        for key,value in (("zero_cell",b"x"+bytes(1023)),("zero_extent",b""),
                          ("payload_written",1),("receipt_written",1023),("io_uncertain",True)):
            case=deepcopy(evidence);self.proof(case)[key]=value
            self.assertTrue(self.evaluate(image,case)["q_frozen"])
        for key in ("authorization","producer","writer","operation","acquisition"):
            case=deepcopy(evidence);ref=case["map_view"][0][key]
            case["references"][ref]["order"]=1000
            self.assertTrue(self.evaluate(image,case)["q_frozen"])

    def test_q_ordering_no_retry_or_reassignment(self):
        image,evidence=fixtures.build_m0_q_fixture((0,1))
        evidence["map_view"][1]["dependencies"]=["0"]
        fixtures.m0_rebind_map(evidence)
        self.assertFalse(self.evaluate(image,evidence)["progression_blocked"])
        case=deepcopy(evidence);case["history"].reverse()
        self.assertTrue(self.evaluate(image,case)["q_frozen"])
        case=deepcopy(evidence);case["history"].append({"capture":0,"order":2000})
        self.assertTrue(self.evaluate(image,case)["q_frozen"])
        case=deepcopy(evidence);case["prior_freeze"]=True
        self.assertTrue(self.evaluate(image,case)["progression_blocked"])
        case=deepcopy(evidence);case["map_view"][0]["dependencies"]=["1"]
        fixtures.m0_rebind_map(case)
        self.assertTrue(self.evaluate(image,case)["q_frozen"])

    def test_q_freeze_does_not_block_authorized_stop(self):
        image,evidence=fixtures.build_m0_q_fixture()
        evidence["prior_freeze"]=True
        fixtures.m0_add_j(evidence)
        result=self.evaluate(image,evidence)
        self.assertTrue(result["q_frozen"])
        self.assertTrue(result["independent_stop_available"])
        self.assertTrue(result["progression_blocked"])
        evidence["references"][evidence["independent_stop"]]["requires_new_q_capture"]=True
        self.assertFalse(self.evaluate(image,evidence)["independent_stop_available"])

    def test_j_bootstrap_is_not_derived_from_q(self):
        image,evidence=fixtures.build_m0_q_fixture((18,))
        fixtures.m0_add_j(evidence)
        self.assertFalse(self.evaluate(image,evidence)["progression_blocked"])
        for key,value in (("bootstrap_source","q"),("conflict",True),("reopened",True),
                          ("active_j_intents_duplicated_in_q",True),("bootstrap_bytes",b"changed")):
            case=deepcopy(evidence);case["j"][key]=value
            self.assertTrue(self.evaluate(image,case)["progression_blocked"])

    def test_failed_compile_prevents_link(self):
        image,evidence=fixtures.build_m0_q_fixture((3,4))
        fixtures.m0_add_build(evidence)
        self.assertFalse(self.evaluate(image,evidence)["progression_blocked"])
        self.assertTrue(all(self.evaluate(image,evidence)["captures"][n]["dispatch"]=="not_dispatched" for n in range(6,12)))
        image,evidence=fixtures.build_m0_q_fixture((3,4,6,7))
        fixtures.m0_add_build(evidence,success=False,linked=True)
        self.assertTrue(self.evaluate(image,evidence)["progression_blocked"])
        fixtures.m0_add_build(evidence,success=True,linked=True)
        self.assertFalse(self.evaluate(image,evidence)["progression_blocked"])
        case=deepcopy(evidence);case["build"]["compile_attempts"]=2
        self.assertTrue(self.evaluate(image,case)["progression_blocked"])

    def test_build_original_status_stream_boundaries_and_prefixes(self):
        image,evidence=fixtures.build_m0_q_fixture((3,4,6,7))
        fixtures.m0_add_build(evidence,success=True,linked=True)
        for stream,field,value in (("stdout","link_start",0),("stderr","start",1),
                                   ("stdout","bytes",b"changed"),("stderr","final_end",100),
                                   ("stdout","bytes",b"x"*32769)):
            case=deepcopy(evidence);case["build"][stream][field]=value
            self.assertTrue(self.evaluate(image,case)["progression_blocked"])
        for status in ({"kind":"signal","value":9},{"kind":"exit","value":1}):
            case=deepcopy(evidence);case["build"]["compile_status"]=status
            self.assertTrue(self.evaluate(image,case)["progression_blocked"])

    def test_filesystem_cleanup_requires_fresh_identity(self):
        image,evidence,action,proof=fixtures.build_m0_cleanup_fixture()
        self.assertEqual("dispatched",self.evaluate(image,evidence)["cleanup"]["I/probe"][0]["dispatch"])
        for key in ("fresh_identity_custody","f_admitted_target","checkpoint","specific_chair_authority",
                    "f_closed","no_remaining_required_use","all_preconditions_passed"):
            case=deepcopy(evidence);case["references"][action["reference"]][key]=False
            result=self.evaluate(image,case)["cleanup"]["I/probe"][0]
            self.assertEqual("dispatched",result["dispatch"])
            self.assertEqual("original-exit-0",result["original_status"])
            self.assertTrue(result["errors"])
            self.assertFalse(result["absence_established"])
            if key != "all_preconditions_passed":
                blocked_image,blocked,_,_=fixtures.build_m0_cleanup_fixture(
                    dispatch="not_dispatched",failed_precondition=key)
                recorded=self.evaluate(blocked_image,blocked)["cleanup"]["I/probe"][0]
                self.assertEqual("not_dispatched",recorded["dispatch"])
                self.assertNotIn("original_status",recorded)
        proof["local_observation_bytes"]=b""
        result=self.evaluate(image,evidence)["cleanup"]["I/probe"][0]
        self.assertEqual("dispatched",result["dispatch"])
        self.assertTrue(result["errors"])

    def test_directory_cleanup_requires_fresh_population_observation(self):
        for target in ("O","I/private","I","P"):
            image,evidence,_,proof=fixtures.build_m0_cleanup_fixture(target)
            self.assertEqual("dispatched",self.evaluate(image,evidence)["cleanup"][target][0]["dispatch"])
            proof["fresh_population"]=False
            result=self.evaluate(image,evidence)["cleanup"][target][0]
            self.assertEqual("dispatched",result["dispatch"])
            self.assertEqual("original-exit-0",result["original_status"])
            self.assertTrue(result["errors"])
            image,evidence,_,_=fixtures.build_m0_cleanup_fixture(
                target,dispatch="not_dispatched",failed_precondition="fresh_population")
            result=self.evaluate(image,evidence)["cleanup"][target][0]
            self.assertEqual("not_dispatched",result["dispatch"])
            self.assertNotIn("original_status",result)

    def eligibility_cases(self,target):
        image,evidence,action,proof=fixtures.build_m0_cleanup_fixture(target)
        self.assertEqual("dispatched",self.evaluate(image,evidence)["cleanup"][target][0]["dispatch"])
        for key,value in (("fresh",False),("conflict",True),("binding","f"*64),
                          ("map","e"*64),("lifecycle","f"*32),("sha256","a"*64),("capture",102)):
            case=deepcopy(evidence)
            case["references"][action["reference"]]["eligibility"][0][key]=value
            result=self.evaluate(image,case)["cleanup"][target][0]
            self.assertEqual("dispatched",result["dispatch"])
            self.assertEqual("original-exit-0",result["original_status"])
            self.assertTrue(result["errors"])
        case=deepcopy(evidence);case["references"][action["reference"]]["eligibility"]=[]
        result=self.evaluate(image,case)["cleanup"][target][0]
        self.assertEqual("dispatched",result["dispatch"])
        self.assertTrue(result["errors"])
        self.proof(evidence,103)["trace"].remove("close")
        result=self.evaluate(image,evidence)["cleanup"][target][0]
        self.assertEqual("dispatched",result["dispatch"])
        self.assertTrue(result["errors"])
        image,evidence,_,_=fixtures.build_m0_cleanup_fixture(
            target,dispatch="not_dispatched",failed_precondition="eligibility")
        recorded=self.evaluate(image,evidence)["cleanup"][target][0]
        self.assertEqual("not_dispatched",recorded["dispatch"])
        self.assertNotIn("original_status",recorded)

    def test_account_cleanup_requires_fresh_capture_103_104_reference(self):
        self.eligibility_cases("temporary_account")

    def test_group_cleanup_requires_fresh_capture_103_104_reference(self):
        self.eligibility_cases("temporary_group")

    def test_cleanup_composite_over_1024_blocks_dispatch(self):
        image,evidence,action,_=fixtures.build_m0_cleanup_fixture()
        action["composite"]=b"x"*1025
        result=self.evaluate(image,evidence)["cleanup"]["I/probe"][0]
        self.assertEqual("dispatched",result["dispatch"])
        self.assertEqual("original-exit-0",result["original_status"])
        self.assertTrue(any("fit" in error for error in result["errors"]))

    def test_cleanup_result_must_match_exact_capture_and_freeze_blocks_cleanup(self):
        image,evidence,action,_=fixtures.build_m0_cleanup_fixture()
        case=deepcopy(evidence);case["cleanup"][0]["composite"]=b"{}"
        recorded=self.evaluate(image,case)["cleanup"]["I/probe"][0]
        self.assertEqual("dispatched",recorded["dispatch"])
        self.assertTrue(recorded["errors"])
        evidence["prior_freeze"]=True
        result=self.evaluate(image,evidence)
        recorded=result["cleanup"]["I/probe"][0]
        self.assertEqual("dispatched",recorded["dispatch"])
        self.assertTrue(recorded["errors"])
        self.assertTrue(result["independent_stop_available"])

    def test_w_work_is_proven_undispatched(self):
        image,evidence=fixtures.build_m0_q_fixture(())
        result=self.evaluate(image,evidence)
        for number in (100,101,102):
            self.assertEqual("EMPTY",result["captures"][number]["physical_state"])
            self.assertEqual("not_dispatched",result["captures"][number]["dispatch"])
        image,evidence=fixtures.build_m0_q_fixture((100,))
        self.assertTrue(self.evaluate(image,evidence)["q_frozen"])
        image,evidence,_,_=fixtures.build_m0_cleanup_fixture("W/work")
        recorded=self.evaluate(image,evidence)["cleanup"]["W/work"][0]
        self.assertEqual("dispatched",recorded["dispatch"])
        self.assertTrue(recorded["errors"])

    def test_exact_q_receipt_and_payload_retention(self):
        image,evidence=fixtures.build_m0_q_fixture()
        item=fixtures.m0_add_retention(image,evidence)
        result=self.evaluate(image,evidence)
        self.assertTrue(result["retention_valid"],result["errors"])
        self.assertEqual(1024,result["retention_usage"]["review_correction"])
        self.assertEqual(18,result["retention_usage"]["a2_evidence"])
        self.assertFalse(result["release"]["normal_eligible"])
        self.assertEqual([],result["release"]["preserve"])
        for field in ("cell","payload"):
            case=deepcopy(evidence);case["retention"][0][field]+=b"!"
            self.assertFalse(self.evaluate(image,case)["retention_valid"])
        self.assertNotEqual(item["roles"][0],item["roles"][1])

    def test_admission_covers_only_exact_bytes_roles_and_originals(self):
        image,evidence=fixtures.build_m0_q_fixture()
        item=fixtures.m0_add_retention(image,evidence)
        fixtures.m0_add_terminal(evidence)
        self.assertTrue(self.evaluate(image,evidence)["release"]["normal_eligible"])
        for scope in ([],[(item["roles"][0],hashlib.sha256(item["cell"]).hexdigest())],[("wrong_role","a"*64)]):
            case=deepcopy(evidence);case["references"][item["checkpoint"]]["scope"]=scope
            result=self.evaluate(image,case)
            self.assertFalse(result["retention_valid"])
            self.assertFalse(result["release"]["normal_eligible"])
        evidence["originals"]=[{"identity":"synthetic-original","role":"source_raw","bytes":b"required-source"}]
        result=self.evaluate(image,evidence)
        self.assertFalse(result["release"]["normal_eligible"])
        self.assertTrue(any(row[0]=="synthetic-original" for row in result["release"]["preserve"]))

    def test_q_unused_space_is_not_routine_retention(self):
        image,evidence=fixtures.build_m0_q_fixture()
        item=fixtures.m0_add_retention(image,evidence)
        item["capture"]=1
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])
        item["capture"]=108
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])
        item["capture"]=0;item["payload"]=image[131072:163840]
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])
        item["payload"]=image
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])

    def test_q_normal_release_requires_terminal_disposition(self):
        image,evidence=fixtures.build_m0_q_fixture()
        fixtures.m0_add_retention(image,evidence)
        self.assertFalse(self.evaluate(image,evidence)["release"]["normal_eligible"])
        for terminal in ("final_complete","final_failed","final_unresolved"):
            fixtures.m0_add_terminal(evidence,terminal)
            self.assertTrue(self.evaluate(image,evidence)["release"]["normal_eligible"])
        evidence["references"][evidence["terminal"]]["r2_terminal_established"]=False
        self.assertFalse(self.evaluate(image,evidence)["release"]["normal_eligible"])

    def test_exceptional_q_release_creates_no_disposition(self):
        image,evidence=fixtures.build_m0_q_fixture()
        before=self.evaluate(image,evidence)
        required=before["release"]["preserve"]
        ref=fixtures._m0_ref("chair-release")
        evidence["chair_releases"]=[ref]
        record={"established":True,"current":True,"kind":"chair_release","binding":evidence["binding"],
            "object":evidence["object"],"reason_terminal_unavailable":"missing-terminal-proof",
            "administrative_action":"specific-external-release","fresh_identity_custody":True,
            "scope":required[:1],"evidence_ceasing":required[:1],"remaining":required[1:],
            "action_scope":required[:1],"destroys_object":False}
        evidence["references"][ref]=record
        result=self.evaluate(image,evidence)
        self.assertFalse(result["release"]["normal_eligible"])
        self.assertEqual(required[:1],result["release"]["exceptional_scope"])
        self.assertEqual(required[1:],result["release"]["preserve"])
        self.assertEqual([],evidence["retention"])
        self.assertNotIn("terminal",evidence)
        for key in ("object","reason_terminal_unavailable","administrative_action","remaining","evidence_ceasing"):
            case=deepcopy(evidence);case["references"][ref].pop(key)
            self.assertEqual([],self.evaluate(image,case)["release"]["exceptional_scope"])

    def test_orphan_and_invalid_retained_only_as_unresolved_raw(self):
        image,evidence=fixtures.build_m0_q_fixture()
        data=bytearray(image);data[:1024]=bytes(1024)
        image=bytes(data)
        item=fixtures.m0_add_retention(image,evidence,unresolved_raw=True)
        result=self.evaluate(image,evidence)
        self.assertEqual("ORPHAN",result["captures"][0]["physical_state"])
        self.assertTrue(result["q_frozen"])
        self.assertTrue(result["retention_valid"],result["errors"])
        item["unresolved_raw"]=False
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])

    def test_closure_unproven_is_not_new_f_field(self):
        image,evidence=fixtures.build_m0_q_fixture()
        item=fixtures.m0_add_retention(image,evidence)
        self.proof(evidence)["trace"].remove("payload_fsync")
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])
        item["qualification"]="closure_unproven"
        result=self.evaluate(image,evidence)
        self.assertTrue(result["retention_valid"])
        self.assertTrue(result["q_frozen"])
        fcase=fixtures.build_v2_1_fixture("valid_admitted_genesis")
        fresult=verify.verify_f(fcase["image"],fcase["evidence"])
        self.assertEqual(set(fixtures.V2_1_RESULT_FIELDS),set(fresult))
        self.assertNotIn("closure_unproven",fresult)
        self.assertEqual(fresult,cjson2.loads(verify.encode_result(fresult)))

    def test_repeated_actual_retention_is_charged_again(self):
        image,evidence=fixtures.build_m0_q_fixture()
        fixtures.m0_add_retention(image,evidence)
        first=self.evaluate(image,evidence)["retention_usage"]
        fixtures.m0_add_retention(image,evidence)
        result=self.evaluate(image,evidence)
        self.assertTrue(result["retention_valid"],result["errors"])
        self.assertEqual({key:value*2 for key,value in first.items()},result["retention_usage"])
        evidence["accounting"]["accounts"]["review_correction"]-=1024
        self.assertFalse(self.evaluate(image,evidence)["retention_valid"])

    def test_generation_lifetime_account_and_phase_bounds(self):
        image,evidence=fixtures.build_m0_q_fixture()
        fixtures.m0_add_retention(image,evidence)
        for field,limit in (("generations",16),("aborted_generations",4),("items",1024),
                            ("physical_attempts",3584),("phases",24)):
            case=deepcopy(evidence);case["accounting"][field]=limit
            self.assertTrue(self.evaluate(image,case)["retention_valid"])
            case["accounting"][field]=limit+1
            self.assertFalse(self.evaluate(image,case)["retention_valid"])
        for field,limit in (("items",128),("records",512),("bytes",2097152)):
            case=deepcopy(evidence);case["accounting"]["generation_usage"][0][field]=limit+1
            self.assertFalse(self.evaluate(image,case)["retention_valid"])
        for account,limit in {"four_a1_snapshot_sets":1048576,"a1_qualification_profile_governance":2097152,"a2_evidence":1048576,"gate_b_ordinary_evidence":3145728,"descriptors_control_framing_padding":1048576,"interruption_abandonment":2097152,"review_correction":2097152}.items():
            case=deepcopy(evidence);case["accounting"]["accounts"][account]=limit+1
            self.assertFalse(self.evaluate(image,case)["retention_valid"])
        case=deepcopy(evidence);case["accounting"]["generation_usage"][0]["bytes"]=0
        self.assertFalse(self.evaluate(image,case)["retention_valid"])

    def test_support_limits_are_independent(self):
        image,evidence=fixtures.build_m0_q_fixture(())
        for support,valid in (([b""]*128,True),([b""]*129,False),([bytes(65536)],True),
                              ([bytes(65537)],False),([bytes(65536)]*64,True),
                              ([bytes(65536)]*65,False)):
            evidence["accounting"]["support"]=support
            self.assertEqual(valid,self.evaluate(image,evidence)["retention_valid"])

    def test_caller_inputs_are_not_mutated(self):
        image,evidence=fixtures.build_m0_q_fixture()
        snapshot=deepcopy(evidence)
        self.evaluate(image,evidence)
        self.assertEqual(snapshot,evidence)


    def test_readback_reports_must_match_actual_bytes_and_freeze(self):
        image,evidence=fixtures.build_m0_q_fixture()
        self.proof(evidence)["readback_payload_sha256"]="a"*64
        evidence["captures"][0]["payload_sha256"]="a"*64
        result=self.evaluate(image,evidence)
        self.assertEqual("RECEIPTED_COMPLETE",result["captures"][0]["physical_state"])
        self.assertTrue(result["q_frozen"])
        image,evidence=fixtures.build_m0_q_fixture()
        self.proof(evidence)["readback_cell_sha256"]="b"*64
        evidence["captures"][0]["cell_sha256"]="b"*64
        self.assertTrue(self.evaluate(image,evidence)["q_frozen"])

    def test_retention_requires_same_object_closed_read_evidence(self):
        image,evidence=fixtures.build_m0_q_fixture()
        item=fixtures.m0_add_retention(image,evidence)
        item.pop("read_reference",None)
        result=self.evaluate(image,evidence)
        self.assertFalse(result["retention_valid"])

    def test_cleanup_requires_exact_admission_and_chair_references(self):
        image,evidence,_,proof=fixtures.build_m0_cleanup_fixture()
        proof.pop("target_admission",None)
        proof.pop("chair_authority",None)
        recorded=self.evaluate(image,evidence)["cleanup"]["I/probe"][0]
        self.assertEqual("dispatched",recorded["dispatch"])
        self.assertEqual("original-exit-0",recorded["original_status"])
        self.assertTrue(recorded["errors"])

    def test_exceptional_release_action_cannot_destroy_other_required_evidence(self):
        image,evidence=fixtures.build_m0_q_fixture()
        required=self.evaluate(image,evidence)["release"]["preserve"]
        ref=fixtures._m0_ref("chair-release-delete-object")
        evidence["chair_releases"]=[ref]
        evidence["references"][ref]={"established":True,"current":True,"kind":"chair_release",
            "binding":evidence["binding"],"object":evidence["object"],"reason_terminal_unavailable":"missing",
            "administrative_action":"delete_whole_q","fresh_identity_custody":True,
            "scope":required[:1],"evidence_ceasing":required[:1],"remaining":required[1:],
            "action_scope":required,"destroys_object":True}
        self.assertEqual([],self.evaluate(image,evidence)["release"]["exceptional_scope"])

    def test_build_and_j_projections_must_bind_exact_capture_bytes(self):
        image,evidence=fixtures.build_m0_q_fixture((3,4))
        fixtures.m0_add_build(evidence)
        evidence["references"][evidence["build"]["reference"]]["capture_scope"]=[]
        self.assertTrue(self.evaluate(image,evidence)["progression_blocked"])
        image,evidence=fixtures.build_m0_q_fixture((18,))
        fixtures.m0_add_j(evidence)
        evidence["references"][evidence["j"]["reference"]]["capture_scope"]=[]
        self.assertTrue(self.evaluate(image,evidence)["progression_blocked"])



    def test_malformed_evidence_containers_fail_closed(self):
        image,evidence=fixtures.build_m0_q_fixture()
        for field in ("references","captures","retention","cleanup","accounting","originals","history","schemas"):
            case=deepcopy(evidence);case[field]=None
            result=self.evaluate(image,case)
            self.assertTrue(result["progression_blocked"])
            self.assertFalse(result["release"]["normal_eligible"])

    def test_lifetime_counts_cannot_undercount_supplied_generations(self):
        image,evidence=fixtures.build_m0_q_fixture()
        fixtures.m0_add_retention(image,evidence)
        for field in ("items","physical_attempts","generations"):
            case=deepcopy(evidence);case["accounting"][field]=0
            self.assertFalse(self.evaluate(image,case)["retention_valid"])

    def test_unobserved_required_original_blocks_release(self):
        image,evidence=fixtures.build_m0_q_fixture()
        fixtures.m0_add_retention(image,evidence)
        fixtures.m0_add_terminal(evidence)
        evidence["originals"]=[{"identity":"required-original","role":"source_raw"}]
        result=self.evaluate(image,evidence)
        self.assertFalse(result["release"]["normal_eligible"])
        self.assertFalse(result["release"]["scope_established"])



    def cleanup_attempts(self, result, target="I/probe"):
        group=result["cleanup"][target]
        return group if isinstance(group,list) else [group]

    def test_cleanup_retry_preserves_failed_and_uncertain_first_attempt(self):
        for uncertain in (False,True):
            image,evidence,action,proof=fixtures.build_m0_cleanup_fixture(original_status="original-exit-1")
            if uncertain:
                proof.pop("dispatch")
            fixtures.m0_add_cleanup(evidence)
            result=self.evaluate(image,evidence)
            attempts=self.cleanup_attempts(result)
            self.assertEqual(2,len(attempts))
            self.assertEqual("uncertain" if uncertain else "dispatched",attempts[0]["dispatch"])
            self.assertEqual("original-exit-1",attempts[0]["original_status"])
            self.assertTrue(any("reuse" in error or "second" in error for error in attempts[1]["errors"]))
            self.assertTrue(result["progression_blocked"])

    def test_cleanup_duplicate_result_capture_cannot_overwrite_another_target(self):
        image,evidence,action,proof=fixtures.build_m0_cleanup_fixture()
        other=deepcopy(action);other["target"]="I/probe.plist"
        other_ref=fixtures._m0_ref("duplicate-result-capture")
        evidence["references"][other_ref]=dict(proof,target="I/probe.plist")
        other["reference"]=other_ref;evidence["cleanup"].append(other)
        result=self.evaluate(image,evidence)
        self.assertEqual("original-exit-0",self.cleanup_attempts(result)[0]["original_status"])
        other_result=self.cleanup_attempts(result,"I/probe.plist")[0]
        self.assertTrue(any("reuse" in error for error in other_result["errors"]))
        self.assertEqual(2,sum(len(self.cleanup_attempts(result,key)) for key in result["cleanup"]))

    def test_cleanup_dispatch_truth_survives_failed_preconditions(self):
        image,evidence,_,_=fixtures.build_m0_cleanup_fixture(
            original_status="original-exit-1",failed_precondition="fresh_identity_custody")
        result=self.evaluate(image,evidence)
        attempt=self.cleanup_attempts(result)[0]
        self.assertEqual("dispatched",attempt["dispatch"])
        self.assertEqual("original-exit-1",attempt["original_status"])
        self.assertTrue(any("violation" in error for error in attempt["errors"]))
        self.assertTrue(result["progression_blocked"])
        image,evidence,_,_=fixtures.build_m0_cleanup_fixture(
            dispatch="not_dispatched",failed_precondition="fresh_identity_custody")
        attempt=self.cleanup_attempts(self.evaluate(image,evidence))[0]
        self.assertEqual("not_dispatched",attempt["dispatch"])
        self.assertNotIn("original_status",attempt)

    def test_cleanup_dispatch_unknown_and_unsupported_non_dispatch(self):
        for mode in ("missing_dispatch","untrusted","unsupported_not_dispatched"):
            image,evidence,_,proof=fixtures.build_m0_cleanup_fixture()
            if mode=="missing_dispatch":proof.pop("dispatch")
            elif mode=="untrusted":proof["established"]=False
            else:proof["dispatch"]="not_dispatched";proof.pop("original_status")
            attempt=self.cleanup_attempts(self.evaluate(image,evidence))[0]
            self.assertEqual("uncertain",attempt["dispatch"])
            self.assertTrue(attempt["errors"])

    def test_cleanup_fixture_intent_and_eligibility_precede_result(self):
        for target,number in (("I/probe",53),("temporary_account",47),("temporary_group",50)):
            image,evidence,_,_=fixtures.build_m0_cleanup_fixture(target)
            result=self.evaluate(image,evidence)
            self.assertFalse(result["progression_blocked"],result)
            self.assertLess(self.proof(evidence,number-1)["order"],self.proof(evidence,number)["order"])
            if number in (47,50):
                for capture in (103,104):
                    self.assertLess(self.proof(evidence,capture)["order"],self.proof(evidence,number)["order"])
            self.assertIsInstance(result["cleanup"][target],list)

    def test_cleanup_result_after_not_dispatched_or_unclosed_intent_is_rejected(self):
        image,source,action,_=fixtures.build_m0_cleanup_fixture()
        image,evidence=fixtures.build_m0_q_fixture((53,),payloads={53:action["composite"]},
            structured={53:fixtures.M0_SYNTHETIC_COMPOSITE_SCHEMA})
        fixtures.m0_add_cleanup(evidence)
        result=self.evaluate(image,evidence)
        attempt=self.cleanup_attempts(result)[0]
        self.assertEqual("not_dispatched",result["captures"][52]["dispatch"])
        self.assertEqual("dispatched",attempt["dispatch"])
        self.assertTrue(any("intent" in error for error in attempt["errors"]))
        self.assertTrue(result["progression_blocked"])
        image,evidence,_,_=fixtures.build_m0_cleanup_fixture()
        self.proof(evidence,52)["trace"].remove("close")
        self.assertTrue(self.cleanup_attempts(self.evaluate(image,evidence))[0]["errors"])

    def test_cleanup_eligibility_references_cannot_point_to_later_captures(self):
        for target,number in (("temporary_account",47),("temporary_group",50)):
            _,_,action,_=fixtures.build_m0_cleanup_fixture(target)
            image,evidence=fixtures.build_m0_q_fixture((number-1,number,103,104),
                payloads={number:action["composite"]},structured={number:fixtures.M0_SYNTHETIC_COMPOSITE_SCHEMA})
            fixtures.m0_add_cleanup(evidence,target)
            result=self.evaluate(image,evidence)
            attempt=self.cleanup_attempts(result,target)[0]
            self.assertEqual("dispatched",attempt["dispatch"])
            self.assertTrue(any("predate" in error or "before" in error for error in attempt["errors"]))
            self.assertTrue(result["progression_blocked"])

    def test_cleanup_absence_cannot_dispatch_after_not_dispatched_action(self):
        image,evidence,_,_=fixtures.build_m0_cleanup_fixture(
            dispatch="not_dispatched",failed_precondition="fresh_identity_custody",absence=True)
        result=self.evaluate(image,evidence)
        attempt=self.cleanup_attempts(result)[0]
        self.assertEqual("dispatched",result["captures"][54]["dispatch"])
        self.assertEqual("not_dispatched",attempt["dispatch"])
        self.assertTrue(any("absence" in error for error in attempt["errors"]))
        self.assertFalse(attempt["absence_established"])
        self.assertTrue(result["progression_blocked"])

    def test_cleanup_authority_references_must_predate_result(self):
        for key in ("target_admission","chair_authority"):
            for order in (None,1010,1020):
                image,evidence,_,proof=fixtures.build_m0_cleanup_fixture()
                evidence["references"][proof[key]]["order"]=order
                attempt=self.cleanup_attempts(self.evaluate(image,evidence))[0]
                self.assertEqual("dispatched",attempt["dispatch"])
                self.assertTrue(any("predate" in error for error in attempt["errors"]))

    def test_j_facts_require_present_matching_trusted_provenance(self):
        for key,bad in (("bootstrap_source","q"),("conflict",True),("reopened",True),
                        ("active_j_intents_duplicated_in_q",True)):
            for missing in (True,False):
                image,evidence=fixtures.build_m0_q_fixture((18,))
                fixtures.m0_add_j(evidence)
                reference=evidence["references"][evidence["j"]["reference"]]
                if missing:reference.pop(key)
                else:reference[key]=bad
                self.assertTrue(self.evaluate(image,evidence)["progression_blocked"],(key,missing))

    def test_j_provenance_required_for_each_pre18_capture(self):
        for capture in range(13,18):
            image,evidence=fixtures.build_m0_q_fixture((capture,))
            self.assertTrue(self.evaluate(image,evidence)["progression_blocked"],capture)
            fixtures.m0_add_j(evidence)
            self.assertFalse(self.evaluate(image,evidence)["progression_blocked"],capture)

    def test_build_attempt_counts_require_present_matching_trusted_provenance(self):
        for linked in (False,True):
            for key in ("compile_attempts","link_attempts"):
                for missing in (True,False):
                    captures=(3,4,6,7) if linked else (3,4)
                    image,evidence=fixtures.build_m0_q_fixture(captures)
                    fixtures.m0_add_build(evidence,success=True,linked=linked)
                    reference=evidence["references"][evidence["build"]["reference"]]
                    if missing:reference.pop(key)
                    else:reference[key]=2
                    self.assertTrue(self.evaluate(image,evidence)["progression_blocked"],(key,linked,missing))



    def test_trusted_j_reopening_cannot_be_suppressed_by_plain_frozen(self):
        for frozen_present in (True, False):
            for reopened in (True, False):
                with self.subTest(frozen_present=frozen_present, reopened=reopened):
                    image, evidence = fixtures.build_m0_q_fixture((18,))
                    fixtures.m0_add_j(evidence)
                    journal = evidence["j"]
                    reference = evidence["references"][journal["reference"]]
                    reference["reopened"] = reopened
                    journal["reopened"] = reopened
                    if frozen_present:
                        journal["frozen"] = False
                    else:
                        journal.pop("frozen")
                    result = self.evaluate(image, evidence)
                    self.assertEqual(reopened, result["progression_blocked"])
                    if reopened:
                        self.assertIn("J cannot reopen", result["errors"])
                    else:
                        self.assertEqual([], result["errors"])


if __name__ == "__main__":
    unittest.main()
