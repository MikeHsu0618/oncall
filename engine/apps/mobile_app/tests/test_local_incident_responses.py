"""[code] TESTS FIRST: finite, unrouted native response parser compatibility.

[code] Intended API: responses.validate_response(method, payload, *, http_status=200)
returns an independent JSON dict only for HTTP 200, without coercion/defaults or
semantic success/readiness claims. Native nullable body.error is retained verbatim.
A valid non-200 Error envelope raises responses.UpstreamResponseError with the
static message below and .http_status; malformed envelopes raise ContractError.
The status must be an exact int in 100..599, never bool/float/string.
[code] ContractError is the accepted json_inputs.ContractError; no new dependency.
[code] Every declared success field is nullable/missing. Requiredness applies ONLY
inside non-null nested models, as projected from the accepted native parsers.
[code] Additive fields survive as bounded independent copies. The two unresolved
object* generic fields are opaque bounded JSON, NOT guessed map key/value types.
[code] Unchanged json_inputs safety policy: UTF-8 strings/keys <=256 KiB, compact
JSON <=1 MiB, root depth one <=16, value/container nodes <=10000, arrays <=1000.
These are local safety decisions, NOT recovered server limits. No request-only
query limit, URL/UUID/date format, enum, user-identity or readiness rule is imported.
[code] Raw-byte decoding is composed with the accepted json_inputs.decode_body;
this slice does not introduce a second decoder or change the accepted guard.
[code] Offline stdlib unittest only; main owns pinned-container RED/GREEN.
"""

import copy
import hashlib
import json
import logging
import unittest
from collections import deque
from pathlib import Path
from unittest.mock import patch

from apps.mobile_app.local_incident import json_inputs, responses


SOURCE_SHA256 = "2e425c76142d36745d979271623f9807e71ba0d20a6e19feca0cef61ff099c5e"
FIXTURE_SHA256 = "a24aa20e9075b5788bf3de2019bbeac65d03216b7b09cabc544fe1bf18512ec4"
FIXTURE_PATH = Path(__file__).with_name("local_incident_native_responses.json")
MAX_BODY_BYTES = 1024 * 1024
MAX_STRING_BYTES = 256 * 1024
MAX_DEPTH = 16
MAX_NODES = 10_000
MAX_LIST_ITEMS = 1000
TRANSPORT_MESSAGE = "upstream incident request failed"
EXPECTED_METHODS = frozenset("""
    ActivityService.FilterActivity ActivityService.QueryActivity
    CommentsService.AddReaction CommentsService.RemoveReaction FieldsService.GetFields
    IncidentContextService.AddIncidentContext IncidentContextService.QueryIncidentContext
    IncidentsService.AssignLabelByUUID IncidentsService.AssignRole
    IncidentsService.CreateIncident IncidentsService.GetIncident
    IncidentsService.QueryIncidentPreviews IncidentsService.UnassignLabelByUUID
    IncidentsService.UnassignRole IncidentsService.UpdateDescription
    IncidentsService.UpdateSeverity IncidentsService.UpdateStatus IncidentsService.UpdateTitle
    KeyUpdatesService.CreateKeyUpdate KeyUpdatesService.GetLastKeyUpdate
    KeyUpdatesService.QueryKeyUpdates OrgService.GetOrg OrgService.GetOrgStatus
    SeveritiesService.GetOrgSeverities StatusService.QueryOrgStatuses
    UsersService.AutocompleteUsers UsersService.GetSession UsersService.GetUser
""".split())
OPAQUE_FIELDS = frozenset((
    ("ActivityItem", "fieldValues"), ("ImportantActivityMatcher", "fieldValues")))


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def minimal_model(models, name):
    """[code] Synthetic type witnesses, not fabricated real users/incidents."""
    primitives = {"string": "synthetic", "int": 1, "bool": False}
    return {key: None if spec["nullable_or_missing"] else primitives[spec["type"]]
            for key, spec in models[name]["fields"].items()}


def model_paths(models, root):
    """[code] One shortest reachable embedding per native model for EACH RPC."""
    found = {root: ()}
    pending = deque([root])
    while pending:
        parent = pending.popleft()
        for key, spec in models[parent]["fields"].items():
            kind = spec["type"]
            child = kind.removesuffix("[]")
            if child in models and child not in found:
                found[child] = found[parent] + ((key, child, kind.endswith("[]")),)
                pending.append(child)
    return found


def embed(models, root, path, value):
    """[code] Fresh local construction is mutable by design, never caller input."""
    if not path:
        return copy.deepcopy(value)
    result = minimal_model(models, root)
    current = result
    for index, (key, child, is_list) in enumerate(path):
        member = copy.deepcopy(value) if index == len(path) - 1 else minimal_model(models, child)
        current[key] = [member] if is_list else member
        current = member
    return result


def valid_member(models, kind):
    if kind.endswith("[]"):
        return []
    if kind in models:
        return minimal_model(models, kind)
    return {"string": "", "int": 0, "bool": False, "object": {}}[kind]


def wrong_members(kind):
    if kind == "string":
        return (False, 1, 1.5, [], {})
    if kind == "int":
        return (True, False, "1", 1.0, [], {})
    if kind == "bool":
        return (0, 1, "false", [], {})
    if kind.endswith("[]"):
        return (False, 1, "[]", {})
    return (False, 1, "{}", [])


def nested_object(depth):
    value = {}
    for _ in range(depth - 1):
        value = {"child": value}
    return value


def node_boundary(extra=0):
    """[code] Root + outer array + ten inner arrays + leaves =10000 (+extra)."""
    return {"addition": [[None] * 1000 for _ in range(9)] + [[None] * (988 + extra)]}


def byte_boundary(extra=0):
    shell = {"addition": ["", "", "", ""]}
    last_size = MAX_BODY_BYTES - len(encoded(shell)) - 3 * MAX_STRING_BYTES
    return {"addition": ["x" * MAX_STRING_BYTES] * 3 + ["x" * (last_size + extra)]}


def mutable_ids(value):
    if type(value) is dict:
        return {id(value)}.union(*(mutable_ids(item) for item in value.values()))
    if type(value) is list:
        return {id(value)}.union(*(mutable_ids(item) for item in value))
    return set()


class LocalIncidentResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = FIXTURE_PATH.read_bytes()
        if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
            raise AssertionError("native response fixture digest changed")
        cls.fixture = json.loads(raw)
        cls.models = cls.fixture["models"]
        cls.samples = {row["method"]: row for row in cls.fixture["methods"]}

    def reject(self, method, payload, field=None, **kwargs):
        with self.assertRaises(json_inputs.ContractError) as raised:
            responses.validate_response(method, payload, **kwargs)
        if field is not None:
            self.assertIn(field, str(raised.exception))
        return raised.exception

    def accept(self, method, payload, **kwargs):
        before = copy.deepcopy(payload)
        result = responses.validate_response(method, payload, **kwargs)
        self.assertIs(type(result), dict)
        self.assertEqual(result, before)
        self.assertEqual(payload, before)
        self.assertTrue(mutable_ids(result).isdisjoint(mutable_ids(payload)))
        return result

    def witnesses(self):
        for method, row in self.samples.items():
            root = row["response_model"]
            for model, path in model_paths(self.models, root).items():
                yield method, root, model, path

    def test_fixture_covers_exact_native_registry_and_source_pin(self):
        self.assertEqual(len(EXPECTED_METHODS), 28)
        self.assertEqual(len(self.fixture["methods"]), 28)
        self.assertEqual(set(self.samples), EXPECTED_METHODS)
        self.assertEqual(self.fixture["source"]["sha256"], SOURCE_SHA256)
        self.assertIn("[code]", self.fixture["provenance"])
        reachable = {model for _, _, model, _ in self.witnesses()}
        self.assertEqual(reachable | {"Error"}, set(self.models))
        self.assertEqual(len(self.models), 75)
        for row in self.fixture["methods"]:
            with self.subTest(method=row["method"]):
                self.assertEqual(row["success_http_status"], 200)
                self.assertEqual(row["non_200_model"], "Error")
                self.assertEqual(row["response_parser"], self.models[row["response_model"]]["parser"])
                self.assertEqual({case["source_fixture"].split("/")[-1] for case in row["cases"]},
                                 {"success", "native-null-fields", "application-error", "http-error"})

    def test_every_exact_method_accepts_original_success_null_and_body_error_fixtures(self):
        for method, row in self.samples.items():
            for case in row["cases"]:
                if case["http_status"] == 200:
                    with self.subTest(method=method, fixture=case["source_fixture"]):
                        self.accept(method, case["payload"], http_status=200)

    def test_every_method_accepts_empty_missing_and_all_nullable_top_level_fields(self):
        for method, row in self.samples.items():
            fields = self.models[row["response_model"]]["fields"]
            with self.subTest(method=method):
                self.assertTrue(all(spec["nullable_or_missing"] for spec in fields.values()))
                self.accept(method, {})
                self.accept(method, dict.fromkeys(fields))
                for key in fields:
                    self.accept(method, {key: None})
                    self.accept(method, {name: None for name in fields if name != key})

    def test_every_known_field_validates_non_null_type_in_every_reachable_method(self):
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                with self.subTest(method=method, model=model, field=key):
                    value = {**minimal_model(self.models, model),
                             key: valid_member(self.models, spec["type"])}
                    self.accept(method, embed(self.models, root, path, value))

    def test_every_known_nonopaque_field_rejects_wrong_types_without_coercion(self):
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                if (model, key) in OPAQUE_FIELDS:
                    continue
                for wrong in wrong_members(spec["type"]):
                    with self.subTest(method=method, model=model, field=key, wrong=type(wrong).__name__):
                        value = {**minimal_model(self.models, model), key: wrong}
                        self.reject(method, embed(self.models, root, path, value), key)

    def test_nested_required_fields_cannot_be_missing_or_null_for_any_method(self):
        covered = set()
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                if spec["nullable_or_missing"]:
                    continue
                covered.add(model)
                original = minimal_model(self.models, model)
                with self.subTest(method=method, model=model, field=key):
                    missing = {name: value for name, value in original.items() if name != key}
                    self.reject(method, embed(self.models, root, path, missing), key)
                    self.reject(method, embed(self.models, root, path, {**original, key: None}), key)
        self.assertEqual(covered, {"ActivityFilter", "ActivityQuery", "Comment", "CommentsQuery",
                                  "CustomMetadataField", "CustomMetadataFieldSelectOption", "Field",
                                  "HookRun", "IncidentPreviewsQuery", "KeyUpdate", "KeyUpdatesQuery",
                                  "Org", "Status", "Task"})

    def test_nested_nullable_fields_allow_missing_null_and_empty_containers(self):
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                if not spec["nullable_or_missing"]:
                    continue
                original = minimal_model(self.models, model)
                with self.subTest(method=method, model=model, field=key):
                    self.accept(method, embed(self.models, root, path, original))
                    missing = {name: value for name, value in original.items() if name != key}
                    self.accept(method, embed(self.models, root, path, missing))

    def test_model_object_lists_reject_null_and_non_object_members(self):
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                if not spec["type"].endswith("[]") or spec["type"] == "string[]":
                    continue
                for wrong in (None, False, 1, "object", []):
                    with self.subTest(method=method, model=model, field=key, wrong=wrong):
                        value = {**minimal_model(self.models, model), key: [wrong]}
                        self.reject(method, embed(self.models, root, path, value), key)

    def test_native_string_lists_allow_null_members_without_rewriting(self):
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                if spec["type"] != "string[]":
                    continue
                for member in ([], [None], ["", None, "opaque", None]):
                    with self.subTest(method=method, model=model, field=key, valid=member):
                        value = {**minimal_model(self.models, model), key: member}
                        self.accept(method, embed(self.models, root, path, value))
                for member in (False, 1, [], {}):
                    with self.subTest(method=method, model=model, field=key, wrong=member):
                        value = {**minimal_model(self.models, model), key: [None, member]}
                        self.reject(method, embed(self.models, root, path, value), key)

    def test_each_model_preserves_additive_bounded_fields_without_schema_expansion(self):
        for method, root, model, path in self.witnesses():
            value = {**minimal_model(self.models, model),
                     "futureNativeField": {"nested": [None, False, 1, 1.25, "synthetic"]}}
            with self.subTest(method=method, model=model):
                self.accept(method, embed(self.models, root, path, value))

    def test_opaque_generics_remain_bounded_json_not_invented_typed_maps(self):
        found = set()
        for method, root, model, path in self.witnesses():
            if (model, "fieldValues") not in OPAQUE_FIELDS:
                continue
            found.add(model)
            for opaque in (None, {}, [], "opaque", False, 1, 1.25,
                           {"unproven": [None, True, 1, 1.25, "x", {"other": []}]}):
                with self.subTest(method=method, model=model, opaque=type(opaque).__name__):
                    value = {**minimal_model(self.models, model), "fieldValues": opaque}
                    self.accept(method, embed(self.models, root, path, value))
        self.assertEqual(found, {"ActivityItem", "ImportantActivityMatcher"})

    def test_cursor_components_are_independently_nullable_missing_or_empty(self):
        for method, root, model, path in self.witnesses():
            if model != "Cursor":
                continue
            for cursor in ({}, {"nextValue": None}, {"hasMore": None},
                           {"nextValue": "opaque-not-an-offset"}, {"hasMore": False},
                           {"nextValue": "", "hasMore": None}):
                with self.subTest(method=method, cursor=cursor):
                    self.accept(method, embed(self.models, root, path, cursor))

    def test_no_request_query_limit_or_semantic_uuid_url_date_enum_validation(self):
        for method, root, model, path in self.witnesses():
            for key, spec in self.models[model]["fields"].items():
                if spec["type"] not in ("string", "int"):
                    continue
                candidates = ("", "opaque-not-a-uuid-or-date-or-url", " future enum ")
                if spec["type"] == "int":
                    candidates = (0, -1, 1001)
                for member in candidates:
                    with self.subTest(method=method, model=model, field=key, member=member):
                        value = {**minimal_model(self.models, model), key: member}
                        self.accept(method, embed(self.models, root, path, value))

    def test_incident_label_uuid_spelling_and_target_user_ids_survive_unchanged(self):
        method = "IncidentsService.GetIncident"
        body = {"incident": {"incidentID": "opaque-inc", "labels": [{
            "keyUUID": "opaque-key", "labelUUID": "opaque-label", "label": "",
            "futureNativeField": "untouched"}]}}
        result = self.accept(method, body)
        self.assertEqual(result["incident"]["labels"][0]["labelUUID"], "opaque-label")
        self.assertNotIn("valueUUID", result["incident"]["labels"][0])
        for method in ("UsersService.GetSession", "UsersService.GetUser"):
            self.accept(method, {"user": {"userID": "target-not-current-caller",
                                         "internalUserID": "separate", "grafanaLogin": None}})
        self.accept("IncidentsService.AssignRole", {"userID": "target", "role": None,
                                                    "didChange": False, "incident": None})

    def test_did_change_true_false_null_missing_are_not_retry_or_success_decisions(self):
        for method in ("CommentsService.AddReaction", "CommentsService.RemoveReaction",
                       "IncidentsService.AssignRole", "IncidentsService.UnassignRole"):
            for body in ({}, {"didChange": None}, {"didChange": False}, {"didChange": True}):
                with self.subTest(method=method, body=body):
                    self.accept(method, body)

    def test_org_status_is_direct_nullable_object_not_readiness_capability_envelope(self):
        method = "OrgService.GetOrgStatus"
        for body in ({}, {"orgID": None, "isEnabled": None, "isSetup": None,
                          "isHealthy": None, "error": None},
                     {"isSetup": False}, {"isSetup": True, "isEnabled": False},
                     {"futureEnvelope": {"isSetup": "uninterpreted additive data"}}):
            self.accept(method, body)
        self.reject(method, {"isSetup": 1}, "isSetup")

    def test_body_error_is_nullable_application_data_on_http_200_for_every_method(self):
        for method in EXPECTED_METHODS:
            for error in (None, "", "synthetic application error"):
                with self.subTest(method=method, error=error):
                    self.accept(method, {"error": error}, http_status=200)
            self.accept(method, {"error": None, "futureTransportStatus": 503})

    def test_non_200_native_error_fixture_is_never_returned_as_success(self):
        self.assertTrue(issubclass(responses.UpstreamResponseError, ValueError))
        self.assertFalse(issubclass(responses.UpstreamResponseError, json_inputs.ContractError))
        for method, row in self.samples.items():
            case = next(case for case in row["cases"] if case["http_status"] != 200)
            before = copy.deepcopy(case["payload"])
            with self.subTest(method=method), self.assertRaises(responses.UpstreamResponseError) as raised:
                responses.validate_response(method, case["payload"], http_status=case["http_status"])
            self.assertEqual(str(raised.exception), TRANSPORT_MESSAGE)
            self.assertEqual(raised.exception.http_status, case["http_status"])
            self.assertEqual(case["payload"], before)

    def test_all_non_200_statuses_require_error_string_then_raise_safe_transport_error(self):
        method = "OrgService.GetOrg"
        for status in range(100, 600):
            if status == 200:
                continue
            with self.subTest(status=status), self.assertRaises(responses.UpstreamResponseError) as raised:
                responses.validate_response(method, {"error": "synthetic raw upstream text"},
                                            http_status=status)
            self.assertEqual(str(raised.exception), TRANSPORT_MESSAGE)
            self.assertEqual(raised.exception.http_status, status)
        for method in EXPECTED_METHODS:
            for body in ({}, {"error": None}, {"error": False}, {"error": 1},
                         {"error": []}, {"error": {}}, {"incident": {}}):
                with self.subTest(method=method, malformed=body):
                    self.reject(method, body, "error", http_status=503)
            with self.assertRaises(responses.UpstreamResponseError):
                responses.validate_response(method, {"error": "", "incident": "not a success model"},
                                            http_status=201)

    def test_status_is_exact_bounded_integer_and_unknown_method_never_dispatches(self):
        for status in (None, False, True, 200.0, "200", 0, -1, 99, 600, [], {}):
            with self.subTest(status=status):
                self.reject("OrgService.GetOrg", {}, "http_status", http_status=status)
        for method in (None, True, 17, "", "OrgService.GetOrgExtra", "/api/OrgService.GetOrg",
                       "OrgService.GetOrg/", "orgservice.getorg", "UsersService.GetSession?x=1"):
            with self.subTest(method=method):
                self.reject(method, {}, "method")

    def test_both_transport_branches_reject_non_object_roots_and_non_json_values(self):
        for status in (200, 503):
            for root in (None, [], False, 1, "{}", b"{}"):
                with self.subTest(status=status, root=type(root).__name__):
                    self.reject("OrgService.GetOrg", root, "body", http_status=status)
            for value in (b"bytes", (1, 2), {"set"}, object(), float("nan"), float("inf")):
                self.reject("OrgService.GetOrg", {"error": "text", "addition": value}, http_status=status)
            self.reject("OrgService.GetOrg", {"error": "text", 1: "key"}, http_status=status)
            cycle = {}
            cycle["self"] = cycle
            self.reject("OrgService.GetOrg", {"error": "text", "addition": cycle}, http_status=status)

    def test_all_methods_copy_mutable_members_without_cross_call_or_input_aliases(self):
        for method, row in self.samples.items():
            case = next(case for case in row["cases"] if case["source_fixture"].endswith("/success"))
            payload = {**copy.deepcopy(case["payload"]), "addition": {"items": [{"value": "before"}]}}
            before = copy.deepcopy(payload)
            first = self.accept(method, payload)
            second = self.accept(method, payload)
            self.assertTrue(mutable_ids(first).isdisjoint(mutable_ids(second)))
            first["addition"]["items"][0]["value"] = "changed-result"
            self.assertEqual(payload, before)
            self.assertEqual(second, before)
            payload["addition"]["items"].append("changed-input")
            self.assertEqual(second, before)
            invalid = {**before, "error": {"bad": "synthetic"}}
            rejected_before = copy.deepcopy(invalid)
            self.reject(method, invalid, "error")
            self.assertEqual(invalid, rejected_before)

    def test_shared_json_guard_limits_are_inherited_unchanged(self):
        self.assertEqual(json_inputs.MAX_BODY_BYTES, MAX_BODY_BYTES)
        self.assertEqual(json_inputs.MAX_STRING_BYTES, MAX_STRING_BYTES)
        self.assertEqual(json_inputs.MAX_DEPTH, MAX_DEPTH)
        self.assertEqual(json_inputs.MAX_NODES, MAX_NODES)
        self.assertEqual(json_inputs.MAX_LIST_ITEMS, MAX_LIST_ITEMS)
        self.accept("OrgService.GetOrg", nested_object(MAX_DEPTH))
        self.reject("OrgService.GetOrg", nested_object(MAX_DEPTH + 1))
        self.accept("OrgService.GetOrg", node_boundary())
        self.reject("OrgService.GetOrg", node_boundary(extra=1))
        self.accept("OrgService.GetOrg", {"addition": [None] * MAX_LIST_ITEMS})
        self.reject("OrgService.GetOrg", {"addition": [None] * (MAX_LIST_ITEMS + 1)})
        self.assertEqual(len(encoded(byte_boundary())), MAX_BODY_BYTES)
        self.accept("OrgService.GetOrg", byte_boundary())
        self.reject("OrgService.GetOrg", byte_boundary(extra=1))

    def test_string_keys_and_values_use_inclusive_utf8_bounds_even_when_unknown(self):
        at_limit = "é" * (MAX_STRING_BYTES // 2)
        for body in ({"error": at_limit}, {"addition": at_limit}, {at_limit: None}):
            self.accept("OrgService.GetOrg", body)
        for body in ({"error": at_limit + "é"}, {"addition": at_limit + "é"},
                     {at_limit + "é": None}, {"error": "\ud800"}, {"\udfff": None}):
            self.reject("OrgService.GetOrg", body)

    def test_known_and_opaque_lists_cannot_bypass_inherited_size_bounds(self):
        method = "UsersService.AutocompleteUsers"
        self.accept(method, {"users": [{} for _ in range(MAX_LIST_ITEMS)]})
        self.reject(method, {"users": [{} for _ in range(MAX_LIST_ITEMS + 1)]}, "users")
        for method, root, model, path in self.witnesses():
            if (model, "fieldValues") in OPAQUE_FIELDS:
                body = {**minimal_model(self.models, model), "fieldValues": [None] * (MAX_LIST_ITEMS + 1)}
                self.reject(method, embed(self.models, root, path, body), "fieldValues")

    def test_non_200_envelopes_are_bounded_before_safe_transport_error(self):
        method = "OrgService.GetOrg"
        for body in ({"error": "x" * (MAX_STRING_BYTES + 1)},
                     {"error": "x", "addition": [None] * (MAX_LIST_ITEMS + 1)},
                     {"error": "x", **nested_object(MAX_DEPTH + 1)},
                     {"error": "x", **node_boundary(extra=1)},
                     {"error": "x", **byte_boundary()}):
            self.reject(method, body, http_status=503)
        with self.assertRaises(responses.UpstreamResponseError):
            responses.validate_response(method, {"error": "x" * MAX_STRING_BYTES}, http_status=503)

    def test_shared_decoder_composes_without_new_response_decode_or_malformed_json_bypass(self):
        for method, row in self.samples.items():
            case = row["cases"][0]
            self.accept(method, json_inputs.decode_body(encoded(case["payload"])))
        for raw in (b"", b"[]", b"null", b"{} trailing", b'{"error":}',
                    b'{"error":null,"error":"duplicate"}', b'{"x":1,"\\u0078":2}',
                    b'{"x":NaN}', b'{"x":1e999}', b'{"error":"\xff"}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(json_inputs.ContractError):
                json_inputs.decode_body(raw)

    def test_validation_errors_redact_arbitrary_values_keys_and_schema_looking_opaque_keys(self):
        secret = "SYNTHETIC-sensitive-upstream-text"
        key = "SYNTHETIC-private-object-key"
        cases = (("OrgService.GetOrg", {key: {"prefix": float("nan")}}),
                 ("UsersService.GetSession", {"user": {"email": {key: secret}}}),
                 ("ActivityService.FilterActivity", {"activityItems": [{
                     "fieldValues": {key: {"limit": {"query": float("nan")}}}}]}),
                 ("OrgService.GetOrg", {"org": {"orgID": "org", "importantActivities": [{
                     "fieldValues": {key: {"userID": float("nan")}}}]}}))
        for method, payload in cases:
            with self.subTest(method=method):
                error = self.reject(method, payload)
                for representation in (str(error), repr(error)):
                    self.assertNotIn(secret, representation)
                    self.assertNotIn(key, representation)
        error = self.reject("ActivityService.FilterActivity", cases[2][1])
        self.assertIn("fieldValues.<key>.<key>.<key>", str(error))
        self.assertNotIn("limit", str(error))
        self.assertNotIn("query", str(error))
        self.assertNotIn(secret, str(self.reject(secret, {})))
        self.assertNotIn(secret, str(self.reject("OrgService.GetOrg", {}, http_status=secret)))

    def test_transport_errors_never_expose_raw_upstream_text_in_message_repr_or_attributes(self):
        for raw_error in ("", "SYNTHETIC-sensitive-email@example.invalid",
                          "SYNTHETIC-sensitive-token", "upstream-host.internal/path?private=value"):
            with self.assertRaises(responses.UpstreamResponseError) as raised:
                responses.validate_response("OrgService.GetOrg", {"error": raw_error}, http_status=403)
            error = raised.exception
            self.assertEqual(str(error), TRANSPORT_MESSAGE)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            if raw_error:
                for representation in (str(error), repr(error), repr(error.args), repr(vars(error))):
                    self.assertNotIn(raw_error, representation)

    def test_validator_never_logs_or_prints_arbitrary_response_data(self):
        secret = "SYNTHETIC-private-upstream@example.invalid"
        with patch.object(logging.Logger, "_log") as log, patch("builtins.print") as output:
            self.accept("UsersService.GetUser", {"user": {"email": secret, "userID": None}})
            self.reject("UsersService.GetUser", {"user": {"userID": {secret: "bad type"}}})
            with self.assertRaises(responses.UpstreamResponseError):
                responses.validate_response("UsersService.GetUser", {"error": secret}, http_status=500)
        log.assert_not_called()
        output.assert_not_called()


if __name__ == "__main__":
    unittest.main()
