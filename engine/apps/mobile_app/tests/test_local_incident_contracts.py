"""[code] Test-first specification for the finite, unrouted native request boundary.

[code] These pure unittest tests exercise the independent contracts module;
no Django setup, database, auth bootstrap, App execution, or Cloud access is used.
[code] Native examples/evidence live in local_incident_native_requests.json.
[code] Bounds below are provisional local policy, NOT recovered server limits.
[code] Run from engine: python -I -B -m unittest discover -s apps/mobile_app/tests
    -t . -p test_local_incident_contracts.py -v
"""

import copy
import hashlib
import json
import logging
import unittest
from pathlib import Path
from unittest.mock import patch

from apps.mobile_app.local_incident import contracts


SOURCE_SHA256 = "2e425c76142d36745d979271623f9807e71ba0d20a6e19feca0cef61ff099c5e"
FIXTURE_SHA256 = "04d7148abb827fdc5284e089858bca84db71485f7a17cc9f428d2748dc012aa4"
FIXTURE_PATH = Path(__file__).with_name("local_incident_native_requests.json")
MAX_BODY_BYTES = 1024 * 1024
MAX_DEPTH = 16
MAX_NODES = 10_000
MAX_STRING_BYTES = 256 * 1024
MAX_LIST_ITEMS = 1000
MAX_QUERY_LIMIT = 100
NATIVE_PREFIX = "mobile_app/v1/gateway/incident"
EXPECTED_METHODS = frozenset(
    """
    ActivityService.FilterActivity ActivityService.QueryActivity
    CommentsService.AddReaction CommentsService.RemoveReaction
    FieldsService.GetFields
    IncidentContextService.AddIncidentContext
    IncidentContextService.QueryIncidentContext
    IncidentsService.AssignLabelByUUID IncidentsService.AssignRole
    IncidentsService.CreateIncident IncidentsService.GetIncident
    IncidentsService.QueryIncidentPreviews IncidentsService.UnassignLabelByUUID
    IncidentsService.UnassignRole IncidentsService.UpdateDescription
    IncidentsService.UpdateSeverity IncidentsService.UpdateStatus
    IncidentsService.UpdateTitle
    KeyUpdatesService.CreateKeyUpdate KeyUpdatesService.GetLastKeyUpdate
    KeyUpdatesService.QueryKeyUpdates OrgService.GetOrg OrgService.GetOrgStatus
    SeveritiesService.GetOrgSeverities StatusService.QueryOrgStatuses
    UsersService.AutocompleteUsers UsersService.GetSession UsersService.GetUser
    """.split()
)
QUERY_WRAPPERS = {
    "ActivityService.FilterActivity": "filter",
    "ActivityService.QueryActivity": "query",
    "IncidentContextService.QueryIncidentContext": "query",
    "IncidentsService.QueryIncidentPreviews": "query",
    "KeyUpdatesService.QueryKeyUpdates": "query",
}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")


def nested_object(depth):
    """[code] The root object is depth one; property names are not value nodes."""
    value = {}
    for _ in range(depth - 1):
        value = {"child": value}
    return value


def node_boundary(extra=0):
    """[code] Root + outer list + ten inner lists + scalar leaves = 10000."""
    return {"fieldValues": [[None] * 1000 for _ in range(9)] + [[None] * (988 + extra)]}


class LocalIncidentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = FIXTURE_PATH.read_bytes()
        if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
            raise AssertionError("native request fixture digest changed")
        cls.fixture = json.loads(raw)
        cls.samples = {row["method"]: row for row in cls.fixture["methods"]}

    def request(self, method):
        return copy.deepcopy(self.samples[method]["request"])

    def reject(self, method, payload, field=None):
        with self.assertRaises(contracts.ContractError) as raised:
            contracts.validate_request(method, payload)
        if field is not None:
            self.assertIn(field.casefold(), str(raised.exception).casefold())
        return raised.exception

    def decode_reject(self, raw):
        with self.assertRaises(contracts.ContractError) as raised:
            contracts.decode_body(raw)
        return raised.exception

    def test_error_is_a_value_error(self):
        self.assertTrue(issubclass(contracts.ContractError, ValueError))

    def test_registry_is_exactly_the_finite_native_surface(self):
        self.assertEqual(len(EXPECTED_METHODS), 28)
        self.assertEqual(set(contracts.METHODS), EXPECTED_METHODS)
        self.assertEqual(len(contracts.METHODS), 28)
        self.assertEqual(set(self.samples), EXPECTED_METHODS)
        self.assertEqual(self.fixture["source"]["sha256"], SOURCE_SHA256)
        self.assertIn("[code]", self.fixture["provenance"])

    def test_all_native_valid_requests_preserve_exact_keys_and_nulls(self):
        for row in self.fixture["methods"]:
            with self.subTest(method=row["method"]):
                original = copy.deepcopy(row["request"])
                self.assertEqual(set(original), set(row["emitted_keys"]))
                self.assertEqual(row["source_fixture"], row["method"] + "/success")
                self.assertEqual(row["path"], NATIVE_PREFIX + "/api/" + row["method"])
                self.assertTrue(row["serializer"].startswith("0x"))
                self.assertTrue(row["route"]["instruction"].startswith("0x"))
                decoded = contracts.decode_body(encoded(original))
                result = contracts.validate_request(row["method"], decoded)
                self.assertEqual(result, original)
                self.assertEqual(decoded, original)
                self.assertIsNot(result, decoded)

    def test_nullable_native_outer_fields_are_not_dropped(self):
        expected = {
            "OrgService.GetOrgStatus": {"withHealthcheck": None},
            "FieldsService.GetFields": {"domainName": None},
            "IncidentsService.AssignRole": {"invite": None},
            "IncidentsService.UpdateStatus": {"status": None},
            "KeyUpdatesService.GetLastKeyUpdate": {"contentType": None},
            "IncidentsService.QueryIncidentPreviews": {"includeIncidentChannels": None},
        }
        for method, nullable in expected.items():
            with self.subTest(method=method):
                result = contracts.validate_request(method, self.request(method))
                for key in nullable:
                    self.assertIn(key, result)
                    self.assertIsNone(result[key])
        preview = self.request("IncidentsService.QueryIncidentPreviews")
        self.assertEqual(len(preview), 5)
        self.assertEqual(len(self.request("IncidentsService.CreateIncident")), 19)

    def test_additional_native_pagination_and_reaction_requests(self):
        for row in self.fixture["additional_requests"]:
            with self.subTest(source_fixture=row["source_fixture"]):
                self.assertEqual(
                    contracts.validate_request(row["method"], copy.deepcopy(row["request"])),
                    row["request"],
                )

    def test_timeline_kind_and_cursor_axes_are_independent_native_inputs(self):
        rows = [row for row in self.fixture["additional_requests"]
                if row["source_fixture"].startswith("activity-kind-cursor-matrix/")]
        self.assertEqual(len(rows), 4)
        for row in rows:
            _, has_kind, has_cursor = row["source_fixture"].split("/")
            method = ("ActivityService.QueryActivity" if has_kind == "True"
                      else "ActivityService.FilterActivity")
            with self.subTest(kind=has_kind, cursor=has_cursor):
                self.assertEqual(row["method"], method)
                self.assertEqual(row["request"]["cursor"] is not None, has_cursor == "True")
                self.assertEqual(contracts.validate_request(method, row["request"]), row["request"])
                wrong = ("ActivityService.FilterActivity" if has_kind == "True"
                         else "ActivityService.QueryActivity")
                self.reject(wrong, row["request"])

    def test_native_query_defaults_are_not_rewritten(self):
        defaults = {
            "ActivityService.FilterActivity": 80,
            "ActivityService.QueryActivity": 80,
            "IncidentContextService.QueryIncidentContext": 12,
            "IncidentsService.QueryIncidentPreviews": 100,
            "KeyUpdatesService.QueryKeyUpdates": 20,
        }
        for method, limit in defaults.items():
            with self.subTest(method=method):
                result = contracts.validate_request(method, self.request(method))
                self.assertEqual(result[QUERY_WRAPPERS[method]]["limit"], limit)

    def test_exact_incident_relative_api_paths_resolve_every_method(self):
        for method in EXPECTED_METHODS:
            with self.subTest(method=method):
                self.assertEqual(contracts.resolve_method("/api/" + method, http_method="POST"), method)

    def test_non_post_verbs_do_not_resolve(self):
        for verb in ("GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "post", "", None):
            with self.subTest(verb=verb), self.assertRaises(contracts.ContractError):
                contracts.resolve_method("/api/OrgService.GetOrg", http_method=verb)

    def test_unknown_paths_and_normalization_aliases_fail_closed(self):
        paths = (
            "/api/IncidentsService.DeleteIncident", "/api/TasksService.AddTask",
            "/api/OrgService.GetOrgExtra", "/api/OrgServiceX.GetOrg",
            "/api/UsersService.GetSession/", "/api/UsersService.GetSession/x",
            "api/OrgService.GetOrg", "OrgService.GetOrg", "/API/OrgService.GetOrg",
            "/x/api/OrgService.GetOrg", "/api//OrgService.GetOrg",
            "/api/../api/OrgService.GetOrg", "/api/./OrgService.GetOrg",
            "/api/OrgService%2eGetOrg", "/api/%2fOrgService.GetOrg",
            "/api/%252fOrgService.GetOrg", "/api/OrgService.GetOrg%2f",
            "/api/OrgService.GetOrg?orgID=other", "/api/OrgService.GetOrg#other",
            "/api/OrgService.GetOrg\\other", "/api/OrgService.GetOrg\x00",
            " /api/OrgService.GetOrg", "/api/OrgService.GetOrg ",
            "https://example.invalid/api/OrgService.GetOrg",
            "/mobile_app/v1/gateway/incident/api/OrgService.GetOrg",
        )
        for path in paths:
            with self.subTest(path=path), self.assertRaises(contracts.ContractError):
                contracts.resolve_method(path, http_method="POST")

    def test_unknown_logical_methods_are_rejected_without_prefix_dispatch(self):
        methods = ("", "OrgService.", "OrgService.GetOrgExtra", "OrgService.GetOrg/x",
                   "IncidentsService.DeleteIncident", "UsersService.GetSession?x=1",
                   "../OrgService.GetOrg", "/api/OrgService.GetOrg", None, 17)
        for method in methods:
            with self.subTest(method=method):
                self.reject(method, {})

    def test_json_accepts_utf8_object_and_preserves_scalar_types(self):
        body = {"text": "事件 café \U0001f680", "integer": 1, "float": 1.25,
                "flag": False, "null": None, "list": [1, "1", None]}
        self.assertEqual(contracts.decode_body(encoded(body)), body)
        self.assertEqual(contracts.decode_body(b'{"text":"\\ud83d\\ude80"}'), {"text": "\U0001f680"})

    def test_json_rejects_malformed_non_object_or_non_utf8_bodies(self):
        bodies = (b"", b" ", b"[]", b"null", b"true", b"1", b'"text"',
                  b"{", b'{"a":}', b'{"a":1,}', b"{} {}", b"{} trailing",
                  b'{"text":"\xff"}', b"\xef\xbb\xbf{}", b"\xff\xfe{\x00}\x00",
                  b'{"text":"\\ud800"}', b'{"text":"\\udfff"}')
        for raw in bodies:
            with self.subTest(raw=raw):
                self.decode_reject(raw)
        for non_bytes in ("{}", None, {}, bytearray(b"{}")):
            with self.subTest(type=type(non_bytes).__name__):
                self.decode_reject(non_bytes)

    def test_duplicate_keys_rejected_at_every_depth_including_escaped_aliases(self):
        bodies = (
            b'{"incidentID":"a","incidentID":"b"}',
            b'{"query":{"limit":1,"limit":2}}',
            b'{"query":{"limit":1,"\\u006cimit":2}}',
            b'{"fieldValues":{"nested":[{"x":1,"x":2}]}}',
        )
        for raw in bodies:
            with self.subTest(raw=raw):
                self.decode_reject(raw)

    def test_nonfinite_json_numbers_are_not_silently_accepted(self):
        for token in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            with self.subTest(token=token):
                self.decode_reject(('{"fieldValues":{"number":' + token + "}}").encode())

    def test_raw_body_byte_limit_is_inclusive_and_checked_before_parse(self):
        at_limit = b"{}" + b" " * (MAX_BODY_BYTES - 2)
        self.assertEqual(contracts.decode_body(at_limit), {})
        self.decode_reject(at_limit + b" ")
        self.decode_reject(b" " * (MAX_BODY_BYTES + 1))

    def test_depth_bound_is_inclusive_with_root_at_one(self):
        self.assertEqual(contracts.decode_body(encoded(nested_object(MAX_DEPTH))), nested_object(MAX_DEPTH))
        self.decode_reject(encoded(nested_object(MAX_DEPTH + 1)))

    def test_node_bound_counts_containers_and_values_not_property_names(self):
        self.assertEqual(contracts.decode_body(encoded(node_boundary())), node_boundary())
        self.decode_reject(encoded(node_boundary(extra=1)))

    def test_array_length_bound_is_inclusive(self):
        self.assertEqual(contracts.decode_body(encoded({"items": [None] * MAX_LIST_ITEMS})),
                         {"items": [None] * MAX_LIST_ITEMS})
        self.decode_reject(encoded({"items": [None] * (MAX_LIST_ITEMS + 1)}))

    def test_string_and_key_bounds_use_utf8_bytes_not_character_count(self):
        at_limit = "é" * (MAX_STRING_BYTES // 2)
        self.assertEqual(contracts.decode_body(encoded({"value": at_limit})), {"value": at_limit})
        self.decode_reject(encoded({"value": at_limit + "é"}))
        self.assertEqual(contracts.decode_body(encoded({at_limit: None})), {at_limit: None})
        self.decode_reject(encoded({at_limit + "é": None}))

    def test_every_method_rejects_unknown_top_level_fields(self):
        for method in EXPECTED_METHODS:
            with self.subTest(method=method):
                self.reject(method, {**self.request(method), "unknownField": "synthetic"}, "<key>")

    def test_routing_authority_and_auth_keys_are_not_request_fields(self):
        keys = ("url", "path", "method", "service", "baseURL", "baseUrl", "orgID",
                "stackID", "grafanaOrgID", "actorUserID", "Authorization", "headers", "token", "email")
        for key in keys:
            with self.subTest(key=key):
                self.reject("OrgService.GetOrg", {key: "not-authority"}, "<key>")

    def test_unknown_nested_query_and_cursor_fields_are_rejected(self):
        for method, wrapper in QUERY_WRAPPERS.items():
            with self.subTest(method=method):
                request = self.request(method)
                request[wrapper] = {**request[wrapper], "unknownField": True}
                self.reject(method, request, "<key>")
                request = {**self.request(method), "cursor": {"nextValue": "opaque", "orgID": "other"}}
                self.reject(method, request, "<key>")

    def test_query_limit_accepts_bounded_positive_integers_without_coercion(self):
        for method, wrapper in QUERY_WRAPPERS.items():
            for limit in (1, MAX_QUERY_LIMIT):
                with self.subTest(method=method, limit=limit):
                    request = self.request(method)
                    request[wrapper] = {**request[wrapper], "limit": limit}
                    self.assertEqual(contracts.validate_request(method, request), request)
            for limit in (0, -1, MAX_QUERY_LIMIT + 1, True, False, "20", 20.0, [], {}):
                with self.subTest(method=method, invalid=limit):
                    request = self.request(method)
                    request[wrapper] = {**request[wrapper], "limit": limit}
                    self.reject(method, request, "limit")

    def test_declared_string_fields_never_coerce_numbers_or_booleans(self):
        non_strings = {"cursor", "query", "filter", "includeCustomFieldValues",
                       "includeMembershipPreview", "includeIncidentChannels", "invite",
                       "isDrill", "metadata", "syncResponse", "fieldValues", "refs",
                       "labels", "withHealthcheck"}
        for method in EXPECTED_METHODS:
            for field in set(self.samples[method]["request"]) - non_strings:
                for value in (1, True, [], {}):
                    with self.subTest(method=method, field=field, invalid=value):
                        self.reject(method, {**self.request(method), field: value}, field)
        for method, wrapper in QUERY_WRAPPERS.items():
            for field in set(self.samples[method]["request"][wrapper]) - {"limit", "activityKind"}:
                request = self.request(method)
                request[wrapper] = {**request[wrapper], field: True}
                with self.subTest(method=method, field=field):
                    self.reject(method, request, field)

    def test_known_query_containers_and_activity_kind_list_are_not_coerced(self):
        for method, wrapper in QUERY_WRAPPERS.items():
            for value in (True, "query", []):
                with self.subTest(method=method, invalid=value):
                    self.reject(method, {**self.request(method), wrapper: value}, wrapper)
        method = "ActivityService.QueryActivity"
        for value in ("userNote", True, {}, [1], [True], [{"kind": "userNote"}]):
            request = self.request(method)
            request["query"] = {**request["query"], "activityKind": value}
            with self.subTest(activityKind=value):
                self.reject(method, request, "activityKind")

    def test_native_nullable_context_query_fields_remain_nullable(self):
        method = "IncidentContextService.QueryIncidentContext"
        request = self.request(method)
        request["query"] = {key: None for key in request["query"]}
        self.assertEqual(contracts.validate_request(method, request), request)

    def test_nullable_partial_cursor_fields_are_independent_and_opaque(self):
        method = "IncidentsService.QueryIncidentPreviews"
        cursors = (None, {}, {"nextValue": None}, {"hasMore": None},
                   {"nextValue": "opaque-not-an-offset"}, {"hasMore": False},
                   {"nextValue": "opaque", "hasMore": None})
        for cursor in cursors:
            with self.subTest(cursor=cursor):
                request = {**self.request(method), "cursor": cursor}
                self.assertEqual(contracts.validate_request(method, request), request)
        for cursor in (False, "opaque", [], {"nextValue": 2}, {"hasMore": 1}, {"hasMore": "true"}):
            with self.subTest(invalid=cursor):
                self.reject(method, {**self.request(method), "cursor": cursor}, "cursor")

    def test_domain_user_id_is_a_legal_target_not_caller_authority(self):
        for method in ("UsersService.GetUser", "IncidentsService.AssignRole", "IncidentsService.UnassignRole"):
            for target in ("irm-target-opaque", "17", "target-other-than-authenticated-caller"):
                with self.subTest(method=method, target=target):
                    request = {**self.request(method), "userID": target}
                    result = contracts.validate_request(method, request)
                    self.assertEqual(result["userID"], target)
                    self.assertNotIn("actorUserID", result)
            for target in (17, True, [], {}):
                with self.subTest(method=method, invalid=target):
                    self.reject(method, {**self.request(method), "userID": target}, "userID")

    def test_optional_boolean_fields_accept_null_and_bool_but_never_numbers_or_text(self):
        fields = {
            "OrgService.GetOrgStatus": ("withHealthcheck",),
            "IncidentsService.AssignRole": ("invite",),
            "IncidentsService.CreateIncident": ("isDrill",),
            "IncidentContextService.AddIncidentContext": ("syncResponse",),
            "IncidentsService.QueryIncidentPreviews": (
                "includeCustomFieldValues", "includeMembershipPreview", "includeIncidentChannels"),
        }
        for method, names in fields.items():
            for field in names:
                for value in (None, False, True):
                    with self.subTest(method=method, field=field, value=value):
                        request = {**self.request(method), field: value}
                        self.assertEqual(contracts.validate_request(method, request), request)
                for value in (0, 1, "true", [], {}):
                    with self.subTest(method=method, field=field, invalid=value):
                        self.reject(method, {**self.request(method), field: value}, field)

    def test_sparse_optional_requests_do_not_acquire_web_schema_requiredness(self):
        samples = {
            "OrgService.GetOrgStatus": {}, "FieldsService.GetFields": {},
            "StatusService.QueryOrgStatuses": {"incidentType": None},
            "IncidentsService.CreateIncident": {"title": "Synthetic minimal incident"},
            "IncidentsService.AssignRole": {"incidentID": "inc", "userID": "target", "role": "commander"},
            "KeyUpdatesService.CreateKeyUpdate": {"incidentID": "inc", "content": "Synthetic update"},
            "IncidentContextService.AddIncidentContext": {"incidentID": "inc", "type": "genericURL", "payload": "https://example.invalid"},
            "KeyUpdatesService.GetLastKeyUpdate": {"incidentID": "inc"},
        }
        for method, request in samples.items():
            with self.subTest(method=method):
                self.assertEqual(contracts.validate_request(method, request), request)

    def test_only_go_operation_mandatory_fields_are_required(self):
        mandatory = {
            "IncidentsService.CreateIncident": ("title",),
            "IncidentsService.AssignRole": ("incidentID", "userID", "role"),
            "IncidentsService.UnassignRole": ("incidentID", "userID", "role"),
            "CommentsService.AddReaction": ("incidentID", "targetID", "targetKind", "reaction"),
            "CommentsService.RemoveReaction": ("incidentID", "targetID", "targetKind", "reaction"),
            "IncidentContextService.AddIncidentContext": ("incidentID", "type", "payload"),
            "KeyUpdatesService.CreateKeyUpdate": ("incidentID", "content"),
        }
        for method, fields in mandatory.items():
            for field in fields:
                with self.subTest(method=method, missing=field):
                    request = {key: value for key, value in self.request(method).items() if key != field}
                    self.reject(method, request, field)
                for value in (None, "", "   ", 1, True):
                    with self.subTest(method=method, field=field, invalid=value):
                        self.reject(method, {**self.request(method), field: value}, field)

    def test_existing_go_query_mandatory_fields_are_not_silently_defaulted(self):
        for method in ("IncidentContextService.QueryIncidentContext", "KeyUpdatesService.QueryKeyUpdates"):
            for value in (None, False, [], "query"):
                with self.subTest(method=method, query=value):
                    self.reject(method, {**self.request(method), "query": value}, "query")
            self.reject(method, {"cursor": None}, "query")
        method = "KeyUpdatesService.QueryKeyUpdates"
        for value in (None, "", 1, True):
            request = self.request(method)
            request["query"] = {**request["query"], "incidentID": value}
            with self.subTest(incidentID=value):
                self.reject(method, request, "incidentID")

    def test_go_create_title_and_content_bounds_are_enforced(self):
        cases = (("IncidentsService.CreateIncident", "title", 300),
                 ("IncidentsService.CreateIncident", "description", 50_000),
                 ("KeyUpdatesService.CreateKeyUpdate", "content", 50_000))
        for method, field, maximum in cases:
            with self.subTest(method=method, field=field):
                request = {**self.request(method), field: "x" * maximum}
                self.assertEqual(contracts.validate_request(method, request), request)
                self.reject(method, {**request, field: "x" * (maximum + 1)}, field)

    def test_native_uuid_write_key_names_are_exact_but_values_are_opaque(self):
        for method in ("IncidentsService.AssignLabelByUUID", "IncidentsService.UnassignLabelByUUID"):
            with self.subTest(method=method):
                request = self.request(method)
                self.assertEqual(contracts.validate_request(method, request), request)
                self.reject(method, {**request, "labelUUID": request["valueUUID"]}, "<key>")
                for field in ("keyUUID", "valueUUID"):
                    for value in (123, True, []):
                        self.reject(method, {**request, field: value}, field)

    def test_native_label_and_ref_objects_are_not_web_aliases(self):
        method = "IncidentsService.CreateIncident"
        label = {"key": "service", "keyUUID": "opaque-key", "label": "api",
                 "labelUUID": "opaque-label", "description": None, "colorHex": None}
        ref = {"key": "source", "ref": "synthetic-reference", "url": None}
        request = {**self.request(method), "labels": [label], "refs": [ref]}
        self.assertEqual(contracts.validate_request(method, request), request)
        for field, invalid in (("labels", ["service:api"]), ("labels", [None]),
                               ("labels", [{**label, "valueUUID": "wrong-field"}]),
                               ("labels", [{**label, "label": 1}]),
                               ("refs", [{**ref, "unknownField": True}]), ("refs", [1])):
            with self.subTest(field=field, invalid=invalid):
                self.reject(method, {**request, field: invalid}, field)

    def test_both_native_reaction_target_kinds_are_valid_not_arbitrary_strings(self):
        for method in ("CommentsService.AddReaction", "CommentsService.RemoveReaction"):
            for kind in ("activityItem", "comment"):
                request = {**self.request(method), "targetKind": kind}
                self.assertEqual(contracts.validate_request(method, request), request)
            for kind in ("activity", "incident", "user", "Comment"):
                with self.subTest(method=method, invalid=kind):
                    self.reject(method, {**self.request(method), "targetKind": kind}, "targetKind")

    def test_query_strings_remain_opaque_not_an_invented_server_grammar(self):
        method = "IncidentsService.QueryIncidentPreviews"
        queries = ("", "state:'active'", "or(and(role:'observer' user.email:'mine@example.invalid') createdby:'mine@example.invalid')")
        for text in queries:
            request = self.request(method)
            request["query"] = {**request["query"], "queryString": text}
            self.assertEqual(contracts.validate_request(method, request), request)

    def test_explicit_opaque_field_values_are_bounded_json_not_guessed_generics(self):
        method = "IncidentsService.CreateIncident"
        opaque = {"synthetic": [None, True, 1, 1.25, "text", {"unresolved": ["x"]}]}
        request = {**self.request(method), "fieldValues": opaque}
        self.assertEqual(contracts.validate_request(method, request), request)
        for value in (float("nan"), float("inf"), b"bytes", {1: "non-string-key"}, {"x"}, (1, 2)):
            with self.subTest(invalid=type(value).__name__):
                self.reject(method, {**request, "fieldValues": value}, "fieldValues")

    def test_direct_validator_cannot_bypass_json_safety_bounds(self):
        method = "IncidentsService.CreateIncident"
        values = ([None] * (MAX_LIST_ITEMS + 1), "x" * (MAX_STRING_BYTES + 1),
                  nested_object(MAX_DEPTH), node_boundary(extra=1))
        for value in values:
            with self.subTest(invalid=type(value).__name__):
                self.reject(method, {**self.request(method), "fieldValues": value})
        cycle = {}
        cycle["self"] = cycle
        self.reject(method, {**self.request(method), "fieldValues": cycle})
        for root in (None, [], True, "{}"):
            self.reject(method, root)

    def test_validator_does_not_mutate_or_alias_nested_input(self):
        method = "IncidentsService.QueryIncidentPreviews"
        request = {**self.request(method), "cursor": {"nextValue": "opaque", "hasMore": None}}
        before = copy.deepcopy(request)
        result = contracts.validate_request(method, request)
        self.assertEqual(request, before)
        self.assertIsNot(result, request)
        self.assertIsNot(result["query"], request["query"])
        self.assertIsNot(result["cursor"], request["cursor"])
        # [code] Deliberately mutate the returned copy to expose input aliasing.
        result["query"]["limit"] = 1
        result["cursor"]["nextValue"] = "changed"
        self.assertEqual(request, before)
        invalid = {**request, "unknownField": True}
        rejected_before = copy.deepcopy(invalid)
        self.reject(method, invalid)
        self.assertEqual(invalid, rejected_before)

    def test_arbitrary_unknown_keys_are_redacted_not_identifier_filtered(self):
        secret = "sk_live_SYNTHETIC_secret"
        method = "IncidentsService.QueryIncidentPreviews"
        cases = (
            ("OrgService.GetOrg", {secret: 0}),
            (method, {**self.request(method), "query": {"limit": 1, secret: 0}}),
            (method, {**self.request(method), "cursor": {secret: 0}}),
            ("IncidentsService.CreateIncident", {
                **self.request("IncidentsService.CreateIncident"),
                "labels": [{"label": "synthetic", secret: 0}]}),
        )
        for logical_method, request in cases:
            with self.subTest(method=logical_method):
                error = self.reject(logical_method, request, "<key>")
                self.assertNotIn(secret, str(error))
                self.assertNotIn(secret, repr(error))
        self.assertIn("<key>", str(self.reject("OrgService.GetOrg", {"query": 0})))
        method_error = self.reject(secret, {})
        with self.assertRaises(contracts.ContractError) as raised:
            contracts.resolve_method("/api/" + secret, http_method="POST")
        for error in (method_error, raised.exception):
            self.assertNotIn(secret, str(error))
            self.assertNotIn(secret, repr(error))

    def test_duplicate_raw_keys_never_expose_arbitrary_names(self):
        secret = "sk_live_SYNTHETIC_secret"
        key = json.dumps(secret).encode()
        duplicate = b"{" + key + b":0," + key + b":1}"
        for raw in (duplicate, b'{"fieldValues":' + duplicate + b"}", b'{"limit":0,"limit":1}'):
            with self.subTest(raw=raw):
                error = self.decode_reject(raw)
                self.assertIn("<key>", str(error))
                self.assertNotIn(secret, str(error))
                self.assertNotIn(secret, repr(error))
        self.assertNotIn("limit", str(self.decode_reject(b'{"limit":0,"limit":1}')))

    def test_opaque_error_paths_redact_all_arbitrary_keys_and_prefixes(self):
        secret = "sk_live_SYNTHETIC_secret"
        prefix = "arbitraryPrefixSYNTHETIC"
        cases = (("IncidentsService.CreateIncident", "fieldValues"),
                 ("IncidentContextService.AddIncidentContext", "metadata"))
        for method, field in cases:
            opaque = {prefix: {secret: [float("nan")]}}
            request = {**self.request(method), field: opaque}
            with self.subTest(field=field):
                error = self.reject(method, request, field)
                self.assertIn("<key>", str(error))
                self.assertNotIn(secret, str(error))
                self.assertNotIn(prefix, str(error))
                self.assertNotIn(secret, repr(error))
                raw = encoded({field: {prefix: {secret: "x" * (MAX_STRING_BYTES + 1)}}})
                error = self.decode_reject(raw)
                self.assertIn("<key>", str(error))
                self.assertNotIn(secret, str(error))
                self.assertNotIn(prefix, str(error))
        request = {**self.request(cases[0][0]), "fieldValues": {"query": {"limit": float("nan")}}}
        error = self.reject(cases[0][0], request)
        self.assertIn("fieldValues.<key>.<key>", str(error))
        self.assertNotIn("query", str(error))
        self.assertNotIn("limit", str(error))

    def test_validation_never_logs_raw_email_token_or_request_values(self):
        email = "synthetic-sensitive-person@example.invalid"
        token = "synthetic-sensitive-token-not-a-real-credential"
        raw = encoded({"email": email, "token": token})
        with patch.object(logging.Logger, "_log") as log, patch("builtins.print") as output:
            self.assertEqual(contracts.decode_body(raw), {"email": email, "token": token})
            error = self.reject("OrgService.GetOrg", {"email": email, "token": token})
            malformed = self.decode_reject(raw + b" trailing")
            self.assertEqual(contracts.validate_request("UsersService.AutocompleteUsers", {"text": email}),
                             {"text": email})
        log.assert_not_called()
        output.assert_not_called()
        for error_value in (str(error), repr(error), str(malformed), repr(malformed)):
            self.assertNotIn(email, error_value)
            self.assertNotIn(token, error_value)


if __name__ == "__main__":
    unittest.main()
