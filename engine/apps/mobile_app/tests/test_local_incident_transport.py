"""[code] TESTS FIRST ONLY: finite server-to-server local Incident HTTP transport.

[code] Intended module/API (not implemented by this specification):
    call_incident(binding, pair, path, raw_body, *, http_method="POST") -> dict
    METHOD_PATHS: immutable logical-method -> reserved Go resource path mapping
    IncidentTransportError(ValueError): static "incident transport unavailable"
[code] binding is the existing frozen web_session.config.Binding, already validated
by the caller; pair is the ephemeral two-key dict returned by tokens.mint_pair.
[code] Core X-Grafana-Org-Id comes ONLY from Binding.grafana_org_id, an exact
positive int64. OnCall org ID, namespace and all inbound selectors are not that ID.
This component neither authenticates nor signs, loads configuration, chooses a
profile, derives actor authority, implements feature mode nor owns a shared limiter.
[code] Current config.origin forbids ALL subpaths. This suite does not silently
widen that policy. Optional trusted subpath support needs a separate config seam.
[code] Request errors and malformed JSON/models reuse json_inputs.ContractError;
valid non-200 envelopes reuse responses.UpstreamResponseError with observed status.
A returned dict is response body only, never headers, credentials or fake success.
[code] Safety policy: raw request/response <=1 MiB, connect/read timeouts (3, 5),
identity encoding, a fresh closed Session per call, no redirects/retries/failover.
Requests timeouts are socket connect/read bounds, NOT a total deadline, immediate
cancellation guarantee or evidence that a timed-out write was not committed.
[code] The exact resource map below reserves a NEW Go entry point; it is not the
existing generic dispatcher or a runtime path-rewrite rule. No Go route is added.
[code] Offline unittest with real requests preparation and tiny send/raw fixtures;
no sockets, database, existing credentials, App or Cloud. Main owns container RED.
"""

import copy
import hashlib
import inspect
import json
import logging
import os
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import requests
from requests.auth import AuthBase
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import ProtocolError, ReadTimeoutError

from apps.mobile_app.local_incident import contracts, json_inputs, responses, transport
from apps.mobile_app.web_session import config, tokens


MAX_BODY_BYTES = 1024 * 1024
TRANSPORT_MESSAGE = "incident transport unavailable"
BASE = "http://grafana:3000"
ACCESS = "synthetic-server-access-token"
IDENTITY = "synthetic-server-identity-token"
PRIVATE = "synthetic-private-key-material"
CLIENT_SECRET = "synthetic-inbound-client-credential"
RealSession = requests.sessions.Session

# [code] Independent literal fixture, intentionally NOT derived from production map.
EXPECTED_PATHS = {
    "ActivityService.FilterActivity":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/ActivityService.FilterActivity",
    "ActivityService.QueryActivity":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/ActivityService.QueryActivity",
    "CommentsService.AddReaction":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/CommentsService.AddReaction",
    "CommentsService.RemoveReaction":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/CommentsService.RemoveReaction",
    "FieldsService.GetFields":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/FieldsService.GetFields",
    "IncidentContextService.AddIncidentContext":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentContextService.AddIncidentContext",
    "IncidentContextService.QueryIncidentContext":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentContextService.QueryIncidentContext",
    "IncidentsService.AssignLabelByUUID":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.AssignLabelByUUID",
    "IncidentsService.AssignRole":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.AssignRole",
    "IncidentsService.CreateIncident":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.CreateIncident",
    "IncidentsService.GetIncident":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.GetIncident",
    "IncidentsService.QueryIncidentPreviews":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.QueryIncidentPreviews",
    "IncidentsService.UnassignLabelByUUID":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UnassignLabelByUUID",
    "IncidentsService.UnassignRole":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UnassignRole",
    "IncidentsService.UpdateDescription":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateDescription",
    "IncidentsService.UpdateSeverity":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateSeverity",
    "IncidentsService.UpdateStatus":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateStatus",
    "IncidentsService.UpdateTitle":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateTitle",
    "KeyUpdatesService.CreateKeyUpdate":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/KeyUpdatesService.CreateKeyUpdate",
    "KeyUpdatesService.GetLastKeyUpdate":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/KeyUpdatesService.GetLastKeyUpdate",
    "KeyUpdatesService.QueryKeyUpdates":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/KeyUpdatesService.QueryKeyUpdates",
    "OrgService.GetOrg":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/OrgService.GetOrg",
    "OrgService.GetOrgStatus":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/OrgService.GetOrgStatus",
    "SeveritiesService.GetOrgSeverities":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/SeveritiesService.GetOrgSeverities",
    "StatusService.QueryOrgStatuses":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/StatusService.QueryOrgStatuses",
    "UsersService.AutocompleteUsers":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.AutocompleteUsers",
    "UsersService.GetSession":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.GetSession",
    "UsersService.GetUser":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.GetUser",
}
EXPECTED_HEADERS = {
    "X-Access-Token": ACCESS,
    "X-Grafana-Id": IDENTITY,
    "X-Grafana-Org-Id": "1",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Accept-Encoding": "identity",
}
FIXTURE_DIGESTS = {
    "local_incident_native_requests.json":
        "04d7148abb827fdc5284e089858bca84db71485f7a17cc9f428d2748dc012aa4",
    "local_incident_native_responses.json":
        "a24aa20e9075b5788bf3de2019bbeac65d03216b7b09cabc544fe1bf18512ec4",
}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def fixture(name):
    raw = Path(__file__).with_name(name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_DIGESTS[name]:
        raise AssertionError("accepted native fixture digest changed")
    return json.loads(raw)


class RawProbe:
    """[code] Bounded raw API only; fixtures never implement automatic decompression."""

    def __init__(self, data, *, fragment=8192, failure=None, fail_after=0):
        self.data = data
        self.fragment = fragment
        self.failure = failure
        self.fail_after = fail_after
        self.reads = []
        self.offset = 0
        self.closed = False
        self.decode_content = True

    def read(self, amt=None, decode_content=None):
        if type(amt) is not int or not 0 < amt <= MAX_BODY_BYTES + 1:
            raise AssertionError("transport used an unbounded raw read")
        if decode_content is not False:
            raise AssertionError("transport allowed implicit decompression")
        self.reads.append((amt, decode_content))
        if self.failure is not None and self.offset >= self.fail_after:
            raise self.failure
        end = min(len(self.data), self.offset + min(amt, self.fragment))
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def close(self):
        self.closed = True


class ResponseProbe(requests.Response):
    def __init__(self, data=b"{}", *, status=200, headers=None, **raw_options):
        super().__init__()
        self.status_code = status
        self.headers = CaseInsensitiveDict({"Content-Type": "application/json", **(headers or {})})
        self.raw = RawProbe(data, **raw_options)
        self.closed = False

    @property
    def content(self):
        raise AssertionError("response.content is unbounded and can decompress")

    @property
    def text(self):
        raise AssertionError("response.text can retain upstream secrets")

    def json(self, **kwargs):
        raise AssertionError("use the accepted strict decoder, not response.json")

    def iter_content(self, *args, **kwargs):
        raise AssertionError("iter_content can decompress before enforcing the byte cap")

    def close(self):
        self.closed = True
        self.raw.close()


class AmbientAuthTrap(AuthBase):
    def __call__(self, request):
        raise AssertionError("ambient session authentication was applied")


class SessionProbe(RealSession):
    """[code] Real prepare/merge logic, but send has no network implementation."""

    def __init__(self, outcome, *, poisoned=False):
        super().__init__()
        self.outcome = outcome
        self.sent = []
        self.closed = False
        if poisoned:
            self.auth = AmbientAuthTrap()
            self.headers.update({
                "Authorization": CLIENT_SECRET, "Cookie": "session=" + CLIENT_SECRET,
                "X-Grafana-Org-Id": "999", "X-WEBAUTH-USER": CLIENT_SECRET,
                "X-Forwarded-User": CLIENT_SECRET, "X-Access-Token": CLIENT_SECRET,
                "X-Grafana-Id": CLIENT_SECRET, "X-Custom-Inbound": CLIENT_SECRET,
            })
            self.cookies.set("ambient", CLIENT_SECRET)
            self.proxies = {"http": "http://proxy.invalid:8080"}
            self.params = {"ambient": CLIENT_SECRET}
            self.hooks = {"response": [lambda *_args, **_kwargs: self._ambient_hook()]}

    def _ambient_hook(self):
        raise AssertionError("ambient response hook was applied")

    def send(self, request, **kwargs):
        snapshot = {
            "request": request, "options": dict(kwargs), "trust_env": self.trust_env,
            "auth": self.auth, "cookies": dict(self.cookies), "hooks": request.hooks,
            "retries": tuple(adapter.max_retries.total for adapter in self.adapters.values()),
        }
        self.sent.append(snapshot)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        self.outcome.request = request
        self.outcome.url = request.url
        # [code] Simulate a malicious Set-Cookie even when redirects are disabled.
        if "Set-Cookie" in self.outcome.headers:
            self.cookies.set("upstream", CLIENT_SECRET)
        return self.outcome

    def close(self):
        self.closed = True
        super().close()


class SessionFactory:
    def __init__(self, *outcomes, poisoned=False):
        self.outcomes = list(outcomes)
        self.poisoned = poisoned
        self.sessions = []

    def __call__(self):
        if len(self.sessions) >= len(self.outcomes):
            raise AssertionError("unexpected retry/failover or extra session")
        session = SessionProbe(self.outcomes[len(self.sessions)], poisoned=self.poisoned)
        self.sessions.append(session)
        return session


class LogProbe(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class LocalIncidentTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = {row["method"]: row["request"]
                        for row in fixture("local_incident_native_requests.json")["methods"]}
        cls.successes = {
            row["method"]: next(case["payload"] for case in row["cases"]
                                if case["source_fixture"] == row["method"] + "/success")
            for row in fixture("local_incident_native_responses.json")["methods"]
        }

    def setUp(self):
        # [code] Existing immutable type; no key loading, signer or real identities.
        self.binding = config.Binding(
            oncall_org_id=100, grafana_org_id=1, internal_origin=BASE,
            public_origin="https://grafana.example.invalid", namespace="synthetic",
            issuer="synthetic-issuer", key_id="synthetic-key-id", ttl_seconds=60,
            private_key_file="/never/read/synthetic-key.pem", public_der=b"synthetic",
            key=PRIVATE,
        )
        self.pair = {"access_token": ACCESS, "id_token": IDENTITY}
        # [code] Fail closed if code escapes the tiny session factory in any test.
        for target in ("socket.create_connection", "socket.socket.connect", "socket.getaddrinfo"):
            self.enterContext(patch(target, side_effect=AssertionError("real network forbidden")))
        self.enterContext(patch.object(config, "load_binding", side_effect=AssertionError("no config loading")))
        self.enterContext(patch.object(tokens, "mint_pair", side_effect=AssertionError("no token minting")))
        self.logs = LogProbe()
        logging.getLogger().addHandler(self.logs)
        self.addCleanup(logging.getLogger().removeHandler, self.logs)

    def call(self, factory, *, method="UsersService.GetSession", payload=None, raw=None, **options):
        body = encoded({} if payload is None else payload) if raw is None else raw
        with patch.object(transport.requests, "Session", factory):
            return transport.call_incident(
                self.binding, self.pair, "/api/" + method, body, **options)

    def assert_closed(self, factory):
        self.assertEqual(len(factory.sessions), len(factory.outcomes))
        for session in factory.sessions:
            self.assertTrue(session.closed)
            self.assertEqual(dict(session.cookies), {})
            if not isinstance(session.outcome, Exception):
                self.assertTrue(session.outcome.closed)
                self.assertTrue(session.outcome.raw.closed)
                self.assertLessEqual(session.outcome.raw.offset, MAX_BODY_BYTES + 1)

    def assert_private(self, error, *extra):
        disclosure = str(error) + repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
        for record in self.logs.records:
            disclosure += record.getMessage() + repr(record.__dict__)
            if record.exc_info:
                disclosure += "".join(traceback.format_exception(*record.exc_info))
        for secret in (ACCESS, IDENTITY, PRIVATE, CLIENT_SECRET, BASE, *extra):
            self.assertNotIn(secret, disclosure)

    def test_minimal_api_has_no_arbitrary_headers_or_client_selector_surface(self):
        signature = inspect.signature(transport.call_incident)
        self.assertEqual(tuple(signature.parameters), ("binding", "pair", "path", "raw_body", "http_method"))
        self.assertEqual(signature.parameters["http_method"].default, "POST")
        self.assertEqual(signature.parameters["http_method"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertTrue(issubclass(transport.IncidentTransportError, ValueError))

    def test_literal_map_freezes_exactly_the_reserved_28_methods(self):
        self.assertEqual(len(EXPECTED_PATHS), 28)
        self.assertEqual(dict(transport.METHOD_PATHS), EXPECTED_PATHS)
        self.assertEqual(set(EXPECTED_PATHS), contracts.METHODS)
        self.assertEqual(set(EXPECTED_PATHS), responses.METHODS)
        self.assertEqual(set(self.requests), set(EXPECTED_PATHS))
        self.assertEqual(set(self.successes), set(EXPECTED_PATHS))
        with self.assertRaises(TypeError):
            transport.METHOD_PATHS["UsersService.GetSession"] = "/api/user"

    def test_every_native_method_sends_validated_json_to_its_fixed_resource_path(self):
        for method, resource_path in EXPECTED_PATHS.items():
            with self.subTest(method=method):
                request_body = copy.deepcopy(self.requests[method])
                original = copy.deepcopy(request_body)
                upstream = copy.deepcopy(self.successes[method])
                response = ResponseProbe(encoded(upstream), fragment=7)
                factory = SessionFactory(response)
                result = self.call(factory, method=method, payload=request_body)
                sent = factory.sessions[0].sent
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0]["request"].method, "POST")
                self.assertEqual(sent[0]["request"].url, BASE + resource_path)
                self.assertEqual(json_inputs.decode_body(sent[0]["request"].body), original)
                self.assertEqual(result, upstream)
                self.assertIs(type(result), dict)
                self.assertEqual(request_body, original)
                self.assertEqual(self.pair, {"access_token": ACCESS, "id_token": IDENTITY})
                self.assert_closed(factory)

    def test_each_call_gets_a_fresh_session_and_no_pair_or_headers_in_result(self):
        factory = SessionFactory(ResponseProbe(), ResponseProbe())
        with patch("builtins.open", side_effect=AssertionError("transport must not persist credentials")), patch(
            "io.open", side_effect=AssertionError("transport must not persist credentials")
        ):
            self.assertEqual(self.call(factory), {})
            self.assertEqual(self.call(factory), {})
        self.assertIsNot(factory.sessions[0], factory.sessions[1])
        self.assert_closed(factory)

    def test_session_is_clean_even_under_ambient_credentials_and_environment_traps(self):
        factory = SessionFactory(ResponseProbe(), poisoned=True)
        environment = {
            "HTTP_PROXY": "http://proxy.invalid:8080", "HTTPS_PROXY": "http://proxy.invalid:8080",
            "ALL_PROXY": "http://proxy.invalid:8080", "NETRC": "/never/read/netrc",
            "REQUESTS_CA_BUNDLE": "/never/read/ambient-ca", "CURL_CA_BUNDLE": "/never/read/ambient-ca",
        }
        with patch.dict(os.environ, environment), patch(
            "requests.sessions.get_netrc_auth", side_effect=AssertionError("netrc forbidden")
        ), patch("requests.sessions.get_environ_proxies", side_effect=AssertionError("env proxies forbidden")):
            self.assertEqual(self.call(factory), {})
        sent = factory.sessions[0].sent[0]
        self.assertIs(sent["trust_env"], False)
        self.assertIsNone(sent["auth"])
        self.assertEqual(sent["cookies"], {})
        self.assertEqual(sent["hooks"], {"response": []})
        actual_headers = dict(sent["request"].headers)
        actual_headers.pop("Content-Length")
        self.assertEqual(actual_headers, EXPECTED_HEADERS)
        self.assertEqual(sent["options"]["proxies"], {})
        self.assertIs(sent["options"]["verify"], True)
        self.assert_closed(factory)

    def test_numeric_core_org_header_is_server_pinned_not_oncall_pk_namespace_or_inbound(self):
        self.binding = replace(self.binding, namespace="stack-5-not-an-org-selector")
        factory = SessionFactory(ResponseProbe(), poisoned=True)
        self.assertEqual(self.call(factory), {})
        sent = factory.sessions[0].sent[0]["request"]
        self.assertEqual(sent.headers["X-Grafana-Org-Id"], "1")
        self.assertEqual(self.binding.oncall_org_id, 100)
        self.assertNotIn("stack-5", str(sent.headers))
        self.assertNotIn("999", str(sent.headers))
        self.assert_closed(factory)

    def test_numeric_core_org_requires_exact_positive_int64_without_default_before_io(self):
        for numeric_id in (None, True, False, 0, -1, 1.0, "1", 2 ** 63):
            with self.subTest(numeric_id=numeric_id):
                self.binding = replace(self.binding, grafana_org_id=numeric_id)
                factory = SessionFactory()
                with self.assertRaises(json_inputs.ContractError) as raised:
                    self.call(factory)
                self.assertEqual(factory.sessions, [])
                self.assert_private(raised.exception)
        self.binding = object()  # [code] Missing server binding must not default to org 1.
        factory = SessionFactory()
        with self.assertRaises(json_inputs.ContractError):
            self.call(factory)
        self.assertEqual(factory.sessions, [])

    def test_numeric_core_org_int64_upper_boundary_is_preserved_as_decimal_header(self):
        self.binding = replace(self.binding, grafana_org_id=2 ** 63 - 1)
        factory = SessionFactory(ResponseProbe())
        self.call(factory)
        self.assertEqual(factory.sessions[0].sent[0]["request"].headers["X-Grafana-Org-Id"],
                         "9223372036854775807")
        self.assert_closed(factory)

    def test_explicit_socket_timeouts_streaming_no_redirects_and_zero_adapter_retries(self):
        factory = SessionFactory(ResponseProbe())
        self.call(factory)
        sent = factory.sessions[0].sent[0]
        self.assertEqual(sent["options"]["timeout"], (3, 5))
        self.assertIs(sent["options"]["stream"], True)
        self.assertIs(sent["options"]["allow_redirects"], False)
        self.assertTrue(sent["retries"])
        self.assertTrue(all(value == 0 for value in sent["retries"]))
        self.assert_closed(factory)

    def test_unknown_absolute_plugin_dispatcher_escaped_and_query_paths_fail_before_io(self):
        paths = (
            "", "/api/UnknownService.Unknown", "/api/IncidentsService.DeleteIncident",
            "https://cloud.invalid/api/UsersService.GetSession", "//cloud.invalid/api/UsersService.GetSession",
            "/api/plugins/grafana-incident-app/resources/api/UsersService.GetSession",
            EXPECTED_PATHS["UsersService.GetSession"], "/api/UsersService.GetSession?orgId=999",
            "/api/UsersService.GetSession#fragment", "/api/UsersService.GetSession/",
            "/api//UsersService.GetSession", "/api/../UsersService.GetSession",
            "/api/%55sersService.GetSession", "/api/UsersService%2eGetSession",
            "/api/UsersService.GetSession%2f..", "/api/UsersService.GetSession\\extra",
            "/api/UsersService.GetSession\r\nX-Header: value", b"/api/UsersService.GetSession", None,
        )
        for path in paths:
            with self.subTest(path=path):
                factory = SessionFactory()
                with patch.object(transport.requests, "Session", factory), self.assertRaises(
                    json_inputs.ContractError
                ) as raised:
                    transport.call_incident(self.binding, self.pair, path, b"{}")
                self.assertEqual(factory.sessions, [])
                self.assert_private(raised.exception, "cloud.invalid", "X-Header")

    def test_non_post_verbs_fail_before_io(self):
        for verb in ("GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "post", "POST ", None, True):
            with self.subTest(verb=verb):
                factory = SessionFactory()
                with self.assertRaises(json_inputs.ContractError):
                    self.call(factory, http_method=verb)
                self.assertEqual(factory.sessions, [])

    def test_current_origin_policy_is_reused_not_expanded_by_transport(self):
        for base in (BASE, "https://grafana.example.invalid", "http://grafana:3000"):
            with self.subTest(base=base):
                self.assertEqual(config.origin(base, "internal_origin"), base)
                self.binding = replace(self.binding, internal_origin=base)
                factory = SessionFactory(ResponseProbe())
                self.call(factory)
                self.assertEqual(factory.sessions[0].sent[0]["request"].url,
                                 base + EXPECTED_PATHS["UsersService.GetSession"])
                self.assert_closed(factory)

    def test_bad_binding_urls_and_unapproved_subpath_seam_fail_closed_before_io(self):
        origins = (
            "http://user:password@grafana:3000", "http://grafana:3000?key=secret",
            "http://grafana:3000?", "http://grafana:3000#fragment", "http://grafana:3000#",
            "file:///tmp/grafana", "ftp://grafana", "//grafana:3000", "http:///grafana",
            "http://grafana:0", "http://grafana:65536", "http://grafana:bad", "http://grafana./",
            "http://grafana:3000/", "http://grafana:3000/trusted-subpath", "http://grafana:3000/a/../b",
            "http://grafana:3000/%2e%2e", "http://grafana:3000/%252f", "http://grafana:3000/%2f",
            "http://grafana%2elocal:3000", "http://grafana\\@cloud.invalid", "http://[::1]:3000",
            "http://grafana:3000\n", " http://grafana:3000", "http://grafana:3000/%", "http://grafana:3000/%zz",
        )
        for base in origins:
            with self.subTest(base=base):
                self.binding = replace(self.binding, internal_origin=base)
                factory = SessionFactory()
                with self.assertRaises((config.Unavailable, json_inputs.ContractError)) as raised:
                    self.call(factory)
                self.assertEqual(factory.sessions, [])
                self.assert_private(raised.exception, "password", "cloud.invalid", "trusted-subpath")

    def test_pair_has_only_two_nonempty_safe_server_header_values(self):
        pairs = (
            {}, {"access_token": ACCESS}, {"id_token": IDENTITY},
            {"access_token": None, "id_token": IDENTITY}, {"access_token": 123, "id_token": IDENTITY},
            {"access_token": "", "id_token": IDENTITY}, {"access_token": ACCESS, "id_token": ""},
            {"access_token": ACCESS + "\r\nCookie: bad", "id_token": IDENTITY},
            {"access_token": ACCESS, "id_token": IDENTITY + "\nX-Bad: bad"},
            {"access_token": ACCESS, "id_token": IDENTITY, "grafana_url": "https://cloud.invalid"},
            {"access_token": ACCESS, "id_token": IDENTITY, "headers": {"Authorization": CLIENT_SECRET}},
        )
        for pair in pairs:
            with self.subTest(keys=tuple(pair)):
                self.pair = pair
                factory = SessionFactory()
                with self.assertRaises(json_inputs.ContractError) as raised:
                    self.call(factory)
                self.assertEqual(factory.sessions, [])
                self.assert_private(raised.exception, "cloud.invalid")

    def test_request_guards_run_before_network_and_never_echo_payload_keys(self):
        payloads = (
            {"profile": CLIENT_SECRET}, {"grafanaURL": "https://cloud.invalid"},
            {"plugin": "grafana-incident-app"}, {"path": "/api/user"},
            {"headers": {"Authorization": CLIENT_SECRET}}, {"actor": {"userID": "admin"}},
            {"userID": "invented-actor"}, {"tenant": 999}, {"orgId": 999}, {"orgID": 999},
            {"grafana_org_id": 999}, {"namespace": "stack-5"}, {"stack_id": 5},
            {CLIENT_SECRET: PRIVATE},
        )
        for payload in payloads:
            with self.subTest(keys=tuple(payload)):
                factory = SessionFactory()
                with self.assertRaises(json_inputs.ContractError) as raised:
                    self.call(factory, payload=payload)
                self.assertEqual(factory.sessions, [])
                self.assert_private(raised.exception, "cloud.invalid", "invented-actor")

    def test_domain_target_user_id_is_not_caller_identity_or_a_header(self):
        payload = {"incidentID": "synthetic-incident", "userID": "synthetic-domain-target", "role": "commander"}
        factory = SessionFactory(ResponseProbe())
        self.assertEqual(self.call(factory, method="IncidentsService.AssignRole", payload=payload), {})
        sent = factory.sessions[0].sent[0]["request"]
        self.assertEqual(json_inputs.decode_body(sent.body), payload)
        self.assertEqual(sent.headers["X-Access-Token"], ACCESS)
        self.assertEqual(sent.headers["X-Grafana-Id"], IDENTITY)
        self.assertNotIn("synthetic-domain-target", str(sent.headers))
        self.assert_closed(factory)

    def test_opaque_domain_data_never_overrides_server_numeric_core_org(self):
        payload = {"title": "Synthetic", "fieldValues": {"orgId": 999, "stack_id": 5, "namespace": "not-authority"}}
        factory = SessionFactory(ResponseProbe())
        self.call(factory, method="IncidentsService.CreateIncident", payload=payload)
        sent = factory.sessions[0].sent[0]["request"]
        self.assertEqual(json_inputs.decode_body(sent.body), payload)
        self.assertEqual(sent.headers["X-Grafana-Org-Id"], "1")
        self.assert_closed(factory)

    def test_request_contract_required_fields_and_nested_bounds_are_applied(self):
        cases = (
            ("IncidentsService.CreateIncident", {}),
            ("IncidentsService.UpdateTitle", {"title": "x" * 301}),
            ("IncidentsService.AssignRole", {"incidentID": "x", "userID": "target", "role": None}),
            ("IncidentsService.QueryIncidentPreviews", {"query": {"limit": 101}}),
            ("CommentsService.AddReaction", {
                "incidentID": "i", "targetID": "a", "targetKind": "bad", "reaction": "x"}),
        )
        for method, payload in cases:
            with self.subTest(method=method):
                factory = SessionFactory()
                with self.assertRaises(json_inputs.ContractError):
                    self.call(factory, method=method, payload=payload)
                self.assertEqual(factory.sessions, [])

    def test_raw_request_is_strict_utf8_json_bytes_and_bounded_before_session(self):
        cases = (b"", b"[]", b"null", b"{", b'{"x":"\xff"}', b'{"x":NaN}',
                 b'{"x":1,"x":2}', b"{} trailing", b"{}" + b" " * (MAX_BODY_BYTES - 1), "{}", None)
        for raw in cases:
            with self.subTest(kind=type(raw).__name__, length=len(raw) if raw is not None else None):
                factory = SessionFactory()
                with patch.object(transport.requests, "Session", factory), self.assertRaises(
                    json_inputs.ContractError
                ):
                    transport.call_incident(self.binding, self.pair, "/api/UsersService.GetSession", raw)
                self.assertEqual(factory.sessions, [])

    def test_exact_one_mib_raw_request_is_admitted_without_adding_defaults(self):
        factory = SessionFactory(ResponseProbe())
        self.assertEqual(self.call(factory, raw=b"{}" + b" " * (MAX_BODY_BYTES - 2)), {})
        self.assertEqual(json_inputs.decode_body(factory.sessions[0].sent[0]["request"].body), {})
        self.assert_closed(factory)

    def test_all_redirect_statuses_are_errors_without_following_cloud_or_location(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                response = ResponseProbe(encoded({"error": CLIENT_SECRET}), status=status, headers={
                    "Location": "https://cloud.invalid/collect?token=" + ACCESS,
                    "Set-Cookie": "session=" + CLIENT_SECRET,
                })
                factory = SessionFactory(response)
                with self.assertRaises(responses.UpstreamResponseError) as raised:
                    self.call(factory)
                self.assertEqual(raised.exception.http_status, status)
                self.assertEqual(len(factory.sessions[0].sent), 1)
                self.assert_private(raised.exception, "cloud.invalid")
                self.assert_closed(factory)

    def test_upstream_status_never_becomes_a_200_result_and_headers_are_not_returned(self):
        for status in (201, 202, 204, 206, 304, 400, 401, 403, 404, 409, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                factory = SessionFactory(ResponseProbe(encoded({"error": CLIENT_SECRET}), status=status,
                                                       headers={"Retry-After": "1", "X-Secret": PRIVATE}))
                with self.assertRaises(responses.UpstreamResponseError) as raised:
                    self.call(factory, method="IncidentsService.CreateIncident", payload={"title": "Synthetic"})
                self.assertEqual(raised.exception.http_status, status)
                self.assertEqual(str(raised.exception), "upstream incident request failed")
                self.assertEqual(len(factory.sessions[0].sent), 1)
                self.assert_private(raised.exception)
                self.assert_closed(factory)

    def test_non_200_malformed_error_envelopes_are_not_fabricated_success(self):
        for data in (b"", b"{}", b'{"error":null}', b'{"error":123}', b"<html>upstream</html>"):
            with self.subTest(data=data):
                factory = SessionFactory(ResponseProbe(data, status=502))
                with self.assertRaises(json_inputs.ContractError):
                    self.call(factory)
                self.assert_closed(factory)

    def test_success_only_returns_validated_body_not_upstream_headers_or_cookies(self):
        factory = SessionFactory(ResponseProbe(b'{"user":null,"error":null}', headers={
            "Set-Cookie": "session=" + CLIENT_SECRET, "Authorization": PRIVATE,
            "X-Access-Token": ACCESS, "X-Grafana-Id": IDENTITY, "Location": "https://cloud.invalid",
        }))
        self.assertEqual(self.call(factory), {"user": None, "error": None})
        self.assert_closed(factory)

    def test_http_200_application_error_stays_native_application_data(self):
        factory = SessionFactory(ResponseProbe(b'{"error":"synthetic domain refusal","user":null}'))
        self.assertEqual(self.call(factory), {"error": "synthetic domain refusal", "user": None})
        self.assert_closed(factory)

    def test_unexpected_content_encoding_is_rejected_without_decoding_or_reading(self):
        for encoding in ("gzip", "br", "deflate", "gzip, identity", "identity, gzip", "unknown"):
            with self.subTest(encoding=encoding):
                response = ResponseProbe(b"compressed-bomb-sentinel", headers={"content-encoding": encoding})
                factory = SessionFactory(response)
                with self.assertRaises(transport.IncidentTransportError) as raised:
                    self.call(factory)
                self.assertEqual(response.raw.reads, [])
                self.assertEqual(str(raised.exception), TRANSPORT_MESSAGE)
                self.assert_private(raised.exception)
                self.assert_closed(factory)

    def test_identity_encoding_and_utf8_json_content_type_are_accepted(self):
        for headers in ({}, {"Content-Encoding": "identity"},
                        {"Content-Type": "application/json; charset=utf-8", "Content-Encoding": "identity"}):
            with self.subTest(headers=headers):
                response = ResponseProbe(b"{}", headers=headers, fragment=1)
                factory = SessionFactory(response)
                self.assertEqual(self.call(factory), {})
                self.assertTrue(response.raw.reads)
                self.assertTrue(all(decode is False for _amount, decode in response.raw.reads))
                self.assert_closed(factory)

    def test_exact_one_mib_response_and_one_byte_fragments_are_bounded(self):
        response = ResponseProbe(b"{}" + b" " * (MAX_BODY_BYTES - 2), fragment=32768)
        factory = SessionFactory(response)
        self.assertEqual(self.call(factory), {})
        self.assertEqual(response.raw.offset, MAX_BODY_BYTES)
        self.assert_closed(factory)
        fragmented = SessionFactory(ResponseProbe(b'{"user":null}', fragment=1))
        self.assertEqual(self.call(fragmented), {"user": None})
        self.assert_closed(fragmented)

    def test_oversize_body_with_absent_forged_or_oversize_length_never_reads_past_cap_plus_one(self):
        for headers in ({}, {"Content-Length": "2"}, {"Content-Length": str(MAX_BODY_BYTES + 1)}):
            with self.subTest(headers=headers):
                response = ResponseProbe(b"{}" + b" " * (MAX_BODY_BYTES * 2), headers=headers, fragment=32768)
                factory = SessionFactory(response)
                with self.assertRaises(transport.IncidentTransportError) as raised:
                    self.call(factory)
                self.assertEqual(str(raised.exception), TRANSPORT_MESSAGE)
                self.assertLessEqual(response.raw.offset, MAX_BODY_BYTES + 1)
                self.assert_private(raised.exception)
                self.assert_closed(factory)

    def test_strict_response_decoder_rejects_utf8_duplicate_keys_nan_scalars_and_truncation(self):
        invalid = (b"", b"null", b"[]", b"true", b"123", b"{", b'{"user":', b"{} trailing",
                   b'{"user":"\xff"}', b'{"user":null,"user":{}}', b'{"extra":NaN}',
                   b'{"extra":Infinity}', b'{"extra":1e9999}', b'{"extra":"\\ud800"}')
        for data in invalid:
            with self.subTest(data=data):
                factory = SessionFactory(ResponseProbe(data, fragment=3))
                with self.assertRaises(json_inputs.ContractError) as raised:
                    self.call(factory)
                self.assert_private(raised.exception)
                self.assert_closed(factory)

    def test_response_model_validation_is_not_replaced_by_json_only(self):
        invalid = (
            ("UsersService.GetSession", {"user": []}),
            ("OrgService.GetOrg", {"org": {}}),
            ("IncidentsService.GetIncident", {"incident": {"version": True}}),
            ("ActivityService.QueryActivity", {"query": {"limit": "80", "orderDirection": "DESC"}}),
        )
        for method, payload in invalid:
            with self.subTest(method=method):
                factory = SessionFactory(ResponseProbe(encoded(payload)))
                with self.assertRaises(json_inputs.ContractError):
                    self.call(factory, method=method, payload=self.requests[method])
                self.assert_closed(factory)

    def test_additive_response_data_is_independent_and_guarded_not_given_actor_authority(self):
        payload = {"user": None, "extra": {"actor": "not-authority", "values": [None, 1]}}
        factory = SessionFactory(ResponseProbe(encoded(payload)))
        result = self.call(factory)
        self.assertEqual(result, payload)
        result["extra"]["values"].append("local mutation")
        self.assertEqual(payload["extra"]["values"], [None, 1])
        self.assert_closed(factory)

    def test_response_shared_string_array_depth_and_node_limits_apply_to_additive_data(self):
        nested = {}
        for _ in range(16):
            nested = {"child": nested}
        payloads = (
            {"extra": "x" * (256 * 1024 + 1)}, {"extra": [None] * 1001}, nested,
            {"extra": [[None] * 1000 for _ in range(10)]},
        )
        for payload in payloads:
            with self.subTest(kind=type(payload.get("extra")).__name__):
                factory = SessionFactory(ResponseProbe(encoded(payload)))
                with self.assertRaises(json_inputs.ContractError):
                    self.call(factory)
                self.assert_closed(factory)

    def test_connect_timeout_read_timeout_connection_and_partial_write_fail_once_with_private_error(self):
        for exception_type in (requests.ConnectTimeout, requests.ReadTimeout, requests.ConnectionError,
                               requests.exceptions.ChunkedEncodingError):
            with self.subTest(exception_type=exception_type.__name__):
                error = exception_type(BASE + " " + ACCESS + " " + CLIENT_SECRET + " " + PRIVATE)
                factory = SessionFactory(error)
                with self.assertRaises(transport.IncidentTransportError) as raised:
                    self.call(factory, method="IncidentsService.CreateIncident", payload={"title": "Synthetic"})
                self.assertEqual(str(raised.exception), TRANSPORT_MESSAGE)
                self.assertEqual(len(factory.sessions[0].sent), 1)
                self.assertTrue(self.logs.records, "transport failures need safe server-side context")
                self.assert_private(raised.exception)
                self.assert_closed(factory)

    def test_partial_raw_read_timeout_or_protocol_failure_closes_stream_without_retry(self):
        errors = (requests.ReadTimeout(ACCESS + " " + BASE),
                  requests.exceptions.ChunkedEncodingError(CLIENT_SECRET + " " + PRIVATE),
                  ReadTimeoutError(None, "/synthetic", ACCESS + " " + BASE),
                  ProtocolError(CLIENT_SECRET + " " + PRIVATE))
        for error in errors:
            with self.subTest(error_type=type(error).__name__):
                response = ResponseProbe(b'{"user":null}', fragment=3, failure=error, fail_after=3)
                factory = SessionFactory(response)
                with self.assertRaises(transport.IncidentTransportError) as raised:
                    self.call(factory, method="IncidentsService.UpdateTitle", payload={"title": "Synthetic"})
                self.assertEqual(response.raw.offset, 3)
                self.assertEqual(len(factory.sessions[0].sent), 1)
                self.assert_private(raised.exception)
                self.assert_closed(factory)

    def test_error_privacy_covers_upstream_unknown_keys_body_and_exception_text(self):
        secret_key = "synthetic-upstream-private-key-name"
        secret_body = "synthetic-upstream-private-body"
        response = ResponseProbe(encoded({secret_key: secret_body, "user": PRIVATE}),
                                 headers={"X-Debug-URL": BASE, "Set-Cookie": CLIENT_SECRET})
        factory = SessionFactory(response)
        with self.assertRaises(json_inputs.ContractError) as raised:
            self.call(factory)
        self.assert_private(raised.exception, secret_key, secret_body)
        self.assert_closed(factory)
