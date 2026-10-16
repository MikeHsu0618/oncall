"""[code] Maintained actor-test support, not a replacement actor validator.

[code] Fixture seams: engine/conftest.py:249-265,318-322,467-484,871-881;
apps/mobile_app/auth.py:30-46; web_session/config.py:102-125.
[code] All literal IDs, URLs, payloads and roles below are synthetic test inputs.
Fixtures generate fresh test signers/tokens; they are not maintained credentials.
[code] The HTTP stub supplies external observations; it does NOT implement
Grafana membership, SDK authorization or Core role policy.
"""

import io
import json
from types import SimpleNamespace
from urllib.parse import urlsplit

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from urllib3.response import HTTPResponse

from apps.api.permissions import LegacyAccessControlRole
from apps.mobile_app.auth import MobileAppAuthTokenAuthentication
from apps.mobile_app.local_incident.transport import METHOD_PATHS
from apps.user_management.models import Organization, User

READ = "IncidentsService.GetIncident"
WRITE = "IncidentsService.UpdateTitle"
DEFAULT_READ = {"incident": {"incidentID": "inc-test", "title": "test result"}}
LOCAL_ACTIONS = ["orgs:read", "plugins.app:access"]
PUBLIC_ACTIONS = [
    "orgs:read", "dashboards:read", "folders:read", "datasources:read",
    "datasources:query", "plugins.app:access", "annotations:read",
    "dashboard.grafana.app/dashboards:get", "folder.grafana.app/folders:get",
    "preferences.grafana.app/preferences:get", "alert.rules:read",
]


def encode(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")


def method_body(method):
    required = {
        "CommentsService.AddReaction": {
            "incidentID": "inc-test", "targetID": "comment-test",
            "targetKind": "comment", "reaction": "thumbsup",
        },
        "CommentsService.RemoveReaction": {
            "incidentID": "inc-test", "targetID": "comment-test",
            "targetKind": "comment", "reaction": "thumbsup",
        },
        "IncidentContextService.AddIncidentContext": {
            "incidentID": "inc-test", "type": "link", "payload": "https://example.test",
        },
        "IncidentContextService.QueryIncidentContext": {"query": {}},
        "IncidentsService.AssignRole": {
            "incidentID": "inc-test", "userID": "domain-target", "role": "commander",
        },
        "IncidentsService.UnassignRole": {
            "incidentID": "inc-test", "userID": "domain-target", "role": "commander",
        },
        "IncidentsService.CreateIncident": {"title": "test title"},
        READ: {"incidentID": "inc-test"},
        WRITE: {"incidentID": "inc-test", "title": "changed title"},
        "KeyUpdatesService.CreateKeyUpdate": {"incidentID": "inc-test", "content": "update"},
        "KeyUpdatesService.QueryKeyUpdates": {"query": {"incidentID": "inc-test"}},
    }
    return required.get(method, {})


def build_request(token, *, meta=None, query="", method="POST", raw=b"{}", initialize_actor=True):
    auth_meta = {} if token is None else {"HTTP_AUTHORIZATION": token}
    incoming = APIRequestFactory().generic(
        method, "/not-a-route" + query, data=raw,
        content_type="application/json", **auth_meta, **(meta or {}),
    )
    request = Request(incoming, authenticators=())
    if initialize_actor:
        # [code] Set DRF's actor only from the real validator; never force_authenticate.
        authenticated = MobileAppAuthTokenAuthentication().authenticate(request)
        if authenticated is not None:
            request.user, request.auth = authenticated
    return request


def decode_pair_from_request(prepared, actor):
    result = {}
    for header in ("X-Access-Token", "X-Grafana-Id"):
        result[header] = jwt.decode(
            prepared.headers[header], actor.key.public_key(), algorithms=["ES256"],
            issuer=actor.binding_values["issuer"], audience="grafana",
        )
    return result


class IdentityWire:
    """[UNVERIFIED] Fresh per-test, network-free external observations only."""

    def __init__(self, user, core_org):
        self.profile = {
            "id": user.user_id, "orgId": core_org,
            "login": user.username, "email": user.email,
        }
        self.core_org = core_org
        # [code] Test event recorders and callbacks are mutation-based by design.
        self.calls = []
        self.counts = {"user": 0, "org": 0, "dispatch": 0}
        self.user_changes = {}
        self.org_changes = {}
        self.probe_failures = {}
        self.on_probe = lambda _kind, _number: None
        self.on_dispatch = lambda: None
        self.dispatch_status = 200
        self.dispatch_payload = DEFAULT_READ

    def send(self, prepared, **kwargs):
        parsed = urlsplit(prepared.url)
        assert parsed.scheme == "http" and parsed.netloc == "grafana-test.invalid:3000"
        assert not parsed.query and not parsed.fragment
        if parsed.path in ("/api/user", "/api/org"):
            return self._probe(prepared, kwargs, parsed.path.rsplit("/", 1)[1])
        assert prepared.method == "POST" and parsed.path in METHOD_PATHS.values()
        self.counts["dispatch"] += 1
        self.calls.append(("dispatch", prepared, kwargs))
        self.on_dispatch()
        return self._response(prepared, self.dispatch_status, self.dispatch_payload)

    def _probe(self, prepared, kwargs, kind):
        assert prepared.method == "GET"
        self.counts[kind] += 1
        number = self.counts[kind]
        self.calls.append((kind, prepared, kwargs))
        self.on_probe(kind, number)
        failure = self.probe_failures.get((kind, number))
        if isinstance(failure, Exception):
            raise failure
        base = self.profile if kind == "user" else {"id": self.core_org}
        changes = self.user_changes if kind == "user" else self.org_changes
        payload = {**base, **changes.get(number, {})}
        return self._response(prepared, failure or 200, payload)

    @staticmethod
    def _response(prepared, status, payload):
        wire = encode(payload)
        response = requests.Response()
        response.status_code = status
        response.url = prepared.url
        response.request = prepared
        response.headers = {"Content-Type": "application/json", "Content-Encoding": "identity"}
        response._content = wire
        response._content_consumed = True
        response.raw = HTTPResponse(body=io.BytesIO(wire), preload_content=False)
        return response


@pytest.fixture
def paired(request, settings, tmp_path, monkeypatch,
           make_organization_and_user_with_mobile_app_auth_token):
    role = getattr(request, "param", LegacyAccessControlRole.VIEWER)
    assert role in (LegacyAccessControlRole.VIEWER, LegacyAccessControlRole.EDITOR)
    organization, user, token = make_organization_and_user_with_mobile_app_auth_token(role=role)
    Organization.objects.filter(pk=organization.pk).update(
        org_id=40009, stack_id=50021, is_grafana_incident_enabled=True,
        grafana_incident_backend_url="https://cloud-must-not-be-used.invalid",
    )
    User.objects.filter(pk=user.pk).update(
        user_id=9381, username="paired-actor", email="paired-actor@example.test",
    )
    organization.refresh_from_db()
    user.refresh_from_db()
    # [UNVERIFIED] Future generation uses the crypto library's OS-CSPRNG signer;
    # no pinned scalar, copied test PEM, old token or maintained credential file.
    key = ec.generate_private_key(ec.SECP256R1())
    keyfile = tmp_path / "new-test-only-signer.pem"
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    keyfile.chmod(0o600)
    core_org = 7000001 + organization.pk
    assert len({organization.pk, organization.org_id, organization.stack_id, core_org}) == 4
    values = {
        "oncall_org_id": organization.pk, "grafana_org_id": core_org,
        "internal_origin": "http://grafana-test.invalid:3000",
        "public_origin": "https://grafana.example.test", "namespace": "test-namespace",
        "issuer": "https://oncall.example.test", "key_id": "new-test-signer",
        "private_key_file": str(keyfile), "ttl_seconds": 60,
    }
    settings.WEB_SESSION_ENABLED = True
    settings.WEB_SESSION_BINDING = values
    settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED = True
    wire = IdentityWire(user, core_org)

    def no_network_send(_session, prepared, **kwargs):
        return wire.send(prepared, **kwargs)

    monkeypatch.setattr(requests.sessions.Session, "send", no_network_send)
    return SimpleNamespace(
        organization=organization, user=user, token=token, key=key, core_org=core_org,
        binding_values=values, wire=wire,
    )


def change_binding(settings, **changes):
    settings.WEB_SESSION_BINDING = {**settings.WEB_SESSION_BINDING, **changes}


def mutate_actor(actor, kind, settings, other_org=None):
    if kind == "revoke":
        from apps.mobile_app.models import MobileAppAuthToken
        MobileAppAuthToken.objects.filter(user=actor.user).delete()
    elif kind in ("inactive", "deleted_user"):
        User.objects.filter(pk=actor.user.pk).update(is_active=False if kind == "inactive" else None)
    elif kind == "user_org":
        User.objects.filter(pk=actor.user.pk).update(organization=other_org)
    elif kind == "token_org":
        from apps.mobile_app.models import MobileAppAuthToken
        MobileAppAuthToken.objects.filter(user=actor.user).update(organization=other_org)
    elif kind in ("email", "username", "user_id"):
        value = 18271 if kind == "user_id" else "mutated@example.test"
        User.objects.filter(pk=actor.user.pk).update(**{kind: value})
    elif kind == "feature":
        Organization.objects.filter(pk=actor.organization.pk).update(is_grafana_incident_enabled=False)
    elif kind == "org_deleted":
        Organization.objects.filter(pk=actor.organization.pk).delete()
    elif kind == "local_off":
        settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED = False
    elif kind == "web_off":
        settings.WEB_SESSION_ENABLED = False
    elif kind == "namespace":
        change_binding(settings, namespace="mutated-namespace")
    elif kind == "grafana_org":
        change_binding(settings, grafana_org_id=actor.core_org + 1)
    else:
        raise AssertionError("unknown static mutation case")
