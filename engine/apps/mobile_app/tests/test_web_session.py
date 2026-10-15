import json
import os
import subprocess
import sys
from unittest.mock import Mock

import jwt
import pytest
import requests
import requests_oauthlib  # Load the requests subclass before replacing the Session factory.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.handlers.wsgi import WSGIRequest
from django.test import Client
from django.urls import reverse
from rest_framework.authentication import get_authorization_header
from rest_framework.test import APIClient

from apps.mobile_app.models import MobileAppAuthToken
from apps.user_management.models import User

pytestmark = pytest.mark.django_db
PATHS = [f"{prefix}/web_session{slash}" for prefix in (
    "/mobile_app/v1", "/api/internal/v1/mobile_app"
) for slash in ("", "/")]
ACTIONS = ["orgs:read", "dashboards:read", "folders:read", "datasources:read",
           "datasources:query", "plugins.app:access", "annotations:read",
           "dashboard.grafana.app/dashboards:get", "folder.grafana.app/folders:get",
           "preferences.grafana.app/preferences:get", "alert.rules:read"]


@pytest.fixture
def paired(settings, tmp_path, make_organization_and_user_with_mobile_app_auth_token, monkeypatch):
    organization, user, token = make_organization_and_user_with_mobile_app_auth_token()
    user.user_id = 9381
    user.username = "paired-user"
    user.email = "paired@example.test"
    user.save()
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "signing.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    path.chmod(0o600)
    settings.WEB_SESSION_ENABLED = True
    settings.WEB_SESSION_BINDING = {
        "oncall_org_id": organization.pk, "grafana_org_id": 1,
        "internal_origin": "http://grafana-test:3000", "public_origin": "https://grafana.example.test",
        "namespace": "default", "issuer": "https://oncall.example.test", "key_id": "test-key",
        "private_key_file": str(path), "ttl_seconds": 60,
    }
    session = Mock()
    session.get.side_effect = lambda url, **kwargs: Mock(status_code=200, json=lambda: (
        {"id": 9381, "orgId": 1, "login": user.username, "email": user.email}
        if url.endswith("/api/user") else {"id": 1}))
    monkeypatch.setattr(requests, "Session", lambda: session)
    return organization, user, token, key, session


def get(paired, path=PATHS[0], **kwargs):
    return APIClient().get(path, HTTP_AUTHORIZATION=paired[2], **kwargs)


@pytest.mark.parametrize("path", PATHS)
def test_wire_contract(paired, path):
    response = get(paired, path)
    assert response.status_code == 200
    assert set(response.data) == {"access_token", "id_token", "grafana_url"}
    assert all(isinstance(v, str) and v for v in response.data.values())
    assert response.data["grafana_url"] == "https://grafana.example.test"
    assert "no-store" in response["Cache-Control"]


def test_jwt_and_transport(paired):
    response = get(paired, PATHS[0] + "?sub=user:1&grafana_url=https://evil.test&permissions=*")
    assert response.status_code == 200
    _, user, _, key, session = paired
    claims = {name: jwt.decode(response.data[name], key.public_key(), algorithms=["ES256"], audience="grafana")
              for name in ("access_token", "id_token")}
    access, identity = claims["access_token"], claims["id_token"]
    assert identity["sub"] == "user:9381" and user.pk != user.user_id
    assert identity["identifier"] == "9381" and identity["type"] == "user"
    assert access["sub"] == "access-policy:oncall-web-session"
    assert access["permissions"] == [] and access["delegatedPermissions"] == ACTIONS
    for name, payload in claims.items():
        assert payload["namespace"] == "default" and payload["aud"] == ["grafana"]
        assert payload["exp"] - payload["iat"] == 60 and payload["nbf"] == payload["iat"]
        assert jwt.get_unverified_header(response.data[name]) == {
            "alg": "ES256", "kid": "test-key", "typ": "jwt" if name == "id_token" else "at+jwt"}
    assert session.trust_env is False
    assert [c.args[0] for c in session.get.call_args_list] == [
        "http://grafana-test:3000/api/user", "http://grafana-test:3000/api/org"]
    for call in session.get.call_args_list:
        assert call.kwargs["allow_redirects"] is False and call.kwargs["verify"] is True
        assert call.kwargs["timeout"] == (3, 5)
        headers = call.kwargs["headers"]
        assert set(headers) == {"X-Access-Token", "X-Grafana-Id"}
        probe = jwt.decode(headers["X-Access-Token"], key.public_key(), algorithms=["ES256"], audience="grafana")
        assert probe["permissions"] == [] and probe["delegatedPermissions"] == ["orgs:read"]
        assert headers["X-Access-Token"] != response.data["access_token"]


@pytest.mark.parametrize("state", ["absent", "invalid", "bearer", "revoked", "inactive", "user_org", "token_org"])
def test_auth_rejections(paired, make_organization, state):
    _, user, token, _, session = paired
    if state == "revoked":
        MobileAppAuthToken.objects.filter(user=user).delete()
    if state == "inactive":
        User.objects.filter(pk=user.pk).update(is_active=False)
    if state == "user_org":
        User.objects.filter(pk=user.pk).update(organization=make_organization())
    if state == "token_org":
        MobileAppAuthToken.objects.filter(user=user).update(organization=make_organization())
    auth = {"absent": "", "invalid": "not-a-token", "bearer": "Bearer " + token}.get(state, token)
    response = APIClient().get(PATHS[0], HTTP_AUTHORIZATION=auth)
    assert response.status_code == 403 and "access_token" not in response.data
    assert response["Cache-Control"] == "no-store"
    session.get.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("oncall_org_id", None), ("grafana_org_id", True), ("namespace", "*"),
    ("public_origin", "http://grafana.example.test"), ("public_origin", "https://localhost"),
    ("public_origin", "https://127.0.0.1"), ("public_origin", "https://user:pass@grafana.example.test"),
    ("public_origin", "https://grafana.example.test/path"),
    ("public_origin", "https://grafana.example.test?x=y"),
    ("internal_origin", "http://grafana-test:3000/path"), ("key_id", ""),
    ("issuer", ""), ("ttl_seconds", True), ("ttl_seconds", 121), ("ttl_seconds", 0),
    ("private_key_file", "/does/not/exist"),
])
def test_bad_binding(paired, settings, field, value):
    settings.WEB_SESSION_BINDING = {**settings.WEB_SESSION_BINDING, field: value}
    response = get(paired)
    assert response.status_code == 503
    assert field in str(response.data)
    paired[4].get.assert_not_called()


@pytest.mark.parametrize("kind", ["missing", "rsa", "p384", "public", "permissions"])
def test_bad_key(paired, settings, tmp_path, kind):
    from cryptography.hazmat.primitives.asymmetric import rsa
    path = tmp_path / "invalid.pem"
    if kind == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP384R1() if kind == "p384" else ec.SECP256R1())
    content = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) if kind == "public" else key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path.write_bytes(b"bad key" if kind == "missing" else content)
    path.chmod(0o644 if kind == "permissions" else 0o600)
    settings.WEB_SESSION_BINDING = {**settings.WEB_SESSION_BINDING, "private_key_file": str(path)}
    response = get(paired)
    assert response.status_code == 503 and "private_key_file" in str(response.data)


@pytest.mark.parametrize("field,value", [
    ("id", True), ("id", None), ("id", 1), ("id", "9381"), ("id_bool", True),
    ("orgId", None), ("orgId", 2), ("orgId", True), ("orgId", "1"),
    ("login", "other"), ("login", "PAIRED-user"), ("login", None), ("login", ""),
    ("email", "OTHER@example.test"), ("email", None), ("email", ""),
    ("isDisabled", True), ("isDisabled", "false"),
    ("isServiceAccount", True), ("isServiceAccount", "false"),
])
def test_identity_rejections(paired, field, value):
    # One invalid field per otherwise valid user, with a separately VALID org probe.
    external_id = 9381
    if field == "id_bool":
        external_id = 1  # True == 1 in Python: prove the integer type guard independently.
        User.objects.filter(pk=paired[1].pk).update(user_id=external_id)
        field = "id"
    valid_user = {"id": external_id, "orgId": 1,
                  "login": "paired-user", "email": "paired@example.test"}
    paired[4].get.side_effect = [
        Mock(status_code=200, json=lambda: {**valid_user, field: value}),
        Mock(status_code=200, json=lambda: {"id": 1}),
    ]
    response = get(paired)
    assert response.status_code == 403
    assert "access_token" not in response.data
    assert paired[4].get.call_count == 2


@pytest.mark.parametrize("payload", [None, []])
def test_malformed_identity_root(paired, payload):
    paired[4].get.side_effect = [
        Mock(status_code=200, json=lambda: payload),
        Mock(status_code=200, json=lambda: {"id": 1}),
    ]
    assert get(paired).status_code == 403


@pytest.mark.parametrize("payload", [None, [], {"id": None}, {"id": True}, {"id": 2}])
def test_org_rejections(paired, payload):
    paired[4].get.side_effect = [Mock(status_code=200, json=lambda: {
        "id": 9381, "orgId": 1, "login": "paired-user", "email": "paired@example.test"}),
        Mock(status_code=200, json=lambda: payload)]
    assert get(paired).status_code == 403


@pytest.mark.parametrize("failure", [301, 302, 401, 403, 500, "json", "timeout"])
def test_upstream_fail_closed(paired, failure):
    session = paired[4]
    if failure == "timeout":
        session.get.side_effect = requests.Timeout()
    else:
        session.get.side_effect = None
        session.get.return_value = Mock(status_code=200 if failure == "json" else failure)
        session.get.return_value.json.side_effect = ValueError("malformed")
    response = get(paired)
    assert response.status_code in (403, 503) and "access_token" not in response.data


@pytest.mark.parametrize("race", ["revoke", "deactivate", "binding", "snapshot", "organization"])
def test_revalidate_after_probe(paired, settings, make_organization, race):
    original = paired[4].get.side_effect
    def mutate(url, **kwargs):
        response = original(url, **kwargs)
        if url.endswith("/api/org"):
            if race == "revoke":
                MobileAppAuthToken.objects.filter(user=paired[1]).delete()
            elif race == "deactivate":
                User.objects.filter(pk=paired[1].pk).update(is_active=False)
            elif race == "binding":
                settings.WEB_SESSION_BINDING = {**settings.WEB_SESSION_BINDING, "namespace": "other"}
            elif race == "snapshot":
                User.objects.filter(pk=paired[1].pk).update(email="changed@example.test")
            else:
                User.objects.filter(pk=paired[1].pk).update(organization=make_organization())
        return response
    paired[4].get.side_effect = mutate
    response = get(paired)
    assert response.status_code == 403 and "access_token" not in response.data


def test_feature_off(paired, settings):
    settings.WEB_SESSION_ENABLED = False
    assert get(paired).status_code == 503
    paired[4].get.assert_not_called()


def test_rate_limit(paired):
    assert get(paired).status_code == 200
    response = get(paired, PATHS[-1])
    assert response.status_code == 429 and response["Cache-Control"] == "no-store"
    assert paired[4].get.call_count == 2


def test_public_jwks(paired):
    response = APIClient().get("/mobile_app/v1/web_session/jwks")
    assert response.status_code == 200
    key = response.data["keys"][0]
    assert set(key) == {"kty", "crv", "x", "y", "use", "alg", "kid"}
    assert key["crv"] == "P-256" and key["kid"] == "test-key" and "d" not in key
    jwt.decode(get(paired).data["id_token"], jwt.PyJWK(key).key, algorithms=["ES256"], audience="grafana")


@pytest.mark.parametrize("enabled,same_org", [(False, True), (True, False), (True, True)])
def test_status_v2_preserves_connection(paired, settings, monkeypatch, make_organization, enabled, same_org):
    from apps.grafana_plugin.helpers import GrafanaAPIClient
    settings.WEB_SESSION_ENABLED = enabled
    if not same_org:
        settings.WEB_SESSION_BINDING = {**settings.WEB_SESSION_BINDING, "oncall_org_id": make_organization().pk}
    call_status = {"url": "http://internal/api/org", "connected": False,
                   "status_code": 401, "message": "bad upstream"}
    monkeypatch.setattr(GrafanaAPIClient, "check_token", lambda self: (None, call_status))
    response = APIClient().get(reverse("grafana-plugin:status-v2"), HTTP_AUTHORIZATION=paired[2])
    assert response.status_code == 200
    result = response.data["connection_to_grafana"]
    assert result == {**call_status, "url": "https://grafana.example.test/api/org" if enabled and same_org else call_status["url"]}
    assert call_status["url"] == "http://internal/api/org"


def production_binding(monkeypatch, enabled=None, raw=None):
    # A fresh interpreter imports the real production settings, not override_settings
    # or an already-cached settings.base module. Dependencies remain test-private.
    for name in ("WEB_SESSION_ENABLED", "WEB_SESSION_BINDING"):
        monkeypatch.delenv(name, raising=False)
    if enabled is not None:
        monkeypatch.setenv("WEB_SESSION_ENABLED", enabled)
    if raw is not None:
        monkeypatch.setenv("WEB_SESSION_BINDING", raw)
    env = {**os.environ, "DJANGO_SETTINGS_MODULE": "settings.helm"}
    script = """
import json, sys
sys.path[:0] = json.loads(sys.argv[1])
from django.conf import settings
from apps.mobile_app.web_session.config import load_binding, Unavailable
result = {"enabled": getattr(settings, "WEB_SESSION_ENABLED", False),
          "raw": getattr(settings, "WEB_SESSION_BINDING", None)}
try:
    binding = load_binding()
    result["loaded"] = {name: getattr(binding, name) for name in result["raw"]}
except Unavailable as exc:
    result["error"] = str(exc.detail)
print(json.dumps(result))
"""
    process = subprocess.run([sys.executable, "-I", "-c", script, json.dumps(sys.path)],
                             env=env, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


def test_production_env_binding(paired, settings, monkeypatch):
    raw = settings.WEB_SESSION_BINDING
    result = production_binding(monkeypatch, "True", json.dumps(raw))
    assert result["enabled"] is True
    assert result["raw"] == raw and result["loaded"] == raw


@pytest.mark.parametrize("enabled", [None, "False", "0", "invalid"])
def test_production_env_disabled_by_default(monkeypatch, enabled):
    result = production_binding(monkeypatch, enabled)
    assert result["enabled"] is False and result["error"] == "WebSession unavailable"


@pytest.mark.parametrize("raw,field", [
    ("{bad-json", "WEB_SESSION_BINDING"), ("[]", "WEB_SESSION_BINDING"),
    ('{"ttl_seconds":"60"}', "ttl_seconds"),
])
def test_production_env_invalid_binding(monkeypatch, raw, field):
    result = production_binding(monkeypatch, "1", raw)
    assert result["enabled"] is True and field in result["error"]


@pytest.mark.parametrize("kind", ["missing", "invalid"])
def test_status_v2_ignores_signer_readiness(paired, settings, monkeypatch, tmp_path, kind):
    from apps.grafana_plugin.helpers import GrafanaAPIClient
    call_status = {"url": "http://internal/api/org", "connected": True,
                   "status_code": 200, "message": "healthy"}
    monkeypatch.setattr(GrafanaAPIClient, "check_token", lambda self: (None, call_status))
    path = tmp_path / "unusable.pem"
    if kind == "invalid":
        path.write_bytes(b"not-a-private-key")
        path.chmod(0o600)
    settings.WEB_SESSION_ENABLED = False
    baseline = APIClient().get(reverse("grafana-plugin:status-v2"), HTTP_AUTHORIZATION=paired[2])
    settings.WEB_SESSION_ENABLED = True
    settings.WEB_SESSION_BINDING = {**settings.WEB_SESSION_BINDING, "private_key_file": str(path)}
    response = APIClient().get(reverse("grafana-plugin:status-v2"), HTTP_AUTHORIZATION=paired[2])
    assert response.status_code == baseline.status_code == 200
    assert response.data == {**baseline.data, "connection_to_grafana": {
        **call_status, "url": "https://grafana.example.test/api/org"}}
    for endpoint in (PATHS[0], PATHS[0] + "/jwks"):
        rejected = get(paired, endpoint)
        assert rejected.status_code == 503 and rejected["Cache-Control"] == "no-store"
        assert "access_token" not in rejected.data and "keys" not in rejected.data
    paired[4].get.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("public_origin", "https://user:SECRET@grafana.example.test/path"),
    ("public_origin", "https://grafana.example.test:bad"),
    ("public_origin", None), ("oncall_org_id", True), ("grafana_org_id", "1"),
    ("WEB_SESSION_BINDING", []),
])
def test_status_v2_invalid_optional_config_keeps_health(paired, settings, monkeypatch, caplog, field, value):
    from apps.grafana_plugin.helpers import GrafanaAPIClient
    call_status = {"url": "http://internal/api/org", "connected": True,
                   "status_code": 200, "message": "healthy"}
    monkeypatch.setattr(GrafanaAPIClient, "check_token", lambda self: (None, call_status))
    settings.WEB_SESSION_ENABLED = False
    baseline = APIClient().get(reverse("grafana-plugin:status-v2"), HTTP_AUTHORIZATION=paired[2])
    settings.WEB_SESSION_ENABLED = True
    settings.WEB_SESSION_BINDING = value if field == "WEB_SESSION_BINDING" else {
        **settings.WEB_SESSION_BINDING, field: value}
    response = APIClient().get(reverse("grafana-plugin:status-v2"), HTTP_AUTHORIZATION=paired[2])
    assert response.status_code == baseline.status_code == 200 and response.data == baseline.data
    assert field in caplog.text and f"organization_id={paired[0].pk}" in caplog.text
    assert "SECRET" not in caplog.text and paired[2] not in caplog.text
    paired[4].get.assert_not_called()


@pytest.mark.parametrize("path", PATHS)
def test_malformed_header_wsgi_is_handled_no_store(paired, monkeypatch, path):
    from apps.mobile_app.web_session import service
    mint = Mock(side_effect=AssertionError("must not mint"))
    monkeypatch.setattr(service, "mint_pair", mint)
    response = Client(raise_request_exception=False).get(path, HTTP_AUTHORIZATION="\xff")
    assert isinstance(response.wsgi_request, WSGIRequest)
    assert get_authorization_header(response.wsgi_request) == b"\xff"
    assert response.status_code == 403
    assert response["Cache-Control"] == "no-store" and response["Pragma"] == "no-cache"
    assert response.json() == {"detail": "Invalid token"}
    assert b"access_token" not in response.content and b"id_token" not in response.content
    mint.assert_not_called()
    paired[4].get.assert_not_called()


@pytest.mark.parametrize("flags", [{}, {"isDisabled": False}, {"isServiceAccount": False},
                                   {"isDisabled": False, "isServiceAccount": False}])
def test_optional_account_flags_allow_absent_or_literal_false(paired, flags):
    # Native UserProfileDTO omits service-account state; positive matching numeric
    # identity plus native auth is authoritative. Never require invented DTO fields.
    paired[4].get.side_effect = [
        Mock(status_code=200, json=lambda: {"id": 9381, "orgId": 1,
             "login": "paired-user", "email": "paired@example.test", **flags}),
        Mock(status_code=200, json=lambda: {"id": 1}),
    ]
    assert get(paired).status_code == 200


def test_delegated_actions_are_read_only():
    # Grafana page render needs these K8s reads; the WebSession pair must never delegate writes.
    from apps.mobile_app.web_session.tokens import ACTIONS as minted
    assert list(minted) == ACTIONS
    for action in minted:
        verb = action.rsplit(":", 1)[1]
        assert verb in {"read", "get", "query", "access"}, action
