"""Contract tests for the fixed internal Local Incident credential profile.

[code] Existing public behavior is specified by engine/apps/mobile_app/tests/test_web_session.py.
[code] The token signer uses ES256 and fixes aud to grafana in web_session/tokens.py.
[code] mint_local_incident_pair(binding, external_id) is the fixed profile API.
[measured 2026-10-16] This API was absent at the pre-implementation baseline; RED evidence is in the private manifest.
[code] external_id shape validation is not actor authentication or proof of caller pairing.
[measured 2026-10-16] Python AST parsing passed during test preparation.
"""
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from apps.mobile_app.web_session.tokens import ACTIONS, mint_local_incident_pair, mint_pair


LOCAL_INCIDENT_ACTIONS = ["orgs:read", "plugins.app:access"]
PUBLIC_ACTIONS = ["orgs:read", "dashboards:read", "folders:read", "datasources:read",
                  "datasources:query", "plugins.app:access", "annotations:read",
                  "dashboard.grafana.app/dashboards:get", "folder.grafana.app/folders:get",
                  "preferences.grafana.app/preferences:get", "alert.rules:read"]
FIXED_NOW = 1_800_000_000


@pytest.fixture
def signer(monkeypatch):
    """Use generated test-only signing material and a deterministic clock."""
    key = ec.generate_private_key(ec.SECP256R1())
    binding = SimpleNamespace(
        key=key,
        key_id="local-incident-test-key",
        issuer="https://oncall.example.test",
        namespace="default",
        ttl_seconds=60,
    )
    monkeypatch.setattr("apps.mobile_app.web_session.tokens.time.time", lambda: FIXED_NOW)
    return binding


def decode_pair(pair, binding):
    """Verify ES256, issuer, and audience; defer only wall-clock claim checks."""
    return {
        name: jwt.decode(
            token,
            binding.key.public_key(),
            algorithms=["ES256"],
            audience="grafana",
            issuer=binding.issuer,
            options={
                "verify_signature": True,
                "verify_iss": True,
                "verify_aud": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
        for name, token in pair.items()
    }


def test_local_incident_pair_has_only_fixed_delegated_actions_and_actor_subject(signer):
    pair = mint_local_incident_pair(signer, 9381)

    assert set(pair) == {"access_token", "id_token"}
    claims = decode_pair(pair, signer)
    access = claims["access_token"]
    identity = claims["id_token"]
    assert access["delegatedPermissions"] == LOCAL_INCIDENT_ACTIONS
    assert access["permissions"] == []
    assert access["sub"] == "access-policy:oncall-web-session"
    assert identity["sub"] == "user:9381"
    assert identity["identifier"] == "9381"
    assert identity["type"] == "user"
    for payload in claims.values():
        assert payload["iss"] == signer.issuer
        assert payload["aud"] == ["grafana"]
        assert payload["namespace"] == signer.namespace
        assert payload["iat"] == FIXED_NOW
        assert payload["nbf"] == FIXED_NOW
        assert payload["exp"] == FIXED_NOW + signer.ttl_seconds
        assert payload["nbf"] == payload["iat"]
        assert payload["exp"] - payload["iat"] == signer.ttl_seconds
    assert jwt.get_unverified_header(pair["access_token"]) == {
        "alg": "ES256", "kid": signer.key_id, "typ": "at+jwt"}
    assert jwt.get_unverified_header(pair["id_token"]) == {
        "alg": "ES256", "kid": signer.key_id, "typ": "jwt"}


@pytest.mark.parametrize("external_id", [None, 0, -1, True, "9381", 9381.0])
def test_local_incident_pair_rejects_external_id_outside_validated_shape_boundary(signer, external_id):
    with pytest.raises((TypeError, ValueError)):
        mint_local_incident_pair(signer, external_id)


def test_local_incident_pair_does_not_accept_caller_selected_permissions(signer):
    with pytest.raises(TypeError):
        mint_local_incident_pair(signer, 9381, actions=["orgs:read", "users:write"])


def test_public_web_session_minter_keeps_its_existing_action_contract(signer):
    pair = mint_pair(signer, 9381)
    claims = decode_pair(pair, signer)

    assert list(ACTIONS) == PUBLIC_ACTIONS
    assert claims["access_token"]["delegatedPermissions"] == PUBLIC_ACTIONS
    assert claims["access_token"]["permissions"] == []
    assert claims["id_token"]["sub"] == "user:9381"
    assert jwt.get_unverified_header(pair["access_token"])["typ"] == "at+jwt"
    assert jwt.get_unverified_header(pair["id_token"])["typ"] == "jwt"
