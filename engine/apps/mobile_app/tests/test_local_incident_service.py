"""[code] Maintained request-operation actor tests for the server-internal API.

[code] Real actor/auth/binding/probe/minter/contract/transport implementations are
required; only HTTP send is stubbed. No test-local actor/role validator is allowed.
[code] Synthetic Viewer/Editor observations exercise forwarding/error behavior,
not evidence that Grafana Core/SDK has enforced those roles.
"""

import inspect
import json
from unittest.mock import Mock

import jwt
import pytest
from django.core.cache import cache
from rest_framework.exceptions import PermissionDenied

from apps.api.permissions import LegacyAccessControlRole
from apps.mobile_app.local_incident.contracts import ContractError
from apps.mobile_app.local_incident.responses import UpstreamResponseError
from apps.mobile_app.local_incident.service import perform_local_incident
from apps.mobile_app.local_incident.transport import METHOD_PATHS
from apps.mobile_app.models import MobileAppAuthToken
from apps.mobile_app.tests.local_incident_service_support import (
    DEFAULT_READ, LOCAL_ACTIONS, PUBLIC_ACTIONS, READ, WRITE, build_request,
    decode_pair_from_request, encode, method_body, paired,
)
from apps.mobile_app.web_session import service as web_service, tokens
from apps.mobile_app.web_session.config import load_binding
from apps.user_management.models import Organization

pytestmark = pytest.mark.django_db


def operate(actor, method=READ, body=None, **options):
    payload = method_body(method) if body is None else body
    request = build_request(actor.token)
    return perform_local_incident(request, "/api/" + method, encode(payload), **options)


def test_minimal_request_only_api_has_no_authority_or_url_injection_parameters():
    signature = inspect.signature(perform_local_incident)
    assert tuple(signature.parameters) == ("request", "path", "raw_body", "http_method")
    assert signature.parameters["http_method"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["http_method"].default == "POST"
    assert signature.return_annotation in (dict, "dict")


@pytest.mark.parametrize("keyword", [
    "actor", "external_id", "binding", "pair", "client", "session", "url",
    "headers", "organization_id", "grafana_org_id", "mode", "dispatch",
])
def test_no_arbitrary_actor_or_generic_proxy_surface(paired, keyword):
    with pytest.raises(TypeError):
        operate(paired, **{keyword: object()})
    assert paired.wire.calls == []


@pytest.mark.parametrize("paired", [
    LegacyAccessControlRole.VIEWER, LegacyAccessControlRole.EDITOR,
], indirect=True)
def test_real_paired_actor_survives_pre_and_post_probes_without_public_mint(paired, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("public mint/throttle must not run"))
    monkeypatch.setattr(web_service, "issue_session", forbidden)
    monkeypatch.setattr(web_service, "rate_limit", forbidden)
    for name in ("add", "get", "set", "get_or_set"):
        monkeypatch.setattr(cache, name, forbidden)
    before_tokens = MobileAppAuthToken.objects.count()
    first = operate(paired)
    second = operate(paired)
    assert first == second == DEFAULT_READ
    assert first is not second and first["incident"] is not second["incident"]
    assert [phase for phase, _, _ in paired.wire.calls] == [
        "user", "org", "dispatch", "user", "org",
        "user", "org", "dispatch", "user", "org",
    ]
    assert MobileAppAuthToken.objects.count() == before_tokens
    forbidden.assert_not_called()
    for phase, prepared, _ in paired.wire.calls:
        claims = decode_pair_from_request(prepared, paired)
        assert claims["X-Grafana-Id"]["sub"] == f"user:{paired.user.user_id}"
        assert claims["X-Grafana-Id"]["identifier"] == str(paired.user.user_id)
        access = claims["X-Access-Token"]
        assert access["permissions"] == []
        assert access["delegatedPermissions"] == (LOCAL_ACTIONS if phase == "dispatch" else ["orgs:read"])
        assert access["sub"] == "access-policy:oncall-web-session"
        for name, token in claims.items():
            assert token["iss"] == paired.binding_values["issuer"]
            assert token["aud"] == ["grafana"]
            assert token["namespace"] == paired.binding_values["namespace"]
            assert token["exp"] - token["iat"] == paired.binding_values["ttl_seconds"]
            assert token["nbf"] == token["iat"]
            assert jwt.get_unverified_header(prepared.headers[name])["alg"] == "ES256"
        if phase == "dispatch":
            assert prepared.headers["X-Grafana-Org-Id"] == str(paired.core_org)
        assert prepared.headers["X-Access-Token"] not in json.dumps(first)
        assert prepared.headers["X-Grafana-Id"] not in json.dumps(first)
    assert list(tokens.ACTIONS) == PUBLIC_ACTIONS
    assert list(tokens.LOCAL_INCIDENT_ACTIONS) == LOCAL_ACTIONS


@pytest.mark.parametrize("method", sorted(METHOD_PATHS))
def test_exact_finite_methods_keep_actual_actor_and_captured_scope(paired, method):
    assert len(METHOD_PATHS) == 28
    # [UNVERIFIED] Empty method-specific response fields are legal parser data,
    # not evidence of operation completeness or semantic success.
    paired.wire.dispatch_payload = {"error": None}
    assert operate(paired, method) == {"error": None}
    dispatched = [(prepared, options) for phase, prepared, options in paired.wire.calls if phase == "dispatch"]
    assert len(dispatched) == 1
    prepared, _ = dispatched[0]
    assert prepared.url == paired.binding_values["internal_origin"] + METHOD_PATHS[method]
    assert json.loads(prepared.body) == method_body(method)
    assert prepared.headers["X-Grafana-Org-Id"] == str(paired.core_org)
    assert decode_pair_from_request(prepared, paired)["X-Grafana-Id"]["sub"] == "user:9381"


@pytest.mark.parametrize("paired,status", [
    (LegacyAccessControlRole.VIEWER, 403),
    (LegacyAccessControlRole.EDITOR, 200),
    (LegacyAccessControlRole.EDITOR, 403),
], indirect=["paired"])
def test_write_permission_is_upstream_authority_not_oncall_role_metadata(paired, status):
    paired.wire.dispatch_status = status
    paired.wire.dispatch_payload = {"error": "forbidden"} if status != 200 else DEFAULT_READ
    if status == 200:
        assert operate(paired, WRITE) == DEFAULT_READ
    else:
        with pytest.raises(UpstreamResponseError) as caught:
            operate(paired, WRITE)
        assert caught.value.http_status == 403
    assert paired.wire.counts["dispatch"] == 1
    dispatch = next(prepared for phase, prepared, _ in paired.wire.calls if phase == "dispatch")
    identity = decode_pair_from_request(dispatch, paired)["X-Grafana-Id"]
    assert identity["sub"] == f"user:{paired.user.user_id}"
    assert "role" not in identity and "isAdmin" not in identity


def test_upstream_http200_application_error_is_not_relabelled_success(paired):
    paired.wire.dispatch_payload = {"error": "operation declined", "incident": None}
    result = operate(paired, WRITE)
    assert result == {"error": "operation declined", "incident": None}
    assert paired.wire.counts == {"user": 2, "org": 2, "dispatch": 1}


def test_inbound_org_headers_query_cookies_and_role_claims_never_select_scope(paired):
    inbound = build_request(paired.token, query=(
        "?orgId=111&grafana_org_id=222&organization_id=333&stack_id=444"
        "&namespace=attacker&mode=cloud&role=Admin&url=https://wrong.invalid"
    ), meta={
        "HTTP_X_GRAFANA_ORG_ID": "888", "HTTP_X_ORG_ID": "777",
        "HTTP_X_ACCESS_TOKEN": "untrusted-inbound-value",
        "HTTP_X_GRAFANA_ID": "untrusted-inbound-identity",
        "HTTP_COOKIE": "session=untrusted-cookie", "HTTP_X_GRAFANA_ROLE": "Admin",
    })
    original_meta = dict(inbound.META)
    assert perform_local_incident(inbound, "/api/" + READ, encode(method_body(READ))) == DEFAULT_READ
    assert dict(inbound.META) == original_meta
    for phase, prepared, _ in paired.wire.calls:
        assert "?" not in prepared.url
        assert "Authorization" not in prepared.headers and "Cookie" not in prepared.headers
        assert "X-Org-Id" not in prepared.headers and "X-Grafana-Role" not in prepared.headers
        assert "untrusted-inbound-value" not in prepared.headers.values()
        assert "untrusted-inbound-identity" not in prepared.headers.values()
        if phase == "dispatch":
            assert prepared.headers["X-Grafana-Org-Id"] == str(paired.core_org)


@pytest.mark.parametrize("field", ["orgID", "orgId", "organization_id", "grafana_org_id", "stack_id", "namespace"])
def test_top_level_body_org_selectors_are_rejected_not_reinterpreted(paired, field):
    with pytest.raises(ContractError):
        operate(paired, body={**method_body(READ), field: "untrusted-scope"})
    assert paired.wire.calls == []


def test_domain_user_target_and_opaque_metadata_cannot_become_caller_or_scope(paired):
    body = {
        "incidentID": "inc-test", "type": "link", "payload": "https://example.test",
        "metadata": {"grafana_org_id": 881, "sub": "user:1", "role": "Admin"},
    }
    paired.wire.dispatch_payload = {"error": None}
    assert operate(paired, "IncidentContextService.AddIncidentContext", body) == {"error": None}
    paired.wire.dispatch_payload = {"user": {"userID": "domain-target"}}
    assert operate(paired, "UsersService.GetUser", {"userID": "domain-target"}) == {
        "user": {"userID": "domain-target"},
    }
    dispatches = [prepared for phase, prepared, _ in paired.wire.calls if phase == "dispatch"]
    assert json.loads(dispatches[0].body)["metadata"] == body["metadata"]
    for prepared in dispatches:
        assert prepared.headers["X-Grafana-Org-Id"] == str(paired.core_org)
        assert decode_pair_from_request(prepared, paired)["X-Grafana-Id"]["sub"] == "user:9381"


def test_external_organization_and_stack_metadata_do_not_replace_numeric_core_scope(paired):
    Organization.objects.filter(pk=paired.organization.pk).update(org_id=30017, stack_id=60031)
    assert operate(paired) == DEFAULT_READ
    dispatch = next(prepared for phase, prepared, _ in paired.wire.calls if phase == "dispatch")
    assert dispatch.headers["X-Grafana-Org-Id"] == str(paired.core_org)
    assert dispatch.headers["X-Grafana-Org-Id"] not in {str(paired.organization.pk), "30017", "60031"}


def test_internal_pair_is_minted_once_only_after_successful_prechecks(paired, monkeypatch):
    actual = tokens.mint_local_incident_pair
    minted = Mock(wraps=actual)
    monkeypatch.setattr(tokens, "mint_local_incident_pair", minted)
    assert operate(paired) == DEFAULT_READ
    minted.assert_called_once()
    binding, external_id = minted.call_args.args
    assert binding.oncall_org_id == paired.organization.pk
    assert binding.grafana_org_id == paired.core_org
    assert external_id == paired.user.user_id
    assert minted.call_args.kwargs == {}


def test_drf_cached_actor_must_match_real_authorization_token(paired, make_organization_and_user_with_mobile_app_auth_token):
    other_org, other_user, other_token = make_organization_and_user_with_mobile_app_auth_token(
        role=LegacyAccessControlRole.VIEWER,
    )
    other = build_request(other_token)
    incoming = build_request(paired.token)
    incoming.user, incoming.auth = other.user, other.auth
    with pytest.raises(PermissionDenied):
        perform_local_incident(incoming, "/api/" + READ, encode(method_body(READ)))
    assert incoming.user.pk == other_user.pk and other_org.pk != paired.organization.pk
    assert paired.wire.calls == []


def _same_org_actor_requests(paired, make_user_for_organization, make_mobile_app_auth_token_for_user):
    # [UNVERIFIED] R2: distinct generated DB actors/tokens, same bound OnCall org.
    other_user = make_user_for_organization(
        organization=paired.organization, role=LegacyAccessControlRole.EDITOR,
        user_id=10517, username="same-org-editor", email="same-org-editor@example.test",
    )
    _, other_token = make_mobile_app_auth_token_for_user(other_user, paired.organization)
    actors = (build_request(paired.token), build_request(other_token))
    binding = load_binding()
    snapshots = tuple(web_service.actor_snapshot(actor.user, actor.auth, binding) for actor in actors)
    assert actors[0].user.pk != actors[1].user.pk
    assert actors[0].auth.pk != actors[1].auth.pk
    assert actors[0].user.user_id != actors[1].user.user_id
    assert snapshots[0] != snapshots[1]
    assert {snapshot[2] for snapshot in snapshots} == {binding.oncall_org_id}
    assert {actor.user.organization_id for actor in actors} == {paired.organization.pk}
    assert {actor.auth.organization_id for actor in actors} == {paired.organization.pk}
    return actors


@pytest.mark.parametrize("header_actor,cached_actor", [(0, 1), (1, 0)])
def test_same_org_cached_actor_mismatch_denied_before_any_probe_or_mint(
    paired, make_user_for_organization, make_mobile_app_auth_token_for_user,
    monkeypatch, header_actor, cached_actor,
):
    actors = _same_org_actor_requests(
        paired, make_user_for_organization, make_mobile_app_auth_token_for_user,
    )
    # [UNVERIFIED] Each actor independently succeeds with its own real header/cache.
    for actor in actors:
        paired.wire.profile = {
            "id": actor.user.user_id, "orgId": paired.core_org,
            "login": actor.user.username, "email": actor.user.email,
        }
        before = len(paired.wire.calls)
        assert perform_local_incident(actor, "/api/" + READ, encode(method_body(READ))) == DEFAULT_READ
        observed = paired.wire.calls[before:]
        assert [phase for phase, _, _ in observed] == ["user", "org", "dispatch", "user", "org"]
        for _, prepared, _ in observed:
            identity = decode_pair_from_request(prepared, paired)["X-Grafana-Id"]
            assert identity["sub"] == f"user:{actor.user.user_id}"
    assert paired.wire.counts["dispatch"] == 2
    local_mint = Mock(wraps=tokens.mint_local_incident_pair)
    probe_mint = Mock(wraps=web_service.mint_pair)
    monkeypatch.setattr(tokens, "mint_local_incident_pair", local_mint)
    monkeypatch.setattr(web_service, "mint_pair", probe_mint)
    incoming = build_request(actors[header_actor].META["HTTP_AUTHORIZATION"])
    incoming.user, incoming.auth = actors[cached_actor].user, actors[cached_actor].auth
    paired.wire.profile = {
        "id": actors[header_actor].user.user_id, "orgId": paired.core_org,
        "login": actors[header_actor].user.username, "email": actors[header_actor].user.email,
    }
    events_before, counts_before = tuple(paired.wire.calls), dict(paired.wire.counts)
    with pytest.raises(PermissionDenied):
        perform_local_incident(incoming, "/api/" + READ, encode(method_body(READ)))
    assert tuple(paired.wire.calls) == events_before
    assert paired.wire.counts == counts_before
    local_mint.assert_not_called()
    probe_mint.assert_not_called()
