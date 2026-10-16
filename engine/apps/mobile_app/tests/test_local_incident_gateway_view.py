"""[code] Routed native Incident gateway: selector, strict local view, fail-closed admission.

[code] Only the HTTP send (via the accepted IdentityWire stub) and explicit seams
(admission.acquire / service.perform_local_incident) are replaced per test.
"""

import json
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.conf import settings as django_settings
from django.urls import resolve, reverse
from rest_framework.exceptions import (
    AuthenticationFailed,
    NotAuthenticated,
    NotFound,
    PermissionDenied,
    Throttled,
)
from rest_framework.response import Response
from rest_framework.test import APIClient

from apps.mobile_app.local_incident import admission, contracts, service, transport
from apps.mobile_app.local_incident.json_inputs import MAX_BODY_BYTES, ContractError
from apps.mobile_app.local_incident.responses import UpstreamResponseError
from apps.mobile_app.local_incident.transport import IncidentTransportError
from apps.mobile_app.local_incident.views import WRITE_METHODS, LocalIncidentGatewayView
from apps.mobile_app.tests.local_incident_service_support import (
    DEFAULT_READ, READ, WRITE, encode, method_body, paired,
)
from apps.mobile_app.views import MobileAppGatewayView
from apps.mobile_app.web_session import tokens
from apps.mobile_app.web_session.config import Unavailable

pytestmark = pytest.mark.django_db

SENTINEL = "secret-sentinel"
SUCCESS = {"incident": {"incidentID": "inc-test", "title": "routed result"}}


def url_for(suffix):
    return reverse("mobile_app:incident_gateway", kwargs={"downstream_path": suffix})


def send(token, suffix, raw=None, *, method="POST", query="", **extra):
    payload = encode(method_body(READ)) if raw is None else raw
    auth = {} if token is None else {"HTTP_AUTHORIZATION": token}
    return APIClient().generic(
        method, url_for(suffix) + query, data=payload, content_type="application/json", **auth, **extra,
    )


def assert_no_store(response):
    assert response["Cache-Control"] == "no-store"
    assert response["Pragma"] == "no-cache"


def assert_error(response, status_code):
    assert response.status_code == status_code
    body = json.loads(response.content)
    assert type(body) is dict and set(body) == {"error"} and type(body["error"]) is str
    assert_no_store(response)
    return body


class FakePermit:
    def __init__(self, ok=True, error=None):
        # [code] Test recorder; mutation-based by design.
        self.releases = 0
        self._ok = ok
        self._error = error
        self.ok = None

    def release(self):
        self.releases += 1
        if self._error is not None:
            raise self._error
        self.ok = self._ok
        return self.ok


def _forbidden_dispatch(calls):
    def dispatch(self, request, *args, **kwargs):
        calls.append(kwargs)
        raise AssertionError("this view must not be invoked")
    return dispatch


@pytest.fixture
def local_actor(settings, make_organization_and_user_with_mobile_app_auth_token):
    settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED = True
    settings.MOBILE_APP_GATEWAY_ENABLED = True
    organization, user, token = make_organization_and_user_with_mobile_app_auth_token()
    return SimpleNamespace(organization=organization, user=user, token=token)


@pytest.fixture
def seams(monkeypatch):
    permit = FakePermit()
    acquire = Mock(return_value=permit)
    perform = Mock(return_value=SUCCESS)
    legacy = []
    monkeypatch.setattr(admission, "acquire", acquire)
    monkeypatch.setattr(service, "perform_local_incident", perform)
    monkeypatch.setattr(MobileAppGatewayView, "dispatch", _forbidden_dispatch(legacy))
    return SimpleNamespace(permit=permit, acquire=acquire, perform=perform, legacy=legacy)


def assert_untouched(seams):
    seams.acquire.assert_not_called()
    seams.perform.assert_not_called()
    assert seams.legacy == []


# --- selector / routing -------------------------------------------------------------


def test_incident_route_precedes_generic_gateway_and_other_backends_stay_generic():
    legacy_incident = reverse("mobile_app:gateway", kwargs={"downstream_backend": "incident", "downstream_path": "x"})
    assert legacy_incident == url_for("x")
    assert resolve(legacy_incident).url_name == "incident_gateway"
    other = reverse("mobile_app:gateway", kwargs={"downstream_backend": "foo", "downstream_path": "x"})
    assert resolve(other).url_name == "gateway"
    assert resolve(url_for("")).kwargs == {"downstream_path": ""}


def test_write_method_literals_are_exact_native_methods():
    assert len(WRITE_METHODS) == 13
    assert WRITE_METHODS <= contracts.METHODS
    assert len(contracts.METHODS - WRITE_METHODS) == 15


@pytest.mark.parametrize("local_value", [False, "True", 1, None])
def test_local_off_routes_to_unchanged_legacy_view_and_never_local(
    settings, monkeypatch, make_organization_and_user_with_mobile_app_auth_token, local_value,
):
    settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED = local_value
    settings.MOBILE_APP_GATEWAY_ENABLED = True
    _, _, token = make_organization_and_user_with_mobile_app_auth_token()
    local_calls, seen = [], []
    monkeypatch.setattr(LocalIncidentGatewayView, "dispatch", _forbidden_dispatch(local_calls))

    def legacy_post(self, request, *args, **kwargs):
        seen.append(kwargs)
        return Response({"legacy": True})

    monkeypatch.setattr(MobileAppGatewayView, "post", legacy_post)
    response = send(token, "api/" + READ)
    assert response.status_code == 200 and response.json() == {"legacy": True}
    assert seen == [{"downstream_backend": "incident", "downstream_path": "api/" + READ}]
    assert local_calls == []


def test_local_off_keeps_legacy_gateway_disabled_404(settings, monkeypatch,
                                                      make_organization_and_user_with_mobile_app_auth_token):
    settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED = False
    settings.MOBILE_APP_GATEWAY_ENABLED = False
    _, _, token = make_organization_and_user_with_mobile_app_auth_token()
    local_calls = []
    monkeypatch.setattr(LocalIncidentGatewayView, "dispatch", _forbidden_dispatch(local_calls))
    response = send(token, "api/" + READ)
    assert response.status_code == 404
    assert "error" not in response.json()  # legacy DRF shape, not the local envelope
    assert local_calls == []


@pytest.mark.parametrize("suffix", [
    "api/UsersService.QueryUsers", "foo", "api/", "", "api", "/api/" + READ,
    "api/" + READ + "/", "api/" + READ + "/extra", "API/" + READ, "api/incidentsservice.getincident",
])
def test_local_on_unknown_suffix_is_local_404_never_legacy(local_actor, seams, suffix):
    assert_error(send(local_actor.token, suffix), 404)
    assert_untouched(seams)


def test_local_on_routes_locally_even_when_legacy_gateway_disabled(local_actor, seams, settings):
    settings.MOBILE_APP_GATEWAY_ENABLED = False
    response = send(local_actor.token, "api/" + READ)
    assert response.status_code == 200 and response.json() == SUCCESS
    seams.acquire.assert_called_once()
    assert seams.legacy == []


# --- methods / query / framing -------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_non_post_is_405_envelope_without_reading_body(local_actor, seams, method):
    response = send(local_actor.token, "api/" + READ, method=method, CONTENT_LENGTH=str(MAX_BODY_BYTES + 1))
    assert_error(response, 405)
    assert response["Allow"] == "POST"
    assert_untouched(seams)


def test_query_string_is_404(local_actor, seams):
    assert_error(send(local_actor.token, "api/" + READ, query="?orgId=111"), 404)
    assert_untouched(seams)


def test_declared_oversize_is_413_before_body_read(local_actor, seams):
    assert_error(send(local_actor.token, "api/" + READ, CONTENT_LENGTH=str(MAX_BODY_BYTES + 1)), 413)
    assert_untouched(seams)


def test_missing_content_length_is_411(local_actor, seams):
    # [code] Django's test factory omits CONTENT_LENGTH for an empty body.
    assert_error(send(local_actor.token, "api/" + READ, raw=b""), 411)
    assert_untouched(seams)


@pytest.mark.parametrize("value", ["abc", "+5", "-1", " 2", "1_0", "٢"])
def test_malformed_content_length_is_400(local_actor, seams, value):
    assert_error(send(local_actor.token, "api/" + READ, CONTENT_LENGTH=value), 400)
    assert_untouched(seams)


@pytest.mark.parametrize("method,raw", [
    (READ, b"not json"),
    (READ, b"[]"),
    (READ, encode({"incidentID": "inc-test", "orgId": 1})),
    (WRITE, encode({"incidentID": "inc-test"})),
])
def test_invalid_native_body_is_400_before_admission(local_actor, seams, method, raw):
    body = assert_error(send(local_actor.token, "api/" + method, raw=raw), 400)
    assert body == {"error": "invalid native incident request"}
    assert_untouched(seams)


# --- authentication ---------------------------------------------------------------------


@pytest.mark.parametrize("header", [None, "potato", "Bearer synthetic-not-a-token", "\xff"])
def test_missing_or_invalid_authorization_is_401_before_admission(local_actor, seams, header):
    response = send(header, "api/" + READ)
    assert_error(response, 401)
    assert_untouched(seams)


# --- admission --------------------------------------------------------------------------


def test_admission_without_redis_store_is_503_with_zero_probes_or_mints(paired, monkeypatch):
    # [code] The test settings use a LocMem cache; django_redis cannot provide a
    # connection, so admission must fail closed before any service work.
    assert "redis" not in django_settings.CACHES["default"]["BACKEND"].lower()
    perform = Mock(wraps=service.perform_local_incident)
    mint = Mock(wraps=tokens.mint_local_incident_pair)
    call = Mock(wraps=transport.call_incident)
    monkeypatch.setattr(service, "perform_local_incident", perform)
    monkeypatch.setattr(tokens, "mint_local_incident_pair", mint)
    monkeypatch.setattr(transport, "call_incident", call)
    assert_error(send(paired.token, "api/" + READ), 503)
    perform.assert_not_called()
    mint.assert_not_called()
    call.assert_not_called()
    assert paired.wire.calls == []
    assert paired.wire.counts == {"user": 0, "org": 0, "dispatch": 0}


@pytest.mark.parametrize("exc,status_code", [
    (Unavailable("Local incident admission unavailable"), 503),
    (Throttled(wait=3), 429),
])
def test_admission_denial_never_reaches_service(local_actor, seams, exc, status_code):
    seams.acquire.side_effect = exc
    response = send(local_actor.token, "api/" + WRITE, raw=encode(method_body(WRITE)))
    assert_error(response, status_code)
    if status_code == 429:
        assert response["Retry-After"] == "3"
    seams.perform.assert_not_called()


@pytest.mark.parametrize("method,write", [(READ, False), (WRITE, True)])
def test_success_passes_exact_body_and_server_scope(local_actor, seams, method, write):
    raw = encode(method_body(method))
    response = send(local_actor.token, "api/" + method, raw=raw)
    assert response.status_code == 200
    assert json.loads(response.content) == SUCCESS
    assert_no_store(response)
    seams.acquire.assert_called_once_with((local_actor.organization.pk, local_actor.user.pk, write))
    seams.perform.assert_called_once()
    request = seams.perform.call_args.args[0]
    assert seams.perform.call_args.args[1:] == ("/api/" + method, raw)
    assert seams.perform.call_args.kwargs == {"http_method": "POST"}
    assert request.user.pk == local_actor.user.pk
    assert seams.permit.releases == 1


def test_application_error_in_http200_result_passes_through_unchanged(local_actor, seams):
    seams.perform.return_value = {"error": "operation declined", "incident": None}
    response = send(local_actor.token, "api/" + WRITE, raw=encode(method_body(WRITE)))
    assert response.status_code == 200
    assert response.json() == {"error": "operation declined", "incident": None}


def test_admission_scope_ignores_body_and_header_org_selectors(local_actor, seams):
    method = "IncidentContextService.AddIncidentContext"
    body = {**method_body(method), "metadata": {"organization_id": 999, "user": 1, "write": False}}
    response = send(local_actor.token, "api/" + method, raw=encode(body),
                    HTTP_X_GRAFANA_ORG_ID="888", HTTP_X_ORG_ID="777")
    assert response.status_code == 200
    seams.acquire.assert_called_once_with((local_actor.organization.pk, local_actor.user.pk, True))


# --- exception mapping ------------------------------------------------------------------


@pytest.mark.parametrize("exc,status_code", [
    (AuthenticationFailed("Invalid mobile authentication"), 401),
    (NotAuthenticated(), 401),
    (PermissionDenied("Mobile pairing changed"), 403),
    (NotFound("Local incident organization unavailable"), 404),
    (Throttled(wait=2), 429),
    (Unavailable("Local incident unavailable"), 503),
    (ContractError("body: upstream-side parse failure"), 502),
    (IncidentTransportError(), 502),
    (UpstreamResponseError(400), 400),
    (UpstreamResponseError(401), 502),
    (UpstreamResponseError(403), 403),
    (UpstreamResponseError(404), 404),
    (UpstreamResponseError(409), 409),
    (UpstreamResponseError(413), 413),
    (UpstreamResponseError(429), 429),
    (UpstreamResponseError(500), 502),
    (UpstreamResponseError(503), 502),
    (UpstreamResponseError(302), 502),
    (RuntimeError(SENTINEL), 500),
])
def test_service_exceptions_map_to_static_envelope_and_release_permit(local_actor, seams, caplog, exc, status_code):
    seams.perform.side_effect = exc
    response = send(local_actor.token, "api/" + WRITE, raw=encode(method_body(WRITE)))
    body = assert_error(response, status_code)
    assert seams.permit.releases == 1
    assert "incident" not in body
    assert SENTINEL not in response.content.decode()
    assert SENTINEL not in caplog.text
    assert all(SENTINEL not in record.getMessage() for record in caplog.records)
    if status_code == 500:
        assert body == {"error": "internal error"}
        ours = [r for r in caplog.records if r.name == "apps.mobile_app.local_incident.views"]
        assert [r.getMessage() for r in ours] == ["Local incident gateway failed: type=RuntimeError"]
        assert all(r.exc_info is None for r in ours)


# --- lease loss after the operation ---------------------------------------------------


@pytest.mark.parametrize("make_permit", [
    lambda: FakePermit(ok=False),
    lambda: FakePermit(error=RuntimeError(SENTINEL)),
], ids=["lease-lost", "release-raises"])
def test_unprovable_release_discards_success_body_without_retry(local_actor, seams, caplog, make_permit):
    permit = make_permit()
    seams.acquire.return_value = permit
    response = send(local_actor.token, "api/" + WRITE, raw=encode(method_body(WRITE)))
    body = assert_error(response, 503)
    assert body == {"error": "local incident admission lost"}
    assert "routed result" not in response.content.decode()
    seams.perform.assert_called_once()
    seams.acquire.assert_called_once()
    assert permit.releases == 1
    assert SENTINEL not in caplog.text


def test_release_failure_does_not_override_service_exception_mapping(local_actor, seams):
    permit = FakePermit(error=RuntimeError(SENTINEL))
    seams.acquire.return_value = permit
    seams.perform.side_effect = UpstreamResponseError(409)
    response = send(local_actor.token, "api/" + WRITE, raw=encode(method_body(WRITE)))
    assert_error(response, 409)
    assert permit.releases == 1
    seams.perform.assert_called_once()


# --- end to end through the real service ------------------------------------------------


def test_real_service_read_through_url_with_admitted_permit(paired, monkeypatch):
    permit = FakePermit()
    acquire = Mock(return_value=permit)
    legacy = []
    monkeypatch.setattr(admission, "acquire", acquire)
    monkeypatch.setattr(MobileAppGatewayView, "dispatch", _forbidden_dispatch(legacy))
    response = send(paired.token, "api/" + READ, raw=encode(method_body(READ)))
    assert response.status_code == 200
    assert json.loads(response.content) == DEFAULT_READ
    assert_no_store(response)
    assert [phase for phase, _, _ in paired.wire.calls] == ["user", "org", "dispatch", "user", "org"]
    acquire.assert_called_once_with((paired.organization.pk, paired.user.pk, False))
    assert permit.releases == 1
    assert legacy == []


# --- CSRF / real permit ------------------------------------------------------------------


def test_csrf_enforcing_client_still_reaches_local_view(local_actor, monkeypatch):
    perform = Mock(return_value=SUCCESS)
    legacy = []
    monkeypatch.setattr(service, "perform_local_incident", perform)
    monkeypatch.setattr(MobileAppGatewayView, "dispatch", _forbidden_dispatch(legacy))
    client = APIClient(enforce_csrf_checks=True)
    response = client.generic(
        "POST", url_for("api/" + READ), data=encode(method_body(READ)),
        content_type="application/json", HTTP_AUTHORIZATION=local_actor.token,
    )
    # [code] 503 from fail-closed admission (LocMem test cache), not a 403 CSRF rejection.
    assert assert_error(response, 503) == {"error": "service unavailable"}
    perform.assert_not_called()
    assert legacy == []


def test_real_permit_lease_loss_discards_result(local_actor, settings, monkeypatch):
    settings.MOBILE_APP_LOCAL_INCIDENT_LEASE_TTL_MS = "300"
    settings.MOBILE_APP_LOCAL_INCIDENT_LEASE_RENEW_MS = "20"
    renewed = threading.Event()

    def renew(**_kwargs):
        renewed.set()
        return 0

    scripts = SimpleNamespace(
        acquire=Mock(return_value=[1, b"ok"]), renew=Mock(side_effect=renew), release=Mock(return_value=1),
    )
    monkeypatch.setattr(admission, "get_redis_connection", Mock(return_value=Mock()))
    monkeypatch.setattr(admission, "_scripts", Mock(return_value=scripts))

    def perform_while_lease_lost(*_args, **_kwargs):
        assert renewed.wait(timeout=2)
        return SUCCESS

    perform = Mock(side_effect=perform_while_lease_lost)
    monkeypatch.setattr(service, "perform_local_incident", perform)
    response = send(local_actor.token, "api/" + WRITE, raw=encode(method_body(WRITE)))
    assert assert_error(response, 503) == {"error": "local incident admission lost"}
    assert "routed result" not in response.content.decode()
    perform.assert_called_once()
    scripts.acquire.assert_called_once()
    scripts.renew.assert_called_once()
    scripts.release.assert_called_once()
