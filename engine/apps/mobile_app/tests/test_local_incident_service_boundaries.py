"""[code] Maintained boundary/default-OFF actor-service tests.

[code] Existing finite schemas and JSON bounds are the authority; see
local_incident/contracts.py:95-104,183-187,236-248,267-280 and
local_incident/json_inputs.py:9-13,126-139.
[code] The actor API remains server-internal, default-OFF and unrouted.
"""

import json

import pytest
from rest_framework.exceptions import APIException

from apps.mobile_app.local_incident.contracts import ContractError
from apps.mobile_app.local_incident.json_inputs import MAX_BODY_BYTES
from apps.mobile_app.local_incident.service import perform_local_incident
from apps.mobile_app.tests.local_incident_service_support import (
    DEFAULT_READ, READ, WRITE, build_request, encode, method_body, paired,
)
from apps.mobile_app.web_session.config import Unavailable

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("enabled", [None, False, 0, 1, "true", "False"])
def test_local_gate_requires_literal_true_not_truthiness(paired, settings, enabled):
    settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED = enabled
    with pytest.raises(Unavailable):
        perform_local_incident(build_request(paired.token), "/api/" + READ, encode(method_body(READ)))
    assert paired.wire.calls == []


def test_missing_source_local_setting_defaults_off(paired, settings):
    del settings.MOBILE_APP_LOCAL_INCIDENT_ENABLED
    with pytest.raises(Unavailable):
        perform_local_incident(build_request(paired.token), "/api/" + READ, encode(method_body(READ)))
    assert paired.wire.calls == []


@pytest.mark.parametrize("header", [None, "", "not-a-token", "Bearer synthetic-not-a-token", "\xff"])
def test_invalid_or_malformed_raw_authorization_is_a_safe_boundary_failure(paired, header, caplog):
    request = build_request(header, initialize_actor=False)
    with pytest.raises(APIException) as caught:
        perform_local_incident(request, "/api/" + READ, encode(method_body(READ)))
    assert paired.wire.calls == []
    if header:
        assert header not in str(caught.value) + caplog.text


def test_null_request_is_authentication_failure_not_unhandled_attribute_error(paired):
    with pytest.raises(APIException):
        perform_local_incident(None, "/api/" + READ, encode(method_body(READ)))
    assert paired.wire.calls == []


@pytest.mark.parametrize("path", [
    None, "", [], 1, True, "https://wrong.invalid/api/UsersService.GetSession",
    "//wrong.invalid/api/UsersService.GetSession", "/api/UsersService.Unknown",
    "/api/UsersService.GetSession/", "/api/UsersService.GetSession?orgId=1",
    "/api/%55sersService.GetSession", "/api/../UsersService.GetSession",
    "/api/plugins/grafana-irm-app/resources/dispatch",
    "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.GetSession",
])
def test_finite_relative_method_resolution_happens_before_identity_io(paired, path):
    with pytest.raises(ContractError):
        perform_local_incident(build_request(paired.token), path, b"{}")
    assert paired.wire.calls == []


@pytest.mark.parametrize("http_method", [None, "", 1, True, "GET", "post", "DELETE", "PATCH"])
def test_only_literal_post_reaches_the_transport(paired, http_method):
    with pytest.raises(ContractError):
        perform_local_incident(build_request(paired.token), "/api/" + READ,
                               encode(method_body(READ)), http_method=http_method)
    assert paired.wire.calls == []


def test_actual_request_method_cannot_be_forged_by_default_post_argument(paired):
    request = build_request(paired.token, method="GET")
    with pytest.raises(ContractError):
        perform_local_incident(request, "/api/" + READ, encode(method_body(READ)))
    assert paired.wire.calls == []


@pytest.mark.parametrize("raw", [
    None, "{}", bytearray(b"{}"), b"", b"[]", b"null", b"true", b"{",
    b'{"incidentID":"a","incidentID":"b"}', b'{"value":NaN}', b"\xff",
])
def test_strict_raw_body_boundary_before_probes_or_minting(paired, raw):
    with pytest.raises(ContractError):
        perform_local_incident(build_request(paired.token), "/api/" + READ, raw)
    assert paired.wire.calls == []


def test_oversize_raw_body_is_rejected_before_any_http(paired):
    with pytest.raises(ContractError):
        perform_local_incident(build_request(paired.token), "/api/" + READ,
                               b" " * (MAX_BODY_BYTES + 1))
    assert paired.wire.calls == []


def test_more_than_ten_thousand_nodes_cannot_start_probes_or_dispatch(paired):
    metadata = {f"bucket-{index}": list(range(1000)) for index in range(11)}
    body = {"incidentID": "inc-test", "type": "link", "payload": "text", "metadata": metadata}
    with pytest.raises(ContractError):
        perform_local_incident(build_request(paired.token),
                               "/api/IncidentContextService.AddIncidentContext", encode(body))
    assert paired.wire.calls == []


@pytest.mark.parametrize("title", [None, "", "  ", [], True, 1, "x" * 301, "界" * 101])
def test_write_field_validation_preserves_existing_byte_boundaries(paired, title):
    body = {"incidentID": "inc-test", "title": title}
    with pytest.raises(ContractError):
        perform_local_incident(build_request(paired.token), "/api/" + WRITE, encode(body))
    assert paired.wire.calls == []


@pytest.mark.parametrize("title", ["x" * 300, "界" * 100, "O'Reilly; DROP TABLE incidents; --", "Unicode 界 and emoji \U0001f9ed"])
def test_valid_boundary_and_special_characters_keep_identity_and_input_unchanged(paired, title):
    body = {"incidentID": "inc-test", "title": title}
    raw = encode(body)
    assert perform_local_incident(build_request(paired.token), "/api/" + WRITE, raw) == DEFAULT_READ
    dispatch = next(prepared for phase, prepared, _ in paired.wire.calls if phase == "dispatch")
    assert json.loads(dispatch.body) == body
    assert raw == encode(body)
    assert paired.wire.counts == {"user": 2, "org": 2, "dispatch": 1}
