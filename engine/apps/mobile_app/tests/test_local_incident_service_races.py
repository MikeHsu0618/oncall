"""[code] Maintained deterministic revocation, binding and identity race tests.

[code] Mutations target actual test DB rows/settings, not a replacement validator.
[code] Controlled interleavings do not prove distributed atomicity, committed-write
rollback, real Core policy or production DB isolation.
"""

import json
from unittest.mock import Mock

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from rest_framework.exceptions import APIException, PermissionDenied

from apps.mobile_app.local_incident.service import perform_local_incident
from apps.mobile_app.local_incident.transport import IncidentTransportError
from apps.mobile_app.tests.local_incident_service_support import (
    DEFAULT_READ, READ, WRITE, build_request, change_binding, encode,
    method_body, mutate_actor, paired,
)
from apps.mobile_app.web_session import tokens

pytestmark = pytest.mark.django_db

MUTATIONS = (
    "revoke", "inactive", "deleted_user", "user_org", "token_org", "email",
    "username", "user_id", "feature", "org_deleted", "local_off", "web_off",
    "namespace", "grafana_org",
)


def operation(actor, request=None, method=READ):
    incoming = request if request is not None else build_request(actor.token)
    return perform_local_incident(incoming, "/api/" + method, encode(method_body(method)))


@pytest.mark.parametrize("mutation", [
    mutation for mutation in MUTATIONS if mutation not in ("namespace", "grafana_org")
])
def test_stale_drf_actor_and_cached_org_cannot_bypass_fresh_entry_checks(
    paired, settings, make_organization, mutation,
):
    incoming = build_request(paired.token)
    cached_org = incoming.user.organization
    assert cached_org.is_grafana_incident_enabled is True
    mutate_actor(paired, mutation, settings, make_organization())
    with pytest.raises(APIException):
        operation(paired, incoming)
    assert paired.wire.calls == []


@pytest.mark.parametrize("phase", ["pre_user", "pre_org", "dispatch", "post_user", "post_org"])
@pytest.mark.parametrize("mutation", MUTATIONS)
def test_fresh_checks_detect_interleaved_mutation_before_dispatch_or_release(
    paired, settings, make_organization, phase, mutation,
):
    incoming = build_request(paired.token)
    assert incoming.user.organization.is_grafana_incident_enabled is True
    other_org = make_organization()

    def mutate():
        mutate_actor(paired, mutation, settings, other_org)

    target = {"pre_user": ("user", 1), "pre_org": ("org", 1),
              "post_user": ("user", 2), "post_org": ("org", 2)}.get(phase)

    def during_probe(kind, number):
        if (kind, number) == target:
            mutate()

    paired.wire.on_probe = during_probe
    if phase == "dispatch":
        paired.wire.on_dispatch = mutate
    with pytest.raises(APIException):
        operation(paired, incoming)
    expected_dispatches = 0 if phase.startswith("pre_") else 1
    assert paired.wire.counts["dispatch"] == expected_dispatches


@pytest.mark.parametrize("number", [1, 2])
@pytest.mark.parametrize("changes", [
    {"id": 181}, {"id": True}, {"id": None}, {"id": "9381"},
    {"orgId": 1}, {"orgId": True}, {"orgId": None},
    {"login": "another-login"}, {"email": "another@example.test"},
    {"isDisabled": True}, {"isDisabled": "false"},
    {"isServiceAccount": True}, {"isServiceAccount": "false"},
])
def test_actual_identity_probe_rejects_nonmember_or_changed_actor_pre_and_post(
    paired, number, changes, monkeypatch,
):
    actual = tokens.mint_local_incident_pair
    minted = Mock(wraps=actual)
    monkeypatch.setattr(tokens, "mint_local_incident_pair", minted)
    paired.wire.user_changes[number] = changes
    with pytest.raises(PermissionDenied):
        operation(paired)
    assert paired.wire.counts["dispatch"] == number - 1
    assert minted.call_count == number - 1


@pytest.mark.parametrize("number", [1, 2])
@pytest.mark.parametrize("org_id", [None, True, "7000001", 1, -1])
def test_actual_org_probe_rejects_wrong_core_org_pre_and_post(paired, number, org_id):
    paired.wire.org_changes[number] = {"id": org_id}
    with pytest.raises(PermissionDenied):
        operation(paired)
    assert paired.wire.counts["dispatch"] == number - 1


@pytest.mark.parametrize("probe", [("user", 1), ("org", 1), ("user", 2), ("org", 2)])
@pytest.mark.parametrize("failure", [301, 403, 500, "timeout", "bad_json"])
def test_each_real_pre_and_post_probe_failure_fails_closed_without_retry(paired, probe, failure):
    if failure == "timeout":
        failure = requests.Timeout("synthetic-private-upstream-detail")
    elif failure == "bad_json":
        # [UNVERIFIED] JSON decode failure supplied only at the HTTP boundary.
        failure = ValueError("synthetic-invalid-json-detail")
    paired.wire.probe_failures[probe] = failure
    with pytest.raises(APIException):
        operation(paired)
    assert paired.wire.counts[probe[0]] == probe[1]
    assert paired.wire.counts["dispatch"] == probe[1] - 1


@pytest.mark.parametrize("phase", ["pre", "post"])
@pytest.mark.parametrize("field,value", [
    ("oncall_org_id", 800003), ("grafana_org_id", 900001),
    ("namespace", "rotated-namespace"), ("issuer", "https://new-issuer.example.test"),
    ("key_id", "new-key-id"), ("ttl_seconds", 61),
    ("internal_origin", "http://new-target.invalid:3000"),
    ("public_origin", "https://new-public.example.test"),
])
def test_entire_binding_is_compared_without_following_changed_destination(
    paired, settings, phase, field, value,
):
    target_number = 1 if phase == "pre" else 2

    def mutate(kind, number):
        if kind == "org" and number == target_number:
            change_binding(settings, **{field: value})

    paired.wire.on_probe = mutate
    with pytest.raises(PermissionDenied):
        operation(paired)
    assert paired.wire.counts["dispatch"] == target_number - 1
    assert all(prepared.url.startswith(paired.binding_values["internal_origin"] + "/")
               for _, prepared, _ in paired.wire.calls)


@pytest.mark.parametrize("number", [1, 2])
def test_signer_rotation_same_filename_and_kid_changes_public_der_binding(
    paired, number,
):
    def rotate(kind, count):
        if kind == "org" and count == number:
            key = ec.generate_private_key(ec.SECP256R1())
            content = key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            # [UNVERIFIED] This is ONLY the newly generated fixture file.
            with open(paired.binding_values["private_key_file"], "wb") as target:
                target.write(content)

    paired.wire.on_probe = rotate
    with pytest.raises(PermissionDenied):
        operation(paired)
    assert paired.wire.counts["dispatch"] == number - 1


@pytest.mark.parametrize("method", [READ, WRITE])
def test_postcheck_failure_discards_result_but_does_not_claim_write_rollback(
    paired, settings, method, caplog,
):
    observed_effects = []
    paired.wire.dispatch_payload = {
        "incident": {"incidentID": "inc-test", "title": "PRIVATE-RESULT-SENTINEL"},
    }

    def observed_dispatch():
        # [UNVERIFIED] A stub's observed effect, NOT a real Core commit proof.
        observed_effects.append(method)
        mutate_actor(paired, "feature", settings)

    paired.wire.on_dispatch = observed_dispatch
    with pytest.raises(APIException) as caught:
        operation(paired, method=method)
    assert observed_effects == [method]
    assert paired.wire.counts["dispatch"] == 1
    assert "PRIVATE-RESULT-SENTINEL" not in caplog.text
    # [UNVERIFIED] R2: check the raised payload/message AND logs, for both verbs.
    serialized_exception = json.dumps({
        "detail": caught.value.detail, "message": str(caught.value),
        "args": caught.value.args,
    }, ensure_ascii=False, default=str)
    private_values = ["PRIVATE-RESULT-SENTINEL"] + [
        prepared.headers[header]
        for _, prepared, _ in paired.wire.calls
        for header in ("X-Access-Token", "X-Grafana-Id")
    ]
    for surface in (serialized_exception, caplog.text):
        for private_value in private_values:
            assert private_value not in surface


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError])
def test_unknown_write_outcome_is_not_retried_or_relabelled_rolled_back(
    paired, failure, caplog,
):
    attempts = []

    def fail_after_send():
        attempts.append("write sent; outcome unknown")
        raise failure("PRIVATE-UPSTREAM-DETAIL")

    paired.wire.on_dispatch = fail_after_send
    with pytest.raises(IncidentTransportError) as caught:
        operation(paired, method=WRITE)
    assert attempts == ["write sent; outcome unknown"]
    assert paired.wire.counts["dispatch"] == 1
    combined = str(caught.value) + caplog.text
    assert "PRIVATE-UPSTREAM-DETAIL" not in combined
    for _, prepared, _ in paired.wire.calls:
        assert prepared.headers["X-Access-Token"] not in combined
        assert prepared.headers["X-Grafana-Id"] not in combined


def test_valid_read_requires_post_probes_not_just_cached_preproof(paired):
    paired.wire.user_changes[2] = {"orgId": paired.core_org + 1}
    with pytest.raises(PermissionDenied):
        operation(paired)
    assert [phase for phase, _, _ in paired.wire.calls] == [
        "user", "org", "dispatch", "user", "org",
    ]
