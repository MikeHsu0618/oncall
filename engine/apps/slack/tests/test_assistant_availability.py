import hashlib
import hmac
import json
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

import pytest
import requests
from django.db import connection, transaction
from django.utils import timezone

from apps.slack.assistant import INVESTIGATE_ALERT_ACTION_ID, assistant_available, shared_installation_owned
from apps.slack.models import SharedSlackInstallation, SlackMessage, SlackTeamIdentity
from apps.slack.scenarios.distribute_alerts import IncomingAlertStep
from apps.slack.tasks import update_alert_group_slack_message
from apps.slack.tests.test_shared_app import alert_context, availability, connected, send  # noqa: F401
from apps.user_management.models import Organization

pytestmark = pytest.mark.django_db(transaction=True)


def actions(blocks):
    return [element.get("action_id", "") for block in blocks for element in block.get("elements", [])]


def sent_actions(kwargs):
    return actions(kwargs["blocks"]) + [action for attachment in kwargs["attachments"]
                                         for action in actions(attachment.get("blocks", []))]


def test_signed_fresh_availability_ignores_saved_bool_and_tracks_toggles(alert_context, availability, settings):
    organization, _, body, group, _, _ = alert_context
    from apps.alerts.incident_appearance.renderers.slack_renderer import AlertGroupSlackRenderer
    renderer = AlertGroupSlackRenderer(group)
    SharedSlackInstallation.objects.update(assistant_enabled=False)
    for enabled in (True, False, True):
        availability.enabled = enabled
        assert (INVESTIGATE_ALERT_ACTION_ID in actions(renderer._get_buttons_blocks())) is enabled
    assert len(availability.calls) == 3
    url, request = availability.calls[0]
    assert url == settings.SHARED_SLACK_AVAILABILITY_URL
    payload = json.loads(request["data"])
    assert payload == {"version": 1, "orgId": "1", "teamId": "T1", "appId": "A1",
                       "installationFingerprint": hashlib.sha256(b"xoxb-test").hexdigest(),
                       "sourceOwner": body["sourceOwner"]}
    timestamp = request["headers"]["X-Oncall-Timestamp"]
    signature = hmac.new(b"bridge-secret", b"v1:" + timestamp.encode() + b":" + request["data"],
                         hashlib.sha256).hexdigest()
    assert request["headers"]["X-Oncall-Signature"] == "v1=" + signature
    assert request["headers"]["Accept-Encoding"] == "identity"
    assert request["timeout"] == (2.5, 2.5)
    assert request["allow_redirects"] is False and request["stream"] is True
    assert all(reply.closed for reply in availability.responses)
    assert not connection.in_atomic_block


@pytest.mark.parametrize("kind", ["missing", "extra", "version_bool", "version_string", "bool_string",
                                   "bool_int", "org", "team", "app", "fingerprint", "duplicate",
                                   "array", "utf8", "malformed", "oversized"])
def test_bad_response_hides_ai_and_closes(alert_context, availability, kind):
    organization = alert_context[0]
    assert assistant_available(organization)
    payload = json.loads(availability.calls[-1][1]["data"])
    result = {**payload, "assistantAvailable": True}
    if kind == "missing":
        result.pop("appId")
    elif kind == "extra":
        result["untrusted"] = True
    elif kind == "version_bool":
        result["version"] = True
    elif kind == "version_string":
        result["version"] = "1"
    elif kind == "bool_string":
        result["assistantAvailable"] = "true"
    elif kind == "bool_int":
        result["assistantAvailable"] = 1
    elif kind in {"org", "team", "app", "fingerprint"}:
        result[{"org": "orgId", "team": "teamId", "app": "appId", "fingerprint": "installationFingerprint"}[kind]] = "wrong"
    availability.raw = json.dumps(result).encode()
    if kind == "duplicate":
        availability.raw = availability.raw[:-1] + b',"assistantAvailable":true}'
    elif kind == "array":
        availability.raw = b"[]"
    elif kind == "utf8":
        availability.raw = b"\xff"
    elif kind == "malformed":
        availability.raw = b"{"
    elif kind == "oversized":
        availability.raw = b" " * 4097
    assert assistant_available(organization) is False
    assert availability.responses[-1].closed


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 409, 429, 500, 503])
def test_non200_never_enables_ai(alert_context, availability, status):
    availability.status = status
    assert assistant_available(alert_context[0]) is False
    assert availability.responses[-1].closed


@pytest.mark.parametrize("failure", [requests.Timeout(), requests.ConnectionError(), UnicodeEncodeError("ascii", "é", 0, 1, "bad")])
def test_transport_exception_preserves_native_render(alert_context, availability, failure):
    from apps.alerts.incident_appearance.renderers.slack_renderer import AlertGroupSlackRenderer
    with patch("apps.slack.assistant.requests.post", side_effect=failure):
        buttons = actions(AlertGroupSlackRenderer(alert_context[3])._get_buttons_blocks())
    assert INVESTIGATE_ALERT_ACTION_ID not in buttons
    assert any(button.startswith("AcknowledgeGroupStep") for button in buttons)


@pytest.mark.parametrize("change", ["token", "app", "team", "revoked", "unlink", "shared_delete", "shared_replace", "map"])
def test_change_during_http_hides_ai(alert_context, availability, settings, change):
    organization = alert_context[0]
    def mutate():
        if change == "token":
            SlackTeamIdentity.objects.update(bot_access_token="xoxb-new")
        elif change == "app":
            SlackTeamIdentity.objects.update(cached_app_id="A2")
        elif change == "team":
            SlackTeamIdentity.objects.update(slack_id="T2")
        elif change == "revoked":
            SlackTeamIdentity.objects.update(detected_token_revoked=timezone.now())
        elif change == "unlink":
            Organization.objects.filter(pk=organization.pk).update(slack_team_identity=None)
        elif change == "shared_delete":
            SharedSlackInstallation.objects.all().delete()
        elif change == "shared_replace":
            row = SharedSlackInstallation.objects.get()
            SharedSlackInstallation.objects.all().delete()
            SharedSlackInstallation.objects.create(organization_id=row.organization_id, team_id=row.team_id)
        else:
            settings.SHARED_SLACK_ORG_MAP = {"2": organization.pk}
    availability.mutate = mutate
    assert assistant_available(organization) is False
    assert len(availability.calls) == 1


def test_stale_orm_after_unlink_neither_renders_nor_owns(alert_context, availability):
    organization = alert_context[0]
    cached_team = organization.slack_team_identity
    assert cached_team is not None
    Organization.objects.filter(pk=organization.pk).update(slack_team_identity=None)
    assert organization.slack_team_identity is cached_team
    assert assistant_available(organization) is False
    assert shared_installation_owned(organization) is False
    assert availability.calls == []


def test_no_http_inside_transaction(alert_context, availability):
    with transaction.atomic():
        assert shared_installation_owned(alert_context[0]) is True
        assert assistant_available(alert_context[0]) is False
    assert availability.calls == []


@pytest.mark.parametrize("missing", ["url", "secret", "map", "ambiguous", "bad_org", "bad_value", "bool_value", "invalid_app", "invalid_team", "long_team", "no_token"])
def test_missing_or_ambiguous_owner_never_calls_http(alert_context, availability, settings, missing):
    organization = alert_context[0]
    if missing == "url":
        settings.SHARED_SLACK_AVAILABILITY_URL = ""
    elif missing == "secret":
        settings.SHARED_SLACK_BRIDGE_SECRET = ""
    elif missing in {"map", "ambiguous", "bad_org", "bad_value", "bool_value"}:
        settings.SHARED_SLACK_ORG_MAP = {"map": {}, "ambiguous": {"1": organization.pk, "2": organization.pk},
            "bad_org": {"01": organization.pk}, "bad_value": {"1": str(organization.pk)},
            "bool_value": {"1": True}}[missing]
    elif missing == "invalid_app":
        SlackTeamIdentity.objects.update(cached_app_id="Aé")
    elif missing == "invalid_team":
        SlackTeamIdentity.objects.update(slack_id="T\n")
    elif missing == "long_team":
        SlackTeamIdentity.objects.update(slack_id="T" + "1" * 64)
    else:
        SlackTeamIdentity.objects.update(bot_access_token="")
    assert assistant_available(organization) is False
    assert availability.calls == []


@pytest.mark.parametrize("phase", ["headers", "chunk", "finish"])
def test_elapsed_deadline_hides_ai_and_closes(alert_context, availability, phase):
    assert assistant_available(alert_context[0])
    clocks = {"headers": [0, 3], "chunk": [0, 0, 3],
              "finish": [0] * (len(availability.responses[-1].raw) + 2) + [3]}[phase]
    with patch("apps.slack.assistant.time.monotonic", side_effect=clocks):
        assert assistant_available(alert_context[0]) is False
    assert availability.responses[-1].closed


@pytest.mark.parametrize("headers", [
    {}, {"Content-Length": "0"}, {"Content-Length": "4097"}, {"Content-Length": "01"},
    {"Content-Length": " 1"}, {"Content-Length": "+1"}, {"Content-Length": "١"},
    {"Content-Length": "1, 1"}, {"Content-Length": 1}, {"Content-Length": "-1"},
    {"Content-Length": "1", "Transfer-Encoding": "chunked"},
    {"Content-Length": "1", "Transfer-Encoding": ""},
    {"Content-Length": "1", "Content-Encoding": "gzip"},
    {"Content-Length": "1", "Content-Encoding": "deflate"},
    {"Content-Length": "1", "Content-Encoding": "identity, identity"},
])
def test_invalid_framing_hides_ai_without_body_read(alert_context, availability, headers):
    availability.headers = headers
    assert assistant_available(alert_context[0]) is False
    assert availability.responses[-1].closed
    assert availability.responses[-1].read_bytes == 0


@pytest.mark.parametrize("offset", [-1, 1])
def test_declared_length_mismatch_hides_ai(alert_context, availability, offset):
    assert assistant_available(alert_context[0])
    length = len(availability.responses[-1].raw)
    availability.headers = {"Content-Length": str(length + offset)}
    assert assistant_available(alert_context[0]) is False
    assert availability.responses[-1].closed


def test_identity_body_is_supported(alert_context, availability):
    assert assistant_available(alert_context[0])
    availability.headers = {"Content-Length": str(len(availability.responses[-1].raw)), "Content-Encoding": "identity"}
    assert assistant_available(alert_context[0])


def test_slow_byte_body_stops_at_deadline_preserving_original_publish(alert_context, availability, make_alert_group, make_alert):
    import time
    organization, _, _, existing_group, _, _ = alert_context
    organization.default_slack_channel = SlackMessage.objects.get(alert_group=existing_group).channel
    organization.save(update_fields=["default_slack_channel"])
    group = make_alert_group(existing_group.channel, slack_message_sent=False)
    alert = make_alert(group, {})
    # Header receipt succeeds, then each individual byte consumes one second.
    # Patch the optional renderer's clock only; Python's global time module is
    # shared with the independent signed owner verifier and must remain real.
    with patch("apps.slack.assistant.time", SimpleNamespace(time=time.time,
            monotonic=MagicMock(side_effect=[0, 0, 1, 2, 3]))):
        with patch("apps.slack.client.SlackClient.chat_postMessage", return_value={"ts": "567.8"}) as post:
            IncomingAlertStep(organization.slack_team_identity).process_signal(alert)
    post.assert_called_once()
    buttons = sent_actions(post.call_args.kwargs)
    assert INVESTIGATE_ALERT_ACTION_ID not in buttons
    assert any(button.startswith("AcknowledgeGroupStep") for button in buttons)
    assert availability.responses[-1].closed
    assert availability.responses[-1].read_bytes == 3


@pytest.mark.parametrize("enabled", [True, False, "outage"])
def test_original_initial_post_and_background_update_preserve_native_controls(
        alert_context, availability, enabled, make_alert_group, make_alert, monkeypatch):
    organization, _, _, existing_group, _, _ = alert_context
    channel = SlackMessage.objects.get(alert_group=existing_group).channel
    organization.default_slack_channel = channel
    organization.save(update_fields=["default_slack_channel"])
    group = make_alert_group(existing_group.channel, slack_message_sent=False)
    alert = make_alert(group, {})
    availability.enabled = enabled is True
    if enabled == "outage":
        monkeypatch.setattr("apps.slack.assistant.requests.post", lambda *a, **kw: (_ for _ in ()).throw(requests.Timeout()))
    with patch("apps.slack.client.SlackClient.chat_postMessage", return_value={"ts": "456.7"}) as post:
        IncomingAlertStep(organization.slack_team_identity).process_signal(alert)
    post.assert_called_once()
    post_buttons = sent_actions(post.call_args.kwargs)
    assert (INVESTIGATE_ALERT_ACTION_ID in post_buttons) is (enabled is True)
    assert any(button.startswith("AcknowledgeGroupStep") for button in post_buttons)
    message = SlackMessage.objects.get(alert_group=group)
    message.set_active_update_task_id("availability-update")
    with patch("apps.slack.tasks.SlackClient.chat_update") as update:
        update_alert_group_slack_message.apply((message.pk,), task_id="availability-update").get()
    update.assert_called_once()
    update_buttons = sent_actions(update.call_args.kwargs)
    assert (INVESTIGATE_ALERT_ACTION_ID in update_buttons) is (enabled is True)
    assert any(button.startswith("AcknowledgeGroupStep") for button in update_buttons)
    assert SharedSlackInstallation.objects.count() == 1
