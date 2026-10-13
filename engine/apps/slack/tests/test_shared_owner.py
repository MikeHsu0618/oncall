"""Original SQL owners and actual SDK physical sends; no live Slack calls."""
import copy
from contextlib import contextmanager, nullcontext
import hashlib
import io
import json
from datetime import timedelta
from types import SimpleNamespace
from urllib.error import URLError
from unittest.mock import MagicMock, patch
from rest_framework.response import Response
from uuid import uuid4

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.slack.client import SharedMutationUnknown, SlackClient
from apps.slack.errors import SlackAPITokenError
from apps.slack.incident_paging import SessionClient, _session_dispatch_snapshot, start_incident_paging
from apps.slack.models import SharedSlackDelivery, SharedSlackInstallation, SharedSlackPagingSession, SlackTeamIdentity
from apps.slack.paging_outbox import deliver_result
from apps.slack.shared_owner import (SharedOwnerError, SharedSourceOwner, local_source_snapshot, modal_owner,
    parse_link, strict_json, using_shared_delivery, using_shared_owner, verify_source)
from apps.slack.tests.test_shared_app import (connected, dispatch_body, install_owner_transport, link_receipt,
    send, source_owner, alert_context)

# Captured at collection, before original conftest's autouse SDK fake runs.
_ORIGINAL_API_CALL = SlackClient.api_call

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def admitted(connected, settings, monkeypatch):
    org, user, body = connected
    wire = install_owner_transport(settings, monkeypatch)
    assert send(body).status_code == 200
    org.refresh_from_db(); user.refresh_from_db()
    return org, user, body, wire


class SlackReply:
    def __init__(self, value=None, *, raw=None, status=200):
        self.buffer = io.BytesIO(raw if raw is not None else json.dumps(value or {"ok": True}).encode())
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self.closed = False
    def read(self, size):
        return self.buffer.read(size)
    def close(self):
        self.closed = True


def physical(monkeypatch, *, response=None, error=None, mutate=None, response_for=None):
    # Selectively restore the ORIGINAL bound implementation. Only the final
    # urllib opener is fake; SDK encoding, owner/business/SQL guards stay real.
    monkeypatch.setattr(SlackClient, "api_call", _ORIGINAL_API_CALL)
    state = SimpleNamespace(calls=[], responses=[])
    class Opener:
        def open(self, request, timeout):
            assert not transaction.get_connection().in_atomic_block
            state.calls.append(request)
            if mutate:
                mutate()
            if error:
                raise error
            reply = response_for(request) if response_for is not None else response or SlackReply({"ok": True, "channel": "C1", "ts": "123.4"})
            state.responses.append(reply)
            return reply
    def build(*handlers):
        # The actual strict transport uses no proxy/redirect handler, SDK retries0.
        assert handlers[0].proxies == {}
        return Opener()
    monkeypatch.setattr("apps.slack.client.build_opener", build)
    return state


@pytest.mark.parametrize("change", [
    {"version": True}, {"stackId": "local"}, {"nativeOrgId": "01"}, {"nativeOrgId": str(2**63)},
    {"installationIncarnation": True}, {"installationIncarnation": 0}, {"installationIncarnation": -1},
    {"installationIncarnation": 2**63}, {"connectionGeneration": 1}, {"teamId": "T_bad"}, {"appId": ""},
    {"tokenSHA256": "A" * 64},
])
def test_source_is_exact_bounded_provenance_not_loose_json(change):
    with pytest.raises(SharedOwnerError):
        SharedSourceOwner.parse(source_owner(**change))


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"nested":{"x":1,"x":2}}',
    b'{"x":NaN}', b'{"x":"\\ud800"}', b'\xff', b'{} trailing'])
def test_duplicate_unicode_and_non_json_values_refuse(raw):
    with pytest.raises(SharedOwnerError):
        strict_json(raw)


@pytest.mark.parametrize("change", [{"appId": "A2"}, {"installationIncarnation": 0},
    {"connectionId": "foreign"}, {"installationId": "foreign"}, {"stackId": "foreign"}, {"teamId": "T2"}])
def test_equal_epoch_or_foreign_source_cannot_replace_original(change):
    with pytest.raises(SharedOwnerError):
        SharedSourceOwner.parse(source_owner(**change)).require_successor(SharedSourceOwner.parse(source_owner()))


def test_repr_and_parse_link_do_not_expose_credentials_or_accept_partial_identity():
    owner = SharedSourceOwner.parse(source_owner())
    assert owner.token_sha256 not in repr(owner)
    assert parse_link(link_receipt(None, revision=2))["grafanaUserId"] is None
    for link in ({"slackUserId": "U1", "grafanaUserId": "7"}, link_receipt("07"),
                 {**link_receipt("7"), "mappingId": None}, {**link_receipt("7"), "grafanaLogin": "\ud800"}):
        with pytest.raises(SharedOwnerError):
            parse_link(link)


@pytest.mark.parametrize("headers,raw,status", [
    ({"Content-Length": "0"}, None, 200), ({"Content-Length": "001"}, None, 200),
    ({"Content-Length": "99999"}, None, 200), ({"Transfer-Encoding": "chunked"}, None, 200),
    ({"Content-Encoding": "gzip"}, None, 200), ({}, None, 200),
    (None, b'{"version":1,"verified":true}', 200), (None, b'{"version":true}', 200),
    (None, None, 302), (None, None, 503),
])
def test_fixed_signed_verifier_protocol_refuses_and_closes(admitted, headers, raw, status):
    _, _, body, wire = admitted
    wire.headers, wire.raw, wire.status = headers, raw, status
    with pytest.raises(SharedOwnerError):
        verify_source(SharedSourceOwner.parse(body["sourceOwner"]), "transport")
    assert wire.responses[-1].closed


def test_no_verifier_http_inside_sql_transaction(admitted):
    _, _, body, wire = admitted
    wire.calls.clear()
    with transaction.atomic(), pytest.raises(SharedOwnerError):
        verify_source(SharedSourceOwner.parse(body["sourceOwner"]), "transport")
    assert wire.calls == []


def test_changed_verifier_configuration_after_response_never_grants_transport(admitted, settings):
    _, _, body, wire = admitted
    wire.mutate = lambda: setattr(settings, "SHARED_SLACK_OWNER_VERIFY_URL", "http://other/owner")
    with pytest.raises(SharedOwnerError):
        verify_source(SharedSourceOwner.parse(body["sourceOwner"]), "transport")
    assert wire.responses[-1].closed


@pytest.mark.parametrize("change", ["token", "app", "bot", "unlink", "tombstone"])
def test_actual_sdk_refuses_original_physical_snapshot_drift_before_send(admitted, monkeypatch, change):
    org, _, body, wire = admitted
    client = SlackClient(org.slack_team_identity, source_owner=body["sourceOwner"], source_organization=org)
    native = physical(monkeypatch)
    def mutate():
        if change == "token":
            SlackTeamIdentity.objects.filter(pk=org.slack_team_identity_id).update(bot_access_token="xoxb-new")
        elif change == "app":
            SlackTeamIdentity.objects.filter(pk=org.slack_team_identity_id).update(cached_app_id="A2")
        elif change == "bot":
            SlackTeamIdentity.objects.filter(pk=org.slack_team_identity_id).update(bot_user_id="UOTHER")
        elif change == "unlink":
            type(org).objects.filter(pk=org.pk).update(slack_team_identity=None)
        else:
            SharedSlackInstallation.objects.filter(organization=org).update(source_disconnected=True)
    wire.mutate = mutate
    with pytest.raises(SharedOwnerError):
        client.chat_postMessage(channel="C1", text="private")
    assert native.calls == []


@pytest.mark.parametrize("failure", ["loss", "server", "malformed", "duplicate", "redirect"])
def test_actual_sdk_does_not_hidden_retry_unknown_physical_write(admitted, monkeypatch, failure):
    org, _, body, _ = admitted
    client = SlackClient(org.slack_team_identity, enable_ratelimit_retry=True,
        source_owner=body["sourceOwner"], source_organization=org)
    assert client.retry_handlers == []
    options = {"error": URLError("lost response")} if failure == "loss" else {"response": SlackReply(
        raw=b'{"ok":true,"ok":false}' if failure == "duplicate" else b'not-json' if failure == "malformed" else b'{"ok":false,"error":"internal_error"}',
        status=503 if failure == "server" else 302 if failure == "redirect" else 200)}
    native = physical(monkeypatch, **options)
    with pytest.raises(SharedMutationUnknown):
        client.chat_postMessage(channel="C1", text="private")
    assert len(native.calls) == 1
    assert all(reply.closed for reply in native.responses)


def test_actual_sdk_allows_original_native_write_and_retains_known_coordinates(admitted, monkeypatch):
    org, _, body, wire = admitted
    native = physical(monkeypatch)
    result = SlackClient(org.slack_team_identity, source_organization=org).chat_postMessage(channel="C1", text="native")
    assert result["ts"] == "123.4"
    assert len(native.calls) == 1 and native.responses[0].closed
    assert native.calls[0].full_url == "https://slack.com/api/chat.postMessage"
    assert native.calls[0].get_header("Authorization") == "Bearer xoxb-test"
    assert wire.calls[-2][1]["purpose"] == "transport"
    assert wire.calls[-1][0].endswith("oncall-publish-verify")


@pytest.mark.parametrize("destination", ["https://www.slack.com/api/", "https://foreign.invalid/api/", "http://slack.com/api/"])
def test_actual_sdk_shared_fixed_base_cannot_be_overridden_after_constructor(admitted, monkeypatch, destination):
    org, _, _, _ = admitted
    client = SlackClient(org.slack_team_identity, source_organization=org)
    assert client.base_url == "https://slack.com/api/"
    native = physical(monkeypatch)
    client.base_url = destination
    with pytest.raises(SharedOwnerError):
        client.chat_postMessage(channel="C1", text="private")
    assert native.calls == []


def test_late_old_token_error_never_marks_replacement_token_revoked(admitted, monkeypatch):
    org, _, body, _ = admitted
    client = SlackClient(org.slack_team_identity, source_organization=org)
    def rotate():
        SlackTeamIdentity.objects.filter(pk=org.slack_team_identity_id).update(bot_access_token="xoxb-new")
        SharedSlackInstallation.objects.filter(organization=org).update(source_owner=source_owner("xoxb-new"))
    native = physical(monkeypatch, response=SlackReply({"ok": False, "error": "token_revoked", "private": "do-not-log"}), mutate=rotate)
    with pytest.raises(SlackAPITokenError) as error:
        client.chat_postMessage(channel="C1", text="private")
    current = SlackTeamIdentity.objects.get(pk=org.slack_team_identity_id)
    assert current.bot_access_token == "xoxb-new" and current.detected_token_revoked is None
    assert "do-not-log" not in str(error.value)
    assert len(native.calls) == 1


def test_original_unproved_shared_projection_never_uses_legacy_transport(admitted, monkeypatch):
    org, _, _, _ = admitted
    SharedSlackInstallation.objects.filter(organization=org).update(source_owner=None)
    native = physical(monkeypatch)
    with pytest.raises(SharedOwnerError):
        SlackClient(org.slack_team_identity, source_owner=None).chat_postMessage(channel="C1", text="native")
    assert native.calls == []


def test_sync_disconnect_reconnect_epochs_preserve_tombstone_and_refuse_delayed_sync(admitted):
    org, user, body, wire = admitted
    disconnected = source_owner()
    assert send({"operation": "disconnect", "orgId": "1", "teamId": "T1", "sourceOwner": disconnected}).status_code == 200
    assert SharedSlackInstallation.objects.get(organization=org).source_disconnected
    # No counter orders a delayed sync: the connector's fresh proof refuses it (the owner is not active).
    wire.status = 409
    assert send(body).status_code == 503
    assert SharedSlackInstallation.objects.get(organization=org).source_disconnected
    wire.status = 200
    reconnected = source_owner(installationIncarnation=2)
    assert send({**body, "sourceOwner": reconnected}).status_code == 200
    assert send({**body, "sourceOwner": disconnected}).status_code == 409  # never back to an older incarnation
    wire.status = 409  # authoritative connector denies old post-retirement tuple
    assert send({"operation": "disconnect", "orgId": "1", "teamId": "T1", "sourceOwner": disconnected}).status_code == 503
    row = SharedSlackInstallation.objects.get(organization=org)
    assert row.source_owner == reconnected and not row.source_disconnected
    user.refresh_from_db(); assert user.slack_user_identity is not None


def test_config_drift_during_native_sql_sync_rolls_back_original_projection(admitted, monkeypatch, settings):
    org, _, body, _ = admitted
    original = SlackTeamIdentity.save
    def changed(team, *args, **kwargs):
        result = original(team, *args, **kwargs)
        settings.SHARED_SLACK_OWNER_VERIFY_URL = "http://other/owner"
        return result
    monkeypatch.setattr(SlackTeamIdentity, "save", changed)
    assert send({**body, "installation": {**body["installation"], "botToken": "xoxb-new"},
        "sourceOwner": source_owner("xoxb-new")}).status_code == 503
    assert SlackTeamIdentity.objects.get(pk=org.slack_team_identity_id).bot_access_token == "xoxb-test"
    assert SharedSlackInstallation.objects.get(organization=org).source_owner == body["sourceOwner"]


def test_complete_link_snapshot_removes_peers_but_partial_sync_preserves_them(admitted, make_user_for_organization):
    org, user, body, _ = admitted
    other = make_user_for_organization(org)
    second = {**link_receipt(str(other.user_id), slack_user="U2", revision=2), "mappingId": "mapping-2"}
    assert send({**body, "link": second}).status_code == 200
    other.refresh_from_db(); assert other.slack_user_identity_id is not None
    partial = {**body}; partial.pop("link")
    assert send(partial).status_code == 200
    other.refresh_from_db(); assert other.slack_user_identity_id is not None
    assert send({**partial, "linksRevision": 3, "links": [link_receipt(str(user.user_id), revision=3)]}).status_code == 200
    other.refresh_from_db(); assert other.slack_user_identity_id is None
    assert send({**body, "link": second}).status_code == 409


def test_known_completed_delivery_replay_drains_without_current_permission(admitted):
    org, _, body, wire = admitted
    data = dispatch_body(body); data["payload"]["command"] = "/grafana"
    with patch("apps.slack.shared_app.SlackEventApiEndpointView.dispatch_payload", return_value=Response({"done": True})) as native:
        assert send(data).data == {"done": True}
        SharedSlackInstallation.objects.filter(organization=org).update(source_disconnected=True)
        wire.status = 503; wire.calls.clear()
        assert send(data).data == {"done": True}
        native.assert_called_once()
    assert wire.calls == []


def test_actual_modal_open_binds_original_view_and_ids_only_origin(admitted, monkeypatch, settings):
    org, user, body, _ = admitted
    owner = SharedSourceOwner.parse(body["sourceOwner"])
    receipt = SharedSlackDelivery.objects.create(key="b" * 64, source_owner=owner.projection())
    native = physical(monkeypatch, response=SlackReply({"ok": True, "view": {"id": "V1"}}))
    view = {"type": "modal", "callback_id": "native_form", "private_metadata": "original-metadata",
        "title": {"type": "plain_text", "text": "Native"}, "blocks": []}
    with using_shared_owner(org.pk, owner), using_shared_delivery(receipt.pk, "U1", "C1", "123.4"):
        SlackClient(org.slack_team_identity, source_organization=org).views_open(trigger_id="original-trigger", view=view)
    assert len(native.calls) == 1
    payload = {"type": "view_submission", "team": {"id": "T1"}, "api_app_id": "A1", "user": {"id": "U1"},
        "view": {"id": "V1", "callback_id": "native_form", "private_metadata": "original-metadata"}}
    assert modal_owner(payload, "T1", "A1")["sourceOwner"] == owner.projection()
    settings.SHARED_SLACK_ORG_MAP = {}  # original discovery must not use a new default
    origin = {"kind": "view", "viewId": "V1", "slackUserId": "U1"}
    result = send({"operation": "origin", "teamId": "T1", "appId": "A1", "origin": origin})
    assert result.data == {"version": 1, "sourceOwner": owner.projection(), "origin": origin}
    not_mine = send({"operation": "origin", "teamId": "T1", "appId": "A1", "origin": {**origin, "slackUserId": "U2"}})
    # The versioned "not mine" lets the connector complete its job instead of retrying it.
    assert not_mine.status_code == 404 and not_mine.data == {"version": 1, "notOwned": True}
    unknown = send({"operation": "origin", "teamId": "T1", "appId": "A1",
        "origin": {"kind": "message", "channelId": "C9", "messageTS": "1.2", "slackUserId": "U1"}})
    assert unknown.status_code == 404 and unknown.data == {"version": 1, "notOwned": True}
    payload["view"]["private_metadata"] = "forged"
    assert modal_owner(payload, "T1", "A1") is None


def test_original_root_null_source_is_not_migrated_by_a_button(admitted, make_alert_receive_channel,
        make_alert_group, make_slack_channel, make_slack_message):
    org, _, body, _ = admitted
    group = make_alert_group(make_alert_receive_channel(org))
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    root = make_slack_message(channel, alert_group=group, slack_id="123.4")
    with patch("apps.slack.shared_app.SlackEventApiEndpointView.dispatch_payload") as native:
        assert send(dispatch_body(body)).status_code == 409
        native.assert_not_called()
    root.refresh_from_db(); assert root.source_owner is None


def test_session_native_view_http_is_outside_sql_and_unknown_never_replayed(admitted, monkeypatch):
    org, user, body, _ = admitted
    session = SharedSlackPagingSession.objects.create(organization=org, team=org.slack_team_identity,
        reservation_token=uuid4(), grafana_org_id="1", slack_user_id="U1", grafana_user_id=str(user.user_id),
        app_id="A1", bot_user_id="UB1", source_owner=body["sourceOwner"], incident_context={"channelId": "C1"},
        view_id="V1", expires_at=timezone.now() + timedelta(minutes=15))
    original = _session_dispatch_snapshot(session)
    native = physical(monkeypatch, error=URLError("ACK lost"))
    proxy = SessionClient(session, SlackClient(org.slack_team_identity, source_organization=org))
    view = {"type": "modal", "callback_id": "FinishDirectPaging", "private_metadata": json.dumps({"organization_id": org.pk}),
        "title": {"type": "plain_text", "text": "Paging"}, "blocks": []}
    with pytest.raises(SharedMutationUnknown):
        proxy.views_update(view_id="V1", view=view)
    session.refresh_from_db(); assert session.view_operation_phase == "uncertain"
    assert _session_dispatch_snapshot(session) != original
    with pytest.raises(SharedOwnerError):
        SessionClient(session, SlackClient(org.slack_team_identity, source_organization=org)).views_update(view_id="V1", view=view)
    assert len(native.calls) == 1


def test_completed_paging_callback_closes_sql_and_does_not_ack_changed_fact(admitted, settings, monkeypatch):
    org, user, body, _ = admitted
    session = SharedSlackPagingSession.objects.create(organization=org, team=org.slack_team_identity,
        reservation_token=uuid4(), grafana_org_id="1", slack_user_id="U1", grafana_user_id=str(user.user_id),
        app_id="A1", bot_user_id="UB1", source_owner=body["sourceOwner"], incident_context={}, view_id="V1",
        expires_at=timezone.now(), phase="completed", result_body='{"version":1,"fact":"original"}')
    settings.SHARED_SLACK_PAGING_RESULT_URL = "http://connector/result"
    SharedSlackInstallation.objects.filter(organization=org).update(source_disconnected=True)
    response = SimpleNamespace(status_code=202, closed=False)
    response.close = lambda: setattr(response, "closed", True)
    def post(url, **kwargs):
        assert not transaction.get_connection().in_atomic_block
        assert kwargs["data"] == b'{"version":1,"fact":"original"}'
        SharedSlackPagingSession.objects.filter(pk=session.pk).update(result_body='{"changed":true}')
        return response
    with patch("apps.slack.paging_outbox.requests.Session") as http:
        http.return_value.__enter__.return_value.post.side_effect = post
        deliver_result(session.pk)
    session.refresh_from_db()
    assert session.callback_attempts == 1 and session.callback_delivered_at is None and response.closed


def test_positive_link_revision_and_tombstone_constraints(admitted):
    org, _, _, _ = admitted
    with pytest.raises(IntegrityError), transaction.atomic():
        SharedSlackInstallation.objects.filter(organization=org).update(source_links_revision=0)
    with pytest.raises(IntegrityError), transaction.atomic():
        SharedSlackInstallation.objects.filter(organization=org).update(source_owner=None, source_disconnected=True)


@pytest.mark.parametrize("operation", ["open", "push"])
def test_real_loading_child_fills_original_view_once_without_expired_trigger(admitted, monkeypatch, operation):
    from apps.slack.shared_owner import using_loading_view
    org, _, body, _ = admitted
    owner = SharedSourceOwner.parse(body["sourceOwner"])
    receipt = SharedSlackDelivery.objects.create(key="c" * 64, source_owner=owner.projection())
    native = physical(monkeypatch, response=SlackReply({"ok": True, "view": {"id": "VLOADING"}}))
    view = {"type": "modal", "callback_id": "native_confirmation", "private_metadata": "original",
        "title": {"type": "plain_text", "text": "Native"}, "blocks": []}
    with using_shared_owner(org.pk, owner), using_shared_delivery(receipt.pk, "U1", "C1", "123.4"), using_loading_view({"id": "VLOADING"}):
        client = SlackClient(org.slack_team_identity, source_organization=org)
        getattr(client, "views_" + operation)(trigger_id="expired-trigger", view=view)
    assert len(native.calls) == 1
    assert native.calls[0].full_url == "https://slack.com/api/views.update"
    request = json.loads(native.calls[0].data)
    assert request["view_id"] == "VLOADING" and "trigger_id" not in request
    receipt.refresh_from_db()
    assert receipt.modal_owners["VLOADING"]["sourceOwner"] == body["sourceOwner"]


def test_provider_cannot_replace_requested_view_identity(admitted, monkeypatch):
    org, _, _, _ = admitted
    native = physical(monkeypatch, response=SlackReply({"ok": True, "view": {"id": "VFOREIGN"}}))
    with pytest.raises(SharedMutationUnknown):
        SlackClient(org.slack_team_identity, source_organization=org).views_update(view_id="V1", view={"type": "modal"})
    assert len(native.calls) == 1 and SharedSlackDelivery.objects.count() == 0


def test_publication_product_refusal_hides_new_effect_without_blocking_known_update(admitted, monkeypatch):
    org, _, _, wire = admitted
    native = physical(monkeypatch, response=SlackReply({"ok": True}))
    original_post = None
    def mutate():
        # Owner proof succeeds; only independent IRM business proof refuses.
        if wire.calls[-1][0].endswith("oncall-publish-verify"):
            wire.status = 403
    wire.mutate = mutate
    client = SlackClient(org.slack_team_identity, source_organization=org)
    with pytest.raises(SharedOwnerError):
        client.chat_postMessage(channel="C1", text="new native publication")
    assert native.calls == []
    wire.status = 200; wire.calls.clear(); wire.mutate = None
    client.chat_update(channel="C1", ts="123.4", text="original committed message")
    assert len(native.calls) == 1
    assert all(not url.endswith("oncall-publish-verify") for url, _ in wire.calls)


def test_original_celery_non_idempotent_tasks_do_not_auto_retry_ambiguous_effect():
    from apps.slack.tasks import send_message_to_thread_if_bot_not_in_channel
    from apps.alerts.tasks.notify_user import perform_notification
    for task in (send_message_to_thread_if_bot_not_in_channel, perform_notification):
        assert SharedMutationUnknown in task.dont_autoretry_for



def test_original_notify_task_terminal_unknown_never_calls_retry(admitted, make_alert_receive_channel,
        make_alert_group, make_slack_channel, make_slack_message, make_user_notification_policy,
        make_user_notification_policy_log_record):
    from apps.alerts.tasks.notify_user import perform_notification
    from apps.base.models import UserNotificationPolicy, UserNotificationPolicyLogRecord
    from apps.slack.models import SlackMessage
    org, user, body, _ = admitted
    group = make_alert_group(make_alert_receive_channel(org))
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"])
    policy = make_user_notification_policy(user, UserNotificationPolicy.Step.NOTIFY,
        notify_by=UserNotificationPolicy.NotificationChannel.SLACK)
    log = make_user_notification_policy_log_record(author=user, alert_group=group, notification_policy=policy,
        type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_TRIGGERED)
    with (patch.object(SlackMessage, "send_slack_notification", side_effect=SharedMutationUnknown()) as send_effect,
            patch.object(perform_notification, "retry", side_effect=AssertionError("unknown must not retry")) as retry):
        result = perform_notification.apply(args=(log.pk, False), throw=False)
        assert result.failed() and isinstance(result.result, SharedMutationUnknown)
        send_effect.assert_called_once()
        retry.assert_not_called()


def test_original_incoming_alert_sent_fence_survives_unknown_and_repeat(admitted, monkeypatch,
        make_slack_channel, make_alert_receive_channel, make_alert_group, make_alert):
    from apps.slack.scenarios.distribute_alerts import IncomingAlertStep
    org, _, body, _ = admitted
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    org.default_slack_channel = channel; org.save(update_fields=["default_slack_channel"])
    group = make_alert_group(make_alert_receive_channel(org), slack_message_sent=False)
    alert = make_alert(group, {})
    native = physical(monkeypatch, error=URLError("accepted response lost"))
    with patch.object(type(group), "render_slack_attachments", return_value=[]), patch.object(type(group), "render_slack_blocks", return_value=[]):
        step = IncomingAlertStep(org.slack_team_identity, org)
        with pytest.raises(SharedMutationUnknown):
            step.process_signal(alert)
        group.refresh_from_db(); alert.refresh_from_db()
        assert group.slack_message_sent is True and group.slack_message is None
        step.process_signal(alert)
    assert len(native.calls) == 1


@pytest.mark.parametrize("failure", ["database", "source"])
def test_successful_physical_write_then_local_failure_is_terminal_uncertain(admitted, monkeypatch, failure):
    from django.db import OperationalError
    org, _, _, _ = admitted
    client = SlackClient(org.slack_team_identity, source_organization=org)
    def mutate():
        if failure == "source":
            SharedSlackInstallation.objects.filter(organization=org).update(source_disconnected=True)
    native = physical(monkeypatch, mutate=mutate)
    if failure == "database":
        monkeypatch.setattr(client, "_unmark_token_revoked", MagicMock(side_effect=OperationalError("private DB detail")))
    with pytest.raises(SharedMutationUnknown) as error:
        client.chat_postMessage(channel="C1", text="committed native notification")
    assert len(native.calls) == 1 and native.responses[0].closed
    assert "private DB detail" not in str(error.value)


@pytest.mark.parametrize("response_action", ["errors", "update", "clear"])
def test_deferred_original_form_keeps_server_origin_and_validation(admitted, monkeypatch, response_action):
    from rest_framework.response import Response
    org, _, body, _ = admitted
    owner = SharedSourceOwner.parse(body["sourceOwner"])
    original = SharedSlackDelivery.objects.create(key="d" * 64, phase="completed", source_owner=body["sourceOwner"],
        modal_owners={"VFORM": {"organizationId": org.pk, "sourceOwner": body["sourceOwner"],
            "slackUserId": "U1", "channelId": "C1", "rootTS": "123.4",
            "callbackId": "native_form", "privateMetadata": "original"}})
    native = physical(monkeypatch, response=SlackReply({"ok": True, "view": {"id": "VFORM"}}))
    view = {"id": "VFORM", "type": "modal", "callback_id": "native_form", "private_metadata": "original",
        "title": {"type": "plain_text", "text": "Native"}, "submit": {"type": "plain_text", "text": "Save"},
        "blocks": [{"type": "input", "block_id": "original-block", "label": {"type": "plain_text", "text": "Name"},
            "element": {"type": "plain_text_input", "action_id": "original-action"}}]}
    view["state"] = {"values": {"original-block": {"original-action": {"type": "plain_text_input", "value": "retained draft"}}}}
    payload = {"type": "view_submission", "api_app_id": "A1", "team": {"id": "T1"},
        "user": {"id": "U1"}, "view": view}
    result = {"response_action": response_action}
    if response_action == "errors":
        result["errors"] = {"original-block": "Required"}
    elif response_action == "update":
        result["view"] = {k: copy.deepcopy(v) for k, v in view.items() if k != "id"}
    data = {**body, "operation": "dispatch", "deliveryId": "e" * 64, "payload": payload,
        "deferredViewSubmission": True}
    with patch("apps.slack.shared_app.SlackEventApiEndpointView.dispatch_payload", return_value=Response(result)) as dispatch:
        assert send(data).status_code == 200
        assert send(data).status_code == 200
        dispatch.assert_called_once()
    assert len(native.calls) == 1
    outgoing = json.loads(native.calls[0].data)
    assert outgoing["view_id"] == "VFORM"
    form = outgoing["view"]
    assert form["private_metadata"] == "original"
    if response_action == "errors":
        restored = form["blocks"][1]
        assert restored["block_id"] == "original-block" and restored["element"]["action_id"] == "original-action"
        assert restored["element"]["initial_value"] == "retained draft" and "Required" in form["blocks"][0]["text"]["text"]
    original.refresh_from_db()
    assert original.modal_owners["VFORM"]["sourceOwner"] == owner.projection()


@pytest.mark.parametrize("changed", ["root", "link", "token"])
def test_private_alert_context_requires_original_root_link_and_current_source(alert_context, changed):
    from apps.slack.models import SlackMessage
    org, _, body, _, _, read = alert_context
    if changed == "root":
        SlackMessage.objects.update(source_owner=None)
    elif changed == "link":
        SharedSlackInstallation.objects.filter(organization=org).update(source_links={})
    else:
        SlackTeamIdentity.objects.filter(pk=org.slack_team_identity_id).update(bot_access_token="xoxb-other")
    result = send(read)
    assert result.status_code in {403, 404, 503} and result.data is None


def test_successful_native_session_view_with_lost_sql_receipt_never_reposts(admitted, monkeypatch):
    from django.db import OperationalError
    org, user, body, _ = admitted
    session = SharedSlackPagingSession.objects.create(organization=org, team=org.slack_team_identity,
        reservation_token=uuid4(), grafana_org_id="1", slack_user_id="U1", grafana_user_id=str(user.user_id),
        app_id="A1", bot_user_id="UB1", source_owner=body["sourceOwner"], incident_context={"channelId": "C1"},
        view_id="V1", expires_at=timezone.now() + timedelta(minutes=15))
    native = physical(monkeypatch, response=SlackReply({"ok": True, "view": {"id": "V1"}}))
    proxy = SessionClient(session, SlackClient(org.slack_team_identity, source_organization=org))
    original_mutate = proxy._mutate
    def save(**changes):
        if changes == {"view_operation_phase": "ready"}:
            raise OperationalError("private receipt write failed")
        return original_mutate(**changes)
    monkeypatch.setattr(proxy, "_mutate", save)
    view = {"type": "modal", "callback_id": "FinishDirectPaging", "private_metadata": json.dumps({"organization_id": org.pk}),
        "title": {"type": "plain_text", "text": "Paging"}, "blocks": []}
    with pytest.raises(SharedMutationUnknown):
        proxy.views_update(view_id="V1", view=view)
    session.refresh_from_db(); assert session.view_operation_phase == "posting"
    with pytest.raises(SharedOwnerError):
        SessionClient(session, SlackClient(org.slack_team_identity, source_organization=org)).views_update(view_id="V1", view=view)
    assert len(native.calls) == 1


def test_original_thread_writer_post_success_sql_failure_is_terminal(admitted, monkeypatch,
        make_alert_receive_channel, make_alert_group, make_slack_channel, make_slack_message):
    from django.db import OperationalError
    from apps.slack.alert_group_slack_service import AlertGroupSlackService
    from apps.slack.models import SlackMessage
    org, _, body, _ = admitted
    group = make_alert_group(make_alert_receive_channel(org))
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"])
    native = physical(monkeypatch)
    with patch.object(SlackMessage, "save", side_effect=OperationalError("lost original receipt")):
        with pytest.raises(SharedMutationUnknown):
            AlertGroupSlackService(org.slack_team_identity).publish_message_to_alert_group_thread(group, text="Committed log")
    assert len(native.calls) == 1


@pytest.mark.parametrize("unknown", [False, True])
def test_original_denied_direct_action_uses_only_signed_private_warning(admitted, monkeypatch,
        make_alert_receive_channel, make_alert_group, make_slack_channel, make_slack_message, unknown):
    from apps.api.permissions import LegacyAccessControlRole
    org, user, body, _ = admitted
    user.role = LegacyAccessControlRole.VIEWER; user.permissions = []; user.save(update_fields=["role", "permissions"])
    group = make_alert_group(make_alert_receive_channel(org))
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"])
    def reply(request):
        # The ORIGINAL dispatcher logs the native identity, whose original
        # slack_login property performs users.info before permission refusal.
        # Exercise that real read/owner transport and return its actual shape;
        # only the physical warning mutation may have an uncertain outcome.
        if request.full_url == "https://slack.com/api/users.info":
            return SlackReply({"ok": True, "user": {"id": "U1", "name": "original-slack-user"}})
        assert request.full_url == "https://slack.com/api/chat.postEphemeral"
        if unknown:
            raise URLError("unknown ephemeral")
        return SlackReply({"ok": True, "message_ts": "123.4"})
    native = physical(monkeypatch, response_for=reply)
    data = dispatch_body(body)
    data["payload"]["actions"][0]["value"] = json.dumps({"organization_id": org.pk, "alert_group_pk": group.pk})
    if unknown:
        with pytest.raises(SharedMutationUnknown):
            send(data)
        assert send(data).status_code == 200  # original uncertain receipt, no repeat
        assert SharedSlackDelivery.objects.get().phase == "uncertain"
    else:
        assert send(data).status_code == 200
    reads = [request for request in native.calls if request.full_url == "https://slack.com/api/users.info"]
    warnings = [request for request in native.calls if request.full_url == "https://slack.com/api/chat.postEphemeral"]
    assert len(reads) == 1 and len(warnings) == 1 and len(native.calls) == 2
    assert native.calls[0] is reads[0] and native.calls[1] is warnings[0]
    assert native.responses[0].closed
    user.slack_user_identity.refresh_from_db()
    assert user.slack_user_identity.cached_slack_login == "original-slack-user"
    request = warnings[0]
    assert request.full_url == "https://slack.com/api/chat.postEphemeral"
    values = json.loads(request.data)
    assert values["channel"] == "C1" and values["user"] == "U1" and "trigger_id" not in values
    group.refresh_from_db(); assert group.acknowledged is False
    assert SharedSlackPagingSession.objects.count() == 0


def test_missing_original_warning_coordinates_refuses_without_current_defaults(admitted, monkeypatch):
    from apps.slack.scenarios.scenario_step import ScenarioStep
    org, user, body, _ = admitted
    native = physical(monkeypatch)
    with using_shared_owner(org.pk, SharedSourceOwner.parse(body["sourceOwner"])), using_shared_delivery("f" * 64, "U1", None, None):
        step = ScenarioStep(org.slack_team_identity, org, user)
        step.open_unauthorized_warning({"trigger_id": "expired", "channel": {"id": "CFORGED"}})
    assert native.calls == [] and step._shared_warning_response.status_code == 403


@pytest.mark.parametrize("error", ["user_not_in_channel", "no_permission"])
def test_original_private_denial_delivery_failure_never_selects_another_surface(admitted, monkeypatch, error):
    from apps.slack.scenarios.scenario_step import ScenarioStep
    org, user, body, _ = admitted
    native = physical(monkeypatch, response=SlackReply({"ok": False, "error": error}))
    with using_shared_owner(org.pk, SharedSourceOwner.parse(body["sourceOwner"])), using_shared_delivery("f" * 64, "U1", "C1", "123.4"):
        step = ScenarioStep(org.slack_team_identity, org, user)
        step.open_unauthorized_warning({"trigger_id": "expired", "channel": {"id": "CFORGED"}})
    assert step._shared_warning_response.status_code == 403 and len(native.calls) == 1
    assert native.calls[0].full_url.endswith("chat.postEphemeral")
    assert json.loads(native.calls[0].data)["channel"] == "C1"


def test_terminal_uncertainty_roundtrips_as_original_celery_exclusion_class():
    import pickle
    original = SharedMutationUnknown()
    restored = pickle.loads(pickle.dumps(original))
    assert type(restored) is SharedMutationUnknown
    assert str(restored) == "Shared Slack operation outcome is uncertain"


@pytest.mark.parametrize("malformed", ["leading_zero", "plus", "space", "unicode_digits", "empty", "oversize"])
def test_native_bridge_rejects_noncanonical_timestamp_even_when_hmac_matches(admitted, malformed):
    import hmac
    import time
    from rest_framework.test import APIRequestFactory
    from apps.slack.shared_app import SharedSlackAppView
    _, _, body, _ = admitted
    raw = json.dumps({"version": 1, **body}).encode()
    current = str(int(time.time()))
    timestamp = {"leading_zero": "0" + current, "plus": "+" + current, "space": current + " ",
        "unicode_digits": "".join(chr(ord(char) + 0x660 - ord("0")) for char in current),
        "empty": "", "oversize": "1" * 100}[malformed]
    signature = hmac.new(b"bridge-secret", timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    request = APIRequestFactory().post("/slack/shared-app/v1/", raw, content_type="application/json",
        HTTP_X_GRAFANA_SLACK_TIMESTAMP=timestamp, HTTP_X_GRAFANA_SLACK_SIGNATURE=signature)
    assert SharedSlackAppView.as_view()(request).status_code == 401


@pytest.mark.parametrize("signature", ["é" * 64, "A" * 64, "0" * 63, "0" * 65, "", "0" * 64 + " "])
def test_native_bridge_malformed_signature_is_coarse_unauthorized_not_server_error(admitted, signature):
    import time
    from rest_framework.test import APIRequestFactory
    from apps.slack.shared_app import SharedSlackAppView
    _, _, body, _ = admitted
    raw = json.dumps({"version": 1, **body}).encode()
    request = APIRequestFactory().post("/slack/shared-app/v1/", raw, content_type="application/json",
        HTTP_X_GRAFANA_SLACK_TIMESTAMP=str(int(time.time())), HTTP_X_GRAFANA_SLACK_SIGNATURE=signature)
    assert SharedSlackAppView.as_view()(request).status_code == 401


@pytest.mark.parametrize("event_type", ["subteam_created", "subteam_updated", "subteam_members_changed"])
def test_signed_actorless_catalog_events_use_original_native_group_writer(admitted, monkeypatch, event_type):
    from apps.slack.models import SlackUserGroup, SlackUserIdentity
    org, _, body, _ = admitted
    original_members = {"UOLD"}
    if event_type != "subteam_created":
        SlackUserGroup.objects.create(slack_team_identity=org.slack_team_identity, slack_id="S1",
            name="Previous", handle="previous", members=list(original_members), is_active=True)
    identities = SlackUserIdentity.objects.count()
    native = physical(monkeypatch)
    event = {"type": event_type, "subteam": {"id": "S1", "team_id": "T1", "name": "Current group",
        "handle": "current-group", "users": ["UNEW"], "date_delete": 0}}
    if event_type == "subteam_members_changed":
        event = {"type": event_type, "team_id": "T1", "subteam_id": "S1",
            "added_users": ["UNEW"], "removed_users": ["UOLD"]}
    data = {key: value for key, value in body.items() if key != "link"}
    data.update(operation="dispatch", deliveryId="d" * 64, payload={"type": "event_callback",
        "team_id": "T1", "api_app_id": "A1", "event_id": "EvCatalog", "event": event})
    assert send(data).status_code == 200
    group = SlackUserGroup.objects.get(slack_team_identity=org.slack_team_identity, slack_id="S1")
    assert set(group.members) == {"UNEW"}
    if event_type != "subteam_members_changed":
        assert group.name == "Current group" and group.handle == "current-group" and group.is_active
    assert SlackUserIdentity.objects.count() == identities and native.calls == []
    receipt = SharedSlackDelivery.objects.get()
    assert receipt.phase == "completed" and receipt.source_owner == body["sourceOwner"]
    assert send(data).status_code == 200 and SharedSlackDelivery.objects.count() == 1


@pytest.mark.parametrize("event_type", ["message", "app_mention", "user_change", "subteam_created_forged"])
def test_other_actorless_events_refuse_before_native_catalog_or_receipt_write(admitted, monkeypatch, event_type):
    from apps.slack.models import SlackUserGroup
    org, _, body, _ = admitted
    native = physical(monkeypatch)
    data = {key: value for key, value in body.items() if key != "link"}
    data.update(operation="dispatch", deliveryId="e" * 64, payload={"type": "event_callback",
        "team_id": "T1", "api_app_id": "A1", "event_id": "EvInvalid", "event": {"type": event_type}})
    assert send(data).status_code == 403
    assert SlackUserGroup.objects.count() == 0 and SharedSlackDelivery.objects.count() == 0
    assert native.calls == []


@pytest.mark.parametrize("change", ["app", "team", "epoch", "mapping", "disconnected"])
def test_actorless_catalog_event_never_bypasses_original_source_proof(admitted, monkeypatch, settings, change):
    from apps.slack.models import SlackUserGroup
    org, _, body, _ = admitted
    native = physical(monkeypatch)
    data = copy.deepcopy({key: value for key, value in body.items() if key != "link"})
    data.update(operation="dispatch", deliveryId="b" * 64, payload={"type": "event_callback",
        "team_id": "T1", "api_app_id": "A1", "event_id": "EvProof", "event": {"type": "subteam_created",
        "subteam": {"id": "S1", "name": "Current", "handle": "current", "users": [], "date_delete": 0}}})
    if change == "app":
        data["payload"]["api_app_id"] = "A2"
    elif change == "team":
        data["payload"]["team_id"] = "T2"
    elif change == "epoch":
        data["sourceOwner"]["installationIncarnation"] = 2
    elif change == "mapping":
        settings.SHARED_SLACK_ORG_MAP = {}
    else:
        SharedSlackInstallation.objects.filter(organization=org).update(source_disconnected=True)
    assert send(data).status_code in {403, 409, 422}
    assert SlackUserGroup.objects.count() == 0 and SharedSlackDelivery.objects.count() == 0
    assert native.calls == []


@pytest.fixture
def recipient_notification(admitted, make_alert_receive_channel, make_alert_group, make_alert,
        make_slack_channel, make_slack_message, make_user_notification_policy):
    from apps.base.models import UserNotificationPolicy
    org, user, body, wire = admitted
    group = make_alert_group(make_alert_receive_channel(org))
    make_alert(group, {})
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    root = make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"],
        cached_permalink="https://example.slack.com/archives/C1/p1234")
    policy = make_user_notification_policy(user, UserNotificationPolicy.Step.NOTIFY,
        notify_by=UserNotificationPolicy.NotificationChannel.SLACK)
    user.slack_user_identity.cached_im_channel_id = "D1"
    user.slack_user_identity.save(update_fields=["cached_im_channel_id"])
    return org, user, body, wire, group, root, policy


def recipient_reply(request):
    method = request.full_url.rsplit("/", 1)[-1]
    if method == "users.info":
        return SlackReply({"ok": True, "user": {"id": "U1", "name": "original-user", "profile": {}}})
    if method == "conversations.members":
        return SlackReply({"ok": True, "members": []})
    if method == "conversations.open":
        return SlackReply({"ok": True, "channel": {"id": "D1"}})
    if method == "chat.getPermalink":
        return SlackReply({"ok": True, "permalink": "https://example.slack.com/archives/C1/p1234"})
    assert method == "chat.postMessage"
    return SlackReply({"ok": True, "channel": json.loads(request.data)["channel"], "ts": "223.4"})


@pytest.mark.parametrize("cached", [True, False])
def test_original_notification_current_recipient_uses_same_guarded_sdk_for_thread_and_dm(
        recipient_notification, monkeypatch, cached):
    org, user, body, wire, group, root, policy = recipient_notification
    if not cached:
        user.slack_user_identity.cached_im_channel_id = None
        user.slack_user_identity.save(update_fields=["cached_im_channel_id"])
        root.cached_permalink = None
        root.save(update_fields=["cached_permalink"])
    native = physical(monkeypatch, response_for=recipient_reply)
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", lambda _: None)
    root.send_slack_notification(user, group, policy)
    sends = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postMessage")]
    assert [data["channel"] for data in sends] == ["C1", "D1"]
    assert "<@U1>" in sends[0]["text"] and sends[0]["thread_ts"] == "123.4"
    assert "https://example.slack.com/archives/C1/p1234" in json.dumps(sends[1])
    methods = [req.full_url.rsplit("/", 1)[-1] for req in native.calls]
    assert ("conversations.open" in methods) is (not cached)
    assert all(reply.closed for reply in native.responses)
    proofs = [data for url, data in wire.calls if url.endswith("/oncall-link-verify")]
    assert proofs and all(proof["link"] == body["link"] and proof["owner"] == body["sourceOwner"] for proof in proofs)


@pytest.mark.parametrize("change", ["unlink", "uid", "user_incarnation", "user_aba", "identity", "policy", "source", "central_unlink", "central_relink"])
def test_original_recipient_snapshot_rejects_drift_before_targeted_thread_send(
        recipient_notification, monkeypatch, make_user_for_organization, change):
    from apps.api.permissions import LegacyAccessControlRole
    org, user, body, wire, group, root, policy = recipient_notification
    native = physical(monkeypatch, response_for=recipient_reply)
    def mutate():
        if not wire.calls[-1][0].endswith("/oncall-link-verify"):
            return
        wire.mutate = None
        if change == "unlink":
            type(user).objects.filter(pk=user.pk).update(slack_user_identity=None)
        elif change == "uid":
            type(user).objects.filter(pk=user.pk).update(user_id=user.user_id + 1)
        elif change == "user_incarnation":
            type(user).objects.filter(pk=user.pk).update(public_primary_key="UFRESHINCARNATION")
        elif change == "user_aba":
            type(user).objects.filter(pk=user.pk).update(is_active=None)
            replacement = make_user_for_organization(org, role=LegacyAccessControlRole.ADMIN,
                user_id=user.user_id, slack_user_identity=user.slack_user_identity)
            assert replacement.pk != user.pk and replacement.user_id == user.user_id
        elif change == "identity":
            type(user.slack_user_identity).objects.filter(pk=user.slack_user_identity_id).update(slack_id="UOTHER")
        elif change == "policy":
            type(user).objects.filter(pk=user.pk).update(role=LegacyAccessControlRole.VIEWER, permissions=[])
        elif change == "source":
            SharedSlackInstallation.objects.filter(organization=org).update(source_disconnected=True)
        else:
            # Local native cache and current installation owner stay unchanged.
            # Only the original central personal-link read rejects the old tuple.
            wire.raw = json.dumps({"version": 1, "verified": False,
                "reason": "removed" if change == "central_unlink" else "new_mapping_revision"}).encode()
    wire.mutate = mutate
    root.send_slack_notification(user, group, policy)
    assert native.calls == []
    assert policy.personal_log_records.filter(reason="Shared Slack recipient is unavailable").count() == 1


def test_recipient_withdrawn_during_verified_http_close_never_reaches_physical_send(
        recipient_notification, monkeypatch):
    org, user, body, wire, group, root, policy = recipient_notification
    native = physical(monkeypatch, response_for=recipient_reply)
    reply_type = type(wire.responses[-1])
    original_close = reply_type.close
    closed = []
    def close(reply):
        original_close(reply)
        if "link" in json.loads(reply.raw) and not closed:
            closed.append(reply)
            type(user).objects.filter(pk=user.pk).update(slack_user_identity=None)
    monkeypatch.setattr(reply_type, "close", close)
    root.send_slack_notification(user, group, policy)
    assert len(closed) == 1 and closed[0].closed and native.calls == []


@pytest.mark.parametrize("missing", ["link", "source"])
def test_unproved_shared_recipient_does_not_bless_original_native_identity(
        recipient_notification, monkeypatch, missing):
    org, user, body, wire, group, root, policy = recipient_notification
    native = physical(monkeypatch, response_for=recipient_reply)
    if missing == "link":
        SharedSlackInstallation.objects.filter(organization=org).update(source_links={})
    else:
        root.source_owner = None
        root.save(update_fields=["source_owner"])
    root.send_slack_notification(user, group, policy)
    assert native.calls == []


def test_shared_cached_im_channel_cannot_be_used_without_original_recipient(
        recipient_notification, monkeypatch):
    _, user, _, _, _, _, _ = recipient_notification
    native = physical(monkeypatch, response_for=recipient_reply)
    with pytest.raises(SharedOwnerError):
        _ = user.slack_user_identity.im_channel_id
    assert native.calls == []


@pytest.mark.parametrize("cached", [True, False])
@pytest.mark.parametrize("change", ["local_unlink", "central_unlink", "central_relink", "uid", "user_incarnation"])
def test_original_committed_thread_then_late_recipient_withdrawal_skips_dm_without_task_retry(
        recipient_notification, monkeypatch, make_user_notification_policy_log_record, cached, change):
    from apps.alerts.tasks.notify_user import perform_notification
    from apps.base.models import UserNotificationPolicyLogRecord
    org, user, body, wire, group, root, policy = recipient_notification
    if not cached:
        user.slack_user_identity.cached_im_channel_id = None
        user.slack_user_identity.save(update_fields=["cached_im_channel_id"])
    native = physical(monkeypatch, response_for=recipient_reply)
    def withdrawn(_):
        if change == "local_unlink":
            type(user).objects.filter(pk=user.pk).update(slack_user_identity=None)
        elif change == "uid":
            type(user).objects.filter(pk=user.pk).update(user_id=user.user_id + 1)
        elif change == "user_incarnation":
            type(user).objects.filter(pk=user.pk).update(public_primary_key="UFRESHINCARNATION")
        else:
            def central():
                wire.raw = b'{"version":1,"verified":false}' if wire.calls[-1][0].endswith("/oncall-link-verify") else None
            wire.mutate = central
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", withdrawn)
    log = make_user_notification_policy_log_record(author=user, alert_group=group, notification_policy=policy,
        type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_TRIGGERED)
    with patch.object(perform_notification, "retry", side_effect=AssertionError("known thread must not repeat")) as retry:
        result = perform_notification.apply(args=(log.pk, False), throw=False)
        assert not result.failed()
        retry.assert_not_called()
    sends = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postMessage")]
    assert len(sends) == 1 and sends[0]["channel"] == "C1"
    assert not any(req.full_url.endswith("/conversations.open") for req in native.calls)
    assert group.slack_messages.filter(slack_id="223.4").count() == 1


@pytest.mark.parametrize("method", ["chat.postMessage", "conversations.open"])
def test_recipient_change_during_physical_success_is_terminal_unknown_before_cache_or_retry(
        recipient_notification, monkeypatch, method):
    org, user, body, wire, group, root, policy = recipient_notification
    if method == "conversations.open":
        user.slack_user_identity.cached_im_channel_id = None
        user.slack_user_identity.save(update_fields=["cached_im_channel_id"])
    def replied(req):
        reply = recipient_reply(req)
        if req.full_url.endswith("/" + method):
            type(user).objects.filter(pk=user.pk).update(slack_user_identity=None)
        return reply
    native = physical(monkeypatch, response_for=replied)
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", lambda _: None)
    with pytest.raises(SharedMutationUnknown):
        root.send_slack_notification(user, group, policy)
    effects = [req for req in native.calls if req.full_url.endswith("/" + method)]
    assert len(effects) == 1 and all(reply.closed for reply in native.responses)
    if method == "conversations.open":
        from apps.slack.models import SlackUserIdentity
        assert SlackUserIdentity.objects.get(pk=user.slack_user_identity_id).cached_im_channel_id is None
    assert not any(req.full_url.endswith("/chat.postMessage") and json.loads(req.data)["channel"] == "D1" for req in native.calls)


def test_actual_original_dm_unknown_is_terminal_in_perform_notification_task(
        recipient_notification, monkeypatch, make_user_notification_policy_log_record):
    from apps.alerts.tasks.notify_user import perform_notification
    from apps.base.models import UserNotificationPolicyLogRecord
    _, user, _, _, group, _, policy = recipient_notification
    def replied(req):
        if req.full_url.endswith("/chat.postMessage") and json.loads(req.data)["channel"] == "D1":
            raise URLError("lost private DM response")
        return recipient_reply(req)
    native = physical(monkeypatch, response_for=replied)
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", lambda _: None)
    log = make_user_notification_policy_log_record(author=user, alert_group=group, notification_policy=policy,
        type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_TRIGGERED)
    with patch.object(perform_notification, "retry", side_effect=AssertionError("unknown DM must not repeat")) as retry:
        result = perform_notification.apply(args=(log.pk, False), throw=False)
        assert result.failed() and isinstance(result.result, SharedMutationUnknown)
        retry.assert_not_called()
    sends = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postMessage")]
    assert [data["channel"] for data in sends] == ["C1", "D1"]


@pytest.mark.parametrize("change", ["slack_id", "team", "counter", "cache", "root_ts", "root_created", "root_channel", "root_group"])
def test_same_pk_stale_caller_cannot_adopt_fresh_recipient_or_message(
        recipient_notification, monkeypatch, make_slack_channel, make_slack_team_identity, make_alert_receive_channel, make_alert_group, change):
    from apps.slack.models import SlackMessage
    org, user, body, wire, group, root, policy = recipient_notification
    identity = user.slack_user_identity
    # Force the caller's loaded coordinates, then mutate the same SQL PK during
    # original mention construction, before the original client captures it.
    _ = root.channel
    original_verbal = type(user).get_username_with_slack_verbal
    def verbal(current, *args, **kwargs):
        rendered = original_verbal(current, *args, **kwargs)
        if change == "slack_id":
            type(identity).objects.filter(pk=identity.pk).update(slack_id="U2")
            new_link = {**body["link"], "slackUserId": "U2"}
            SharedSlackInstallation.objects.filter(organization=org).update(source_links={"U2": new_link})
        elif change == "team":
            other = make_slack_team_identity(slack_id="TOTHER")
            type(identity).objects.filter(pk=identity.pk).update(slack_team_identity=other)
        elif change == "counter":
            type(identity).objects.filter(pk=identity.pk).update(counter=identity.counter + 1)
        elif change == "cache":
            type(identity).objects.filter(pk=identity.pk).update(cached_im_channel_id="DOTHER")
        elif change == "root_ts":
            SlackMessage.objects.filter(pk=root.pk).update(slack_id="987.6")
        elif change == "root_created":
            SlackMessage.objects.filter(pk=root.pk).update(created_at=root.created_at + timedelta(seconds=1))
        elif change == "root_channel":
            other = make_slack_channel(org.slack_team_identity, slack_id="COTHER")
            SlackMessage.objects.filter(pk=root.pk).update(channel=other)
        else:
            other = make_alert_group(make_alert_receive_channel(org))
            SlackMessage.objects.filter(pk=root.pk).update(alert_group=other)
        return rendered
    monkeypatch.setattr(type(user), "get_username_with_slack_verbal", verbal)
    native = physical(monkeypatch, response_for=recipient_reply)
    root.send_slack_notification(user, group, policy)
    assert native.calls == []


@pytest.mark.parametrize("cached", [True, False])
@pytest.mark.parametrize("change", ["slack_id", "counter", "cache"])
def test_original_dm_address_cannot_change_during_physical_admission(
        recipient_notification, monkeypatch, cached, change):
    org, user, body, wire, group, root, policy = recipient_notification
    identity = user.slack_user_identity
    if not cached:
        identity.cached_im_channel_id = None
        identity.save(update_fields=["cached_im_channel_id"])
    native = physical(monkeypatch, response_for=recipient_reply)
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", lambda _: None)
    # Change only after original thread and membership reads, at the transport
    # owner proof for the next original DM operation. No target is substituted.
    def drift():
        if (not any(req.full_url.endswith("/conversations.members") for req in native.calls)
                or not wire.calls[-1][0].endswith("/oncall-owner-verify")):
            return
        wire.mutate = None
        if change == "slack_id":
            type(identity).objects.filter(pk=identity.pk).update(slack_id="U2")
        elif change == "counter":
            type(identity).objects.filter(pk=identity.pk).update(counter=identity.counter + 1)
        else:
            type(identity).objects.filter(pk=identity.pk).update(cached_im_channel_id="DOTHER")
    wire.mutate = drift
    root.send_slack_notification(user, group, policy)
    sends = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postMessage")]
    assert [data["channel"] for data in sends] == ["C1"]
    assert not any(req.full_url.endswith("/conversations.open") for req in native.calls)


@pytest.mark.parametrize("cached", [True, False])
@pytest.mark.parametrize("withdraw", [False, True])
def test_original_completed_paging_fallback_uses_same_asking_client_not_notification_role(
        admitted, monkeypatch, make_team, cached, withdraw):
    from apps.alerts.models import AlertGroup
    from apps.slack.scenarios.paging import FinishDirectPaging
    from apps.slack.tests.scenario_steps.test_paging import make_paging_view_slack_payload
    org, user, body, wire = admitted
    from apps.api.permissions import RBACPermission, get_required_permission_values
    # Genuine current direct-paging permission, with notification access absent.
    org.is_rbac_permissions_enabled = True
    org.save(update_fields=["is_rbac_permissions_enabled"])
    user.permissions = [{"action": action} for action in get_required_permission_values(org,
        [RBACPermission.Permissions.ALERT_GROUPS_DIRECT_PAGING])]
    user.save(update_fields=["permissions"])
    assert not user.is_notification_allowed
    identity = user.slack_user_identity
    identity.cached_im_channel_id = "D1" if cached else None
    identity.save(update_fields=["cached_im_channel_id"])
    team = make_team(org)
    payload = make_paging_view_slack_payload(selected_org=org, team=team)
    metadata = json.loads(payload["view"]["private_metadata"])
    metadata["channel_id"] = "C1"
    payload["view"]["private_metadata"] = json.dumps(metadata)
    payload["channel_id"] = "C1"
    def replied(req):
        if req.full_url.endswith("/chat.postEphemeral"):
            data = json.loads(req.data)
            if data["channel"] == "C1":
                if withdraw:
                    type(user).objects.filter(pk=user.pk).update(slack_user_identity=None)
                return SlackReply({"ok": False, "error": "channel_not_found"})
            assert data["channel"] == "D1" and data["user"] == "U1"
            return SlackReply({"ok": True, "message_ts": "234.5"})
        return recipient_reply(req)
    native = physical(monkeypatch, response_for=replied)
    step = FinishDirectPaging(org.slack_team_identity, organization=org, user=user)
    with original_completion_dispatch(org, user, body, payload):
        step.process_scenario(identity, org.slack_team_identity, payload)
    assert AlertGroup.objects.count() == 1
    notices = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postEphemeral")]
    assert [data["channel"] for data in notices] == (["C1"] if withdraw else ["C1", "D1"])
    assert all(data["user"] == "U1" and data["text"].startswith(":white_check_mark: Escalation created:") for data in notices)
    assert ("conversations.open" in [req.full_url.rsplit("/", 1)[-1] for req in native.calls]) is (not cached and not withdraw)
    assert not any(url.endswith("/oncall-publish-verify") for url, _ in wire.calls)
    assert step._slack_client._notification_recipient is None
    assert all(reply.closed for reply in native.responses)


@pytest.mark.parametrize("phase", ["response", "cache_save"])
def test_original_cold_dm_cache_loss_after_provider_success_is_terminal_uncertain(
        recipient_notification, monkeypatch, phase):
    from django.db import OperationalError
    from django.db.models.query import QuerySet
    org, user, body, wire, group, root, policy = recipient_notification
    identity = user.slack_user_identity
    identity.cached_im_channel_id = None
    identity.save(update_fields=["cached_im_channel_id"])
    def replied(req):
        response = recipient_reply(req)
        if phase == "response" and req.full_url.endswith("/conversations.open"):
            type(identity).objects.filter(pk=identity.pk).update(cached_im_channel_id="DOTHER")
        return response
    native = physical(monkeypatch, response_for=replied)
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", lambda _: None)
    original_update = QuerySet.update
    def update(queryset, **kwargs):
        if phase == "cache_save" and queryset.model is type(identity) and kwargs == {"cached_im_channel_id": "D1"}:
            raise OperationalError("original cache receipt save failed")
        return original_update(queryset, **kwargs)
    monkeypatch.setattr(QuerySet, "update", update)
    with pytest.raises(SharedMutationUnknown):
        root.send_slack_notification(user, group, policy)
    assert len([req for req in native.calls if req.full_url.endswith("/conversations.open")]) == 1
    sends = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postMessage")]
    assert [data["channel"] for data in sends] == ["C1"]
    assert all(reply.closed for reply in native.responses)
    identity.refresh_from_db()
    assert identity.cached_im_channel_id == ("DOTHER" if phase == "response" else None)


@contextmanager
def original_completion_dispatch(org, user, body, payload):
    # Genuine original modal storage + accepted dispatch namespace, not caller
    # channel/text privileges. The real FinishDirectPaging writer remains used.
    payload["user"] = {"id": user.slack_user_identity.slack_id}
    payload["view"]["callback_id"] = "FinishDirectPaging"
    channel = json.loads(payload["view"]["private_metadata"])["channel_id"]
    origin = {"organizationId": org.pk, "sourceOwner": body["sourceOwner"], "slackUserId": "U1",
        "channelId": channel, "rootTS": None, "callbackId": "FinishDirectPaging",
        "privateMetadata": payload["view"]["private_metadata"]}
    key = "b" * 64
    SharedSlackDelivery.objects.create(key=key, source_owner=body["sourceOwner"], phase="dispatching",
        modal_owners={payload["view"]["id"]: origin})
    with using_shared_delivery(key, "U1", channel, None):
        yield


@pytest.mark.parametrize("fake", ["constructor", "dict", "forged", "old_arguments"])
def test_public_shared_client_cannot_mint_arbitrary_product_disabled_completion(
        admitted, monkeypatch, fake):
    from apps.slack.shared_owner import SharedPagingCompletion
    org, user, body, wire = admitted
    native = physical(monkeypatch, response_for=recipient_reply)
    client = SlackClient(org.slack_team_identity, source_owner=body["sourceOwner"], source_organization=org)
    if fake == "old_arguments":
        with pytest.raises(TypeError):
            client.bind_completion_recipient(user, user.slack_user_identity, channel_id="C1", text="arbitrary private notice")
    else:
        if fake == "constructor":
            candidate = SharedPagingCompletion()
        elif fake == "dict":
            candidate = {"owner": body["sourceOwner"], "channel_id": "C1", "text": "arbitrary private notice"}
        else:
            candidate = object.__new__(SharedPagingCompletion)
            object.__setattr__(candidate, "owner", SharedSourceOwner.parse(body["sourceOwner"]))
            object.__setattr__(candidate, "channel_id", "C1")
            object.__setattr__(candidate, "text", "arbitrary private notice")
        with pytest.raises(SharedOwnerError):
            client.bind_completion_recipient(candidate)
    assert client._completion_notice is None and native.calls == []


@pytest.mark.parametrize("bad", ["nonexistent", "foreign", "ordinary", "prior_outcome", "uncommitted", "wrong_source", "wrong_origin"])
def test_completion_mint_requires_original_committed_outcome_and_retained_modal_source(
        admitted, monkeypatch, make_team, make_organization_and_user, make_alert_receive_channel, make_alert_group, bad):
    from apps.alerts.paging import direct_paging
    from apps.slack.shared_owner import SharedPagingCompletion
    from apps.slack.scenarios.paging import FinishDirectPaging
    from apps.slack.tests.scenario_steps.test_paging import make_paging_view_slack_payload
    org, user, body, wire = admitted
    team = make_team(org)
    payload = make_paging_view_slack_payload(selected_org=org, team=team)
    metadata = json.loads(payload["view"]["private_metadata"])
    metadata["channel_id"] = "C1"
    payload["view"]["private_metadata"] = json.dumps(metadata)
    native = physical(monkeypatch, response_for=recipient_reply)
    owner = SharedSourceOwner.parse(body["sourceOwner"])
    started = timezone.now()
    group = direct_paging(org, user, "original committed page", team=team)
    if bad == "nonexistent":
        group_id = group.pk
        group.delete()
        group.pk = group_id
    elif bad == "foreign":
        other_org, other_user = make_organization_and_user()
        group = direct_paging(other_org, other_user, "foreign committed page", team=make_team(other_org))
    elif bad == "ordinary":
        group = make_alert_group(make_alert_receive_channel(org))
    elif bad == "prior_outcome":
        started = timezone.now() + timedelta(seconds=1)
    elif bad == "wrong_source":
        owner = SharedSourceOwner.parse({**body["sourceOwner"], "installationIncarnation": 2})
    with original_completion_dispatch(org, user, body, payload):
        if bad == "wrong_origin":
            payload["view"]["private_metadata"] = json.dumps({**metadata, "channel_id": "COTHER"})
        context = transaction.atomic() if bad == "uncommitted" else nullcontext()
        with context, pytest.raises(SharedOwnerError):
            SharedPagingCompletion._from_original_finish(owner, user, user.slack_user_identity, group, payload, started)
    assert native.calls == []


@pytest.mark.parametrize("bad", ["text", "channel", "outcome_deleted", "creator_changed", "origin_changed", "delivery_completed", "outcome_during_link"])
def test_minted_original_completion_rechecks_outcome_and_refuses_notice_tampering(
        admitted, monkeypatch, make_team, bad):
    from apps.alerts.paging import direct_paging
    from apps.slack.shared_owner import SharedPagingCompletion
    from apps.slack.tests.scenario_steps.test_paging import make_paging_view_slack_payload
    org, user, body, wire = admitted
    team = make_team(org)
    payload = make_paging_view_slack_payload(selected_org=org, team=team)
    metadata = json.loads(payload["view"]["private_metadata"])
    metadata["channel_id"] = "C1"
    payload["view"]["private_metadata"] = json.dumps(metadata)
    started = timezone.now()
    group = direct_paging(org, user, "original committed page", team=team)
    owner = SharedSourceOwner.parse(body["sourceOwner"])
    native = physical(monkeypatch, response_for=recipient_reply)
    client = SlackClient(org.slack_team_identity, source_owner=body["sourceOwner"], source_organization=org)
    with original_completion_dispatch(org, user, body, payload):
        completion = SharedPagingCompletion._from_original_finish(owner, user, user.slack_user_identity, group, payload, started)
        if bad in {"text", "channel"}:
            object.__setattr__(completion, "text" if bad == "text" else "channel_id", "forged notice" if bad == "text" else "COTHER")
        elif bad == "outcome_deleted":
            group.delete()
        elif bad == "creator_changed":
            group.alerts.update(integration_unique_data={"created_by": "not-original-creator"})
        elif bad == "origin_changed":
            SharedSlackDelivery.objects.filter(key="b" * 64).update(modal_owners={})
        elif bad == "delivery_completed":
            SharedSlackDelivery.objects.filter(key="b" * 64).update(phase="completed")
        else:
            def drift():
                if wire.calls[-1][0].endswith("/oncall-link-verify"):
                    wire.mutate = None
                    group.alerts.update(integration_unique_data={"created_by": "not-original-creator"})
            wire.mutate = drift
        with pytest.raises(SharedOwnerError):
            client.bind_completion_recipient(completion)
    assert client._completion_notice is None and native.calls == []
