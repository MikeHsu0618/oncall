import copy
import json
import hashlib
import hmac
from datetime import timedelta
from unittest.mock import MagicMock, patch
from types import SimpleNamespace
from uuid import uuid4

import pytest
import requests
from celery import current_app
from kombu import Connection
from django.db import transaction
from django.utils import timezone

from apps.alerts.models import AlertGroup
from apps.alerts.tasks.notify_user import notify_user_task, perform_notification
from apps.api.permissions import LegacyAccessControlRole
from apps.slack.incident_paging import dispatch_session
from apps.slack.models import SharedSlackPagingNotification, SharedSlackPagingSession
from apps.slack.paging_outbox import deliver_result, publish_notification
from apps.slack.scenarios import paging
from apps.slack.tests.test_shared_app import connected, send
from apps.slack.tests.test_shared_owner import physical, recipient_reply

pytestmark = pytest.mark.django_db(transaction=True)

# Preserve original task publication before conftest's autouse broker fake.
_NOTIFY_APPLY_ASYNC = notify_user_task.apply_async
_PERFORM_APPLY_ASYNC = perform_notification.apply_async


@pytest.fixture
def paging_verification(settings):
    settings.SHARED_SLACK_PAGING_VERIFY_URL = "http://connector/internal/irm/slack/paging-verify"
    settings.SHARED_SLACK_BRIDGE_SECRET = "bridge-secret"

    def verified(*args, **kwargs):
        result = {**json.loads(kwargs["data"]), "verified": True}
        response = MagicMock(status_code=200)
        response.iter_content.return_value = [json.dumps(result).encode()]
        return response

    client = MagicMock()
    client.__enter__.return_value = client
    client.post.side_effect = verified
    # Patch only this original HTTP seam, not the global requests module used
    # independently by source/link/publication verification fixtures.
    factory = MagicMock(return_value=client)
    with patch("apps.slack.incident_paging.requests", SimpleNamespace(Session=factory, RequestException=requests.RequestException)):
        yield client.post


@pytest.fixture(autouse=True)
def verified_paging_defaults(paging_verification):
    pass


@pytest.fixture
def started(connected):
    org, user, body = connected
    context = {"reservationToken": str(uuid4()), "incidentId": "IRM-1", "channelId": "C1",
               "title": "Database unavailable", "sourceUrl": "http://grafana:3000/a/grafana-irm-app/incidents/IRM-1",
               "expiresAt": (timezone.now() + timedelta(minutes=15)).isoformat()}
    data = {**body, "operation": "incident_paging_start", "deliveryId": "a" * 64,
            "incidentContext": context, "loadingView": {"id": "V1", "hash": "hash"},
            "payload": {"type": "block_actions", "team": {"id": "T1"}, "user": {"id": "U1"},
                        "channel": {"id": "C1"}, "actions": [{"action_id": "irm_incident_escalate"}],
                        "trigger_id": "trigger"}}
    assert send(body).status_code == 200
    data["payload"]["api_app_id"] = "A1"
    with patch("apps.slack.incident_paging.SlackClient") as client:
        response = send(data)
        assert response.status_code == 200
        rendered = client.return_value.views_update.call_args.kwargs["view"]
        assert set(json.loads(rendered["private_metadata"])) == {"pagingSessionId"}
        assert next(b for b in rendered["blocks"] if b.get("block_id") == "paging_message_input")["optional"] is True
    user.refresh_from_db(); org.refresh_from_db()
    session = SharedSlackPagingSession.objects.get()
    return org, user, data, session


def submit(session, users=None, message=None):
    if users is not None:
        session.form_metadata["users"] = users
        session.save(update_fields=["form_metadata"])
    return {"type": "view_submission", "team": {"id": session.team.slack_id},
            "user": {"id": session.slack_user_id}, "view": {
                "id": session.view_id, "callback_id": "FinishDirectPaging",
                "private_metadata": json.dumps({"pagingSessionId": str(session.pk)}),
                "state": {"values": {"paging_message_input": {"FinishDirectPaging": {"value": message}}}}}}


def dispatch(org, user, session, payload):
    return dispatch_session(org, session.team, user.slack_user_identity, payload)


def test_native_page_and_result_are_one_transaction_and_retry_does_not_page(started, make_user_for_organization):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    payload = submit(session, {str(responder.pk): "important"})
    before = AlertGroup.objects.count()
    assert dispatch(org, user, session, payload).status_code == 200
    session.refresh_from_db()
    assert session.phase == "completed"
    assert session.result_data["targets"] == [{"kind": "user", "id": responder.public_primary_key,
                                               "name": responder.username, "important": True}]
    group = AlertGroup.objects.get(public_primary_key=session.result_data["alertGroupId"])
    assert group.grafana_incident_id == "IRM-1"
    assert SharedSlackPagingNotification.objects.get().alert_group_id == group.pk
    assert dispatch(org, user, session, payload).status_code == 200
    assert AlertGroup.objects.count() == before + 1
    changed = copy.deepcopy(payload)
    changed["view"]["state"]["values"]["paging_message_input"]["FinishDirectPaging"]["value"] = "changed"
    assert dispatch(org, user, session, changed).status_code == 409
    assert AlertGroup.objects.count() == before + 1


def test_result_write_failure_rolls_back_native_page(started, make_user_for_organization):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    payload = submit(session, {str(responder.pk): "default"})
    with patch.object(SharedSlackPagingSession, "save", side_effect=RuntimeError("storage down")):
        with pytest.raises(RuntimeError):
            dispatch(org, user, session, payload)
    assert AlertGroup.objects.count() == 0
    assert SharedSlackPagingNotification.objects.count() == 0
    session.refresh_from_db()
    assert session.phase == "open"


@pytest.mark.parametrize("change", ["metadata", "view", "expiry", "uid", "role", "installation"])
def test_stale_and_stolen_session_cannot_page(started, change, paging_verification):
    org, user, _, session = started
    payload = submit(session)
    if change == "metadata":
        payload["view"]["private_metadata"] = json.dumps({"pagingSessionId": str(session.pk), "users": {"9": "important"}})
    elif change == "view":
        payload["view"]["id"] = "foreign"
    elif change == "expiry":
        session.expires_at = timezone.now() - timedelta(seconds=1); session.save()
    elif change == "uid":
        user.user_id = "9999"; user.save()
    elif change == "role":
        user.role = LegacyAccessControlRole.VIEWER; user.permissions = []; user.save()
    else:
        org.slack_team_identity = None; org.save()
    assert dispatch(org, user, session, payload).status_code in {403, 410}
    paging_verification.assert_not_called()
    assert AlertGroup.objects.count() == 0


def test_foreign_org_user_and_policy_action_cannot_enter_session(started, make_organization_and_user):
    org, user, _, session = started
    _, foreign = make_organization_and_user()
    payload = submit(session, {str(foreign.pk): "important"})
    assert dispatch(org, user, session, payload).status_code == 422
    assert AlertGroup.objects.count() == 0


def test_callback_retry_preserves_fact_after_revoke_and_has_session_delivery_id(started, make_user_for_organization, settings):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    assert dispatch(org, user, session, submit(session, {str(responder.pk): "default"})).status_code == 200
    settings.SHARED_SLACK_PAGING_RESULT_URL = "http://connector/internal/irm/slack/paging-result"
    settings.SHARED_SLACK_BRIDGE_SECRET = "bridge-secret"
    user.slack_user_identity = None; user.save()
    with patch("apps.slack.paging_outbox.requests.Session") as http:
        http.return_value.__enter__.return_value.post.side_effect = requests.Timeout()
        deliver_result(session.pk)
    session.refresh_from_db(); original = session.result_body
    assert session.callback_delivered_at is None and session.callback_attempts == 1
    session.callback_next_attempt_at = timezone.now() - timedelta(seconds=1)
    session.save(update_fields=["callback_next_attempt_at"])
    with patch("apps.slack.paging_outbox.requests.Session") as http:
        post = http.return_value.__enter__.return_value.post
        post.return_value = MagicMock(status_code=202)
        deliver_result(session.pk)
    session.refresh_from_db()
    assert session.callback_delivered_at is not None
    assert post.call_args.kwargs["data"] == original.encode()
    assert post.call_args.kwargs["headers"]["X-Grafana-Slack-Delivery-Id"] == str(session.pk)
    assert AlertGroup.objects.count() == 1


def test_broker_failure_before_publication_retries_but_uncertain_publish_does_not(started, make_user_for_organization):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    dispatch(org, user, session, submit(session, {str(responder.pk): "important"}))
    intent = SharedSlackPagingNotification.objects.get()
    with patch("apps.slack.paging_outbox.current_app") as app:
        app.connection_for_write.return_value.ensure_connection.side_effect = OSError("broker down")
        with patch("apps.slack.paging_outbox.notify_user_task.apply_async") as publish:
            publish_notification(intent.pk)
            publish.assert_not_called()
    intent.refresh_from_db(); assert intent.phase == "pending"
    with patch("apps.slack.paging_outbox.current_app") as app:
        with patch("apps.slack.paging_outbox.notify_user_task.apply_async", side_effect=OSError("ACK lost")) as publish:
            publish_notification(intent.pk)
            publish_notification(intent.pk)
            publish.assert_called_once()
    intent.refresh_from_db(); assert intent.phase == "uncertain"
    assert AlertGroup.objects.count() == 1


def test_committed_page_notification_wire_reaches_original_consumer_and_guarded_sdk(
        started, make_user_notification_policy, make_slack_channel, make_slack_message, monkeypatch):
    from apps.base.models import UserNotificationPolicy, UserNotificationPolicyLogRecord
    org, user, body, session = started
    make_user_notification_policy(user, UserNotificationPolicy.Step.NOTIFY,
        notify_by=UserNotificationPolicy.NotificationChannel.SLACK, important=True)
    assert dispatch(org, user, session, submit(session, {str(user.pk): "important"})).status_code == 200
    intent = SharedSlackPagingNotification.objects.get()
    group = intent.alert_group
    # The existing original alert-root publication is a separate task. Seed its
    # durable result explicitly; this case proves the paging notification path.
    channel = make_slack_channel(org.slack_team_identity, slack_id="C1")
    make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"],
        cached_permalink="https://example.slack.com/archives/C1/p1234")
    user.slack_user_identity.cached_im_channel_id = "D1"
    user.slack_user_identity.save(update_fields=["cached_im_channel_id"])
    native = physical(monkeypatch, response_for=recipient_reply)
    monkeypatch.setattr("apps.slack.models.slack_message.time.sleep", lambda _: None)
    monkeypatch.setattr(notify_user_task, "apply_async", _NOTIFY_APPLY_ASYNC)
    monkeypatch.setattr(perform_notification, "apply_async", _PERFORM_APPLY_ASYNC)

    with Connection("memory://") as broker:
        # Real Kombu serialization/publication, isolated from the deployment
        # broker. Only transport selection is controlled, not the task bodies.
        monkeypatch.setattr(current_app, "connection_for_write", lambda *a, **k: broker)
        publish_notification(intent.pk)
        intent.refresh_from_db()
        assert intent.phase == "posted" and intent.attempts == 1

        def consume(task, *, expected_id=None):
            route = current_app.amqp.router.route({}, task.name)
            with broker.SimpleQueue(route["queue"]) as queue:
                message = queue.get(block=False)
                assert message.headers["task"] == task.name
                if expected_id is not None:
                    assert message.headers["id"] == expected_id
                args, kwargs, _ = message.payload
                result = task.apply(args=args, kwargs=kwargs, task_id=message.headers["id"], throw=True)
                assert result.successful()
                message.ack()

        consume(notify_user_task, expected_id=str(intent.pk))
        triggered = UserNotificationPolicyLogRecord.objects.get(author=user, alert_group=group,
            type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_TRIGGERED)
        assert triggered.notification_policy.important is True
        consume(perform_notification)
        sends = [json.loads(req.data) for req in native.calls if req.full_url.endswith("/chat.postMessage")]
        assert [data["channel"] for data in sends] == ["C1", "D1"]
        assert sends[0]["thread_ts"] == "123.4" and "<@U1>" in sends[0]["text"]
        assert UserNotificationPolicyLogRecord.objects.filter(author=user, alert_group=group,
            type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_SUCCESS).exists()
        assert all(response.closed for response in native.responses)
        before = len(native.calls)
        publish_notification(intent.pk)
        intent.refresh_from_db()
        assert intent.phase == "posted" and intent.attempts == 1 and len(native.calls) == before
        # The original plan may have queued its later escalation step. No
        # daemon consumes it here; remove only this isolated memory transport's
        # pending work so another test cannot inherit it.
        for task in (notify_user_task, perform_notification):
            route = current_app.amqp.router.route({}, task.name)
            with broker.SimpleQueue(route["queue"]) as queue:
                queue.clear()


def test_original_offcall_confirmation_keeps_incident_and_user_policy(started, make_user_for_organization, paging_verification):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    prefix = session.form_metadata["input_id_prefix"]
    state = {"values": {
        prefix + paging.DIRECT_PAGING_USER_SELECT_ID: {"OnPagingUserChange": {
            "selected_option": {"value": json.dumps({"id": responder.pk, "organization_id": org.pk})}}},
        "paging_message_input": {"FinishDirectPaging": {"value": "Please help"}},
    }}
    payload = {"type": "block_actions", "trigger_id": "trigger", "view": {
        "id": "V1", "private_metadata": json.dumps({"pagingSessionId": str(session.pk)}), "state": state},
        "actions": [{"type": "static_select", "action_id": "OnPagingUserChange"}]}
    with patch("apps.slack.incident_paging.SlackClient") as client:
        client.return_value.views_push.return_value = {"view": {"id": "VC1"}}
        with patch("apps.slack.scenarios.paging.user_is_oncall", return_value=False):
            assert dispatch(org, user, session, payload).status_code == 200
        session.refresh_from_db()
        assert session.confirmation_view_id == "VC1"
        assert json.loads(client.return_value.views_push.call_args.kwargs["view"]["private_metadata"]) == {"pagingSessionId": str(session.pk)}
        confirmation = {"type": "view_submission", "trigger_id": "trigger", "view": {
            "id": "VC1", "previous_view_id": "V1", "callback_id": "OnPagingConfirmUserChange",
            "private_metadata": json.dumps({"pagingSessionId": str(session.pk)})}}
        assert dispatch(org, user, session, confirmation).status_code == 200
    session.refresh_from_db()
    paging_verification.assert_not_called()
    assert session.form_metadata["users"][str(responder.pk)] in {"default", "important"}
    assert session.incident_context["incidentId"] == "IRM-1"
    assert dispatch(org, user, session, submit(session)).status_code == 200
    session.refresh_from_db()
    assert session.result_data["targets"][0]["id"] == responder.public_primary_key


def test_cross_org_picker_selection_cannot_page_or_render_foreign_user(started, make_organization_and_user):
    org, user, _, session = started
    _, foreign = make_organization_and_user()
    prefix = session.form_metadata["input_id_prefix"]
    payload = {"type": "block_actions", "trigger_id": "trigger", "view": {
        "id": "V1", "private_metadata": json.dumps({"pagingSessionId": str(session.pk)}),
        "state": {"values": {prefix + paging.DIRECT_PAGING_USER_SELECT_ID: {"OnPagingUserChange": {
            "selected_option": {"value": json.dumps({"id": foreign.pk, "organization_id": org.pk})}}}}}},
        "actions": [{"type": "static_select", "action_id": "OnPagingUserChange"}]}
    with patch("apps.slack.incident_paging.SlackClient") as client:
        assert dispatch(org, user, session, payload).status_code == 422
        client.assert_not_called()
    assert AlertGroup.objects.count() == 0


@pytest.mark.django_db(transaction=True)
def test_original_on_commit_broker_failure_keeps_completed_fact_and_ack(started, make_user_for_organization):
    from kombu.exceptions import OperationalError
    org, user, _, session = started
    responder = make_user_for_organization(org)
    payload = submit(session, {str(responder.pk): "important"})
    with patch("apps.alerts.models.alert.send_alert_create_signal.apply_async", side_effect=OperationalError("broker unavailable")):
        assert dispatch(org, user, session, payload).status_code == 200
    session.refresh_from_db()
    assert session.phase == "completed" and session.result_data["alertGroupId"]
    assert AlertGroup.objects.count() == 1
    assert SharedSlackPagingNotification.objects.get().phase == "pending"
    assert dispatch(org, user, session, payload).status_code == 200
    assert AlertGroup.objects.count() == 1


@pytest.mark.parametrize("name", ["值" * 300, "😀" * 300])
def test_native_completion_preserves_full_unicode_name(started, make_user_for_organization, name):
    org, actor, _, session = started
    responder = make_user_for_organization(org, username=name)
    assert dispatch(org, actor, session, submit(session, {str(responder.pk): "default"})).status_code == 200
    session.refresh_from_db()
    assert session.result_data["targets"][0]["name"] == name
    assert name.encode() in session.result_body.encode()


@pytest.mark.parametrize("invalid", ["name", "origin", "target_count"])
def test_callback_bound_refusal_precedes_native_page(started, make_user_for_organization, invalid):
    org, actor, _, session = started
    responders = [make_user_for_organization(org, username="x" * 301 if invalid == "name" else "responder")]
    if invalid == "target_count":
        responders += [make_user_for_organization(org) for _ in range(100)]
    if invalid == "origin":
        session.incident_context["incidentId"] = "I" * 129
        session.save(update_fields=["incident_context"])
    payload = submit(session, {str(u.pk): "default" for u in responders})
    with patch("apps.slack.incident_paging.direct_paging") as page:
        assert dispatch(org, actor, session, payload).status_code == 422
        page.assert_not_called()
    assert AlertGroup.objects.count() == 0
    assert SharedSlackPagingNotification.objects.count() == 0


def test_crashed_publication_becomes_visible_uncertain_without_replay(started, make_user_for_organization):
    from apps.slack.paging_outbox import recover_shared_paging
    org, actor, _, session = started
    responder = make_user_for_organization(org)
    dispatch(org, actor, session, submit(session, {str(responder.pk): "default"}))
    intent = SharedSlackPagingNotification.objects.get()
    intent.phase = "publishing"
    intent.next_attempt_at = timezone.now() - timedelta(seconds=1)
    intent.save()
    with patch("apps.slack.paging_outbox.deliver_result"), patch("apps.slack.paging_outbox.publish_notification") as publish:
        recover_shared_paging()
        publish.assert_not_called()
    intent.refresh_from_db()
    assert intent.phase == "uncertain"



def test_incident_unconfigured_team_records_team_fact_and_native_fallback_intents(started, make_team, make_user_for_organization):
    org, actor, _, session = started
    team = make_team(org, name="Core Platform")
    members = [make_user_for_organization(org), make_user_for_organization(org)]
    team.users.add(*members)
    payload = submit(session)
    prefix = session.form_metadata["input_id_prefix"]
    payload["view"]["state"]["values"][prefix + paging.DIRECT_PAGING_TEAM_SELECT_ID] = {
        paging.OnPagingTeamChange.routing_uid(): {"selected_option": {"value": json.dumps({"id": team.pk})}}}
    assert dispatch(org, actor, session, payload).status_code == 200
    session.refresh_from_db()
    assert session.result_data["targets"] == [{"kind": "team", "id": team.public_primary_key,
                                               "name": team.name, "important": False}]
    intents = list(SharedSlackPagingNotification.objects.all())
    assert {i.user_id for i in intents} == {u.pk for u in members}
    assert all(i.force_default_fallback for i in intents)
    with patch("apps.slack.paging_outbox.current_app"), patch("apps.slack.paging_outbox.notify_user_task.apply_async") as publish:
        publish_notification(intents[0].pk)
        assert publish.call_args.args[0] == (intents[0].user_id, intents[0].alert_group_id)
        assert publish.call_args.args[1]["force_default_fallback"] is True
    assert dispatch(org, actor, session, payload).status_code == 200
    assert AlertGroup.objects.count() == 1 and SharedSlackPagingNotification.objects.count() == 2



def test_final_dispatch_signed_preflight_has_stored_origin_and_no_sql_lock(started, make_user_for_organization, paging_verification):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    original = paging_verification.side_effect

    def verified(*args, **kwargs):
        assert not transaction.get_connection().in_atomic_block
        from apps.slack import incident_paging
        assert incident_paging.requests.Session.return_value.trust_env is False
        assert kwargs["timeout"] == 5 and kwargs["allow_redirects"] is False and kwargs["stream"] is True
        assert args == ("http://connector/internal/irm/slack/paging-verify",)
        raw = kwargs["data"]
        headers = kwargs["headers"]
        expected = hmac.new(b"bridge-secret", headers["X-Grafana-Slack-Timestamp"].encode() + b"." + raw, hashlib.sha256).hexdigest()
        assert headers["X-Grafana-Slack-Signature"] == expected
        assert headers["X-Grafana-Slack-Delivery-Id"] == str(session.pk)
        assert json.loads(raw) == {"version": 1, "orgId": session.grafana_org_id, "teamId": "T1",
            "channelId": "C1", "slackUserId": "U1", "grafanaUserId": session.grafana_user_id,
            "reservationToken": str(session.reservation_token), "sessionId": str(session.pk),
            "incidentId": "IRM-1", "appId": "A1"}
        return original(*args, **kwargs)

    paging_verification.side_effect = verified
    assert dispatch(org, user, session, submit(session, {str(responder.pk): "default"})).status_code == 200
    paging_verification.assert_called_once()


@pytest.mark.parametrize("failure", [403, 404, 409, 429, 500, 302, "timeout", "body_timeout", "json", "oversize", "false", "bool_version",
                                         "reservationToken", "sessionId", "incidentId", "teamId", "channelId", "grafanaUserId", "orgId", "slackUserId", "appId"])
def test_final_dispatch_unknown_or_denied_preflight_never_pages(started, make_user_for_organization, paging_verification, failure):
    org, user, _, session = started
    responder = make_user_for_organization(org)

    def refusal(*args, **kwargs):
        if failure == "timeout":
            raise requests.Timeout()
        result = {**json.loads(kwargs["data"]), "verified": True}
        status = failure if isinstance(failure, int) else 200
        if failure == "false":
            result["verified"] = False
        elif failure == "bool_version":
            result["version"] = True
        elif isinstance(failure, str) and failure in result:
            result[failure] = "foreign"
        response = MagicMock(status_code=status)
        response.iter_content.return_value = [b"{" if failure == "json" else b" " * (16 * 1024 + 1) if failure == "oversize" else json.dumps(result).encode()]
        if failure == "body_timeout":
            response.iter_content.side_effect = requests.Timeout()
        return response

    paging_verification.side_effect = refusal
    with patch("apps.slack.incident_paging.direct_paging") as page:
        assert dispatch(org, user, session, submit(session, {str(responder.pk): "default"})).status_code == (failure if failure in {403, 404, 409} else 503)
        page.assert_not_called()
    session.refresh_from_db()
    assert session.phase == "open" and AlertGroup.objects.count() == 0 and SharedSlackPagingNotification.objects.count() == 0


@pytest.mark.parametrize("change", ["context", "nonce", "metadata", "expiry", "app", "team", "unlink", "uid", "role"])
def test_changes_during_preflight_are_rechecked_before_paging(started, make_user_for_organization, paging_verification, change):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    original = paging_verification.side_effect

    def change_owner(*args, **kwargs):
        if change == "context":
            altered = {**session.incident_context, "title": "changed"}
            SharedSlackPagingSession.objects.filter(pk=session.pk).update(incident_context=altered)
        elif change == "nonce":
            SharedSlackPagingSession.objects.filter(pk=session.pk).update(reservation_token=uuid4())
        elif change == "metadata":
            SharedSlackPagingSession.objects.filter(pk=session.pk).update(form_metadata={**session.form_metadata, "users": {}})
        elif change == "expiry":
            SharedSlackPagingSession.objects.filter(pk=session.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        elif change == "app":
            type(session.team).objects.filter(pk=session.team_id).update(cached_app_id="A2")
        elif change == "team":
            type(org).objects.filter(pk=org.pk).update(slack_team_identity=None)
        elif change == "unlink":
            type(user).objects.filter(pk=user.pk).update(slack_user_identity=None)
        elif change == "uid":
            type(user).objects.filter(pk=user.pk).update(user_id="9999")
        elif change == "role":
            type(user).objects.filter(pk=user.pk).update(role=LegacyAccessControlRole.VIEWER, permissions=[])
        return original(*args, **kwargs)

    paging_verification.side_effect = change_owner
    with patch("apps.slack.incident_paging.direct_paging") as page:
        assert dispatch(org, user, session, submit(session, {str(responder.pk): "default"})).status_code in {403, 409, 410}
        page.assert_not_called()
    assert AlertGroup.objects.count() == 0


@pytest.mark.parametrize("missing", ["SHARED_SLACK_PAGING_VERIFY_URL", "SHARED_SLACK_BRIDGE_SECRET", "transaction"])
def test_missing_preflight_configuration_or_outer_transaction_refuses_before_http(started, make_user_for_organization, paging_verification, settings, missing):
    from contextlib import nullcontext
    org, user, _, session = started
    responder = make_user_for_organization(org)
    if missing != "transaction":
        setattr(settings, missing, "")
    with transaction.atomic() if missing == "transaction" else nullcontext():
        assert dispatch(org, user, session, submit(session, {str(responder.pk): "default"})).status_code == 503
    paging_verification.assert_not_called()
    assert AlertGroup.objects.count() == 0


def test_completed_exact_replay_and_native_dialogs_do_not_verify(started, make_user_for_organization, paging_verification, settings):
    org, user, _, session = started
    responder = make_user_for_organization(org)
    payload = submit(session, {str(responder.pk): "default"})
    assert dispatch(org, user, session, payload).status_code == 200
    paging_verification.reset_mock()
    settings.SHARED_SLACK_PAGING_VERIFY_URL = ""
    assert dispatch(org, user, session, payload).status_code == 200
    changed = copy.deepcopy(payload)
    changed["view"]["state"]["values"]["paging_message_input"]["FinishDirectPaging"]["value"] = "different"
    assert dispatch(org, user, session, changed).status_code == 409
    assert dispatch_session(org, session.team, user.slack_user_identity, {"view": {"private_metadata": "{}"}}) is None
    paging_verification.assert_not_called()
    assert AlertGroup.objects.count() == 1


@pytest.mark.parametrize("setting", ["SHARED_SLACK_PAGING_VERIFY_URL", "SHARED_SLACK_BRIDGE_SECRET"])
@pytest.mark.parametrize("phase", ["response", "close", "locked", "targets"])
def test_new_native_page_refuses_verifier_configuration_drift_at_final_boundaries(
        started, make_user_for_organization, paging_verification, settings, monkeypatch, setting, phase):
    from apps.slack import incident_paging
    org, user, _, session = started
    responder = make_user_for_organization(org)
    payload = submit(session, {str(responder.pk): "default"})
    original = paging_verification.side_effect
    replies = []
    def drift():
        setattr(settings, setting, "http://foreign/verifier" if setting.endswith("URL") else "rotated-bridge-secret")
    def verified(*args, **kwargs):
        reply = original(*args, **kwargs)
        replies.append(reply)
        if phase == "response":
            drift()
        elif phase == "close":
            reply.close.side_effect = drift
        return reply
    paging_verification.side_effect = verified
    if phase == "locked":
        prepare = incident_paging._prepare_session_dispatch
        def prepared(*args):
            result = prepare(*args)
            if transaction.get_connection().in_atomic_block:
                drift()
            return result
        monkeypatch.setattr(incident_paging, "_prepare_session_dispatch", prepared)
    elif phase == "targets":
        targets = incident_paging.scoped_targets
        def scoped(*args):
            result = targets(*args)
            if transaction.get_connection().in_atomic_block:
                drift()
            return result
        monkeypatch.setattr(incident_paging, "scoped_targets", scoped)
    with patch("apps.slack.incident_paging.direct_paging") as page:
        assert dispatch(org, user, session, payload).status_code == 503
        page.assert_not_called()
    paging_verification.assert_called_once()
    assert len(replies) == 1 and replies[0].close.called
    session.refresh_from_db()
    assert session.phase == "open" and not session.result_body
    assert AlertGroup.objects.count() == 0 and SharedSlackPagingNotification.objects.count() == 0
