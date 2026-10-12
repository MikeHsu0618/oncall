from unittest.mock import patch

import pytest
from kombu.exceptions import OperationalError

from apps.alerts.models import AlertGroup, AlertReceiveChannel
from apps.api.permissions import LegacyAccessControlRole
from apps.slack.models import SharedSlackPagingCommand, SharedSlackPagingNotification, SlackUserIdentity
from apps.slack.paging_commands import command_target
from apps.slack.tests.test_shared_app import connected, send, link_receipt

pytestmark = pytest.mark.django_db(transaction=True)


def command(body, text="escalate @bob"):
    assert send(body).status_code == 200
    return {**body, "operation": "dispatch", "deliveryId": "a" * 64, "payload": {
        "api_app_id": "A1", "command": "/grafana", "text": text, "team_id": "T1", "user_id": "U1", "channel_id": "C1",
        "trigger_id": "command-trigger", "response_url": "https://hooks.slack.com/commands/test"}}


@pytest.mark.parametrize("text,expected", [
    ("escalate", ""), (" escalate   @bob ", "@bob"),
    ('escalate "Core Platform"', "Core Platform"), ("escalate Core Platform", "Core Platform"),
    ("escalate <@U123|Bob Jones>", "<@U123|Bob Jones>"),
])
def test_typed_target_parser_preserves_exact_target(text, expected):
    assert command_target({"command": "/grafana", "text": text}) == expected


@pytest.mark.parametrize("text", ['escalate "unfinished', "escalate @bob\n@alice", 'escalate "bob" "alice"'])
def test_invalid_target_syntax_is_rejected(text):
    with pytest.raises(ValueError):
        command_target({"command": "/grafana", "text": text})


@pytest.mark.parametrize("target", ["@bob", "bob", "<@U2>", "<@U2|renamed>"])
def test_typed_user_pages_native_once_without_requiring_modal(connected, make_user_for_organization, target):
    org, _, body = connected
    assert send(body).status_code == 200
    org.refresh_from_db()
    identity = SlackUserIdentity.objects.create(slack_id="U2", slack_team_identity=org.slack_team_identity, cached_slack_login="bob")
    responder = make_user_for_organization(org, username="bob", slack_user_identity=identity)
    data = command(body, "escalate " + target)
    with patch("apps.slack.client.SlackClient.views_open") as modal:
        first = send(data)
        assert first.status_code == 200 and "Escalation created" in first.data["text"]
        assert send(data).data == first.data
        modal.assert_not_called()
    assert AlertGroup.objects.count() == 1
    assert SharedSlackPagingCommand.objects.get().alert_group_id == AlertGroup.objects.get().public_primary_key
    intent = SharedSlackPagingNotification.objects.get()
    assert intent.user_id == responder.pk and intent.command_id and intent.session_id is None


def test_exact_team_without_integration_pages_all_current_members_using_fallback(connected, make_team, make_user_for_organization):
    org, _, body = connected
    team = make_team(org, name="Core Platform")
    members = [make_user_for_organization(org), make_user_for_organization(org)]
    team.users.add(*members)
    data = command(body, 'escalate "Core Platform"')
    assert send(data).status_code == 200
    group = AlertGroup.objects.get()
    assert group.channel.team_id == team.pk
    intents = list(SharedSlackPagingNotification.objects.all())
    assert {intent.user_id for intent in intents} == {u.pk for u in members}
    assert all(intent.force_default_fallback and not intent.important for intent in intents)
    assert send(data).status_code == 200
    assert AlertGroup.objects.count() == 1 and SharedSlackPagingNotification.objects.count() == 2


def test_configured_team_uses_native_chain_without_fallback(connected, make_team, make_user_for_organization, make_alert_receive_channel, make_channel_filter, make_escalation_chain):
    org, _, body = connected
    team = make_team(org, name="Operations")
    team.users.add(make_user_for_organization(org))
    arc = make_alert_receive_channel(org, team=team, integration=AlertReceiveChannel.INTEGRATION_DIRECT_PAGING)
    chain = make_escalation_chain(org)
    make_channel_filter(arc, is_default=True, escalation_chain=chain)
    assert send(command(body, "escalate Operations")).status_code == 200
    group = AlertGroup.objects.get()
    assert group.channel_filter.escalation_chain_id == chain.pk
    assert SharedSlackPagingNotification.objects.count() == 0


def test_ambiguous_foreign_unlinked_or_missing_targets_never_page(connected, make_team, make_user_for_organization, make_organization_and_user):
    org, _, body = connected
    make_user_for_organization(org, username="collision")
    make_team(org, name="collision")
    _, foreign = make_organization_and_user()
    for target in ("collision", foreign.public_primary_key, "<@UNOTLINKED>", "no-such-team"):
        response = send(command(body, "escalate " + target))
        assert response.status_code == 200 and "missing or ambiguous" in response.data["text"]
    assert AlertGroup.objects.count() == 0 and SharedSlackPagingNotification.objects.count() == 0


def test_current_native_permission_precedes_target_lookup_and_page(connected, make_user_for_organization):
    org, actor, body = connected
    actor.role = LegacyAccessControlRole.VIEWER; actor.permissions = []; actor.save()
    make_user_for_organization(org, username="bob")
    response = send(command(body))
    assert response.status_code == 403
    assert AlertGroup.objects.count() == 0 and SharedSlackPagingCommand.objects.count() == 0


def test_command_receipt_failure_rolls_back_native_page(connected, make_user_for_organization):
    org, _, body = connected
    make_user_for_organization(org, username="bob")
    with patch.object(SharedSlackPagingCommand, "save", side_effect=RuntimeError("receipt unavailable")):
        with pytest.raises(RuntimeError):
            send(command(body))
    assert AlertGroup.objects.count() == 0 and SharedSlackPagingNotification.objects.count() == 0


@pytest.mark.django_db(transaction=True)
def test_original_post_commit_broker_failure_preserves_page_and_command_ack(connected, make_user_for_organization):
    org, _, body = connected
    make_user_for_organization(org, username="bob")
    with patch("apps.alerts.models.alert.send_alert_create_signal.apply_async", side_effect=OperationalError("broker down")):
        response = send(command(body))
        assert response.status_code == 200 and "Escalation created" in response.data["text"]
    assert AlertGroup.objects.count() == 1
    assert SharedSlackPagingCommand.objects.get().phase == "completed"
    assert SharedSlackPagingNotification.objects.get().phase == "pending"
    assert send(command(body)).status_code == 200
    assert AlertGroup.objects.count() == 1


def test_native_fallback_does_not_repeat_explicit_responder_or_cross_org_member(connected, make_team, make_user_for_organization, make_organization_and_user):
    from apps.alerts.paging import direct_paging
    org, actor, _ = connected
    team = make_team(org)
    explicit = make_user_for_organization(org)
    member = make_user_for_organization(org)
    _, foreign = make_organization_and_user()
    team.users.add(explicit, member, foreign)
    enqueued = []
    direct_paging(org, actor, "", team=team, users=[(explicit, True)],
                  notification_enqueue=lambda *args, **kwargs: enqueued.append((args, kwargs)))
    assert [(args[0].pk, args[2], kwargs.get("force_default_fallback", False)) for args, kwargs in enqueued] == [
        (explicit.pk, True, False), (member.pk, False, True)]


def test_native_fallback_policy_uses_original_task_even_with_personal_policies(connected, make_user_for_organization, make_alert_receive_channel, make_alert_group, make_user_notification_policy, django_capture_on_commit_callbacks, settings):
    from apps.alerts.tasks.notify_user import notify_user_task
    from apps.base.models import UserNotificationPolicy, UserNotificationPolicyLogRecord
    # CI registers TestOnlyBackend instead of real email; retain native dispatch.
    settings.EMAIL_BACKEND_INTERNAL_ID = 42
    org, _, _ = connected
    responder = make_user_for_organization(org)
    make_user_notification_policy(user=responder, step=UserNotificationPolicy.Step.NOTIFY,
                                  notify_by=UserNotificationPolicy.NotificationChannel.TESTONLY)
    group = make_alert_group(make_alert_receive_channel(org))
    with patch("apps.alerts.tasks.notify_user.perform_notification.apply_async") as publish:
        with django_capture_on_commit_callbacks(execute=True):
            notify_user_task(responder.pk, group.pk, force_default_fallback=True, notify_anyway=True)
    record = UserNotificationPolicyLogRecord.objects.filter(author=responder, alert_group=group,
        type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_TRIGGERED).get()
    assert record.notification_policy_id is None
    assert record.notification_channel == responder.get_default_fallback_notification_policy().notify_by
    assert publish.call_args.args[0][1] is True
