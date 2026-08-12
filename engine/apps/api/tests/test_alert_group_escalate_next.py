from datetime import timedelta
from unittest.mock import patch

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.alerts.models import AlertGroupLogRecord, EscalationPolicy
from apps.api.permissions import LegacyAccessControlRole


@pytest.fixture()
def alert_group_with_wait_and_notification(
    make_organization_and_user_with_plugin_token,
    make_alert_receive_channel,
    make_escalation_chain,
    make_escalation_policy,
    make_channel_filter,
    make_alert_group,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    alert_receive_channel = make_alert_receive_channel(organization)
    escalation_chain = make_escalation_chain(organization)
    wait_step = make_escalation_policy(
        escalation_chain=escalation_chain,
        escalation_policy_step=EscalationPolicy.STEP_WAIT,
    )
    wait_step.wait_delay = timedelta(minutes=10)
    wait_step.save(update_fields=["wait_delay"])
    notification_step = make_escalation_policy(
        escalation_chain=escalation_chain,
        escalation_policy_step=EscalationPolicy.STEP_NOTIFY_MULTIPLE_USERS,
    )
    notification_step.notify_to_users_queue.set([user])
    channel_filter = make_channel_filter(
        alert_receive_channel,
        is_default=True,
        escalation_chain=escalation_chain,
    )
    alert_group = make_alert_group(alert_receive_channel, channel_filter=channel_filter)
    alert_group.raw_escalation_snapshot = alert_group.build_raw_escalation_snapshot()
    alert_group.active_escalation_id = "old-task-id"
    alert_group.save(update_fields=["raw_escalation_snapshot", "active_escalation_id"])
    return alert_group, user, token


@pytest.mark.django_db
def test_escalate_next_preview_skips_wait_and_reports_recipients(
    alert_group_with_wait_and_notification,
    make_user_auth_headers,
):
    alert_group, user, token = alert_group_with_wait_and_notification
    snapshot_before = alert_group.raw_escalation_snapshot
    client = APIClient()

    response = client.get(
        reverse("api-internal:alertgroup-escalate-next-preview", kwargs={"pk": alert_group.public_primary_key}),
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "next_step_eta": None,
        "steps": [
            {
                "step": EscalationPolicy.STEP_WAIT,
                "step_display": wait_step_display(),
                "schedule_name": None,
                "webhook_name": None,
            },
            {
                "step": EscalationPolicy.STEP_NOTIFY_MULTIPLE_USERS,
                "step_display": notify_multiple_users_step_display(),
                "schedule_name": None,
                "webhook_name": None,
            },
        ],
        "users": [{"pk": user.public_primary_key, "username": user.username}],
        "count": 1,
        "can_escalate_next": True,
        "escalation_exhausted": False,
    }
    alert_group.refresh_from_db()
    assert alert_group.raw_escalation_snapshot == snapshot_before
    assert alert_group.active_escalation_id == "old-task-id"


@pytest.mark.django_db(transaction=True)
def test_escalate_next_invalidates_old_task_and_queues_next_action_immediately(
    alert_group_with_wait_and_notification,
    make_user_auth_headers,
):
    alert_group, user, token = alert_group_with_wait_and_notification
    client = APIClient()

    with patch("apps.api.escalation_next.escalate_alert_group.apply_async") as apply_async:
        response = client.post(
            reverse("api-internal:alertgroup-escalate-next", kwargs={"pk": alert_group.public_primary_key}),
            **make_user_auth_headers(user, token),
        )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    alert_group.refresh_from_db()
    assert alert_group.active_escalation_id != "old-task-id"
    assert alert_group.escalation_snapshot.last_active_escalation_policy_order == 0
    skip_log = alert_group.log_records.get(reason="wait skipped manually")
    assert skip_log.type == AlertGroupLogRecord.TYPE_ESCALATION_TRIGGERED
    assert skip_log.author == user
    assert skip_log.escalation_policy_step == EscalationPolicy.STEP_WAIT
    apply_async.assert_called_once_with(
        (alert_group.pk,),
        immutable=True,
        task_id=alert_group.active_escalation_id,
    )


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("state", ["acknowledged", "silenced"])
def test_escalate_next_clears_paused_alert_group_state(
    alert_group_with_wait_and_notification,
    make_user_auth_headers,
    state,
):
    alert_group, user, token = alert_group_with_wait_and_notification
    if state == "acknowledged":
        alert_group.acknowledged = True
        alert_group.acknowledged_at = timezone.now()
        alert_group.acknowledged_by_user = user
    else:
        alert_group.silenced = True
        alert_group.silenced_at = timezone.now()
        alert_group.silenced_until = timezone.now() + timedelta(hours=1)
        alert_group.silenced_by_user = user
    alert_group.save()

    client = APIClient()
    with patch("apps.api.escalation_next.escalate_alert_group.apply_async"):
        response = client.post(
            reverse("api-internal:alertgroup-escalate-next", kwargs={"pk": alert_group.public_primary_key}),
            **make_user_auth_headers(user, token),
        )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    alert_group.refresh_from_db()
    assert alert_group.acknowledged is False
    assert alert_group.silenced is False


@pytest.mark.django_db
def test_escalate_next_preview_reports_exhausted_chain(
    alert_group_with_wait_and_notification,
    make_user_auth_headers,
):
    alert_group, user, token = alert_group_with_wait_and_notification
    snapshot = alert_group.escalation_snapshot
    snapshot.last_active_escalation_policy_order = 1
    alert_group.raw_escalation_snapshot = snapshot.convert_to_dict()
    alert_group.is_escalation_finished = True
    alert_group.save(update_fields=["raw_escalation_snapshot", "is_escalation_finished"])

    client = APIClient()
    response = client.get(
        reverse("api-internal:alertgroup-escalate-next-preview", kwargs={"pk": alert_group.public_primary_key}),
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["steps"] == []
    assert response.json()["users"] == []
    assert response.json()["can_escalate_next"] is False
    assert response.json()["escalation_exhausted"] is True


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("invalid_state", ["resolved", "dependent", "wiped"])
def test_escalate_next_rejects_non_actionable_alert_group(
    alert_group_with_wait_and_notification,
    make_alert_group,
    make_user_auth_headers,
    invalid_state,
):
    alert_group, user, token = alert_group_with_wait_and_notification
    if invalid_state == "resolved":
        alert_group.resolved = True
    elif invalid_state == "dependent":
        alert_group.root_alert_group = make_alert_group(alert_group.channel)
    else:
        alert_group.wiped_at = timezone.now()
    alert_group.save()

    client = APIClient()
    with patch("apps.api.escalation_next.escalate_alert_group.apply_async") as apply_async:
        response = client.post(
            reverse("api-internal:alertgroup-escalate-next", kwargs={"pk": alert_group.public_primary_key}),
            **make_user_auth_headers(user, token),
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    apply_async.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "method,role,expected_status",
    [
        ("get", LegacyAccessControlRole.VIEWER, status.HTTP_200_OK),
        ("post", LegacyAccessControlRole.VIEWER, status.HTTP_403_FORBIDDEN),
        ("post", LegacyAccessControlRole.EDITOR, status.HTTP_204_NO_CONTENT),
    ],
)
def test_escalate_next_permissions(
    alert_group_with_wait_and_notification,
    make_user_for_organization,
    make_user_auth_headers,
    method,
    role,
    expected_status,
):
    alert_group, _, token = alert_group_with_wait_and_notification
    user = make_user_for_organization(alert_group.channel.organization, role)
    action = "escalate-next-preview" if method == "get" else "escalate-next"
    client = APIClient()

    with patch("apps.api.escalation_next.escalate_alert_group.apply_async"):
        response = getattr(client, method)(
            reverse(f"api-internal:alertgroup-{action}", kwargs={"pk": alert_group.public_primary_key}),
            **make_user_auth_headers(user, token),
        )

    assert response.status_code == expected_status


@pytest.mark.django_db
def test_escalate_next_cannot_access_another_organization(
    alert_group_with_wait_and_notification,
    make_organization_and_user_with_plugin_token,
    make_user_auth_headers,
):
    alert_group, _, _ = alert_group_with_wait_and_notification
    _, other_user, other_token = make_organization_and_user_with_plugin_token()
    client = APIClient()

    preview_response = client.get(
        reverse("api-internal:alertgroup-escalate-next-preview", kwargs={"pk": alert_group.public_primary_key}),
        **make_user_auth_headers(other_user, other_token),
    )
    execute_response = client.post(
        reverse("api-internal:alertgroup-escalate-next", kwargs={"pk": alert_group.public_primary_key}),
        **make_user_auth_headers(other_user, other_token),
    )

    assert preview_response.status_code == status.HTTP_404_NOT_FOUND
    assert execute_response.status_code == status.HTTP_404_NOT_FOUND


def wait_step_display():
    return dict(EscalationPolicy.STEP_CHOICES)[EscalationPolicy.STEP_WAIT]


def notify_multiple_users_step_display():
    return dict(EscalationPolicy.STEP_CHOICES)[EscalationPolicy.STEP_NOTIFY_MULTIPLE_USERS]
