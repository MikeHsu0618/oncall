from dataclasses import dataclass
from functools import partial
from typing import Iterable, List

from django.db import transaction
from django.utils import timezone
from kombu.utils.uuid import uuid as celery_uuid

from apps.alerts.models import AlertGroup, AlertGroupLogRecord, EscalationPolicy
from apps.alerts.tasks import escalate_alert_group, send_alert_group_signal
from apps.schedules.ical_utils import list_users_to_notify_from_ical


@dataclass(frozen=True)
class EscalationNextPreview:
    next_step_eta: object
    steps: List[dict]
    users: List[object]
    can_escalate_next: bool
    escalation_exhausted: bool

    @property
    def count(self):
        return len(self.users)


def build_escalation_next_preview(alert_group: AlertGroup) -> EscalationNextPreview:
    snapshot = alert_group.escalation_snapshot
    if snapshot is None:
        return EscalationNextPreview(None, [], [], False, True)

    policy_snapshots = _policies_to_execute_now(snapshot)
    exhausted = len(policy_snapshots) == 0
    actionable = not (
        alert_group.resolved
        or alert_group.root_alert_group_id is not None
        or alert_group.wiped_at is not None
        or alert_group.is_maintenance_incident
    )
    users = _preview_users(alert_group, policy_snapshots[-1:])
    steps = [
        {
            "step": policy.step,
            "step_display": policy.step_display,
            "schedule_name": policy.notify_schedule.name if policy.notify_schedule is not None else None,
            "webhook_name": policy.custom_webhook.name if policy.custom_webhook is not None else None,
        }
        for policy in policy_snapshots
    ]
    return EscalationNextPreview(
        next_step_eta=snapshot.next_step_eta,
        steps=steps,
        users=users,
        can_escalate_next=actionable and not exhausted,
        escalation_exhausted=exhausted,
    )


def escalate_next(alert_group: AlertGroup, user) -> None:
    """Invalidate the old escalation task and queue the next action immediately.

    The HTTP request does not execute notification delivery. It only advances
    completed wait snapshots and rotates the active Celery task ID, preserving
    OnCall's existing duplicate-delivery guard and task state machine.
    """
    with transaction.atomic():
        locked_alert_group = AlertGroup.objects.select_for_update().get(pk=alert_group.pk)
        preview = build_escalation_next_preview(locked_alert_group)
        if not preview.can_escalate_next:
            raise ValueError("Alert group cannot advance to the next escalation step")

        snapshot = locked_alert_group.escalation_snapshot
        _advance_wait_steps(snapshot, locked_alert_group, user)
        _clear_paused_state(locked_alert_group, user)

        task_id = celery_uuid()
        locked_alert_group.active_escalation_id = task_id
        locked_alert_group.is_escalation_finished = False
        locked_alert_group.raw_escalation_snapshot = snapshot.convert_to_dict()
        locked_alert_group.save(
            update_fields=[
                "active_escalation_id",
                "is_escalation_finished",
                "raw_escalation_snapshot",
            ]
        )
        transaction.on_commit(
            partial(
                escalate_alert_group.apply_async,
                (locked_alert_group.pk,),
                immutable=True,
                task_id=task_id,
            )
        )


def _policies_to_execute_now(snapshot):
    policies = []
    policy = snapshot.next_active_escalation_policy_snapshot
    while policy is not None:
        policies.append(policy)
        if policy.step != EscalationPolicy.STEP_WAIT:
            break
        next_index = snapshot.escalation_policies_snapshots.index(policy) + 1
        if next_index >= len(snapshot.escalation_policies_snapshots):
            break
        policy = snapshot.escalation_policies_snapshots[next_index]
    return policies


def _advance_wait_steps(snapshot, alert_group: AlertGroup, user):
    for policy in _policies_to_execute_now(snapshot):
        if policy.step != EscalationPolicy.STEP_WAIT:
            break
        policy.passed_last_time = timezone.now()
        snapshot.last_active_escalation_policy_order = snapshot.escalation_policies_snapshots.index(policy)
        alert_group.log_records.create(
            type=AlertGroupLogRecord.TYPE_ESCALATION_TRIGGERED,
            author=user,
            reason="wait skipped manually",
            escalation_policy=policy.escalation_policy,
            escalation_policy_step=policy.step,
        )
    snapshot.next_step_eta = None
    snapshot.pause_escalation = False


def _clear_paused_state(alert_group: AlertGroup, user) -> None:
    initial_state = alert_group.state
    update_fields = []
    log_types = []

    if alert_group.acknowledged:
        alert_group.acknowledged = False
        alert_group.acknowledged_at = None
        alert_group.acknowledged_by_user = None
        alert_group.acknowledged_by = AlertGroup.NOT_YET
        update_fields.extend(["acknowledged", "acknowledged_at", "acknowledged_by_user", "acknowledged_by"])
        log_types.append(AlertGroupLogRecord.TYPE_UN_ACK)

    if alert_group.silenced:
        alert_group.silenced_until = None
        alert_group.silenced_by_user = None
        alert_group.silenced_at = None
        alert_group.silenced = False
        alert_group.unsilence_task_uuid = None
        alert_group.restarted_at = timezone.now()
        update_fields.extend(
            [
                "silenced_until",
                "silenced_by_user",
                "silenced_at",
                "silenced",
                "unsilence_task_uuid",
                "restarted_at",
            ]
        )
        log_types.append(AlertGroupLogRecord.TYPE_UN_SILENCE)

    if not update_fields:
        return

    alert_group.save(update_fields=update_fields)
    alert_group._update_metrics(
        organization_id=alert_group.channel.organization_id,
        previous_state=initial_state,
        state=alert_group.state,
    )
    for log_type in log_types:
        log_record = alert_group.log_records.create(
            type=log_type,
            author=user,
            reason="Skip to next escalation",
        )
        transaction.on_commit(partial(send_alert_group_signal.delay, log_record.pk))


def _preview_users(alert_group: AlertGroup, policies: Iterable[object]):
    users = []
    for policy in policies:
        if policy.step in (
            EscalationPolicy.STEP_NOTIFY_USERS_QUEUE,
            EscalationPolicy.STEP_NOTIFY_USERS_QUEUE_IMPORTANT,
        ):
            if policy.notify_to_users_queue:
                users.append(policy.next_user_in_sorted_queue)
        elif policy.step in (
            EscalationPolicy.STEP_NOTIFY_MULTIPLE_USERS,
            EscalationPolicy.STEP_NOTIFY_MULTIPLE_USERS_IMPORTANT,
        ):
            users.extend(policy.notify_to_users_queue or [])
        elif policy.step in (
            EscalationPolicy.STEP_NOTIFY_SCHEDULE,
            EscalationPolicy.STEP_NOTIFY_SCHEDULE_IMPORTANT,
        ):
            if policy.notify_schedule is not None:
                users.extend(list_users_to_notify_from_ical(policy.notify_schedule) or [])
        elif policy.step in (
            EscalationPolicy.STEP_NOTIFY_TEAM_MEMBERS,
            EscalationPolicy.STEP_NOTIFY_TEAM_MEMBERS_IMPORTANT,
        ):
            if policy.notify_to_team_members is not None:
                users.extend(policy.notify_to_team_members.users.all())
        elif policy.step in (
            EscalationPolicy.STEP_NOTIFY_GROUP,
            EscalationPolicy.STEP_NOTIFY_GROUP_IMPORTANT,
        ):
            if policy.notify_to_group is not None:
                users.extend(
                    policy.notify_to_group.get_users_from_members_for_organization(alert_group.channel.organization)
                )

    return list({user.pk: user for user in users}.values())
