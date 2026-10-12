"""Deliver committed native paging facts independently of current user grants."""

import hashlib
import hmac
import logging
import time
from datetime import timedelta

import requests
from celery import current_app, shared_task
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.alerts.tasks.notify_user import notify_user_task
from apps.slack.models import SharedSlackPagingNotification, SharedSlackPagingSession

logger = logging.getLogger(__name__)


def due(field):
    return Q(**{field + "__isnull": True}) | Q(**{field + "__lte": timezone.now()})


def deliver_result(session_id):
    url = getattr(settings, "SHARED_SLACK_PAGING_RESULT_URL", "")
    secret = getattr(settings, "SHARED_SLACK_BRIDGE_SECRET", "")
    if not url or not secret or transaction.get_connection().in_atomic_block:
        return
    # Reserve one exact immutable completion attempt, then close the SQL lock.
    # A lost ACK retries the original fact, never the native page/notification.
    with transaction.atomic():
        session = SharedSlackPagingSession.objects.select_for_update().get(pk=session_id)
        if session.phase != "completed" or session.callback_delivered_at is not None:
            return
        if session.callback_next_attempt_at is not None and session.callback_next_attempt_at > timezone.now():
            return
        raw = session.result_body.encode("utf-8")
        if not raw or len(raw) > 256 * 1024:
            return
        session.callback_attempts += 1
        attempt = session.callback_attempts
        session.callback_next_attempt_at = timezone.now() + timedelta(seconds=min(300, 2 ** min(attempt, 8)))
        session.save(update_fields=["callback_attempts", "callback_next_attempt_at"])
    timestamp = str(int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    response = None
    accepted = False
    try:
        with requests.Session() as client:
            client.trust_env = False
            if (getattr(settings, "SHARED_SLACK_PAGING_RESULT_URL", ""),
                    getattr(settings, "SHARED_SLACK_BRIDGE_SECRET", "")) != (url, secret):
                return
            response = client.post(url, data=raw, headers={"Content-Type": "application/json",
                "X-Grafana-Slack-Timestamp": timestamp, "X-Grafana-Slack-Signature": signature,
                "X-Grafana-Slack-Delivery-Id": str(session_id)}, timeout=5, allow_redirects=False, stream=True)
            accepted = response.status_code == 202
            if not accepted:
                logger.warning("IRM paging fact delivery unavailable")
    except requests.RequestException:
        logger.warning("IRM paging fact delivery unavailable")
    finally:
        if response is not None:
            response.close()
    if accepted:
        # No active installation/member grant is required for a completed fact.
        # A concurrent newer attempt or changed immutable result cannot be ACKed.
        SharedSlackPagingSession.objects.filter(pk=session_id, phase="completed", result_body=raw.decode("utf-8"),
            callback_attempts=attempt, callback_delivered_at__isnull=True).update(callback_delivered_at=timezone.now())


def publish_notification(notification_id):
    # A broker connection failure is definitely before publication and retryable.
    # Once publication starts, response loss is ambiguous; never blindly publish
    # again. Task ID is correlation only, not an exactly-once Celery claim.
    connection = None
    try:
        connection = current_app.connection_for_write()
        connection.ensure_connection(max_retries=0)
    except Exception:
        if connection is not None:
            connection.release()
        with transaction.atomic():
            intent = SharedSlackPagingNotification.objects.select_for_update().get(pk=notification_id)
            if intent.phase == "pending":
                intent.attempts += 1
                intent.next_attempt_at = timezone.now() + timedelta(seconds=min(300, 2 ** min(intent.attempts, 8)))
                intent.save(update_fields=["attempts", "next_attempt_at"])
        return
    try:
        with transaction.atomic():
            intent = SharedSlackPagingNotification.objects.select_for_update().get(pk=notification_id)
            if intent.phase != "pending":
                return
            intent.phase = "publishing"
            intent.attempts += 1
            intent.next_attempt_at = timezone.now() + timedelta(minutes=5)
            intent.save(update_fields=["phase", "attempts", "next_attempt_at"])
        try:
            with current_app.amqp.Producer(connection) as producer:
                kwargs = {"important": intent.important, "notify_even_acknowledged": True, "notify_anyway": True}
                if intent.force_default_fallback:
                    kwargs["force_default_fallback"] = True
                notify_user_task.apply_async((intent.user_id, intent.alert_group_id),
                    kwargs,
                    producer=producer, retry=False, task_id=str(intent.pk))
            phase = "posted"
        except Exception:
            phase = "uncertain"
            logger.warning("Native paging notification publication uncertain")
        SharedSlackPagingNotification.objects.filter(pk=intent.pk, phase="publishing").update(phase=phase)
    finally:
        connection.release()


@shared_task(queue="slack")
def recover_shared_paging():
    # A process can die after claiming publication, before its outcome is known.
    # Surface that state without replaying a possibly accepted native task.
    abandoned = SharedSlackPagingNotification.objects.filter(phase="publishing").filter(due("next_attempt_at"))
    count = abandoned.update(phase="uncertain")
    if count:
        logger.warning("%s native paging notification publication(s) require reconciliation", count)
    # Native beat discovers work even if the broker failed at request commit.
    sessions = SharedSlackPagingSession.objects.filter(phase="completed", callback_delivered_at__isnull=True).filter(due("callback_next_attempt_at"))
    for session_id in list(sessions.values_list("pk", flat=True)[:50]):
        deliver_result(session_id)
    notifications = SharedSlackPagingNotification.objects.filter(phase="pending").filter(due("next_attempt_at"))
    for notification_id in list(notifications.values_list("pk", flat=True)[:100]):
        publish_notification(notification_id)
