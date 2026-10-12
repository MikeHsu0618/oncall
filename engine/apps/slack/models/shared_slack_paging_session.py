from uuid import uuid4

from django.db import models


class SharedSlackPagingSession(models.Model):
    """Native direct paging session and its immutable completion outbox.

    A session records an IRM reservation, never a persisted permission grant.
    Every interactive step resolves its current linked native user again.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    reservation_token = models.UUIDField(unique=True)
    organization = models.ForeignKey("user_management.Organization", on_delete=models.CASCADE)
    team = models.ForeignKey("slack.SlackTeamIdentity", on_delete=models.CASCADE)
    grafana_org_id = models.CharField(max_length=64)
    slack_user_id = models.CharField(max_length=100)
    grafana_user_id = models.CharField(max_length=32)
    app_id = models.CharField(max_length=100)
    bot_user_id = models.CharField(max_length=100)
    source_owner = models.JSONField(null=True, default=None)
    incident_context = models.JSONField()
    view_id = models.CharField(max_length=100)
    confirmation_view_id = models.CharField(max_length=100, blank=True)
    form_metadata = models.JSONField(default=dict)
    confirmation_metadata = models.JSONField(default=dict)
    phase = models.CharField(max_length=16, default="open")
    view_operation_phase = models.CharField(max_length=16, default="ready")
    semantic_fingerprint = models.CharField(max_length=64, blank=True)
    result_data = models.JSONField(null=True)
    result_body = models.TextField(blank=True)
    callback_delivered_at = models.DateTimeField(null=True)
    callback_attempts = models.PositiveIntegerField(default=0)
    callback_next_attempt_at = models.DateTimeField(null=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["phase", "callback_delivered_at"], name="slack_paging_result_pending")]
        constraints = [models.CheckConstraint(check=models.Q(view_operation_phase__in=["ready", "posting", "uncertain"]),
            name="slack_shared_view_phase")]


class SharedSlackPagingNotification(models.Model):
    """Native notify_user_task intent; uncertain publication is never replayed."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    session = models.ForeignKey(SharedSlackPagingSession, on_delete=models.CASCADE, null=True)
    command = models.ForeignKey("slack.SharedSlackPagingCommand", on_delete=models.CASCADE, null=True)
    user = models.ForeignKey("user_management.User", on_delete=models.CASCADE)
    alert_group = models.ForeignKey("alerts.AlertGroup", on_delete=models.CASCADE)
    important = models.BooleanField(default=False)
    force_default_fallback = models.BooleanField(default=False)
    phase = models.CharField(max_length=16, default="pending")
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["session", "user"], name="slack_paging_notify_user_once"),
            models.UniqueConstraint(fields=["command", "user"], name="slack_paging_cmd_user_once"),
            models.CheckConstraint(
                check=(models.Q(session__isnull=False, command__isnull=True)
                       | models.Q(session__isnull=True, command__isnull=False)),
                name="slack_paging_notify_one_owner",
            ),
        ]
