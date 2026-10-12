from django.db import models


class SharedSlackInstallation(models.Model):
    """Local shared-app capability snapshot; never an IRM permission grant."""

    organization = models.OneToOneField(
        "user_management.Organization", on_delete=models.CASCADE, related_name="shared_slack_installation"
    )
    team = models.ForeignKey("slack.SlackTeamIdentity", on_delete=models.CASCADE)
    assistant_enabled = models.BooleanField(default=False)
    source_owner = models.JSONField(null=True, default=None)
    source_links = models.JSONField(default=dict)
    source_links_revision = models.BigIntegerField(default=1)
    source_disconnected = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.CheckConstraint(
            check=models.Q(source_links_revision__gte=1, source_links_revision__lte=2**63 - 1),
            name="slack_shared_links_revision"),
            models.CheckConstraint(check=models.Q(source_disconnected=False) | models.Q(source_owner__isnull=False),
            name="slack_shared_disconnect_source")]
