from django.db import models


class SharedSlackPagingCommand(models.Model):
    """Native typed escalation receipt, committed with its original page."""

    key = models.CharField(max_length=64, primary_key=True)
    organization = models.ForeignKey("user_management.Organization", on_delete=models.CASCADE)
    team = models.ForeignKey("slack.SlackTeamIdentity", on_delete=models.PROTECT)
    slack_user_id = models.CharField(max_length=100)
    grafana_user_id = models.CharField(max_length=32)
    phase = models.CharField(max_length=16, default="open")
    alert_group_id = models.CharField(max_length=100, blank=True)
    response_data = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
