import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("slack", "0014_shared_slack_installation")]
    operations = [migrations.CreateModel(
        name="SharedSlackPagingSession",
        fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("reservation_token", models.UUIDField(unique=True)),
            ("grafana_org_id", models.CharField(max_length=64)),
            ("slack_user_id", models.CharField(max_length=100)),
            ("grafana_user_id", models.CharField(max_length=32)),
            ("app_id", models.CharField(max_length=100)),
            ("bot_user_id", models.CharField(max_length=100)),
            ("incident_context", models.JSONField()),
            ("view_id", models.CharField(max_length=100)),
            ("confirmation_view_id", models.CharField(blank=True, max_length=100)),
            ("form_metadata", models.JSONField(default=dict)),
            ("confirmation_metadata", models.JSONField(default=dict)),
            ("phase", models.CharField(default="open", max_length=16)),
            ("semantic_fingerprint", models.CharField(blank=True, max_length=64)),
            ("result_data", models.JSONField(null=True)),
            ("result_body", models.TextField(blank=True)),
            ("callback_delivered_at", models.DateTimeField(null=True)),
            ("callback_attempts", models.PositiveIntegerField(default=0)),
            ("callback_next_attempt_at", models.DateTimeField(null=True)),
            ("expires_at", models.DateTimeField()),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="user_management.organization")),
            ("team", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="slack.slackteamidentity")),
        ],
        options={"indexes": [models.Index(fields=["phase", "callback_delivered_at"], name="slack_paging_result_pending")]},
    )]
