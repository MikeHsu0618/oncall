import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("slack", "0015_shared_slack_paging_session")]
    operations = [
        migrations.CreateModel(
            name="SharedSlackPagingNotification",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("important", models.BooleanField(default=False)),
                ("phase", models.CharField(default="pending", max_length=16)),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("next_attempt_at", models.DateTimeField(null=True)),
                ("session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="slack.sharedslackpagingsession")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="user_management.user")),
                ("alert_group", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="alerts.alertgroup")),
            ],
        ),
        migrations.AddConstraint(
            model_name="sharedslackpagingnotification",
            constraint=models.UniqueConstraint(fields=("session", "user"), name="slack_paging_notify_user_once"),
        ),
    ]
