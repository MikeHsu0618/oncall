import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("slack", "0013_shared_slack_delivery"),
        ("user_management", "0028_remove_organization_general_log_channel_id_state"),
    ]
    operations = [
        migrations.CreateModel(
            name="SharedSlackInstallation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("assistant_enabled", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("organization", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE,
                    related_name="shared_slack_installation", to="user_management.organization")),
                ("team", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="slack.slackteamidentity")),
            ],
        ),
    ]
