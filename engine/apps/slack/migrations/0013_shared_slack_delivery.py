from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("slack", "0012_remove_slackmessage_organization_state")]
    operations = [
        migrations.CreateModel(
            name="SharedSlackDelivery",
            fields=[
                ("key", models.CharField(max_length=64, primary_key=True, serialize=False)),
                ("phase", models.CharField(max_length=16, default="dispatching")),
                ("response_status", models.PositiveIntegerField(null=True)),
                ("response_data", models.JSONField(null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
