from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_management', '0029_remove_organization_general_log_channel_id_db'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='irm_working_hours',
            field=models.JSONField(default=None, null=True),
        ),
    ]
