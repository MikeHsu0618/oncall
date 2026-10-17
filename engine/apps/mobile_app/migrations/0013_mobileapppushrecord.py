import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alerts', '0075_alter_alertgrouplogrecord_action_source'),
        ('user_management', '0029_remove_organization_general_log_channel_id_db'),
        ('mobile_app', '0012_mobileappusersettings_override_dnd_and_incident_notifications'),
    ]

    operations = [
        migrations.CreateModel(
            name='MobileAppPushRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('notification_type', models.CharField(choices=[('oncall.message', 'oncall.message'), ('oncall.critical_message', 'oncall.critical_message'), ('oncall.info', 'oncall.info')], max_length=50)),
                ('title', models.TextField()),
                ('subtitle', models.TextField(default='')),
                ('sent_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('fcm_payload', models.JSONField()),
                ('alert_group', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='mobile_app_push_records', to='alerts.alertgroup')),
                ('device', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='mobile_app.fcmdevice')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='mobile_app_push_records', to='user_management.user')),
            ],
            options={
                'indexes': [models.Index(fields=['user', 'sent_at'], name='mobile_app_push_user_sent_idx')],
            },
        ),
    ]
