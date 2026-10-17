import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mobile_app', '0012_mobileappusersettings_override_dnd_and_incident_notifications'),
        ('base', '0005_drop_unused_dynamic_settings'),
    ]

    operations = [
        migrations.AddField(
            model_name='usernotificationpolicy',
            name='notify_device',
            field=models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='mobile_app.fcmdevice'),
        ),
    ]
