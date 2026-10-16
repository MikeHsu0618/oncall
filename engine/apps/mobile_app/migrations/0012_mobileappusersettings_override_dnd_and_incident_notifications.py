from django.db import migrations, models
from django_add_default_value import AddDefaultValue


class Migration(migrations.Migration):

    dependencies = [
        ('mobile_app', '0011_alter_mobileappusersettings_going_oncall_notification_timing'),
    ]

    operations = [
        migrations.AddField(
            model_name='mobileappusersettings',
            name='default_notification_override_dnd',
            field=models.BooleanField(default=False),
        ),
        # migrations.AddField enforces the default value on the app level, which leads to the issues during release
        # adding same default value on the database level
        AddDefaultValue(
            model_name='mobileappusersettings',
            name='default_notification_override_dnd',
            value=False,
        ),
        migrations.AddField(
            model_name='mobileappusersettings',
            name='info_notification_override_dnd',
            field=models.BooleanField(default=False),
        ),
        AddDefaultValue(
            model_name='mobileappusersettings',
            name='info_notification_override_dnd',
            value=False,
        ),
        migrations.AddField(
            model_name='mobileappusersettings',
            name='incident_notifications_enabled',
            field=models.BooleanField(default=False),
        ),
        AddDefaultValue(
            model_name='mobileappusersettings',
            name='incident_notifications_enabled',
            value=False,
        ),
    ]
