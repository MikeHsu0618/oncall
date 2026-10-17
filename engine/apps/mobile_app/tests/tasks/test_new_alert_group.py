from unittest.mock import patch

import pytest

from apps.base.models import UserNotificationPolicy, UserNotificationPolicyLogRecord
from apps.mobile_app.models import FCMDevice, MobileAppPushRecord, MobileAppUserSettings
from apps.mobile_app.tasks.new_alert_group import _get_fcm_message, notify_user_about_new_alert_group

MOBILE_APP_BACKEND_ID = 5
CLOUD_LICENSE_NAME = "Cloud"
OPEN_SOURCE_LICENSE_NAME = "OpenSource"


@patch("apps.mobile_app.tasks.new_alert_group.send_push_notification")
@pytest.mark.django_db
def test_notify_user_about_new_alert_group(
    mock_send_push_notification,
    make_organization_and_user,
    make_user_notification_policy,
    make_alert_receive_channel,
    make_channel_filter,
    make_alert_group,
    make_alert,
):
    # create a user and connect a mobile device
    organization, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    # set up notification policy and alert group
    notification_policy = make_user_notification_policy(
        user,
        UserNotificationPolicy.Step.NOTIFY,
        notify_by=MOBILE_APP_BACKEND_ID,
    )
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    channel_filter = make_channel_filter(alert_receive_channel)
    alert_group = make_alert_group(alert_receive_channel, channel_filter=channel_filter)
    make_alert(alert_group=alert_group, raw_request_data={})

    notify_user_about_new_alert_group(
        user_pk=user.pk,
        alert_group_pk=alert_group.pk,
        notification_policy_pk=notification_policy.pk,
        critical=False,
    )

    mock_send_push_notification.assert_called_once()
    user_arg, devices_arg, message = mock_send_push_notification.call_args.args
    assert user_arg == user
    assert devices_arg == [device]
    assert message.data["alertGroupId"] == alert_group.public_primary_key
    assert mock_send_push_notification.call_args.kwargs == {"alert_group": alert_group}
    log_record = notification_policy.personal_log_records.last()
    assert log_record.type == UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_SUCCESS


@patch("apps.mobile_app.tasks.new_alert_group.send_push_notification")
@pytest.mark.django_db
def test_notify_user_about_new_alert_group_no_device_connected(
    mock_send_push_notification,
    make_organization_and_user,
    make_user_notification_policy,
    make_alert_receive_channel,
    make_channel_filter,
    make_alert_group,
    make_alert,
):
    # create a user without mobile device
    organization, user = make_organization_and_user()

    # set up notification policy and alert group
    notification_policy = make_user_notification_policy(
        user,
        UserNotificationPolicy.Step.NOTIFY,
        notify_by=MOBILE_APP_BACKEND_ID,
    )
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    channel_filter = make_channel_filter(alert_receive_channel)
    alert_group = make_alert_group(alert_receive_channel, channel_filter=channel_filter)
    make_alert(alert_group=alert_group, raw_request_data={})

    notify_user_about_new_alert_group(
        user_pk=user.pk,
        alert_group_pk=alert_group.pk,
        notification_policy_pk=notification_policy.pk,
        critical=False,
    )
    mock_send_push_notification.assert_not_called()

    log_record = alert_group.personal_log_records.last()
    assert log_record.type == UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_FAILED
    assert (
        log_record.notification_error_code
        == UserNotificationPolicyLogRecord.ERROR_NOTIFICATION_MOBILE_USER_HAS_NO_ACTIVE_DEVICE
    )


@patch("apps.mobile_app.utils.send_message_to_fcm_device", return_value=False)
@pytest.mark.django_db
def test_notify_user_about_new_alert_group_error_log_if_not_succeeded(
    mock_send_message_to_fcm_device,
    settings,
    make_organization_and_user,
    make_user_notification_policy,
    make_alert_receive_channel,
    make_channel_filter,
    make_alert_group,
    make_alert,
):
    # create a user and connect a mobile device
    organization, user = make_organization_and_user()
    FCMDevice.objects.create(user=user, registration_id="test_device_id")
    # set up notification policy and alert group
    notification_policy = make_user_notification_policy(
        user,
        UserNotificationPolicy.Step.NOTIFY,
        notify_by=MOBILE_APP_BACKEND_ID,
    )
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    channel_filter = make_channel_filter(alert_receive_channel)
    alert_group = make_alert_group(alert_receive_channel, channel_filter=channel_filter)
    make_alert(alert_group=alert_group, raw_request_data={})
    # check FCM is contacted directly when using the cloud license
    settings.LICENSE = CLOUD_LICENSE_NAME
    settings.IS_OPEN_SOURCE = False

    notify_user_about_new_alert_group(
        user_pk=user.pk,
        alert_group_pk=alert_group.pk,
        notification_policy_pk=notification_policy.pk,
        critical=False,
    )
    mock_send_message_to_fcm_device.assert_called_once()
    log_record = alert_group.personal_log_records.last()
    assert log_record.type == UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_FAILED
    assert alert_group.personal_log_records.count() == 1
    # nothing was handed off, so nothing shows up in the notification history
    assert not MobileAppPushRecord.objects.exists()


@pytest.mark.django_db
def test_fcm_message_user_settings(
    make_organization_and_user, make_alert_receive_channel, make_alert_group, make_alert
):
    organization, user = make_organization_and_user()
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    alert_group = make_alert_group(alert_receive_channel)
    make_alert(alert_group=alert_group, raw_request_data={})

    message = _get_fcm_message(alert_group, user, critical=False)

    # Check user settings are passed to FCM message
    assert message.data["default_notification_sound_name"] == "default_sound.mp3"
    assert message.data["default_notification_volume_type"] == "constant"
    assert message.data["default_notification_volume_override"] == "false"
    assert message.data["default_notification_volume"] == "0.8"
    assert message.data["important_notification_sound_name"] == "default_sound_important.mp3"
    assert message.data["important_notification_volume_type"] == "constant"
    assert message.data["important_notification_volume"] == "0.8"
    assert message.data["important_notification_volume_override"] == "true"
    assert message.data["important_notification_override_dnd"] == "true"
    assert message.data["default_notification_override_dnd"] == "false"
    assert message.data["type"] == "oncall.message"
    assert message.token is None

    # Check APNS notification sound is set correctly
    apns_sound = message.apns.payload.aps.sound
    assert apns_sound.critical is False
    assert apns_sound.name == "default_sound.aiff"
    assert apns_sound.volume is None  # APNS doesn't allow to specify volume for non-critical notifications


@pytest.mark.django_db
def test_fcm_message_user_settings_critical(
    make_organization_and_user, make_alert_receive_channel, make_alert_group, make_alert
):
    organization, user = make_organization_and_user()
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    alert_group = make_alert_group(alert_receive_channel)
    make_alert(alert_group=alert_group, raw_request_data={})

    message = _get_fcm_message(alert_group, user, critical=True)

    # Check user settings are passed to FCM message
    assert message.data["default_notification_sound_name"] == "default_sound.mp3"
    assert message.data["default_notification_volume_type"] == "constant"
    assert message.data["default_notification_volume_override"] == "false"
    assert message.data["default_notification_volume"] == "0.8"
    assert message.data["important_notification_sound_name"] == "default_sound_important.mp3"
    assert message.data["important_notification_volume_type"] == "constant"
    assert message.data["important_notification_volume"] == "0.8"
    assert message.data["important_notification_volume_override"] == "true"
    assert message.data["important_notification_override_dnd"] == "true"
    assert message.data["type"] == "oncall.critical_message"

    # Check APNS notification sound is set correctly
    apns_sound = message.apns.payload.aps.sound
    assert apns_sound.critical is True
    assert apns_sound.name == "default_sound_important.aiff"
    assert apns_sound.volume == 0.8
    assert message.apns.payload.aps.custom_data["interruption-level"] == "critical"


@pytest.mark.django_db
def test_fcm_message_user_settings_critical_override_dnd_disabled(
    make_organization_and_user, make_alert_receive_channel, make_alert_group, make_alert
):
    organization, user = make_organization_and_user()
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    alert_group = make_alert_group(alert_receive_channel)
    make_alert(alert_group=alert_group, raw_request_data={})

    # Disable important notification override DND
    MobileAppUserSettings.objects.create(user=user, important_notification_override_dnd=False)
    message = _get_fcm_message(alert_group, user, critical=True)

    # Check user settings are passed to FCM message
    assert message.data["important_notification_override_dnd"] == "false"

    # Check APNS notification sound is set correctly
    apns_sound = message.apns.payload.aps.sound
    assert apns_sound.critical is False
    assert message.apns.payload.aps.custom_data["interruption-level"] == "time-sensitive"
    assert apns_sound.volume is None


def _make_alert_group_and_policy(
    make_user_notification_policy,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
    organization,
    user,
    **policy_kwargs,
):
    notification_policy = make_user_notification_policy(
        user, UserNotificationPolicy.Step.NOTIFY, notify_by=MOBILE_APP_BACKEND_ID, **policy_kwargs
    )
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    alert_group = make_alert_group(alert_receive_channel)
    make_alert(alert_group=alert_group, raw_request_data={})
    return notification_policy, alert_group


@pytest.mark.parametrize(
    "chosen_device_name,expected_device_names",
    [
        # no device chosen on the step: all active devices
        (None, ["phone", "tablet"]),
        # chosen active device: only that device
        ("tablet", ["tablet"]),
        # chosen device is no longer active: fall back to all active devices
        ("old_phone", ["phone", "tablet"]),
    ],
)
@patch("apps.mobile_app.tasks.new_alert_group.send_push_notification", return_value=True)
@pytest.mark.django_db
def test_notify_user_about_new_alert_group_targets_notify_device(
    mock_send_push_notification,
    make_organization_and_user,
    make_user_notification_policy,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
    chosen_device_name,
    expected_device_names,
):
    organization, user = make_organization_and_user()
    _, other_user = make_organization_and_user()
    devices = {
        "phone": FCMDevice.objects.create(user=user, registration_id="phone"),
        "tablet": FCMDevice.objects.create(user=user, registration_id="tablet"),
        "old_phone": FCMDevice.objects.create(user=user, registration_id="old_phone", active=False),
    }
    FCMDevice.objects.create(user=other_user, registration_id="other_users_phone")

    notification_policy, alert_group = _make_alert_group_and_policy(
        make_user_notification_policy,
        make_alert_receive_channel,
        make_alert_group,
        make_alert,
        organization,
        user,
        notify_device=devices[chosen_device_name] if chosen_device_name else None,
    )

    notify_user_about_new_alert_group(
        user_pk=user.pk,
        alert_group_pk=alert_group.pk,
        notification_policy_pk=notification_policy.pk,
        critical=True,
    )

    mock_send_push_notification.assert_called_once()
    assert mock_send_push_notification.call_args.args[1] == [devices[name] for name in expected_device_names]


@patch.object(FCMDevice, "send_message", return_value="ok")
@pytest.mark.django_db
def test_notify_user_about_new_alert_group_records_notification_history(
    mock_send_message,
    settings,
    make_organization_and_user,
    make_user_notification_policy,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
):
    settings.LICENSE = CLOUD_LICENSE_NAME
    settings.IS_OPEN_SOURCE = False

    organization, user = make_organization_and_user()
    phone = FCMDevice.objects.create(user=user, registration_id="phone")
    tablet = FCMDevice.objects.create(user=user, registration_id="tablet")
    notification_policy, alert_group = _make_alert_group_and_policy(
        make_user_notification_policy,
        make_alert_receive_channel,
        make_alert_group,
        make_alert,
        organization,
        user,
    )

    notify_user_about_new_alert_group(
        user_pk=user.pk,
        alert_group_pk=alert_group.pk,
        notification_policy_pk=notification_policy.pk,
        critical=True,
    )

    # each device gets its own copy of the message, addressed to its registration id
    sent_messages = [c.args[0] for c in mock_send_message.call_args_list]
    assert [m.token for m in sent_messages] == [phone.registration_id, tablet.registration_id]
    assert sent_messages[0].data == sent_messages[1].data

    # one history record for the logical push, holding exactly the data payload that was sent
    record = MobileAppPushRecord.objects.get()
    assert record.user == user
    assert record.device is None  # fanned out to several devices
    assert record.alert_group == alert_group
    assert record.notification_type == "oncall.critical_message"
    assert record.title == sent_messages[0].data["title"]
    assert record.subtitle == sent_messages[0].data["subtitle"]
    assert record.fcm_payload == sent_messages[0].data
