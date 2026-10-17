import pytest
from django.utils import timezone

from apps.mobile_app.demo_push import _get_test_escalation_fcm_message
from apps.mobile_app.models import MobileAppUserSettings
from apps.mobile_app.tasks.going_oncall_notification import _get_fcm_message as get_going_oncall_message
from apps.mobile_app.tasks.new_alert_group import _get_fcm_message as get_alert_group_message
from apps.mobile_app.tasks.new_shift_swap_request import _get_fcm_message as get_shift_swap_request_message
from apps.mobile_app.types import MessageType, Platform
from apps.mobile_app.utils import get_notification_sound
from apps.schedules.models import OnCallScheduleWeb

OVERRIDE_DND_FIELD = {
    MessageType.DEFAULT: "default_notification_override_dnd",
    MessageType.IMPORTANT: "important_notification_override_dnd",
    MessageType.INFO: "info_notification_override_dnd",
}


def _settings_with_override(user, message_type: MessageType, override_dnd: bool) -> MobileAppUserSettings:
    """Only `message_type`'s own switch is `override_dnd`; the other types' switches are the opposite."""
    return MobileAppUserSettings.objects.create(
        user=user,
        info_notifications_enabled=True,
        default_notification_volume=0.3,
        important_notification_volume=0.6,
        info_notification_volume=0.9,
        **{field: (override_dnd if t == message_type else not override_dnd) for t, field in OVERRIDE_DND_FIELD.items()},
    )


def _assert_dnd_presentation(message, message_type: MessageType, override_dnd: bool, expected_volume: float):
    # iOS: a critical alert (breaks through DND) only when the type's override switch is on
    aps = message.apns.payload.aps
    assert aps.sound.critical is override_dnd
    assert aps.sound.volume == (expected_volume if override_dnd else None)
    assert aps.custom_data == {"interruption-level": "critical" if override_dnd else "time-sensitive"}
    # Android: the type's switch is passed in the data payload
    assert message.data[OVERRIDE_DND_FIELD[message_type]] == ("true" if override_dnd else "false")


@pytest.mark.parametrize(
    "message_type,expected_volume",
    [(MessageType.DEFAULT, 0.3), (MessageType.IMPORTANT, 0.6), (MessageType.INFO, 0.9)],
)
@pytest.mark.parametrize("override_dnd", [True, False])
@pytest.mark.django_db
def test_get_notification_sound_uses_override_of_message_type(
    make_organization_and_user, message_type, expected_volume, override_dnd
):
    _, user = make_organization_and_user()
    mobile_app_user_settings = _settings_with_override(user, message_type, override_dnd)

    sound = get_notification_sound(mobile_app_user_settings, message_type)

    assert sound.apns_sound.critical is override_dnd
    assert sound.apns_sound.volume == (expected_volume if override_dnd else None)
    assert sound.apns_sound.name == mobile_app_user_settings.get_notification_sound_name(message_type, Platform.IOS)
    assert sound.apns_custom_data == {"interruption-level": "critical" if override_dnd else "time-sensitive"}
    assert sound.data[OVERRIDE_DND_FIELD[message_type]] == ("true" if override_dnd else "false")


@pytest.mark.django_db
def test_get_notification_sound_data_keys(make_organization_and_user):
    _, user = make_organization_and_user()
    mobile_app_user_settings = MobileAppUserSettings.objects.create(user=user)

    escalation_keys = {
        f"{prefix}_notification_{suffix}"
        for prefix in ("default", "important")
        for suffix in ("sound_name", "volume_type", "volume", "volume_override", "override_dnd")
    }
    info_keys = {
        f"info_notification_{suffix}"
        for suffix in ("sound_name", "volume_type", "volume", "volume_override", "override_dnd")
    }
    assert set(get_notification_sound(mobile_app_user_settings, MessageType.DEFAULT).data) == escalation_keys
    assert set(get_notification_sound(mobile_app_user_settings, MessageType.IMPORTANT).data) == escalation_keys
    assert set(get_notification_sound(mobile_app_user_settings, MessageType.INFO).data) == info_keys


@pytest.mark.parametrize("critical", [True, False])
@pytest.mark.parametrize("override_dnd", [True, False])
@pytest.mark.django_db
def test_alert_group_push_dnd(
    make_organization_and_user, make_alert_receive_channel, make_alert_group, make_alert, critical, override_dnd
):
    organization, user = make_organization_and_user()
    alert_group = make_alert_group(make_alert_receive_channel(organization=organization))
    make_alert(alert_group=alert_group, raw_request_data={})
    message_type = MessageType.IMPORTANT if critical else MessageType.DEFAULT
    _settings_with_override(user, message_type, override_dnd)

    message = get_alert_group_message(alert_group, user, critical)

    assert message.data["type"] == message_type
    _assert_dnd_presentation(message, message_type, override_dnd, 0.6 if critical else 0.3)


@pytest.mark.parametrize("critical", [True, False])
@pytest.mark.parametrize("override_dnd", [True, False])
@pytest.mark.django_db
def test_test_push_dnd(make_organization_and_user, critical, override_dnd):
    _, user = make_organization_and_user()
    message_type = MessageType.IMPORTANT if critical else MessageType.DEFAULT
    _settings_with_override(user, message_type, override_dnd)

    message = _get_test_escalation_fcm_message(user, critical)

    assert message.data["type"] == message_type
    _assert_dnd_presentation(message, message_type, override_dnd, 0.6 if critical else 0.3)


@pytest.mark.parametrize("override_dnd", [True, False])
@pytest.mark.django_db
def test_going_oncall_push_dnd(make_organization, make_user_for_organization, make_schedule, override_dnd):
    organization = make_organization()
    user = make_user_for_organization(organization)
    schedule = make_schedule(organization, schedule_class=OnCallScheduleWeb)
    _settings_with_override(user, MessageType.INFO, override_dnd)
    now = timezone.now()
    schedule_event = {
        "start": now + timezone.timedelta(minutes=10),
        "end": now + timezone.timedelta(hours=1),
        "shift": {"pk": "shift-pk"},
        "users": [{"pk": user.public_primary_key}],
    }

    message = get_going_oncall_message(user, schedule, 600, schedule_event)

    assert message.data["type"] == MessageType.INFO
    _assert_dnd_presentation(message, MessageType.INFO, override_dnd, 0.9)


@pytest.mark.parametrize("override_dnd", [True, False])
@pytest.mark.django_db
def test_shift_swap_request_push_dnd(
    make_organization, make_user, make_schedule, make_shift_swap_request, override_dnd
):
    organization = make_organization()
    beneficiary = make_user(organization=organization)
    benefactor = make_user(organization=organization)
    schedule = make_schedule(organization, schedule_class=OnCallScheduleWeb)
    now = timezone.now()
    swap_start = now + timezone.timedelta(days=100)
    shift_swap_request = make_shift_swap_request(
        schedule, beneficiary, swap_start=swap_start, swap_end=swap_start + timezone.timedelta(days=1), created_at=now
    )
    mobile_app_user_settings = _settings_with_override(benefactor, MessageType.INFO, override_dnd)

    message = get_shift_swap_request_message(shift_swap_request, benefactor, mobile_app_user_settings)

    assert message.data["type"] == MessageType.INFO
    _assert_dnd_presentation(message, MessageType.INFO, override_dnd, 0.9)
