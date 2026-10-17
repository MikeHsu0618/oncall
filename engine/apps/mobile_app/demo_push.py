import logging
import random
import string

from firebase_admin.messaging import APNSPayload, Aps, ApsAlert, Message

from apps.mobile_app.exceptions import DeviceNotSet
from apps.mobile_app.types import FCMMessageData, MessageType
from apps.mobile_app.utils import construct_fcm_message, get_notification_sound, send_push_notification
from apps.user_management.models import User

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def send_test_push(user, critical=False):
    from apps.mobile_app.models import FCMDevice

    devices_to_notify = FCMDevice.get_devices_to_notify(user)
    if not devices_to_notify:
        logger.info(f"send_test_push: fcm_device not found user_id={user.id}")
        raise DeviceNotSet
    message = _get_test_escalation_fcm_message(user, critical)
    send_push_notification(user, devices_to_notify, message)


def _get_test_escalation_fcm_message(user: User, critical: bool) -> Message:
    from apps.mobile_app.models import MobileAppUserSettings

    thread_id = f"{''.join(random.choices(string.digits, k=6))}:test_push"

    mobile_app_user_settings, _ = MobileAppUserSettings.objects.get_or_create(user=user)
    # critical defines the type of notification, the same way as for alert group pushes
    message_type = MessageType.IMPORTANT if critical else MessageType.DEFAULT
    notification_sound = get_notification_sound(mobile_app_user_settings, message_type)

    fcm_message_data: FCMMessageData = {
        "title": get_test_push_title(critical),
        "orgName": user.organization.stack_slug,
        # Pass user settings, so the Android app can use them to play the correct sound and volume
        **notification_sound.data,
    }

    apns_payload = APNSPayload(
        aps=Aps(
            thread_id=thread_id,
            alert=ApsAlert(title=get_test_push_title(critical)),
            sound=notification_sound.apns_sound,
            custom_data=notification_sound.apns_custom_data,
        ),
    )

    return construct_fcm_message(message_type, thread_id, fcm_message_data, apns_payload)


def get_test_push_title(critical: bool) -> str:
    return f"Hi, this is a {'critical ' if critical else ''}test notification from Grafana OnCall"
