import json
import logging
import typing

import requests
from django.conf import settings
from django.db import DatabaseError
from firebase_admin.exceptions import FirebaseError
from firebase_admin.messaging import (
    AndroidConfig,
    APNSConfig,
    APNSPayload,
    CriticalSound,
    Message,
    SendResponse,
    UnregisteredError,
)
from requests import HTTPError
from rest_framework import status

from apps.base.utils import live_settings
from apps.mobile_app.types import FCMMessageData, MessageType, NotificationSoundData, Platform
from common.api_helpers.utils import create_engine_url

if typing.TYPE_CHECKING:
    from apps.alerts.models import AlertGroup
    from apps.mobile_app.models import FCMDevice, MobileAppUserSettings
    from apps.user_management.models import Organization, User


MAX_RETRIES = 1 if settings.DEBUG else 10

# UnregisteredError
# App instance was unregistered from FCM. This usually means that the token used is no longer valid and a
# new one must be used.
#
# In other words, this error occurs outside of our control and retrying will never fix it, therefore we should skip
FIREBASE_ERRORS_TO_NOT_RETRY = (UnregisteredError,)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def _send_push_notification_to_fcm_relay(message: Message) -> requests.Response:
    """
    Send push notification to FCM relay on cloud instance: apps.mobile_app.fcm_relay.FCMRelayView
    """
    url = create_engine_url("mobile_app/v1/fcm_relay", override_base=settings.GRAFANA_CLOUD_ONCALL_API_URL)

    response = requests.post(
        url, headers={"Authorization": live_settings.GRAFANA_CLOUD_ONCALL_TOKEN}, json=json.loads(str(message))
    )
    response.raise_for_status()

    return response


def send_message_to_fcm_device(device: "FCMDevice", message: Message) -> bool:
    """
    https://firebase.google.com/docs/cloud-messaging/http-server-ref#interpret-downstream
    """
    response = device.send_message(message)

    if isinstance(response, SendResponse):
        logger.debug(
            f"FCM response: success={response.success} message_id={response.message_id} exception={response.exception}"
        )
    elif isinstance(response, FirebaseError):
        logger.exception(
            f"FCM error occured in mobile_app.utils.send_message_to_fcm_device fcm_device_info={device} "
            f"firebase_error_code={response._code} firebase_error_cause={response._cause} "
            f"firebase_error_http_response={response._http_response}"
        )

        if isinstance(response, FIREBASE_ERRORS_TO_NOT_RETRY):
            logger.warning(f"FCM error {response} is not being retried as we explicitly do not want to retry it")
            return False

        raise response
    else:
        logger.debug(f"FCM response: {response}")

    return True


def _hand_off_to_device(device: "FCMDevice", message: Message) -> bool:
    """
    Hand off a message addressed to one device: to the FCM relay on OSS installations, to FCM directly otherwise.

    Returns False on errors that retrying will not fix and raises on errors that are worth retrying.
    """
    if settings.IS_OPEN_SOURCE:
        try:
            response = _send_push_notification_to_fcm_relay(message)
            logger.debug(f"FCM relay response: {response}")
        except HTTPError as e:
            if status.HTTP_400_BAD_REQUEST <= e.response.status_code < status.HTTP_500_INTERNAL_SERVER_ERROR:
                # do not retry on HTTP client errors (4xx errors)
                logger.error(
                    f"Error while sending a mobile push notification: HTTP client error {e.response.status_code}"
                )
                return False
            raise
        return True

    return send_message_to_fcm_device(device, message)


def _message_for_device(message: Message, device: "FCMDevice") -> Message:
    return Message(
        data=message.data,
        notification=message.notification,
        android=message.android,
        webpush=message.webpush,
        apns=message.apns,
        fcm_options=message.fcm_options,
        token=device.registration_id,
    )


def send_push_notification(
    user: "User",
    devices: typing.Sequence["FCMDevice"],
    message: Message,
    alert_group: typing.Optional["AlertGroup"] = None,
) -> bool:
    """
    Single delivery path for every mobile push: hands one logical push (built by construct_fcm_message, without a
    device token) off to each of `devices`, and records it once in the user's notification history
    (MobileAppPushRecord) if at least one device accepted it.

    Returns True if at least one device accepted the push. Retryable errors are re-raised (so the calling celery task
    retries) only when no device accepted the push: retrying after a partial success would notify the devices that
    already got it a second time.
    """
    if settings.IS_OPEN_SOURCE:
        # FCM relay uses cloud connection to send push notifications
        from apps.oss_installation.models import CloudConnector

        if not CloudConnector.objects.exists():
            logger.error("Error while sending a mobile push notification: not connected to cloud")
            return False

    delivered_to: typing.List["FCMDevice"] = []
    retryable_errors: typing.List[Exception] = []
    for device in devices:
        device_message = _message_for_device(message, device)
        logger.debug(f"Sending push notification to device type {device.type} with message: {device_message}")
        try:
            if _hand_off_to_device(device, device_message):
                delivered_to.append(device)
        except Exception as e:
            logger.exception(f"Retryable error while sending a mobile push notification to device {device.pk}")
            retryable_errors.append(e)

    if not delivered_to:
        if retryable_errors:
            raise retryable_errors[0]
        return False

    if retryable_errors:
        logger.error(
            f"Mobile push notification for user {user.pk} reached {len(delivered_to)} of {len(devices)} devices; "
            "not retrying the failed ones to avoid notifying the others twice"
        )
    _record_sent_push(user, devices, message, alert_group)
    return True


def _record_sent_push(
    user: "User",
    devices: typing.Sequence["FCMDevice"],
    message: Message,
    alert_group: typing.Optional["AlertGroup"],
) -> None:
    from apps.mobile_app.models import MobileAppPushRecord

    targeted_device = devices[0] if len(devices) == 1 else None
    try:
        MobileAppPushRecord.record_sent_push(user, targeted_device, message, alert_group)
    except DatabaseError:
        # The push has already been handed off. Letting this propagate would make the celery task retry and notify
        # the user again, so a failed history write is logged instead of failing the delivery.
        logger.exception(f"Failed to record mobile push notification in notification history for user {user.pk}")


def construct_fcm_message(
    message_type: MessageType,
    thread_id: str,
    data: FCMMessageData,
    apns_payload: typing.Optional[APNSPayload] = None,
) -> Message:
    """
    Build a push without a device token; send_push_notification addresses a copy of it to each target device.
    """
    apns_config_kwargs = {}

    if apns_payload is not None:
        apns_config_kwargs["payload"] = apns_payload

    return Message(
        data={
            # from the docs..
            # A dictionary of data fields (optional). All keys and values in the dictionary must be strings
            **data,
            "type": message_type,
            "thread_id": thread_id,
        },
        android=AndroidConfig(
            # from the docs
            # https://firebase.google.com/docs/cloud-messaging/concept-options#setting-the-priority-of-a-message
            #
            # Normal priority.
            # Normal priority messages are delivered immediately when the app is in the foreground.
            # For backgrounded apps, delivery may be delayed. For less time-sensitive messages, such as notifications
            # of new email, keeping your UI in sync, or syncing app data in the background, choose normal delivery
            # priority.
            #
            # High priority.
            # FCM attempts to deliver high priority messages immediately even if the device is in Doze mode.
            # High priority messages are for time-sensitive, user visible content.
            priority="high",
        ),
        apns=APNSConfig(
            **apns_config_kwargs,
            headers={
                # From the docs
                # https://firebase.google.com/docs/cloud-messaging/concept-options#setting-the-priority-of-a-message
                "apns-priority": "10",
            },
        ),
    )


class NotificationSound(typing.NamedTuple):
    apns_sound: CriticalSound
    apns_custom_data: typing.Dict[str, str]
    data: NotificationSoundData


def get_notification_sound(
    mobile_app_user_settings: "MobileAppUserSettings", message_type: MessageType
) -> NotificationSound:
    """
    Sound, volume and "override DND" presentation of a push, shared by every push builder.

    The per-type "override DND" setting (important / default / info) decides whether the push breaks through Do Not
    Disturb: on iOS it makes the sound a critical alert with interruption level "critical" (otherwise
    "time-sensitive"); the Android app reads the same settings from the FCM data payload.
    """
    s = mobile_app_user_settings
    override_dnd, volume = {
        MessageType.DEFAULT: (s.default_notification_override_dnd, s.default_notification_volume),
        MessageType.IMPORTANT: (s.important_notification_override_dnd, s.important_notification_volume),
        MessageType.INFO: (s.info_notification_override_dnd, s.info_notification_volume),
    }[message_type]

    apns_sound = CriticalSound(
        critical=override_dnd,
        name=s.get_notification_sound_name(message_type, Platform.IOS),
        # APNS only allows to specify volume for critical notifications
        volume=volume if override_dnd else None,
    )
    apns_custom_data = {"interruption-level": "critical" if override_dnd else "time-sensitive"}

    data: NotificationSoundData
    if message_type == MessageType.INFO:
        data = {
            "info_notification_sound_name": s.get_notification_sound_name(MessageType.INFO, Platform.ANDROID),
            "info_notification_volume_type": s.info_notification_volume_type,
            "info_notification_volume": str(s.info_notification_volume),
            "info_notification_volume_override": json.dumps(s.info_notification_volume_override),
            "info_notification_override_dnd": json.dumps(s.info_notification_override_dnd),
        }
    else:
        # Escalation pushes carry both default and important settings, the Android app picks them by message type
        data = {
            "default_notification_sound_name": s.get_notification_sound_name(MessageType.DEFAULT, Platform.ANDROID),
            "default_notification_volume_type": s.default_notification_volume_type,
            "default_notification_volume": str(s.default_notification_volume),
            "default_notification_volume_override": json.dumps(s.default_notification_volume_override),
            "default_notification_override_dnd": json.dumps(s.default_notification_override_dnd),
            "important_notification_sound_name": s.get_notification_sound_name(
                MessageType.IMPORTANT, Platform.ANDROID
            ),
            "important_notification_volume_type": s.important_notification_volume_type,
            "important_notification_volume": str(s.important_notification_volume),
            "important_notification_volume_override": json.dumps(s.important_notification_volume_override),
            "important_notification_override_dnd": json.dumps(s.important_notification_override_dnd),
        }

    return NotificationSound(apns_sound=apns_sound, apns_custom_data=apns_custom_data, data=data)


def add_stack_slug_to_message_title(title: str, organization: "Organization") -> str:
    return f"[{organization.stack_slug}] {title}"
