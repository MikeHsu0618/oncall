import logging

from celery.utils.log import get_task_logger
from firebase_admin.messaging import APNSPayload, Aps, ApsAlert, Message

from apps.alerts.models import AlertGroup
from apps.mobile_app.alert_rendering import get_push_notification_subtitle, get_push_notification_title
from apps.mobile_app.types import FCMMessageData, MessageType
from apps.mobile_app.utils import MAX_RETRIES, construct_fcm_message, get_notification_sound, send_push_notification
from apps.user_management.models import User
from common.custom_celery_tasks import shared_dedicated_queue_retry_task

logger = get_task_logger(__name__)
logger.setLevel(logging.DEBUG)


def _get_fcm_message(alert_group: AlertGroup, user: User, critical: bool) -> Message:
    # avoid circular import
    from apps.mobile_app.models import MobileAppUserSettings

    thread_id = f"{alert_group.channel.organization.public_primary_key}:{alert_group.public_primary_key}"

    alert_title = get_push_notification_title(alert_group, critical)
    alert_subtitle = get_push_notification_subtitle(alert_group)

    mobile_app_user_settings, _ = MobileAppUserSettings.objects.get_or_create(user=user)

    # critical defines the type of notification
    message_type = MessageType.IMPORTANT if critical else MessageType.DEFAULT
    notification_sound = get_notification_sound(mobile_app_user_settings, message_type)

    fcm_message_data: FCMMessageData = {
        "title": alert_title,
        "subtitle": alert_subtitle,
        "orgId": alert_group.channel.organization.public_primary_key,
        "orgName": alert_group.channel.organization.stack_slug,
        "alertGroupId": alert_group.public_primary_key,
        # alert_group.status is an int so it must be casted...
        "status": str(alert_group.status),
        # Pass user settings, so the Android app can use them to play the correct sound and volume
        **notification_sound.data,
    }

    number_of_alerts = alert_group.alerts.count()
    apns_payload = APNSPayload(
        aps=Aps(
            thread_id=thread_id,
            badge=number_of_alerts,
            alert=ApsAlert(title=alert_title, body=alert_subtitle),
            sound=notification_sound.apns_sound,
            custom_data=notification_sound.apns_custom_data,
        ),
    )

    return construct_fcm_message(message_type, thread_id, fcm_message_data, apns_payload)


@shared_dedicated_queue_retry_task(autoretry_for=(Exception,), retry_backoff=True, max_retries=MAX_RETRIES)
def notify_user_about_new_alert_group(user_pk, alert_group_pk, notification_policy_pk, critical):
    # avoid circular import
    from apps.base.models import UserNotificationPolicy, UserNotificationPolicyLogRecord
    from apps.mobile_app.models import FCMDevice

    try:
        user = User.objects.get(pk=user_pk)
    except User.DoesNotExist:
        logger.warning(f"User {user_pk} does not exist")
        return

    try:
        alert_group = AlertGroup.objects.get(pk=alert_group_pk)
    except AlertGroup.DoesNotExist:
        logger.warning(f"Alert group {alert_group_pk} does not exist")
        return

    try:
        notification_policy = UserNotificationPolicy.objects.get(pk=notification_policy_pk)
    except UserNotificationPolicy.DoesNotExist:
        logger.warning(f"User notification policy {notification_policy_pk} does not exist")
        return

    def _create_error_log_record(notification_error_code=None):
        """
        Utility method to create a UserNotificationPolicyLogRecord with error
        """
        UserNotificationPolicyLogRecord.objects.create(
            author=user,
            type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_FAILED,
            notification_policy=notification_policy,
            alert_group=alert_group,
            reason="Mobile push notification error",
            notification_step=notification_policy.step,
            notification_channel=notification_policy.notify_by,
            notification_error_code=notification_error_code,
        )

    devices_to_notify = FCMDevice.get_devices_to_notify(user, notification_policy.notify_device_id)

    # create an error log in case user has no devices set up
    if not devices_to_notify:
        _create_error_log_record(UserNotificationPolicyLogRecord.ERROR_NOTIFICATION_MOBILE_USER_HAS_NO_ACTIVE_DEVICE)
        logger.error(f"Error while sending a mobile push notification: user {user_pk} has no device set up")
        return

    message = _get_fcm_message(alert_group, user, critical)
    succeeded = send_push_notification(user, devices_to_notify, message, alert_group=alert_group)

    if succeeded:
        UserNotificationPolicyLogRecord.objects.create(
            author=user,
            type=UserNotificationPolicyLogRecord.TYPE_PERSONAL_NOTIFICATION_SUCCESS,
            notification_policy=notification_policy,
            alert_group=alert_group,
            notification_step=notification_policy.step,
            notification_channel=notification_policy.notify_by,
        )
    else:
        _create_error_log_record()
