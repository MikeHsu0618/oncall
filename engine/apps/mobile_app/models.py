from __future__ import annotations  # https://stackoverflow.com/a/33533514

import typing

from django.core import validators
from django.db import models
from django.db.models import JSONField
from django.utils import timezone
from fcm_django.models import FCMDevice as BaseFCMDevice

from apps.auth_token import constants, crypto
from apps.auth_token.models import BaseAuthToken
from apps.mobile_app.types import MessageType, Platform

if typing.TYPE_CHECKING:
    from firebase_admin.messaging import Message

    from apps.alerts.models import AlertGroup
    from apps.user_management.models import Organization, User

MOBILE_APP_AUTH_VERIFICATION_TOKEN_TIMEOUT_SECONDS = 60 * 5  # 5 minutes


def get_expire_date():
    return timezone.now() + timezone.timedelta(seconds=MOBILE_APP_AUTH_VERIFICATION_TOKEN_TIMEOUT_SECONDS)


def default_notification_timing_options():
    return [MobileAppUserSettings.FIFTEEN_MINUTES_IN_SECONDS]


class ActiveFCMDeviceQuerySet(models.QuerySet):
    def filter(self, *args, **kwargs):
        return super().filter(*args, **kwargs, active=True)


class FCMDevice(BaseFCMDevice):
    active_objects = ActiveFCMDeviceQuerySet.as_manager()

    class Meta:
        # don't create a table for this model..
        # https://docs.djangoproject.com/en/dev/topics/db/models/#differences-between-proxy-inheritance-and-unmanaged-models
        proxy = True

    @classmethod
    def get_devices_to_notify(cls, user: "User", notify_device_id: int | None = None) -> list[FCMDevice]:
        """
        Devices a push for `user` is delivered to: the chosen device (a notification policy step's `notify_device`)
        while it is still one of the user's active devices, otherwise all of the user's active devices.
        """
        active_devices = list(cls.active_objects.filter(user=user).order_by("id"))
        if notify_device_id is not None:
            chosen_devices = [device for device in active_devices if device.pk == notify_device_id]
            if chosen_devices:
                return chosen_devices
        return active_devices


class MobileAppVerificationTokenQueryset(models.QuerySet):
    def filter(self, *args, **kwargs):
        now = timezone.now()
        return super().filter(*args, **kwargs, revoked_at=None, expire_date__gte=now)

    def delete(self):
        self.update(revoked_at=timezone.now())


class MobileAppVerificationToken(BaseAuthToken):
    objects = MobileAppVerificationTokenQueryset.as_manager()
    user = models.ForeignKey(
        "user_management.User",
        related_name="mobile_app_verification_token_set",
        on_delete=models.CASCADE,
    )
    organization = models.ForeignKey(
        "user_management.Organization", related_name="mobile_app_verification_token_set", on_delete=models.CASCADE
    )
    expire_date = models.DateTimeField(default=get_expire_date)

    @classmethod
    def create_auth_token(
        cls, user: "User", organization: "Organization"
    ) -> typing.Tuple["MobileAppVerificationToken", str]:
        token_string = crypto.generate_short_token_string()
        digest = crypto.hash_token_string(token_string)

        instance = cls.objects.create(
            token_key=token_string[: constants.TOKEN_KEY_LENGTH],
            digest=digest,
            user=user,
            organization=organization,
        )
        return instance, token_string


class MobileAppAuthToken(BaseAuthToken):
    objects: models.Manager["MobileAppAuthToken"]

    user = models.OneToOneField(to="user_management.User", null=False, blank=False, on_delete=models.CASCADE)
    organization = models.ForeignKey(
        to="user_management.Organization",
        null=False,
        blank=False,
        related_name="mobile_app_auth_tokens",
        on_delete=models.CASCADE,
    )

    @classmethod
    def create_auth_token(cls, user: "User", organization: "Organization") -> typing.Tuple["MobileAppAuthToken", str]:
        token_string = crypto.generate_token_string()
        digest = crypto.hash_token_string(token_string)

        instance = cls.objects.create(
            token_key=token_string[: constants.TOKEN_KEY_LENGTH],
            digest=digest,
            user=user,
            organization=organization,
        )
        return instance, token_string


class MobileAppUserSettings(models.Model):
    # Sound names are stored without extension, extension is added when sending push notifications
    IOS_SOUND_NAME_EXTENSION = ".aiff"
    ANDROID_SOUND_NAME_EXTENSION = ".mp3"

    class VolumeType(models.TextChoices):
        CONSTANT = "constant"
        INTENSIFYING = "intensifying"

    user = models.OneToOneField(to="user_management.User", null=False, on_delete=models.CASCADE)

    # Push notification settings for default notifications
    default_notification_sound_name = models.CharField(max_length=100, default="default_sound")
    default_notification_volume_type = models.CharField(
        max_length=50, choices=VolumeType.choices, default=VolumeType.CONSTANT
    )

    # APNS only allows to specify volume for critical notifications,
    # so "default_notification_volume" and "default_notification_volume_override" are only used on Android
    default_notification_volume = models.FloatField(
        validators=[validators.MinValueValidator(0.0), validators.MaxValueValidator(1.0)], default=0.8
    )
    default_notification_volume_override = models.BooleanField(default=False)

    # Push notification settings for important notifications
    important_notification_sound_name = models.CharField(max_length=100, default="default_sound_important")
    important_notification_volume_type = models.CharField(
        max_length=50, choices=VolumeType.choices, default=VolumeType.CONSTANT
    )
    important_notification_volume = models.FloatField(
        validators=[validators.MinValueValidator(0.0), validators.MaxValueValidator(1.0)], default=0.8
    )
    important_notification_volume_override = models.BooleanField(default=True, null=True)

    # For the "Mobile push important" step it's possible to make notifications non-critical
    # if "override DND" setting is disabled in the app
    important_notification_override_dnd = models.BooleanField(default=True)

    # Push notification settings for info notifications
    # this is used for non escalation related push notifications such as the
    # "You're going OnCall soon" and "You have a new shift swap request" push notifications
    info_notifications_enabled = models.BooleanField(default=False)

    info_notification_sound_name = models.CharField(max_length=100, default="default_sound", null=True)
    info_notification_volume_type = models.CharField(
        max_length=50, choices=VolumeType.choices, default=VolumeType.CONSTANT, null=True
    )

    # APNS only allows to specify volume for critical notifications,
    # so "info_notification_volume" and "info_notification_volume_override" are only used on Android
    info_notification_volume = models.FloatField(
        validators=[validators.MinValueValidator(0.0), validators.MaxValueValidator(1.0)], default=0.8, null=True
    )
    info_notification_volume_override = models.BooleanField(default=False, null=True)

    # Per-type "Override DND" switches the mobile app sends for default and info pushes. The app parses a
    # missing value as false, so false is the default here as well (non-critical pushes respect DND).
    default_notification_override_dnd = models.BooleanField(default=False)
    info_notification_override_dnd = models.BooleanField(default=False)

    # "Incident notifications" switch (status updates in incidents where the user is a participant).
    # Defaults to false, matching the mobile app's own fallback when the field is absent.
    incident_notifications_enabled = models.BooleanField(default=False)

    # these choices + the below column are used to calculate when to send the "You're Going OnCall soon"
    # push notification
    FIFTEEN_MINUTES_IN_SECONDS = 15 * 60
    ONE_HOUR_IN_SECONDS = 60 * 60
    SIX_HOURS_IN_SECONDS = 6 * 60 * 60
    TWELVE_HOURS_IN_SECONDS = 12 * 60 * 60
    ONE_DAY_IN_SECONDS = TWELVE_HOURS_IN_SECONDS * 2

    NOTIFICATION_TIMING_CHOICES = (
        (FIFTEEN_MINUTES_IN_SECONDS, "15 minutes before"),
        (ONE_HOUR_IN_SECONDS, "1 hour before"),
        (SIX_HOURS_IN_SECONDS, "6 hours before"),
        (TWELVE_HOURS_IN_SECONDS, "12 hours before"),
        (ONE_DAY_IN_SECONDS, "1 day before"),
    )
    ALL_NOTIFICATION_TIMING_CHOICES_SECONDS = [choice[0] for choice in NOTIFICATION_TIMING_CHOICES]

    going_oncall_notification_timing = JSONField(default=default_notification_timing_options)

    locale = models.CharField(max_length=50, null=True)
    time_zone = models.CharField(max_length=100, default="UTC")

    def get_notification_sound_name(self, message_type: MessageType, platform: Platform) -> str:
        sound_name = {
            MessageType.DEFAULT: self.default_notification_sound_name,
            MessageType.IMPORTANT: self.important_notification_sound_name,
            MessageType.INFO: self.info_notification_sound_name,
        }[message_type]

        # If sound name already contains an extension, return it as is
        if "." in sound_name:
            return sound_name

        # Add appropriate extension based on platform, for cases when no extension is specified in the sound name
        extension = {
            Platform.IOS: self.IOS_SOUND_NAME_EXTENSION,
            Platform.ANDROID: self.ANDROID_SOUND_NAME_EXTENSION,
        }[platform]

        return f"{sound_name}{extension}"


class MobileAppPushRecord(models.Model):
    """
    A mobile push that was handed off for delivery (to FCM directly, or to the FCM relay on OSS installations).

    Backs `GET mobile_app/notification_history`, read by the app's notification history page and its missed-push
    poller. The poller rebuilds a push from `fcm_payload` and shows it, so `fcm_payload` is exactly the FCM data
    payload that was sent, and a record is only written after a successful hand-off
    (see apps.mobile_app.utils.send_push_notification). One record is written per logical push, not per device: the
    app reads the history with a per-user token and does not identify the calling device.
    """

    # Newest records kept per user; older ones are deleted when a new push is recorded.
    MAX_RECORDS_PER_USER = 50

    user = models.ForeignKey("user_management.User", on_delete=models.CASCADE, related_name="mobile_app_push_records")
    # The device the push was targeted at, or null when it was fanned out to several devices.
    device = models.ForeignKey("mobile_app.FCMDevice", on_delete=models.SET_NULL, null=True, related_name="+")
    notification_type = models.CharField(max_length=50, choices=[(t.value, t.value) for t in MessageType])
    title = models.TextField()
    subtitle = models.TextField(default="")
    sent_at = models.DateTimeField(default=timezone.now)
    fcm_payload = JSONField()
    alert_group = models.ForeignKey(
        "alerts.AlertGroup", on_delete=models.CASCADE, null=True, related_name="mobile_app_push_records"
    )

    class Meta:
        indexes = [models.Index(fields=["user", "sent_at"], name="mobile_app_push_user_sent_idx")]

    @classmethod
    def newest_for_user(cls, user: "User") -> models.QuerySet["MobileAppPushRecord"]:
        return cls.objects.filter(user=user).order_by("-sent_at", "-id")

    @classmethod
    def record_sent_push(
        cls,
        user: "User",
        device: FCMDevice | None,
        message: "Message",
        alert_group: "AlertGroup | None" = None,
    ) -> "MobileAppPushRecord":
        data = message.data
        record = cls.objects.create(
            user=user,
            device=device,
            notification_type=data["type"],
            title=data["title"],
            subtitle=data.get("subtitle") or "",
            fcm_payload=dict(data),
            alert_group=alert_group,
        )
        stale_record_ids = list(cls.newest_for_user(user).values_list("id", flat=True)[cls.MAX_RECORDS_PER_USER :])
        if stale_record_ids:
            cls.objects.filter(id__in=stale_record_ids).delete()
        return record
