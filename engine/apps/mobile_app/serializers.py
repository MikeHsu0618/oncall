import typing

from fcm_django.api.rest_framework import FCMDeviceSerializer as BaseFCMDeviceSerializer
from rest_framework import serializers
from rest_framework.serializers import ValidationError

from apps.api.serializers.alert_group import ShortAlertGroupSerializer
from apps.mobile_app.models import MobileAppPushRecord, MobileAppUserSettings
from common.api_helpers.custom_fields import TimeZoneField


class MobileAppUserSettingsSerializer(serializers.ModelSerializer):
    time_zone = TimeZoneField(required=False, allow_null=False)
    going_oncall_notification_timing = serializers.ListField(required=False, allow_null=False)

    class Meta:
        model = MobileAppUserSettings
        fields = (
            "info_notification_sound_name",
            "info_notification_volume_type",
            "info_notification_volume",
            "info_notification_volume_override",
            "default_notification_sound_name",
            "default_notification_volume_type",
            "default_notification_volume",
            "default_notification_volume_override",
            "important_notification_sound_name",
            "important_notification_volume_type",
            "important_notification_volume",
            "important_notification_volume_override",
            "important_notification_override_dnd",
            "info_notifications_enabled",
            "default_notification_override_dnd",
            "info_notification_override_dnd",
            "incident_notifications_enabled",
            "going_oncall_notification_timing",
            "locale",
            "time_zone",
        )

    def validate_going_oncall_notification_timing(
        self, going_oncall_notification_timing: typing.Optional[typing.List[int]]
    ) -> typing.Optional[typing.List[int]]:
        if going_oncall_notification_timing is not None:
            if len(going_oncall_notification_timing) == 0:
                raise serializers.ValidationError(detail="invalid timing options")
            notification_timing_options = [opt[0] for opt in MobileAppUserSettings.NOTIFICATION_TIMING_CHOICES]
            for option in going_oncall_notification_timing:
                if option not in notification_timing_options:
                    raise serializers.ValidationError(detail="invalid timing options")
        return going_oncall_notification_timing


class FCMDeviceSerializer(BaseFCMDeviceSerializer):
    def validate(self, attrs):
        """
        Overrides `validate` method from BaseFCMDeviceSerializer to allow different users have same device
        `registration_id` (multi-stack support).
        Removed deactivating devices with the same `registration_id` during validation.
        """
        devices = None
        request_method = None
        request = self.context["request"]

        if self.initial_data.get("registration_id", None):
            request_method = "update" if self.instance else "create"
        else:
            if request.method in ["PUT", "PATCH"]:
                request_method = "update"
            elif request.method == "POST":
                request_method = "create"

        Device = self.Meta.model
        # unique together with registration_id and user
        user = request.user
        registration_id = attrs.get("registration_id")

        if request_method == "update":
            if registration_id:
                devices = Device.objects.filter(registration_id=registration_id, user=user).exclude(id=self.instance.id)
        elif request_method == "create":
            devices = Device.objects.filter(user=user, registration_id=registration_id)

        if devices:
            raise ValidationError({"registration_id": "This field must be unique per us."})
        return attrs


class NotificationHistoryAlertGroupSerializer(ShortAlertGroupSerializer):
    class Meta(ShortAlertGroupSerializer.Meta):
        fields = ShortAlertGroupSerializer.Meta.fields + ["started_at"]
        read_only_fields = fields


class MobileAppPushRecordSerializer(serializers.ModelSerializer):
    """
    One entry of the app's notification history (`NotificationHistoryLogModel` in the app).

    The app picks a type-specific tile when the matching nested object is non-null (alert_group for
    oncall.message / oncall.critical_message; shift_swap_request; schedule + schedule_event for oncall.info;
    incident_data) and falls back to a generic tile otherwise. Only alert_group is served: the app's nested shapes
    for the other objects are not verified, and a key it cannot parse would fail the whole list, so they are null.
    """

    UNSERVED_NESTED_OBJECTS = ("shift_swap_request", "schedule", "schedule_event", "incident_data")

    id = serializers.CharField(read_only=True)
    alert_group = NotificationHistoryAlertGroupSerializer(read_only=True, allow_null=True)

    class Meta:
        model = MobileAppPushRecord
        fields = ("id", "notification_type", "title", "subtitle", "sent_at", "fcm_payload", "alert_group")
        read_only_fields = fields

    def to_representation(self, instance):
        return {
            **super().to_representation(instance),
            **{field_name: None for field_name in self.UNSERVED_NESTED_OBJECTS},
        }
