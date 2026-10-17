from datetime import timedelta

from rest_framework import serializers

from apps.base.models import UserNotificationPolicy
from apps.base.models.user_notification_policy import NotificationChannelAPIOptions
from apps.mobile_app.models import FCMDevice
from apps.user_management.models import User
from common.api_helpers.custom_fields import DurationSecondsField, OrganizationFilteredPrimaryKeyRelatedField
from common.api_helpers.exceptions import Forbidden
from common.api_helpers.mixins import EagerLoadingMixin


# This serializer should not be user directly
class UserNotificationPolicyBaseSerializer(EagerLoadingMixin, serializers.ModelSerializer):
    id = serializers.CharField(read_only=True, source="public_primary_key")
    notify_by = serializers.ChoiceField(
        read_only=False,
        required=False,
        default=UserNotificationPolicy.NotificationChannel.SLACK,
        choices=NotificationChannelAPIOptions.AVAILABLE_FOR_USE,
    )
    step = serializers.ChoiceField(
        read_only=False,
        required=False,
        default=UserNotificationPolicy.Step.NOTIFY,
        choices=UserNotificationPolicy.Step.choices,
    )
    wait_delay = DurationSecondsField(
        required=False,
        allow_null=True,
        min_value=timedelta(minutes=1),
        max_value=timedelta(hours=24),
    )
    # Written by the mobile app on mobile push steps: an FCMDevice id (as listed by mobile_app/devices), or null for
    # all devices.
    notify_device = serializers.IntegerField(source="notify_device_id", required=False, allow_null=True)

    SELECT_RELATED = [
        "user",
    ]

    class Meta:
        model = UserNotificationPolicy
        fields = ["id", "step", "notify_by", "wait_delay", "important", "user", "notify_device"]

        # Field "order" is not consumed by the plugin frontend, but is used by the mobile app
        # TODO: remove this field when the mobile app is updated
        fields += ["order"]
        read_only_fields = ["order"]

    def to_internal_value(self, data):
        data = self._notify_by_to_internal_value(data)
        return super().to_internal_value(data)

    def _get_policy_user(self, attrs) -> User:
        raise NotImplementedError

    def validate(self, attrs):
        attrs = super().validate(attrs)
        notify_device_id = attrs.get("notify_device_id")
        # A stored device that has since been deactivated is echoed back unchanged by clients that send the whole
        # step; keep accepting it (delivery already falls back to all active devices) so the step stays editable.
        is_unchanged = self.instance is not None and self.instance.notify_device_id == notify_device_id
        if notify_device_id is not None and not is_unchanged:
            # Only an active device of the policy's owner (not necessarily the requesting user, admins can edit
            # other users' policies). Unknown ids and other users' devices get the same error.
            policy_user = self._get_policy_user(attrs)
            if not FCMDevice.active_objects.filter(pk=notify_device_id, user=policy_user).exists():
                raise serializers.ValidationError({"notify_device": "Must be one of the user's active devices."})
        return attrs

    def to_representation(self, instance):
        result = super().to_representation(instance)
        result = self._notify_by_to_representation(instance, result)
        return result

    #  _notify_by_to_internal_value and _notify_by_to_representation are exists because of in EscalationPolicy model
    #  notify_by field has default value NotificationChannel.SLACK and not nullable
    #  We don't want any notify_by value in response if step != Step.NOTIFY
    def _notify_by_to_internal_value(self, data):
        if not data.get("notify_by", None):
            data["notify_by"] = UserNotificationPolicy.NotificationChannel.SLACK
        return data

    def _notify_by_to_representation(self, instance, result):
        if instance.step != UserNotificationPolicy.Step.NOTIFY:
            result["notify_by"] = None
        return result


class UserNotificationPolicySerializer(UserNotificationPolicyBaseSerializer):
    user = OrganizationFilteredPrimaryKeyRelatedField(
        queryset=User.objects,
        required=False,
        allow_null=True,
        many=False,
        display_func=lambda instance: instance.username,
    )
    notify_by = serializers.ChoiceField(
        choices=NotificationChannelAPIOptions.AVAILABLE_FOR_USE,
        default=NotificationChannelAPIOptions.DEFAULT_NOTIFICATION_CHANNEL,
    )

    def _get_policy_user(self, attrs) -> User:
        return attrs.get("user") or self.context["request"].user

    def create(self, validated_data):
        user = validated_data.get("user") or self.context["request"].user

        if not user.self_or_has_user_settings_admin_permission(
            user_to_check=self.context["request"].user, organization=self.context["request"].auth.organization
        ):
            raise Forbidden()
        return UserNotificationPolicy.objects.create(**validated_data)


class UserNotificationPolicyUpdateSerializer(UserNotificationPolicyBaseSerializer):
    user = OrganizationFilteredPrimaryKeyRelatedField(
        many=False,
        read_only=True,
        display_func=lambda instance: instance.username,
    )

    class Meta(UserNotificationPolicyBaseSerializer.Meta):
        read_only_fields = UserNotificationPolicyBaseSerializer.Meta.read_only_fields + ["user", "important"]

    def _get_policy_user(self, attrs) -> User:
        return self.instance.user

    def update(self, instance, validated_data):
        if not instance.user.self_or_has_user_settings_admin_permission(
            user_to_check=self.context["request"].user, organization=self.context["request"].user.organization
        ):
            raise Forbidden()
        if validated_data.get("step") == UserNotificationPolicy.Step.WAIT and not validated_data.get("wait_delay"):
            validated_data["wait_delay"] = UserNotificationPolicy.FIVE_MINUTES
        return super().update(instance, validated_data)
