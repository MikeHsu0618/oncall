from rest_framework import serializers

from apps.api.serializers.user import FastUserSerializer
from apps.mobile_app.models import FCMDevice


class MobileDeviceSerializer(serializers.ModelSerializer):
    """IRM desktop projection of an OnCall FCM device.

    Deliberately omits the FCM registration ID because it is a delivery secret,
    not display data.
    """

    user = FastUserSerializer(read_only=True)
    device_name = serializers.CharField(source="name", read_only=True)
    device_platform = serializers.CharField(source="type", read_only=True, allow_null=True)
    created_at = serializers.DateTimeField(source="date_created", read_only=True)

    class Meta:
        model = FCMDevice
        fields = ("id", "user", "device_name", "device_platform", "created_at")
        read_only_fields = fields
