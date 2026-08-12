from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from apps.api.permissions import RBACPermission
from apps.api.serializers.mobile_devices import MobileDeviceSerializer
from apps.auth_token.auth import PluginAuthentication
from apps.mobile_app.models import FCMDevice


class MobileDeviceViewSet(
    mixins.ListModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Manage the logged-in user's devices through the IRM desktop API."""

    authentication_classes = (PluginAuthentication,)
    permission_classes = (IsAuthenticated, RBACPermission)
    rbac_permissions = {
        "list": [RBACPermission.Permissions.USER_SETTINGS_READ],
        "destroy": [RBACPermission.Permissions.USER_SETTINGS_READ],
    }
    serializer_class = MobileDeviceSerializer
    lookup_url_kwarg = "device_id"

    def get_queryset(self):
        return FCMDevice.active_objects.filter(user=self.request.user).select_related("user").order_by("-date_created")
