from django.urls import re_path

from apps.mobile_app.web_session.views import WebSessionJWKSView, WebSessionView
from apps.mobile_app.fcm_relay import FCMRelayView
from apps.mobile_app.local_incident.views import incident_gateway_selector
from apps.mobile_app.views import (
    FCMDeviceAuthorizedViewSet,
    MobileAppAuthTokenAPIView,
    MobileAppGatewayView,
    MobileAppLogoutAPIView,
    MobileAppNotificationHistoryAPIView,
    MobileAppUserSettingsViewSet,
)
from common.api_helpers.optional_slash_router import OptionalSlashRouter, optional_slash_path

app_name = "mobile_app"
router = OptionalSlashRouter()

router.register("fcm", FCMDeviceAuthorizedViewSet, basename="fcm")

urlpatterns = [
    optional_slash_path("web_session", WebSessionView.as_view(), name="web_session"),
    optional_slash_path("web_session/jwks", WebSessionJWKSView.as_view(), name="web_session_jwks"),
    *router.urls,
    optional_slash_path("auth_token", MobileAppAuthTokenAPIView.as_view(), name="auth_token"),
    optional_slash_path("logout", MobileAppLogoutAPIView.as_view(), name="logout"),
    optional_slash_path(
        "notification_history", MobileAppNotificationHistoryAPIView.as_view(), name="notification_history"
    ),
    optional_slash_path(
        "user_settings/notification_timing_options",
        MobileAppUserSettingsViewSet.as_view({"get": "notification_timing_options"}),
        name="notification_timing_options",
    ),
    optional_slash_path(
        "user_settings",
        MobileAppUserSettingsViewSet.as_view({"get": "retrieve", "put": "update", "patch": "partial_update"}),
        name="user_settings",
    ),
]

urlpatterns += [
    optional_slash_path("fcm_relay", FCMRelayView.as_view(), name="fcm_relay"),
]

urlpatterns += [
    # Must precede the generic gateway route: selects local vs legacy per request.
    re_path(
        r"^gateway/incident/(?P<downstream_path>.*)$",
        incident_gateway_selector,
        name="incident_gateway",
    ),
    re_path(
        r"^gateway/(?P<downstream_backend>\w*)/(?P<downstream_path>.*)$",
        MobileAppGatewayView.as_view(),
        name="gateway",
    ),
]
