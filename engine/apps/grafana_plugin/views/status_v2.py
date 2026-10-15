import logging

from django.conf import settings
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.auth_token.auth import BasePluginAuthentication
from apps.grafana_plugin.helpers import GrafanaAPIClient
from apps.mobile_app.web_session.config import public_status
from apps.mobile_app.auth import MobileAppAuthTokenAuthentication
from apps.mobile_app.models import MobileAppAuthToken
from common.api_helpers.mixins import GrafanaHeadersMixin
from common.api_helpers.utils import create_engine_url

logger = logging.getLogger(__name__)


def _reported_license(request: Request) -> str:
    # Only mobile-app-token callers see the optional override; plugin callers always
    # receive the engine license so install/sync behaviour is unaffected.
    if isinstance(request.auth, MobileAppAuthToken) and settings.MOBILE_APP_STATUS_LICENSE:
        return settings.MOBILE_APP_STATUS_LICENSE
    return settings.LICENSE


class StatusV2View(GrafanaHeadersMixin, APIView):
    authentication_classes = (
        MobileAppAuthTokenAuthentication,
        BasePluginAuthentication,
    )

    def get(self, request: Request) -> Response:
        # Check if the plugin is currently undergoing maintenance, and return response without querying db
        if settings.CURRENTLY_UNDERGOING_MAINTENANCE_MESSAGE:
            return Response(
                data={
                    "currently_undergoing_maintenance_message": settings.CURRENTLY_UNDERGOING_MAINTENANCE_MESSAGE,
                }
            )

        organization = request.auth.organization
        api_url = create_engine_url("")

        # If /status is called frequently this can be skipped with a cache
        grafana_api_client = GrafanaAPIClient(api_url=organization.grafana_url, api_token=organization.api_token)
        _, call_status = grafana_api_client.check_token()
        call_status = public_status(organization.pk, call_status)

        return Response(
            data={
                "connection_to_grafana": {
                    "url": call_status["url"],
                    "connected": call_status["connected"],
                    "status_code": call_status["status_code"],
                    "message": call_status["message"],
                },
                "license": _reported_license(request),
                "version": settings.VERSION,
                "currently_undergoing_maintenance_message": settings.CURRENTLY_UNDERGOING_MAINTENANCE_MESSAGE,
                "api_url": api_url,
            }
        )
