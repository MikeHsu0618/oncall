import gzip
import json
import logging
from dataclasses import asdict, is_dataclass
from hmac import compare_digest

from django.conf import settings
from django.db import transaction
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.auth_token.auth import BasePluginAuthentication
from apps.auth_token.models import PluginAuthToken
from apps.grafana_plugin.serializers.sync_data import SyncDataSerializer
from apps.user_management.models import Organization
from apps.user_management.sync import apply_sync_data, get_or_create_organization
from common.api_helpers.errors import INVALID_SELF_HOSTED_ID

logger = logging.getLogger(__name__)


class SyncException(Exception):
    def __init__(self, error_data):
        self.error_data = error_data


class SyncV2View(APIView):
    authentication_classes = (BasePluginAuthentication,)

    def do_sync(self, request: Request) -> Organization:
        if request.headers.get("Content-Encoding") == "gzip":
            gzip_data = gzip.GzipFile(fileobj=request).read()
            decoded_data = gzip_data.decode("utf-8")
            data = json.loads(decoded_data)
        else:
            data = request.data

        serializer = SyncDataSerializer(data=data)
        if not serializer.is_valid():
            raise SyncException(serializer.errors)

        sync_data = serializer.save()

        if settings.LICENSE == settings.OPEN_SOURCE_LICENSE_NAME:
            if self.authentication_classes:
                return self._sync_authenticated_oss(request.auth, sync_data)
            stack_id = settings.SELF_HOSTED_SETTINGS["STACK_ID"]
            org_id = settings.SELF_HOSTED_SETTINGS["ORG_ID"]
        else:
            org_id = request.auth.organization.org_id
            stack_id = request.auth.organization.stack_id

        if sync_data.settings.org_id != org_id or sync_data.settings.stack_id != stack_id:
            raise SyncException(INVALID_SELF_HOSTED_ID)

        organization = get_or_create_organization(sync_data.settings.org_id, sync_data.settings.stack_id, sync_data)
        apply_sync_data(organization, sync_data)
        return organization

    @transaction.atomic
    def _sync_authenticated_oss(self, authenticated, sync_data) -> Organization:
        # The original authenticated token selects an existing organization.
        # The unauthenticated install subclass retains the global OSS tuple.
        if not isinstance(authenticated, PluginAuthToken):
            raise SyncException(INVALID_SELF_HOSTED_ID)
        token = PluginAuthToken.objects.select_for_update().filter(pk=authenticated.pk).first()
        if token is None or (token.digest, token.salt, token.organization_id) != (
            authenticated.digest, authenticated.salt, authenticated.organization_id
        ):
            raise SyncException(INVALID_SELF_HOSTED_ID)
        organization = Organization.objects.select_for_update().filter(pk=token.organization_id).first()
        if organization is None or organization.is_moved:
            raise SyncException(INVALID_SELF_HOSTED_ID)
        selected = sync_data.settings
        if (
            (selected.stack_id, selected.org_id) != (organization.stack_id, organization.org_id)
            or selected.grafana_url != organization.grafana_url.rstrip("/")
            or not compare_digest(selected.grafana_token.encode(), organization.api_token.encode())
        ):
            raise SyncException(INVALID_SELF_HOSTED_ID)
        apply_sync_data(organization, sync_data)
        return organization

    def post(self, request: Request) -> Response:
        try:
            self.do_sync(request)
        except SyncException as e:
            return Response(
                data=asdict(e.error_data) if is_dataclass(e.error_data) else e.error_data,
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(status=status.HTTP_200_OK)
