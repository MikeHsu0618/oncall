import logging

import requests
from drf_spectacular.utils import extend_schema, inline_serializer
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from apps.api.permissions import RBACPermission
from apps.api.serializers.labels import (
    LabelKeySerializer,
    LabelOptionSerializer,
    LabelReprSerializer,
    LabelsDropdownContextSerializer,
    LabelValueSerializer,
)
from apps.auth_token.auth import PluginAuthentication
from apps.labels.client import LabelsAPIClient, LabelsRepoAPIException
from apps.labels.tasks import update_instances_labels_cache, update_label_option_cache
from apps.labels.types import LabelOption
from apps.labels.utils import is_labels_feature_enabled
from common.api_helpers.exceptions import BadRequest

logger = logging.getLogger(__name__)


class LabelsFeatureFlagViewSet(ViewSet):
    def initial(self, request, *args, **kwargs):
        if not is_labels_feature_enabled(self.request.auth.organization):
            raise NotFound
        super().initial(request, *args, **kwargs)


class LabelsViewSet(LabelsFeatureFlagViewSet):
    """
    Proxy requests to labels-app to create/update labels
    """

    permission_classes = (IsAuthenticated, RBACPermission)
    authentication_classes = (PluginAuthentication,)
    rbac_permissions = {
        "create_label": [RBACPermission.Permissions.LABEL_CREATE],
        "rename_key": [RBACPermission.Permissions.LABEL_WRITE],
        "add_value": [RBACPermission.Permissions.LABEL_WRITE],
        "rename_value": [RBACPermission.Permissions.LABEL_WRITE],
        "get_keys": [RBACPermission.Permissions.LABEL_READ],
        "get_key": [RBACPermission.Permissions.LABEL_READ],
        "get_key_by_name": [RBACPermission.Permissions.LABEL_READ],
        "get_value": [RBACPermission.Permissions.LABEL_READ],
        "dropdown_context": [RBACPermission.Permissions.LABEL_READ],
        "add_value_by_key_name": [RBACPermission.Permissions.LABEL_WRITE],
    }

    @extend_schema(responses=LabelKeySerializer(many=True))
    def get_keys(self, request):
        """List of labels keys"""
        organization = self.request.auth.organization
        keys, response = LabelsAPIClient(organization.grafana_url, organization.api_token).get_keys()
        return Response(keys, status=response.status_code)

    @extend_schema(responses=LabelOptionSerializer)
    def get_key(self, request, key_id):
        """
        get_key returns LabelOption – key with the list of values
        """
        organization = self.request.auth.organization
        label_option, response = LabelsAPIClient(organization.grafana_url, organization.api_token).get_label_by_key_id(
            key_id
        )
        self._update_labels_cache(label_option)
        return Response(label_option, status=response.status_code)

    @extend_schema(responses=LabelOptionSerializer)
    def get_key_by_name(self, request, key_name):
        """
        get_key_by_name returns LabelOption – key with the list of values
        """
        organization = self.request.auth.organization
        label_option, response = LabelsAPIClient(
            organization.grafana_url,
            organization.api_token,
        ).get_label_by_key_name(key_name)
        return Response(label_option, status=response.status_code)

    @extend_schema(responses=LabelValueSerializer)
    def get_value(self, request, key_id, value_id):
        """get_value returns a Value"""
        organization = self.request.auth.organization
        value, response = LabelsAPIClient(organization.grafana_url, organization.api_token).get_value(key_id, value_id)
        # TODO: update_labels_cache expects LabelOption, but get value returns a Value. Investigate, temporary disable.
        # self._update_labels_cache(value)
        return Response(value, status=response.status_code)

    @extend_schema(responses=LabelsDropdownContextSerializer)
    def dropdown_context(self, request):
        """Return the label options needed by the IRM labels dropdown."""
        organization = self.request.auth.organization
        client = LabelsAPIClient(organization.grafana_url, organization.api_token)
        keys, response = client.get_keys()
        if response.status_code != 200:
            return Response({"label_options": [], "archived": []}, status=response.status_code)

        label_options = []
        for key in keys or []:
            label_option, option_response = client.get_label_by_key_id(key["id"])
            if option_response.status_code == 200 and label_option:
                label_options.append(label_option)
        return Response({"label_options": label_options, "archived": []})

    @extend_schema(request=LabelReprSerializer, responses=LabelOptionSerializer)
    def add_value_by_key_name(self, request, key_name):
        """Create a label value after resolving the stable key name to its ID."""
        organization = self.request.auth.organization
        serializer = LabelReprSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        label_data = serializer.validated_data
        client = LabelsAPIClient(organization.grafana_url, organization.api_token)
        label_option, _ = client.get_label_by_key_name(key_name)
        if not label_option or not label_option.get("key", {}).get("id"):
            raise NotFound
        result, response = client.add_value(label_option["key"]["id"], label_data)
        self._update_labels_cache(result)
        return Response(result, status=response.status_code)

    @extend_schema(request=LabelReprSerializer, responses=LabelOptionSerializer)
    def rename_key(self, request, key_id):
        """Rename the key"""
        organization = self.request.auth.organization
        label_data = self.request.data
        if not label_data:
            raise BadRequest(detail="name is required")
        label_option, response = LabelsAPIClient(organization.grafana_url, organization.api_token).rename_key(
            key_id, label_data
        )
        self._update_labels_cache(label_option)
        return Response(label_option, status=response.status_code)

    @extend_schema(
        request=inline_serializer(
            name="LabelCreateSerializer",
            fields={"key": LabelReprSerializer(), "values": LabelReprSerializer(many=True)},
            many=True,
        ),
        responses={201: LabelOptionSerializer},
    )
    def create_label(self, request):
        """Create a new label key with values(Optional)"""
        organization = self.request.auth.organization
        label_data = self.request.data
        if not label_data:
            raise BadRequest(detail="key data (name, values) is required")
        label_option, response = LabelsAPIClient(organization.grafana_url, organization.api_token).create_label(
            label_data
        )
        return Response(label_option, status=response.status_code)

    @extend_schema(request=LabelReprSerializer, responses=LabelOptionSerializer)
    def add_value(self, request, key_id):
        """Add a new value to the key"""
        organization = self.request.auth.organization
        label_data = self.request.data
        if not label_data:
            raise BadRequest(detail="name is required")
        label_option, response = LabelsAPIClient(organization.grafana_url, organization.api_token).add_value(
            key_id, label_data
        )
        return Response(label_option, status=response.status_code)

    @extend_schema(request=LabelReprSerializer, responses=LabelOptionSerializer)
    def rename_value(self, request, key_id, value_id):
        """Rename the value"""
        organization = self.request.auth.organization
        label_data = self.request.data
        if not label_data:
            raise BadRequest(detail="name is required")
        label_option, response = LabelsAPIClient(organization.grafana_url, organization.api_token).rename_value(
            key_id, value_id, label_data
        )
        status = response.status_code
        self._update_labels_cache(label_option)
        return Response(label_option, status=status)

    def _update_labels_cache(self, label_option: LabelOption):
        if not label_option:
            return
        serializer = LabelOptionSerializer(data=label_option)
        if serializer.is_valid():
            update_label_option_cache.apply_async((label_option,))
            # update_labels_cache.apply_async((label_data,))

    def handle_exception(self, exc):
        if isinstance(exc, LabelsRepoAPIException):
            logging.error(f'msg="LabelsViewSet: LabelRepo error: {exc}"')
            return Response({"message": exc.msg}, status=exc.status)
        elif isinstance(exc, requests.RequestException):
            logging.error(f'msg="LabelsViewSet: error while requesting LabelRepo: {exc}"')
            return Response({"message": "Something went wrong"}, status=500)
        else:
            return super().handle_exception(exc)


# specifying a tag explicitly to avoid these endpoints being grouped with alert group endpoints
@extend_schema(tags=["alert group labels"])
class AlertGroupLabelsViewSet(LabelsFeatureFlagViewSet):
    """
    This viewset is similar to LabelsViewSet, but it works with alert group labels.
    Alert group labels are stored in the database, not in the label repo.
    """

    permission_classes = (IsAuthenticated, RBACPermission)
    authentication_classes = (PluginAuthentication,)
    rbac_permissions = {
        "get_keys": [RBACPermission.Permissions.ALERT_GROUPS_READ],
        "get_key": [RBACPermission.Permissions.ALERT_GROUPS_READ],
        "get_key_by_name": [RBACPermission.Permissions.ALERT_GROUPS_READ],
    }

    @extend_schema(responses=LabelKeySerializer(many=True))
    def get_keys(self, request):
        """
        List of alert group label keys.
        IDs are the same as names to keep the response format consistent with LabelsViewSet.get_keys().
        """
        names = self.request.auth.organization.alert_group_labels.values_list("key_name", flat=True).distinct()
        return Response([{"id": name, "name": name} for name in names])

    @extend_schema(responses=LabelOptionSerializer)
    def get_key(self, request, key_id):
        """Key with the list of values. IDs and names are interchangeable (see get_keys() for more details)."""
        values = (
            self.request.auth.organization.alert_group_labels.filter(key_name=key_id)
            .values_list("value_name", flat=True)
            .distinct()
        )
        return Response(
            {"key": {"id": key_id, "name": key_id}, "values": [{"id": value, "name": value} for value in values]}
        )

    @extend_schema(responses=LabelOptionSerializer)
    def get_key_by_name(self, request, key_name):
        return self.get_key(request, key_name)


def schedule_update_label_cache(model_name, org, ids):
    if not is_labels_feature_enabled(org):
        return
    logger.info(f"start update_instances_labels_cache for ids: {ids}")
    update_instances_labels_cache.apply_async((org.id, ids, model_name))
