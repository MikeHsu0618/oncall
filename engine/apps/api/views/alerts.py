from rest_framework import mixins, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.alerts.models import Alert
from apps.api.permissions import RBACPermission
from apps.api.serializers.alert import AlertRawSerializer, AlertSerializer
from apps.auth_token.auth import PluginAuthentication
from common.api_helpers.mixins import TeamFilteringMixin
from common.api_helpers.paginators import FiftyPageSizePaginator


class AlertView(TeamFilteringMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    """IRM-compatible list of alerts belonging to visible alert groups."""

    TEAM_LOOKUP = "group__channel__team"
    authentication_classes = (PluginAuthentication,)
    permission_classes = (IsAuthenticated, RBACPermission)
    rbac_permissions = {"list": [RBACPermission.Permissions.ALERT_GROUPS_READ]}
    serializer_class = AlertSerializer
    pagination_class = FiftyPageSizePaginator

    def get_queryset(self):
        queryset = Alert.objects.filter(group__channel__organization=self.request.auth.organization)
        queryset = queryset.filter(*self.available_teams_lookup_args).distinct()
        alert_group_id = self.request.query_params.get("alert_group_id")
        if alert_group_id:
            queryset = queryset.filter(group__public_primary_key=alert_group_id)
        return queryset.select_related("group", "group__channel").order_by("-id")


class AlertDetailView(TeamFilteringMixin, APIView):
    TEAM_LOOKUP = "group__channel__team"
    authentication_classes = [PluginAuthentication]
    permission_classes = [IsAuthenticated, RBACPermission]
    rbac_permissions = {"get": [RBACPermission.Permissions.ALERT_GROUPS_READ]}

    def get(self, request, id):
        try:
            alert = (
                Alert.objects.filter(
                    public_primary_key=id,
                    group__channel__organization=request.auth.organization,
                )
                .filter(*self.available_teams_lookup_args)
                .select_related("group", "group__channel")
                .distinct()
                .get()
            )
        except Alert.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = AlertRawSerializer(alert)
        return Response(serializer.data)
