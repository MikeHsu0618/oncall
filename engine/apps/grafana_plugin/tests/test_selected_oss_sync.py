from unittest.mock import patch

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.auth_token.models import PluginAuthToken
from apps.grafana_plugin.serializers.sync_data import SyncDataSerializer


def payload(organization):
    return {
        "users": [{"id": 77, "name": "Current member", "login": "current-member",
                   "email": "current@example.test", "role": "Admin", "avatar_url": "",
                   "permissions": [], "teams": []}],
        "teams": [], "team_members": {},
        "settings": {"stack_id": organization.stack_id, "org_id": organization.org_id,
                     "license": "OpenSource", "oncall_api_url": "http://oncall-engine:8080",
                     "oncall_token": "", "grafana_url": organization.grafana_url,
                     "grafana_token": organization.api_token, "rbac_enabled": False,
                     "incident_enabled": False, "incident_backend_url": "",
                     "labels_enabled": False, "irm_enabled": True},
    }


@pytest.fixture
def owners(settings, make_organization):
    settings.LICENSE = settings.OPEN_SOURCE_LICENSE_NAME
    settings.SELF_HOSTED_SETTINGS = {**settings.SELF_HOSTED_SETTINGS, "STACK_ID": 5, "ORG_ID": 100}
    primary = make_organization(stack_id=5, org_id=100, grafana_url="http://grafana:3000", api_token="primary-directory")
    secondary = make_organization(stack_id=6, org_id=100, grafana_url="http://grafana-secondary:3002", api_token="secondary-directory")
    return primary, secondary


def send(organization, data, headers, token):
    return APIClient().post(reverse("grafana-plugin:sync-v2"), data=data, format="json",
                            **headers(None, token, organization=organization))


@pytest.mark.django_db
@pytest.mark.parametrize("index", [0, 1])
def test_original_token_syncs_only_its_existing_owner(owners, index, make_user_auth_headers):
    organization, untouched = owners[index], owners[1 - index]
    expected_actor = organization.grafana_url, organization.api_token
    _, token = PluginAuthToken.create_auth_token(organization)
    with patch("apps.grafana_plugin.helpers.client.GrafanaAPIClient.check_token", return_value=(None, {"connected": True})):
        response = send(organization, payload(organization), make_user_auth_headers, token)
    assert response.status_code == 200
    organization.refresh_from_db()
    assert organization.is_grafana_irm_enabled
    assert organization.users.get(user_id=77).username == "current-member"
    assert not untouched.users.filter(user_id=77).exists()
    assert (organization.grafana_url, organization.api_token) == expected_actor


@pytest.mark.django_db
@pytest.mark.parametrize("field,value", [("stack_id", 5), ("org_id", 101),
    ("grafana_url", "http://grafana:3000"), ("grafana_token", "primary-directory")])
def test_authenticated_selector_cannot_change_original_owner(owners, make_user_auth_headers, field, value):
    organization = owners[1]
    _, token = PluginAuthToken.create_auth_token(organization)
    data = payload(organization)
    data["settings"][field] = value
    with patch("apps.grafana_plugin.views.sync_v2.apply_sync_data") as write:
        response = send(organization, data, make_user_auth_headers, token)
    assert response.status_code == 400
    write.assert_not_called()
    assert not organization.users.exists()


@pytest.mark.django_db
def test_foreign_and_revoked_original_tokens_never_sync(owners, make_user_auth_headers):
    primary, secondary = owners
    original, token = PluginAuthToken.create_auth_token(primary)
    with patch("apps.grafana_plugin.views.sync_v2.apply_sync_data") as write:
        assert send(primary, payload(secondary), make_user_auth_headers, token).status_code == 400
        assert send(secondary, payload(secondary), make_user_auth_headers, token).status_code == 401
        original.revoked_at = timezone.now()
        original.save(update_fields=["revoked_at"])
        assert send(primary, payload(primary), make_user_auth_headers, token).status_code == 401
    write.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("change", ["token", "directory", "deleted"])
def test_post_authentication_owner_change_refuses_before_original_write(owners, make_user_auth_headers, change):
    organization = owners[1]
    original, token = PluginAuthToken.create_auth_token(organization)
    data = payload(organization)
    save = SyncDataSerializer.save
    def changed(serializer, **kwargs):
        result = save(serializer, **kwargs)
        if change == "token":
            original.revoked_at = timezone.now()
            original.save(update_fields=["revoked_at"])
        elif change == "directory":
            organization.api_token = "rotated-secondary-directory"
            organization.save(update_fields=["api_token"])
        else:
            organization.deleted_at = timezone.now()
            organization.save(update_fields=["deleted_at"])
        return result
    with patch.object(SyncDataSerializer, "save", changed), patch("apps.grafana_plugin.views.sync_v2.apply_sync_data") as write:
        response = send(organization, data, make_user_auth_headers, token)
    assert response.status_code == 400
    write.assert_not_called()


@pytest.mark.django_db
def test_unauthenticated_install_keeps_original_global_tuple(owners):
    primary, secondary = owners
    with patch("apps.grafana_plugin.views.sync_v2.apply_sync_data") as write:
        response = APIClient().post(reverse("grafana-plugin:install-v2"), data=payload(secondary), format="json")
    assert response.status_code == 400
    write.assert_not_called()
    with patch("apps.grafana_plugin.helpers.client.GrafanaAPIClient.check_token", return_value=(None, {"connected": True})):
        response = APIClient().post(reverse("grafana-plugin:install-v2"), data=payload(primary), format="json")
    assert response.status_code == 200
    assert (response.data["stackId"], response.data["orgId"]) == (5, 100)
    assert primary.users.get(user_id=77).username == "current-member"
    assert not secondary.users.exists()
