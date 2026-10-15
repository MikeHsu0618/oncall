import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.grafana_plugin.helpers import GrafanaAPIClient

CALL_STATUS = {"url": "http://grafana/api/org", "connected": True, "status_code": 200, "message": ""}


@pytest.fixture(autouse=True)
def _no_grafana(monkeypatch):
    monkeypatch.setattr(GrafanaAPIClient, "check_token", lambda self: (None, CALL_STATUS))


def _mobile_status(make_organization_and_user_with_mobile_app_auth_token):
    _, _, token = make_organization_and_user_with_mobile_app_auth_token()
    return APIClient().get(reverse("grafana-plugin:status-v2"), HTTP_AUTHORIZATION=token)


@pytest.mark.django_db
def test_mobile_token_sees_configured_status_license(
    settings, make_organization_and_user_with_mobile_app_auth_token
):
    settings.LICENSE = "OpenSource"
    settings.MOBILE_APP_STATUS_LICENSE = "SelfHosted"
    response = _mobile_status(make_organization_and_user_with_mobile_app_auth_token)
    assert response.status_code == 200
    assert response.data["license"] == "SelfHosted"


@pytest.mark.django_db
def test_mobile_token_default_reports_engine_license(
    settings, make_organization_and_user_with_mobile_app_auth_token
):
    settings.LICENSE = "OpenSource"
    settings.MOBILE_APP_STATUS_LICENSE = None
    response = _mobile_status(make_organization_and_user_with_mobile_app_auth_token)
    assert response.status_code == 200
    assert response.data["license"] == "OpenSource"


@pytest.mark.django_db
def test_plugin_token_always_reports_engine_license(
    settings, make_organization_and_user_with_plugin_token, make_user_auth_headers
):
    settings.LICENSE = "OpenSource"
    settings.MOBILE_APP_STATUS_LICENSE = "SelfHosted"
    _, user, token = make_organization_and_user_with_plugin_token()
    headers = make_user_auth_headers(user, token)
    response = APIClient().get(reverse("grafana-plugin:status-v2"), format="json", **headers)
    assert response.status_code == 200
    assert response.data["license"] == "OpenSource"
