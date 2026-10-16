import pytest
from rest_framework import status
from rest_framework.test import APIClient

from apps.mobile_app.models import MobileAppUserSettings

APP_FIELDS = ("default_notification_override_dnd", "info_notification_override_dnd", "incident_notifications_enabled")
URL = "/mobile_app/v1/user_settings"


@pytest.mark.django_db
def test_app_fields_default_to_false(make_organization_and_user_with_mobile_app_auth_token):
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().get(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    for field in APP_FIELDS:
        assert response.json()[field] is False


@pytest.mark.django_db
@pytest.mark.parametrize("field", APP_FIELDS)
def test_app_field_patch_is_persisted(make_organization_and_user_with_mobile_app_auth_token, field):
    _, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    client = APIClient()

    response = client.patch(URL, data={field: True}, format="json", HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()[field] is True
    assert getattr(MobileAppUserSettings.objects.get(user=user), field) is True
    # Other app fields are untouched.
    for other in APP_FIELDS:
        if other != field:
            assert response.json()[other] is False


@pytest.mark.django_db
def test_app_fields_are_per_user(make_organization_and_user_with_mobile_app_auth_token):
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    _, _, other_org_token = make_organization_and_user_with_mobile_app_auth_token()
    client = APIClient()

    client.patch(URL, data={"incident_notifications_enabled": True}, format="json", HTTP_AUTHORIZATION=auth_token)
    response = client.get(URL, HTTP_AUTHORIZATION=other_org_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["incident_notifications_enabled"] is False


@pytest.mark.django_db
def test_user_settings_requires_token():
    assert APIClient().get(URL).status_code == status.HTTP_403_FORBIDDEN
