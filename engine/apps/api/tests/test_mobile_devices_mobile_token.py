import pytest
from fcm_django.models import DeviceType
from rest_framework import status
from rest_framework.test import APIClient

from apps.mobile_app.models import FCMDevice

LIST_URL = "/api/internal/v1/mobile_app/devices"


def _device(user, registration_id, name):
    return FCMDevice.objects.create(
        user=user, registration_id=registration_id, name=name, type=DeviceType.IOS, active=True
    )


@pytest.mark.django_db
def test_list_devices_with_mobile_app_token_is_scoped_to_token_user(
    make_organization_and_user_with_mobile_app_auth_token,
    make_user_for_organization,
):
    organization, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    own_device = _device(user, "own-token", "Own phone")
    _device(make_user_for_organization(organization), "same-org-token", "Colleague phone")
    _, other_org_user, _ = make_organization_and_user_with_mobile_app_auth_token()
    _device(other_org_user, "other-org-token", "Other org phone")

    response = APIClient().get(LIST_URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    assert [item["id"] for item in response.json()] == [own_device.id]
    assert response.json()[0]["device_name"] == "Own phone"
    assert "registration_id" not in response.json()[0]


@pytest.mark.django_db
def test_mobile_app_token_cannot_delete_other_org_device(make_organization_and_user_with_mobile_app_auth_token):
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    _, other_org_user, _ = make_organization_and_user_with_mobile_app_auth_token()
    other_device = _device(other_org_user, "other-org-token", "Other org phone")

    response = APIClient().delete(f"{LIST_URL}/{other_device.id}", HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert FCMDevice.objects.filter(id=other_device.id).exists()


@pytest.mark.django_db
def test_list_devices_plugin_auth_still_works(make_organization_and_user_with_plugin_token, make_user_auth_headers):
    _, user, token = make_organization_and_user_with_plugin_token()
    device = _device(user, "plugin-user-token", "Plugin user phone")

    response = APIClient().get(LIST_URL, **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_200_OK
    assert [item["id"] for item in response.json()] == [device.id]


@pytest.mark.django_db
@pytest.mark.parametrize("headers", [{}, {"HTTP_AUTHORIZATION": "not-a-real-token"}])
def test_list_devices_rejects_missing_or_invalid_token(headers):
    response = APIClient().get(LIST_URL, **headers)

    # The mobile authenticator is first and declares no challenge, so DRF reports the failure as 403.
    assert response.status_code == status.HTTP_403_FORBIDDEN
