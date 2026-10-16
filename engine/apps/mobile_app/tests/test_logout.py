import pytest
from fcm_django.models import DeviceType
from rest_framework import status
from rest_framework.test import APIClient

from apps.mobile_app.models import FCMDevice, MobileAppAuthToken

URL = "/api/internal/v1/mobile_app/logout"


def _device(user, registration_id, active=True):
    return FCMDevice.objects.create(user=user, registration_id=registration_id, type=DeviceType.IOS, active=active)


@pytest.mark.django_db
def test_logout_revokes_token_and_keeps_all_devices_active(make_organization_and_user_with_mobile_app_auth_token):
    # The app's logout request carries no device/registration id and devices are not linked to the token, so
    # the server cannot identify the signing-out phone; the user's other phones must keep receiving pushes.
    _, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    phone_a = _device(user, "phone-a")
    phone_b = _device(user, "phone-b")
    client = APIClient()

    response = client.delete(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not MobileAppAuthToken.objects.filter(user=user).exists()
    for device in (phone_a, phone_b):
        device.refresh_from_db()
        assert device.active is True

    # The revoked token can no longer authenticate any mobile endpoint.
    assert client.get("/mobile_app/v1/user_settings", HTTP_AUTHORIZATION=auth_token).status_code == (
        status.HTTP_403_FORBIDDEN
    )


@pytest.mark.django_db
def test_logout_repeat_call_is_rejected_without_side_effects(make_organization_and_user_with_mobile_app_auth_token):
    _, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    client = APIClient()

    assert client.delete(URL, HTTP_AUTHORIZATION=auth_token).status_code == status.HTTP_204_NO_CONTENT
    # Re-activated after logout (e.g. a later re-login registered it again); a stale logout must not touch it.
    device = _device(user, "re-registered-device")

    response = client.delete(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_403_FORBIDDEN
    device.refresh_from_db()
    assert device.active is True


@pytest.mark.django_db
def test_logout_trailing_slash_and_v1_mount(make_organization_and_user_with_mobile_app_auth_token):
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().delete("/mobile_app/v1/logout/", HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.django_db
def test_logout_requires_token():
    assert APIClient().delete(URL).status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_logout_only_affects_requesting_user(
    make_organization_and_user_with_mobile_app_auth_token,
    make_user_for_organization,
    make_mobile_app_auth_token_for_user,
):
    organization, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    same_org_user = make_user_for_organization(organization)
    make_mobile_app_auth_token_for_user(same_org_user, organization)
    same_org_device = _device(same_org_user, "same-org-device")

    _, other_user, _ = make_organization_and_user_with_mobile_app_auth_token()
    other_org_device = _device(other_user, "other-org-device")

    response = APIClient().delete(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_204_NO_CONTENT
    for device in (same_org_device, other_org_device):
        device.refresh_from_db()
        assert device.active is True
    assert MobileAppAuthToken.objects.filter(user=same_org_user).exists()
    assert MobileAppAuthToken.objects.filter(user=other_user).exists()
