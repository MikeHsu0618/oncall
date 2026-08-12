import pytest
from django.urls import reverse
from fcm_django.models import DeviceType
from rest_framework import status
from rest_framework.test import APIClient

from apps.mobile_app.models import FCMDevice


@pytest.mark.django_db
def test_list_mobile_devices_returns_only_current_users_active_devices_without_registration_tokens(
    make_organization_and_user_with_plugin_token,
    make_user_for_organization,
    make_user_auth_headers,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    other_user = make_user_for_organization(organization)

    ios_device = FCMDevice.objects.create(
        user=user,
        registration_id="secret-ios-registration-token",
        name="Mike's iPhone",
        type=DeviceType.IOS,
        active=True,
    )
    FCMDevice.objects.create(
        user=user,
        registration_id="inactive-registration-token",
        name="Old phone",
        type=DeviceType.ANDROID,
        active=False,
    )
    FCMDevice.objects.create(
        user=other_user,
        registration_id="other-user-registration-token",
        name="Other phone",
        type=DeviceType.ANDROID,
        active=True,
    )

    response = APIClient().get(
        reverse("api-internal:mobile-devices-list"),
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == [
        {
            "id": ios_device.id,
            "user": {"pk": user.public_primary_key, "username": user.username},
            "device_name": "Mike's iPhone",
            "device_platform": DeviceType.IOS,
            "created_at": response.json()[0]["created_at"],
        }
    ]
    assert response.json()[0]["created_at"] is not None
    assert "registration_id" not in response.json()[0]


@pytest.mark.django_db
def test_disconnect_mobile_device_deletes_current_users_device(
    make_organization_and_user_with_plugin_token,
    make_user_auth_headers,
):
    _, user, token = make_organization_and_user_with_plugin_token()
    device = FCMDevice.objects.create(
        user=user,
        registration_id="current-user-registration-token",
        active=True,
    )

    response = APIClient().delete(
        reverse("api-internal:mobile-devices-detail", kwargs={"device_id": device.id}),
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not FCMDevice.objects.filter(id=device.id).exists()


@pytest.mark.django_db
def test_disconnect_mobile_device_cannot_delete_another_users_device(
    make_organization_and_user_with_plugin_token,
    make_user_for_organization,
    make_user_auth_headers,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    other_user = make_user_for_organization(organization)
    other_device = FCMDevice.objects.create(
        user=other_user,
        registration_id="other-user-registration-token",
        active=True,
    )

    response = APIClient().delete(
        reverse("api-internal:mobile-devices-detail", kwargs={"device_id": other_device.id}),
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert FCMDevice.objects.filter(id=other_device.id).exists()
