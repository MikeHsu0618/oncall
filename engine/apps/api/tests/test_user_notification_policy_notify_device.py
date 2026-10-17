import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.api.permissions import LegacyAccessControlRole
from apps.base.models import UserNotificationPolicy
from apps.mobile_app.models import FCMDevice

NOTIFY_BY = UserNotificationPolicy.NotificationChannel.SLACK


def _detail_url(policy):
    return reverse("api-internal:notification_policy-detail", kwargs={"pk": policy.public_primary_key})


@pytest.fixture()
def mobile_user_with_policy(make_organization_and_user_with_mobile_app_auth_token, make_user_notification_policy):
    organization, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    policy = make_user_notification_policy(user, UserNotificationPolicy.Step.NOTIFY, notify_by=NOTIFY_BY)
    return organization, user, auth_token, policy


@pytest.mark.django_db
def test_notify_device_defaults_to_all_devices(mobile_user_with_policy):
    _, _, auth_token, policy = mobile_user_with_policy

    response = APIClient().get(_detail_url(policy), HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["notify_device"] is None


@pytest.mark.django_db
def test_set_notify_device_to_own_active_device(mobile_user_with_policy):
    _, user, auth_token, policy = mobile_user_with_policy
    device = FCMDevice.objects.create(user=user, registration_id="phone")

    response = APIClient().patch(
        _detail_url(policy),
        data={"notify_by": NOTIFY_BY, "notify_device": device.pk},
        format="json",
        HTTP_AUTHORIZATION=auth_token,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["notify_device"] == device.pk
    policy.refresh_from_db()
    assert policy.notify_device_id == device.pk

    # null means "All devices" again
    response = APIClient().patch(
        _detail_url(policy),
        data={"notify_by": NOTIFY_BY, "notify_device": None},
        format="json",
        HTTP_AUTHORIZATION=auth_token,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["notify_device"] is None
    policy.refresh_from_db()
    assert policy.notify_device_id is None


@pytest.mark.django_db
@pytest.mark.parametrize("device_kind", ["other_users_device", "inactive_own_device", "unknown_device"])
def test_set_notify_device_rejects_invalid_device(
    mobile_user_with_policy, make_user_for_organization, device_kind
):
    organization, user, auth_token, policy = mobile_user_with_policy
    other_user = make_user_for_organization(organization)
    device_ids = {
        "other_users_device": FCMDevice.objects.create(user=other_user, registration_id="other").pk,
        "inactive_own_device": FCMDevice.objects.create(user=user, registration_id="old", active=False).pk,
        "unknown_device": 999999,
    }

    response = APIClient().patch(
        _detail_url(policy),
        data={"notify_by": NOTIFY_BY, "notify_device": device_ids[device_kind]},
        format="json",
        HTTP_AUTHORIZATION=auth_token,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "notify_device" in response.json()
    policy.refresh_from_db()
    assert policy.notify_device_id is None


@pytest.mark.django_db
def test_create_policy_with_notify_device(mobile_user_with_policy):
    _, user, auth_token, _ = mobile_user_with_policy
    device = FCMDevice.objects.create(user=user, registration_id="phone")

    response = APIClient().post(
        reverse("api-internal:notification_policy-list"),
        data={
            "step": UserNotificationPolicy.Step.NOTIFY,
            "notify_by": NOTIFY_BY,
            "notify_device": device.pk,
            "user": user.public_primary_key,
        },
        format="json",
        HTTP_AUTHORIZATION=auth_token,
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["notify_device"] == device.pk
    assert UserNotificationPolicy.objects.get(public_primary_key=response.json()["id"]).notify_device_id == device.pk


@pytest.mark.django_db
def test_admin_sets_notify_device_of_policy_owner(
    make_organization_and_user_with_plugin_token,
    make_user_for_organization,
    make_user_notification_policy,
    make_user_auth_headers,
):
    organization, admin, token = make_organization_and_user_with_plugin_token()
    user = make_user_for_organization(organization, role=LegacyAccessControlRole.EDITOR)
    policy = make_user_notification_policy(user, UserNotificationPolicy.Step.NOTIFY, notify_by=NOTIFY_BY)
    admins_device = FCMDevice.objects.create(user=admin, registration_id="admin-phone")
    users_device = FCMDevice.objects.create(user=user, registration_id="user-phone")
    client = APIClient()

    # validated against the policy's owner, not the requesting admin
    response = client.patch(
        _detail_url(policy),
        data={"notify_by": NOTIFY_BY, "notify_device": admins_device.pk},
        format="json",
        **make_user_auth_headers(admin, token),
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    response = client.patch(
        _detail_url(policy),
        data={"notify_by": NOTIFY_BY, "notify_device": users_device.pk},
        format="json",
        **make_user_auth_headers(admin, token),
    )
    assert response.status_code == status.HTTP_200_OK
    policy.refresh_from_db()
    assert policy.notify_device_id == users_device.pk


@pytest.mark.django_db
def test_deleting_device_resets_notify_device_to_all_devices(mobile_user_with_policy):
    _, user, _, policy = mobile_user_with_policy
    device = FCMDevice.objects.create(user=user, registration_id="phone")
    policy.notify_device = device
    policy.save(update_fields=["notify_device"])

    device.delete()

    policy.refresh_from_db()
    assert policy.notify_device_id is None


@pytest.mark.django_db
def test_step_with_deactivated_notify_device_stays_editable(mobile_user_with_policy):
    _, user, auth_token, policy = mobile_user_with_policy
    device = FCMDevice.objects.create(user=user, registration_id="phone")
    policy.notify_device = device
    policy.save(update_fields=["notify_device"])
    device.active = False
    device.save(update_fields=["active"])

    # a client sending the whole step back echoes the stored (now inactive) device unchanged
    response = APIClient().patch(
        _detail_url(policy),
        data={"notify_by": NOTIFY_BY, "notify_device": device.pk, "step": UserNotificationPolicy.Step.WAIT},
        format="json",
        HTTP_AUTHORIZATION=auth_token,
    )

    assert response.status_code == status.HTTP_200_OK
    policy.refresh_from_db()
    assert policy.step == UserNotificationPolicy.Step.WAIT
    assert policy.notify_device_id == device.pk
    # delivery for the stale choice goes to all active devices
    phone = FCMDevice.objects.create(user=user, registration_id="new-phone")
    assert FCMDevice.get_devices_to_notify(user, policy.notify_device_id) == [phone]
