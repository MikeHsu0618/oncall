import pytest

from apps.mobile_app.backend import MobileAppBackend
from apps.mobile_app.models import FCMDevice, MobileAppAuthToken


@pytest.mark.django_db
def test_unlink_user_removes_token_and_all_devices(make_organization_and_user, make_mobile_app_auth_token_for_user):
    organization, user = make_organization_and_user()
    _, other_user = make_organization_and_user()
    make_mobile_app_auth_token_for_user(user, organization)
    FCMDevice.objects.create(user=user, registration_id="phone")
    FCMDevice.objects.create(user=user, registration_id="tablet")
    FCMDevice.objects.create(user=user, registration_id="old", active=False)
    other_users_device = FCMDevice.objects.create(user=other_user, registration_id="other")

    MobileAppBackend().unlink_user(user)

    assert not MobileAppAuthToken.objects.filter(user=user).exists()
    assert not FCMDevice.objects.filter(user=user).exists()
    assert FCMDevice.objects.filter(pk=other_users_device.pk).exists()
