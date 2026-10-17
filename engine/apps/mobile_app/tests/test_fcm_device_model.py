import pytest

from apps.mobile_app.models import FCMDevice


@pytest.mark.django_db
def test_get_devices_to_notify_returns_all_active_devices(make_organization_and_user):
    _, user = make_organization_and_user()
    _, other_user = make_organization_and_user()
    phone = FCMDevice.objects.create(user=user, registration_id="phone", active=True)
    FCMDevice.objects.create(user=user, registration_id="inactive_device_id", active=False)
    tablet = FCMDevice.objects.create(user=user, registration_id="tablet", active=True)
    FCMDevice.objects.create(user=other_user, registration_id="other_users_device", active=True)

    assert FCMDevice.get_devices_to_notify(user) == [phone, tablet]


@pytest.mark.django_db
def test_get_devices_to_notify_chosen_device(make_organization_and_user):
    _, user = make_organization_and_user()
    _, other_user = make_organization_and_user()
    phone = FCMDevice.objects.create(user=user, registration_id="phone", active=True)
    tablet = FCMDevice.objects.create(user=user, registration_id="tablet", active=True)
    inactive = FCMDevice.objects.create(user=user, registration_id="inactive", active=False)
    other_users_device = FCMDevice.objects.create(user=other_user, registration_id="other", active=True)

    # the chosen active device only
    assert FCMDevice.get_devices_to_notify(user, tablet.pk) == [tablet]
    # a chosen device that is inactive, unknown or someone else's falls back to all active devices
    assert FCMDevice.get_devices_to_notify(user, inactive.pk) == [phone, tablet]
    assert FCMDevice.get_devices_to_notify(user, other_users_device.pk) == [phone, tablet]
    assert FCMDevice.get_devices_to_notify(user, 999999) == [phone, tablet]


@pytest.mark.django_db
def test_get_devices_to_notify_no_devices(make_organization_and_user):
    _, user = make_organization_and_user()
    FCMDevice.objects.create(user=user, registration_id="inactive", active=False)

    assert FCMDevice.get_devices_to_notify(user) == []
