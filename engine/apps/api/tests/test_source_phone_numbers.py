import pytest
from rest_framework import status
from rest_framework.test import APIClient

from apps.twilioapp.models import TwilioAccount, TwilioPhoneCallSender, TwilioSmsSender

URL = "/api/internal/v1/source_phone_numbers"


def _entry(number, voice, sms):
    return {
        "phone_number": number,
        "friendly_name": "Grafana IRM",
        "status": "in-use",
        "capabilities": {"voice": voice, "sms": sms, "mms": False, "fax": False},
    }


@pytest.mark.django_db
def test_returns_twilio_numbers_with_boolean_capabilities(
    make_organization_and_user_with_mobile_app_auth_token, settings
):
    settings.PHONE_PROVIDER = "twilio"
    settings.TWILIO_NUMBER = "+15550000001"
    account = TwilioAccount.objects.create(name="acc", account_sid="test-account-sid")
    TwilioPhoneCallSender.objects.create(account=account, number="+15550000002", country_code="1")
    # Same number as the call sender: capabilities are merged into one entry.
    TwilioSmsSender.objects.create(account=account, sender="+15550000002", country_code="1")
    # Alphanumeric sender ids are not dialable and are skipped.
    TwilioSmsSender.objects.create(account=account, sender="GrafanaIRM", country_code="44")
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().get(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        "phone_numbers": [
            _entry("+15550000001", voice=True, sms=True),
            _entry("+15550000002", voice=True, sms=True),
        ]
    }


@pytest.mark.django_db
def test_trailing_slash_and_plugin_auth(make_organization_and_user_with_plugin_token, make_user_auth_headers, settings):
    settings.PHONE_PROVIDER = "twilio"
    settings.TWILIO_NUMBER = "+15550000001"
    _, user, token = make_organization_and_user_with_plugin_token()

    response = APIClient().get(URL + "/", **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"phone_numbers": [_entry("+15550000001", voice=True, sms=True)]}


@pytest.mark.django_db
@pytest.mark.parametrize("twilio_number", [None, "", "not-a-number"])
def test_empty_list_when_no_usable_number(make_organization_and_user_with_mobile_app_auth_token, settings, twilio_number):
    settings.PHONE_PROVIDER = "twilio"
    settings.TWILIO_NUMBER = twilio_number
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().get(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"phone_numbers": []}


@pytest.mark.django_db
def test_empty_list_for_non_twilio_provider(make_organization_and_user_with_mobile_app_auth_token, settings):
    if "zvonok" not in settings.PHONE_PROVIDERS:
        pytest.skip("zvonok provider is only registered in open-source mode")
    settings.PHONE_PROVIDER = "zvonok"
    settings.TWILIO_NUMBER = "+15550000001"
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().get(URL, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"phone_numbers": []}


@pytest.mark.django_db
def test_requires_authentication():
    response = APIClient().get(URL)

    # MobileAppAuthTokenAuthentication is the first authenticator and declares no challenge, so DRF answers 403.
    assert response.status_code == status.HTTP_403_FORBIDDEN
