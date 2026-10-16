import pytest
from rest_framework import status
from rest_framework.test import APIClient

# The app calls the api/internal/v1/mobile_app/ mount; mobile_app/v1/ serves the same urlconf.
URLS = ["/api/internal/v1/mobile_app/notification_history/", "/mobile_app/v1/notification_history"]


@pytest.mark.django_db
@pytest.mark.parametrize("url", URLS)
def test_notification_history_returns_bare_list(make_organization_and_user_with_mobile_app_auth_token, url):
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().get(url, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    # The app maps the top-level body as a JSON array, not a paginated {"results": [...]} envelope.
    assert response.json() == []


@pytest.mark.django_db
def test_notification_history_requires_mobile_app_token():
    response = APIClient().get(URLS[0])

    # MobileAppAuthTokenAuthentication declares no WWW-Authenticate challenge, so DRF answers 403 (not 401).
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_notification_history_rejects_invalid_token():
    response = APIClient().get(URLS[0], HTTP_AUTHORIZATION="not-a-real-token")

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
def test_notification_history_rejects_plugin_token(make_organization_and_user_with_plugin_token, make_user_auth_headers):
    _, user, token = make_organization_and_user_with_plugin_token()

    response = APIClient().get(URLS[0], **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_403_FORBIDDEN
