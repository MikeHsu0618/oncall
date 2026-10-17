import pytest
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.test import APIClient

from apps.mobile_app.models import MobileAppPushRecord
from apps.mobile_app.types import MessageType
from apps.mobile_app.utils import construct_fcm_message

# The app calls the api/internal/v1/mobile_app/ mount; mobile_app/v1/ serves the same urlconf.
URLS = ["/api/internal/v1/mobile_app/notification_history/", "/mobile_app/v1/notification_history"]


def _record_push(user, title, sent_at, alert_group=None, message_type=MessageType.DEFAULT, subtitle="subtitle"):
    data = {"title": title, "orgName": "stack"}
    if subtitle is not None:
        data["subtitle"] = subtitle
    message = construct_fcm_message(message_type, f"thread:{title}", data)
    record = MobileAppPushRecord.record_sent_push(user, None, message, alert_group)
    MobileAppPushRecord.objects.filter(pk=record.pk).update(sent_at=sent_at)
    return record


@pytest.mark.django_db
@pytest.mark.parametrize("url", URLS)
def test_notification_history_empty_is_bare_list(make_organization_and_user_with_mobile_app_auth_token, url):
    _, _, auth_token = make_organization_and_user_with_mobile_app_auth_token()

    response = APIClient().get(url, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    # The app maps the top-level body as a JSON array, not a paginated {"results": [...]} envelope.
    assert response.json() == []


@pytest.mark.django_db
@pytest.mark.parametrize("url", URLS)
def test_notification_history_entry_shape(
    make_organization_and_user_with_mobile_app_auth_token,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
    url,
):
    organization, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    alert_receive_channel = make_alert_receive_channel(organization=organization)
    alert_group = make_alert_group(alert_receive_channel)
    make_alert(alert_group=alert_group, raw_request_data={})
    sent_at = timezone.now() - timezone.timedelta(minutes=5)
    record = _record_push(
        user, "Alert group #1", sent_at, alert_group=alert_group, message_type=MessageType.IMPORTANT
    )

    response = APIClient().get(url, HTTP_AUTHORIZATION=auth_token)

    assert response.status_code == status.HTTP_200_OK
    [entry] = response.json()
    assert entry["id"] == str(record.pk)
    assert entry["notification_type"] == "oncall.critical_message"
    assert entry["title"] == "Alert group #1"
    assert entry["subtitle"] == "subtitle"
    assert parse_datetime(entry["sent_at"]) == sent_at
    # exactly the data payload that was handed off, so the missed-push poller rebuilds the same push
    assert entry["fcm_payload"] == {
        "title": "Alert group #1",
        "subtitle": "subtitle",
        "orgName": "stack",
        "type": "oncall.critical_message",
        "thread_id": "thread:Alert group #1",
    }
    assert entry["alert_group"]["pk"] == alert_group.public_primary_key
    assert entry["alert_group"]["inside_organization_number"] == alert_group.inside_organization_number
    assert parse_datetime(entry["alert_group"]["started_at"]) == alert_group.started_at
    assert entry["alert_group"]["alert_receive_channel"]["id"] == alert_receive_channel.public_primary_key
    assert "title" in entry["alert_group"]["render_for_web"]
    for nested_object in ("shift_swap_request", "schedule", "schedule_event", "incident_data"):
        assert entry[nested_object] is None


@pytest.mark.django_db
def test_notification_history_non_alert_group_push(make_organization_and_user_with_mobile_app_auth_token):
    _, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    _record_push(user, "Test push", timezone.now(), subtitle=None)

    response = APIClient().get(URLS[0], HTTP_AUTHORIZATION=auth_token)

    [entry] = response.json()
    assert entry["notification_type"] == "oncall.message"
    # never null: the app's parser fails the whole list on a field it cannot parse
    assert entry["subtitle"] == ""
    assert entry["alert_group"] is None


@pytest.mark.django_db
def test_notification_history_newest_first_and_per_user(
    make_organization_and_user_with_mobile_app_auth_token, make_user_for_organization
):
    organization, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    other_user = make_user_for_organization(organization)
    now = timezone.now()
    _record_push(user, "oldest", now - timezone.timedelta(hours=2))
    _record_push(user, "newest", now)
    _record_push(user, "middle", now - timezone.timedelta(hours=1))
    _record_push(other_user, "someone else's push", now)

    response = APIClient().get(URLS[0], HTTP_AUTHORIZATION=auth_token)

    assert [entry["title"] for entry in response.json()] == ["newest", "middle", "oldest"]


@pytest.mark.django_db
def test_notification_history_limit(make_organization_and_user_with_mobile_app_auth_token, monkeypatch):
    monkeypatch.setattr(MobileAppPushRecord, "MAX_RECORDS_PER_USER", 2)
    _, user, auth_token = make_organization_and_user_with_mobile_app_auth_token()
    now = timezone.now()
    _record_push(user, "first", now - timezone.timedelta(hours=2))
    _record_push(user, "second", now - timezone.timedelta(hours=1))
    # bypass the retention trimming in record_sent_push to check the endpoint's own limit
    MobileAppPushRecord.objects.create(
        user=user, notification_type="oncall.message", title="third", sent_at=now, fcm_payload={"title": "third"}
    )

    response = APIClient().get(URLS[0], HTTP_AUTHORIZATION=auth_token)

    assert [entry["title"] for entry in response.json()] == ["third", "second"]


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
