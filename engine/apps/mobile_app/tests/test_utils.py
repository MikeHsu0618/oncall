from unittest.mock import patch

import firebase_admin.messaging
import pytest
from django.db import DatabaseError
from firebase_admin.exceptions import FirebaseError
from requests import HTTPError

from apps.mobile_app import utils
from apps.mobile_app.models import FCMDevice, MobileAppPushRecord
from apps.mobile_app.types import MessageType
from apps.mobile_app.utils import add_stack_slug_to_message_title
from apps.oss_installation.models import CloudConnector

MOBILE_APP_BACKEND_ID = 5
CLOUD_LICENSE_NAME = "Cloud"
OPEN_SOURCE_LICENSE_NAME = "OpenSource"


def _make_message(title="Test title", subtitle="Test subtitle"):
    return utils.construct_fcm_message(MessageType.DEFAULT, "thread-id", {"title": title, "subtitle": subtitle})


class MockClientErrorResponse:
    status_code = 400


class MockServerErrorResponse:
    status_code = 500


@patch.object(FCMDevice, "send_message", return_value="ok")
@pytest.mark.django_db
def test_send_push_notification_cloud(
    mock_send_message,
    settings,
    make_organization_and_user,
):
    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")
    message = _make_message()

    # check FCM is contacted directly when using the cloud license
    settings.LICENSE = CLOUD_LICENSE_NAME
    settings.IS_OPEN_SOURCE = False

    succeeded = utils.send_push_notification(user, [device], message)
    assert succeeded
    mock_send_message.assert_called_once()
    sent_message = mock_send_message.call_args.args[0]
    assert sent_message.token == device.registration_id
    assert sent_message.data == message.data

    # handed off, so recorded in the user's notification history with the exact data payload
    record = MobileAppPushRecord.objects.get()
    assert record.user == user
    assert record.device == device
    assert record.alert_group is None
    assert record.notification_type == "oncall.message"
    assert record.title == "Test title"
    assert record.subtitle == "Test subtitle"
    assert record.fcm_payload == message.data


@patch.object(FCMDevice, "send_message")
@pytest.mark.django_db
def test_send_push_notification_cloud_firebase_error(
    mock_send_message,
    settings,
    make_organization_and_user,
):
    mock_send_message.return_value = FirebaseError(code="test_error_code", message="test_error_message")

    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    # check FCM is contacted directly when using the cloud license
    settings.LICENSE = CLOUD_LICENSE_NAME
    settings.IS_OPEN_SOURCE = False

    with pytest.raises(FirebaseError):
        utils.send_push_notification(user, [device], _make_message())

    mock_send_message.assert_called_once()
    assert not MobileAppPushRecord.objects.exists()


@patch.object(FCMDevice, "send_message")
@pytest.mark.parametrize(
    "ExceptionClass,exception_kwargs",
    [
        (firebase_admin.messaging.UnregisteredError, {"message": "test_error_message"}),
    ],
)
@pytest.mark.django_db
def test_send_push_notification_cloud_ignores_certain_errors(
    mock_send_message,
    settings,
    make_organization_and_user,
    ExceptionClass,
    exception_kwargs,
):
    mock_send_message.return_value = ExceptionClass(**exception_kwargs)

    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    # check FCM is contacted directly when using the cloud license
    settings.LICENSE = CLOUD_LICENSE_NAME
    settings.IS_OPEN_SOURCE = False

    try:
        succeeded = utils.send_push_notification(user, [device], _make_message())
    except Exception:
        pytest.fail(f"send_push_notification should not raise an exception for {ExceptionClass.__name__} errors")

    assert not succeeded
    mock_send_message.assert_called_once()
    assert not MobileAppPushRecord.objects.exists()


@patch("apps.mobile_app.utils._send_push_notification_to_fcm_relay", return_value="ok")
@pytest.mark.django_db
def test_send_push_notification_oss(
    mock_send_push_notification_to_fcm_relay,
    settings,
    make_organization_and_user,
):
    settings.LICENSE = OPEN_SOURCE_LICENSE_NAME

    # create cloud connection
    CloudConnector.objects.create(cloud_url="test")

    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")
    message = _make_message()

    succeeded = utils.send_push_notification(user, [device], message)
    assert succeeded
    mock_send_push_notification_to_fcm_relay.assert_called_once()
    relayed_message = mock_send_push_notification_to_fcm_relay.call_args.args[0]
    assert relayed_message.token == device.registration_id
    assert relayed_message.data == message.data
    assert MobileAppPushRecord.objects.get().fcm_payload == message.data


@patch("apps.mobile_app.utils._send_push_notification_to_fcm_relay")
@pytest.mark.django_db
def test_send_push_notification_oss_no_cloud_connector(
    mock_send_push_notification_to_fcm_relay,
    settings,
    make_organization_and_user,
):
    settings.LICENSE = OPEN_SOURCE_LICENSE_NAME

    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    succeeded = utils.send_push_notification(user, [device], _make_message())

    assert not succeeded
    mock_send_push_notification_to_fcm_relay.assert_not_called()
    assert not MobileAppPushRecord.objects.exists()


@patch("apps.mobile_app.utils._send_push_notification_to_fcm_relay")
@pytest.mark.django_db
def test_send_push_notification_oss_fcm_relay_returns_client_error(
    mock_send_push_notification_to_fcm_relay,
    settings,
    make_organization_and_user,
):
    settings.LICENSE = OPEN_SOURCE_LICENSE_NAME
    mock_send_push_notification_to_fcm_relay.side_effect = HTTPError(response=MockClientErrorResponse)

    # create cloud connection
    CloudConnector.objects.create(cloud_url="test")

    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    succeeded = utils.send_push_notification(user, [device], _make_message())
    assert not succeeded
    mock_send_push_notification_to_fcm_relay.assert_called_once()
    assert not MobileAppPushRecord.objects.exists()


@patch("apps.mobile_app.utils._send_push_notification_to_fcm_relay")
@pytest.mark.django_db
def test_send_push_notification_oss_fcm_relay_returns_server_error(
    mock_send_push_notification_to_fcm_relay,
    settings,
    make_organization_and_user,
):
    settings.LICENSE = OPEN_SOURCE_LICENSE_NAME
    mock_send_push_notification_to_fcm_relay.side_effect = HTTPError(response=MockServerErrorResponse)

    # create cloud connection
    CloudConnector.objects.create(cloud_url="test")

    # create a user and connect a mobile device
    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    with pytest.raises(HTTPError):
        utils.send_push_notification(user, [device], _make_message())

    mock_send_push_notification_to_fcm_relay.assert_called_once()
    assert not MobileAppPushRecord.objects.exists()


@patch("apps.mobile_app.utils._send_push_notification_to_fcm_relay")
@pytest.mark.django_db
def test_send_push_notification_partial_failure_is_not_retried(
    mock_send_push_notification_to_fcm_relay,
    settings,
    make_organization_and_user,
):
    settings.LICENSE = OPEN_SOURCE_LICENSE_NAME
    # first device accepted, second fails with a retryable error
    mock_send_push_notification_to_fcm_relay.side_effect = ["ok", HTTPError(response=MockServerErrorResponse)]
    CloudConnector.objects.create(cloud_url="test")

    _, user = make_organization_and_user()
    phone = FCMDevice.objects.create(user=user, registration_id="phone")
    tablet = FCMDevice.objects.create(user=user, registration_id="tablet")
    message = _make_message()

    # no exception: a celery retry would push to the phone a second time
    succeeded = utils.send_push_notification(user, [phone, tablet], message)

    assert succeeded
    assert mock_send_push_notification_to_fcm_relay.call_count == 2
    record = MobileAppPushRecord.objects.get()
    assert record.device is None
    assert record.fcm_payload == message.data


@patch("apps.mobile_app.utils._send_push_notification_to_fcm_relay", return_value="ok")
@patch.object(MobileAppPushRecord, "record_sent_push", side_effect=DatabaseError("db down"))
@pytest.mark.django_db
def test_send_push_notification_history_write_failure_does_not_fail_delivery(
    mock_record_sent_push,
    mock_send_push_notification_to_fcm_relay,
    settings,
    make_organization_and_user,
):
    settings.LICENSE = OPEN_SOURCE_LICENSE_NAME
    CloudConnector.objects.create(cloud_url="test")

    _, user = make_organization_and_user()
    device = FCMDevice.objects.create(user=user, registration_id="test_device_id")

    assert utils.send_push_notification(user, [device], _make_message())
    mock_record_sent_push.assert_called_once()


@pytest.mark.django_db
def test_record_sent_push_keeps_newest_records_per_user(make_organization_and_user, monkeypatch):
    monkeypatch.setattr(MobileAppPushRecord, "MAX_RECORDS_PER_USER", 3)
    _, user = make_organization_and_user()
    _, other_user = make_organization_and_user()

    MobileAppPushRecord.record_sent_push(other_user, None, _make_message(title="other user"))
    for i in range(5):
        MobileAppPushRecord.record_sent_push(user, None, _make_message(title=f"push {i}"))

    assert list(MobileAppPushRecord.newest_for_user(user).values_list("title", flat=True)) == [
        "push 4",
        "push 3",
        "push 2",
    ]
    # retention is per user
    assert MobileAppPushRecord.objects.filter(user=other_user).count() == 1


@pytest.mark.django_db
def test_record_sent_push_without_subtitle(make_organization_and_user):
    _, user = make_organization_and_user()
    message = utils.construct_fcm_message(MessageType.DEFAULT, "thread-id", {"title": "Test push"})

    record = MobileAppPushRecord.record_sent_push(user, None, message)

    assert record.subtitle == ""
    assert record.fcm_payload == {"title": "Test push", "type": "oncall.message", "thread_id": "thread-id"}


@pytest.mark.django_db
def test_add_stack_slug_to_message_title(make_organization):
    test_stack_slug = "my-org"
    organization = make_organization(stack_slug=test_stack_slug)
    some_message_title = "Test title"
    expected_result = "[my-org] Test title"
    result = add_stack_slug_to_message_title(some_message_title, organization)
    assert result == expected_result
