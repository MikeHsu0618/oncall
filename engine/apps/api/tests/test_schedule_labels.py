import json
from unittest.mock import patch

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.labels.models import MAX_KEY_NAME_LENGTH, ScheduleAssociatedLabel
from apps.schedules.models import OnCallScheduleCalendar, OnCallScheduleICal, OnCallScheduleWeb

ICAL_URL = "https://example.com"


def _label(key, value):
    return {"key": {"name": key}, "value": {"name": value}}


@pytest.fixture(autouse=True)
def patch_fetch_ical_file():
    with patch("apps.schedules.ical_utils.fetch_ical_file", return_value=""):
        yield


@pytest.fixture()
def labels_setup(make_organization_and_user_with_plugin_token, make_schedule):
    organization, user, token = make_organization_and_user_with_plugin_token()

    def _make(schedule_class=OnCallScheduleWeb, labels=(), **kwargs):
        if schedule_class is OnCallScheduleICal:
            kwargs.setdefault("ical_url_primary", ICAL_URL)
        schedule = make_schedule(organization, schedule_class=schedule_class, **kwargs)
        for key, value in labels:
            ScheduleAssociatedLabel.objects.create(
                schedule=schedule, organization=organization, key_name=key, value_name=value
            )
        return schedule

    return organization, user, token, _make


def _put(client, schedule, data, user, token, make_user_auth_headers):
    url = reverse("api-internal:schedule-detail", kwargs={"pk": schedule.public_primary_key})
    return client.put(
        url, data=json.dumps(data), content_type="application/json", **make_user_auth_headers(user, token)
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "schedule_type,extra",
    [
        (0, {"time_zone": "UTC"}),
        (1, {"ical_url_primary": ICAL_URL}),
        (2, {"time_zone": "UTC"}),
    ],
)
def test_create_schedule_with_labels(labels_setup, make_user_auth_headers, schedule_type, extra):
    _, user, token, _ = labels_setup
    client = APIClient()
    labels = [_label("service", "checkout"), _label("service", "payments"), _label("tier", "1")]
    data = {"type": schedule_type, "name": "with labels", "team": None, "labels": labels, **extra}

    with patch(
        "apps.api.serializers.schedule_ical.ScheduleICalSerializer.validate_ical_url_primary", return_value=ICAL_URL
    ), patch("apps.schedules.tasks.refresh_ical_final_schedule.apply_async"):
        response = client.post(
            reverse("api-internal:schedule-list"), data, format="json", **make_user_auth_headers(user, token)
        )

    assert response.status_code == status.HTTP_201_CREATED, response.data
    assert response.json()["labels"] == labels

    detail = client.get(
        reverse("api-internal:schedule-detail", kwargs={"pk": response.json()["id"]}),
        **make_user_auth_headers(user, token),
    )
    assert detail.json()["labels"] == labels


@pytest.mark.django_db
def test_create_schedule_without_labels_returns_empty_list(labels_setup, make_user_auth_headers):
    _, user, token, _ = labels_setup
    client = APIClient()
    data = {"type": 2, "name": "no labels", "team": None, "time_zone": "UTC"}

    response = client.post(
        reverse("api-internal:schedule-list"), data, format="json", **make_user_auth_headers(user, token)
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["labels"] == []


@pytest.mark.django_db
@pytest.mark.parametrize(
    "schedule_class,schedule_type",
    [(OnCallScheduleCalendar, 0), (OnCallScheduleICal, 1), (OnCallScheduleWeb, 2)],
)
def test_update_schedule_replaces_labels(labels_setup, make_user_auth_headers, schedule_class, schedule_type):
    _, user, token, make = labels_setup
    schedule = make(schedule_class, labels=[("service", "checkout"), ("tier", "1")])
    client = APIClient()
    labels = [_label("service", "checkout"), _label("service", "search"), _label("region", "eu")]

    response = _put(
        client,
        schedule,
        {"name": schedule.name, "type": schedule_type, "team": None, "labels": labels},
        user,
        token,
        make_user_auth_headers,
    )

    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.json()["labels"] == labels
    stored = list(schedule.labels.order_by("pk").values_list("key_name", "value_name"))
    assert stored == [("service", "checkout"), ("service", "search"), ("region", "eu")]


@pytest.mark.django_db
def test_update_schedule_without_labels_keeps_labels(labels_setup, make_user_auth_headers):
    """The schedule form omits `labels` from the PUT when the user did not change them."""
    _, user, token, make = labels_setup
    schedule = make(labels=[("service", "checkout"), ("tier", "1")])
    client = APIClient()

    response = _put(client, schedule, {"name": "renamed", "type": 2, "team": None}, user, token, make_user_auth_headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["labels"] == [_label("service", "checkout"), _label("tier", "1")]


@pytest.mark.django_db
def test_update_schedule_with_empty_labels_clears_labels(labels_setup, make_user_auth_headers):
    _, user, token, make = labels_setup
    schedule = make(labels=[("service", "checkout")])
    client = APIClient()

    response = _put(
        client,
        schedule,
        {"name": schedule.name, "type": 2, "team": None, "labels": []},
        user,
        token,
        make_user_auth_headers,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["labels"] == []
    assert not schedule.labels.exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "labels",
    [
        [_label("service", "checkout"), _label("service", "checkout")],
        [_label("", "checkout")],
        [_label("service", "")],
        [_label("k" * (MAX_KEY_NAME_LENGTH + 1), "v")],
        [{"key": {"name": "service"}}],
    ],
)
def test_update_schedule_rejects_invalid_labels(labels_setup, make_user_auth_headers, labels):
    _, user, token, make = labels_setup
    schedule = make(labels=[("service", "checkout")])
    client = APIClient()

    response = _put(
        client,
        schedule,
        {"name": schedule.name, "type": 2, "team": None, "labels": labels},
        user,
        token,
        make_user_auth_headers,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "labels" in response.json()
    assert list(schedule.labels.values_list("key_name", "value_name")) == [("service", "checkout")]


@pytest.mark.django_db
def test_list_schedules_returns_labels(labels_setup, make_user_auth_headers):
    _, user, token, make = labels_setup
    first = make(name="a", labels=[("service", "checkout"), ("tier", "1")])
    second = make(name="b")
    client = APIClient()

    response = client.get(reverse("api-internal:schedule-list"), **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_200_OK
    labels_by_id = {item["id"]: item["labels"] for item in response.json()["results"]}
    assert labels_by_id == {
        first.public_primary_key: [_label("service", "checkout"), _label("tier", "1")],
        second.public_primary_key: [],
    }


@pytest.mark.django_db
def test_list_schedules_labels_are_prefetched(labels_setup, make_user_auth_headers):
    _, user, token, make = labels_setup
    for index in range(3):
        make(name=f"s{index}", labels=[("service", f"svc{index}")])
    client = APIClient()
    url = reverse("api-internal:schedule-list")

    with CaptureQueriesContext(connection) as queries:
        client.get(url, **make_user_auth_headers(user, token))
    label_queries = [q["sql"] for q in queries.captured_queries if "labels_scheduleassociatedlabel" in q["sql"]]
    # one batched prefetch per evaluation of the page (on-call users context + serialization), never one per schedule
    assert label_queries
    assert all('"schedule_id" IN (' in sql for sql in label_queries)


@pytest.mark.django_db
def test_list_schedules_filter_labels_any(labels_setup, make_user_auth_headers):
    _, user, token, make = labels_setup
    checkout = make(name="checkout", labels=[("service", "checkout"), ("tier", "1")])
    search = make(name="search", labels=[("service", "search"), ("tier", "1")])
    make(name="other", labels=[("service", "other")])
    make(name="unlabelled")
    client = APIClient()
    url = reverse("api-internal:schedule-list")

    labels_any = json.dumps([{"key": "service", "value": "checkout"}, {"key": "service", "value": "search"}])
    response = client.get(url, {"labels_any": labels_any}, **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_200_OK
    assert sorted(item["id"] for item in response.json()["results"]) == sorted(
        [checkout.public_primary_key, search.public_primary_key]
    )
    assert response.json()["count"] == 2

    # a pair matching both schedules returns each schedule once
    response = client.get(
        url, {"labels_any": json.dumps([{"key": "tier", "value": "1"}])}, **make_user_auth_headers(user, token)
    )
    assert response.json()["count"] == 2


@pytest.mark.django_db
@pytest.mark.parametrize(
    "labels_any",
    ["not json", json.dumps({"key": "service", "value": "x"}), json.dumps([{"key": "service"}]), json.dumps([1])],
)
def test_list_schedules_filter_labels_any_invalid(labels_setup, make_user_auth_headers, labels_any):
    _, user, token, _ = labels_setup
    client = APIClient()

    response = client.get(
        reverse("api-internal:schedule-list"), {"labels_any": labels_any}, **make_user_auth_headers(user, token)
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "labels_any" in response.json()
