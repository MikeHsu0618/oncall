import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.api.permissions import LegacyAccessControlRole


@pytest.mark.django_db
def test_list_alerts_for_alert_group_is_paginated_and_organization_scoped(
    make_organization_and_user_with_plugin_token,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
    make_user_auth_headers,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    alert_receive_channel = make_alert_receive_channel(organization)
    alert_group = make_alert_group(alert_receive_channel)
    first_alert = make_alert(alert_group, {"title": "first"})
    second_alert = make_alert(alert_group, {"title": "second"})

    other_organization, _, _ = make_organization_and_user_with_plugin_token()
    other_channel = make_alert_receive_channel(other_organization)
    other_group = make_alert_group(other_channel)
    make_alert(other_group, {"title": "not visible"})

    client = APIClient()
    response = client.get(
        reverse("api-internal:alerts-list"),
        {"alert_group_id": alert_group.public_primary_key, "page": 1},
        format="json",
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["count"] == 2
    assert response.json()["current_page_number"] == 1
    assert response.json()["total_pages"] == 1
    assert {item["id"] for item in response.json()["results"]} == {
        first_alert.public_primary_key,
        second_alert.public_primary_key,
    }
    assert all("render_for_web" in item for item in response.json()["results"])


@pytest.mark.django_db
def test_alert_detail_is_team_scoped(
    make_organization,
    make_user,
    make_token_for_organization,
    make_team,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
    make_user_auth_headers,
):
    organization = make_organization()
    user = make_user(organization=organization, role=LegacyAccessControlRole.VIEWER)
    _, token = make_token_for_organization(organization)
    visible_team = make_team(organization)
    hidden_team = make_team(organization)
    user.teams.add(visible_team)

    visible_channel = make_alert_receive_channel(organization, team=visible_team)
    visible_alert = make_alert(make_alert_group(visible_channel), {"title": "visible"})
    hidden_channel = make_alert_receive_channel(organization, team=hidden_team)
    hidden_alert = make_alert(make_alert_group(hidden_channel), {"title": "hidden"})

    client = APIClient()
    visible_response = client.get(
        reverse("api-internal:alerts-detail", kwargs={"id": visible_alert.public_primary_key}),
        **make_user_auth_headers(user, token),
    )
    hidden_response = client.get(
        reverse("api-internal:alerts-detail", kwargs={"id": hidden_alert.public_primary_key}),
        **make_user_auth_headers(user, token),
    )

    assert visible_response.status_code == status.HTTP_200_OK
    assert hidden_response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_alert_detail_requires_alert_group_read_permission(
    make_organization,
    make_user,
    make_token_for_organization,
    make_alert_receive_channel,
    make_alert_group,
    make_alert,
    make_user_auth_headers,
):
    organization = make_organization()
    user = make_user(organization=organization, permissions=[])
    _, token = make_token_for_organization(organization)
    channel = make_alert_receive_channel(organization)
    alert = make_alert(make_alert_group(channel), {"title": "protected"})

    response = APIClient().get(
        reverse("api-internal:alerts-detail", kwargs={"id": alert.public_primary_key}),
        **make_user_auth_headers(user, token),
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
