import json

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from common.api_helpers.filters import NO_TEAM_VALUE


@pytest.fixture()
def escalation_chain_internal_api_setup(make_organization_and_user_with_plugin_token, make_escalation_chain):
    organization, user, token = make_organization_and_user_with_plugin_token()
    escalation_chain = make_escalation_chain(organization)
    return user, token, escalation_chain


@pytest.mark.django_db
def test_delete_escalation_chain(escalation_chain_internal_api_setup, make_user_auth_headers):
    user, token, escalation_chain = escalation_chain_internal_api_setup
    client = APIClient()
    url = reverse("api-internal:escalation_chain-detail", kwargs={"pk": escalation_chain.public_primary_key})

    response = client.delete(url, **make_user_auth_headers(user, token))
    assert response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.django_db
def test_update_escalation_chain(escalation_chain_internal_api_setup, make_user_auth_headers):
    user, token, escalation_chain = escalation_chain_internal_api_setup
    client = APIClient()
    url = reverse("api-internal:escalation_chain-detail", kwargs={"pk": escalation_chain.public_primary_key})
    data = {
        "name": "escalation_chain_updated",
        "organization": escalation_chain.organization.public_primary_key,
        "team": None,
    }
    response = client.put(
        url, data=json.dumps(data), content_type="application/json", **make_user_auth_headers(user, token)
    )
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_list_escalation_chains(escalation_chain_internal_api_setup, make_user_auth_headers):
    user, token, escalation_chain = escalation_chain_internal_api_setup
    client = APIClient()

    url = reverse("api-internal:escalation_chain-list")
    response = client.get(url, **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == [
        {
            "id": escalation_chain.public_primary_key,
            "name": escalation_chain.name,
            "number_of_integrations": 0,
            "number_of_routes": 0,
            "team": None,
        }
    ]


@pytest.mark.django_db
def test_list_escalation_chains_irm_contract_is_paginated(
    make_organization_and_user_with_plugin_token,
    make_escalation_chain,
    make_user_auth_headers,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    escalation_chains = [
        make_escalation_chain(organization, name="Primary"),
        make_escalation_chain(organization, name="Secondary"),
        make_escalation_chain(organization, name="Tertiary"),
    ]
    client = APIClient()
    headers = {
        **make_user_auth_headers(user, token),
        "HTTP_X_GRAFANA_IRM_API_CONTRACT": "0.114.0",
    }
    url = reverse("api-internal:escalation_chain-list")

    first_page = client.get(url + "?page=1&page_size=2", **headers)
    second_page = client.get(url + "?page=2&page_size=2", **headers)

    assert first_page.status_code == status.HTTP_200_OK
    assert second_page.status_code == status.HTTP_200_OK
    assert first_page.json()["count"] == 3
    assert first_page.json()["page_size"] == 2
    assert len(first_page.json()["results"]) == 2
    assert len(second_page.json()["results"]) == 1
    assert {item["id"] for page in (first_page, second_page) for item in page.json()["results"]} == {
        chain.public_primary_key for chain in escalation_chains
    }


@pytest.mark.django_db
def test_list_escalation_chains_filters(escalation_chain_internal_api_setup, make_user_auth_headers):
    user, token, escalation_chain = escalation_chain_internal_api_setup
    client = APIClient()

    url = reverse("api-internal:escalation_chain-list") + "?filters=true"
    response = client.get(url, **make_user_auth_headers(user, token))

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == [
        {
            "value": escalation_chain.public_primary_key,
            "display_name": escalation_chain.name,
        }
    ]

    irm_response = client.get(
        url,
        HTTP_X_GRAFANA_IRM_API_CONTRACT="0.114.0",
        **make_user_auth_headers(user, token),
    )
    assert irm_response.status_code == status.HTTP_200_OK
    assert irm_response.json() == response.json()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "team_name,new_team_name",
    [
        (None, None),
        (None, "team_1"),
        ("team_1", None),
        ("team_1", "team_1"),
        ("team_1", "team_2"),
    ],
)
def test_escalation_chain_copy(
    make_organization_and_user_with_plugin_token,
    make_user_auth_headers,
    make_escalation_chain,
    make_team,
    team_name,
    new_team_name,
):
    organization, user, token = make_organization_and_user_with_plugin_token()

    team = make_team(organization, name=team_name) if team_name else None
    new_team = make_team(organization, name=new_team_name) if new_team_name else None

    escalation_chain = make_escalation_chain(organization, team=team)
    data = {
        "name": "escalation_chain_updated",
        "team": new_team.public_primary_key if new_team else NO_TEAM_VALUE,
    }

    client = APIClient()
    url = reverse("api-internal:escalation_chain-copy", kwargs={"pk": escalation_chain.public_primary_key})
    response = client.post(url, data, format="json", **make_user_auth_headers(user, token))
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["team"] == (new_team.public_primary_key if new_team else None)


@pytest.mark.django_db
def test_escalation_chain_copy_empty_name(
    make_organization_and_user_with_plugin_token,
    make_user_auth_headers,
    make_escalation_chain,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    escalation_chain = make_escalation_chain(organization)

    client = APIClient()
    url = reverse("api-internal:escalation_chain-copy", kwargs={"pk": escalation_chain.public_primary_key})

    response = client.post(
        url, {"name": "", "team": NO_TEAM_VALUE}, format="json", **make_user_auth_headers(user, token)
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_team_not_updated_if_not_in_data(
    make_organization_and_user_with_plugin_token,
    make_team,
    make_escalation_chain,
    make_user_auth_headers,
):
    organization, user, token = make_organization_and_user_with_plugin_token()
    team = make_team(organization)
    escalation_chain = make_escalation_chain(organization, team=team)

    assert escalation_chain.team == team

    client = APIClient()
    url = reverse("api-internal:escalation_chain-detail", kwargs={"pk": escalation_chain.public_primary_key})
    data = {"name": "escalation_chain_updated"}
    response = client.put(url, data=data, format="json", **make_user_auth_headers(user, token))
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["team"] == escalation_chain.team.public_primary_key

    escalation_chain.refresh_from_db()
    assert escalation_chain.team == team
