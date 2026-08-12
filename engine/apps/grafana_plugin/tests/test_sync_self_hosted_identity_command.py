from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.test import override_settings

from apps.grafana_plugin.tests.test_self_hosted_install import (
    CLUSTER_SLUG,
    ORG_ID,
    ORG_SLUG,
    ORG_TITLE,
    REGION_SLUG,
    SELF_HOSTED_SETTINGS,
    STACK_ID,
    STACK_SLUG,
)


@override_settings(SELF_HOSTED_SETTINGS=SELF_HOSTED_SETTINGS)
@pytest.mark.django_db
@patch("apps.grafana_plugin.management.commands.sync_self_hosted_identity.calculate_and_cache_user_was_notified_metric")
@patch("apps.grafana_plugin.management.commands.sync_self_hosted_identity.calculate_and_cache_metrics")
def test_sync_self_hosted_identity_updates_existing_organization(
    mocked_calculate_metrics,
    mocked_calculate_user_metrics,
    make_organization,
):
    organization = make_organization(
        stack_id=STACK_ID,
        org_id=ORG_ID,
        stack_slug="stale_stack_slug",
        org_slug="stale_org_slug",
        org_title="Stale organization title",
        region_slug="stale_region_slug",
        cluster_slug="stale_cluster_slug",
    )

    call_command("sync_self_hosted_identity")

    organization.refresh_from_db()
    assert organization.stack_slug == STACK_SLUG
    assert organization.org_slug == ORG_SLUG
    assert organization.org_title == ORG_TITLE
    assert organization.region_slug == REGION_SLUG
    assert organization.cluster_slug == CLUSTER_SLUG
    mocked_calculate_metrics.run.assert_called_once_with(organization.id)
    mocked_calculate_user_metrics.run.assert_called_once_with(organization.id)


@override_settings(SELF_HOSTED_SETTINGS=SELF_HOSTED_SETTINGS)
@pytest.mark.django_db
def test_sync_self_hosted_identity_is_a_noop_before_install():
    call_command("sync_self_hosted_identity")
