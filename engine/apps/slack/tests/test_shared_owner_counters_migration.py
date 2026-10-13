"""0019: every stored source owner loses the connector's dropped counters (IRM P4)."""
from datetime import timedelta
from uuid import uuid4

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.slack.models import SharedSlackDelivery, SharedSlackInstallation, SharedSlackPagingSession, SlackMessage
from apps.slack.shared_owner import SharedSourceOwner
from apps.slack.tests.test_shared_app import source_owner

pytestmark = pytest.mark.django_db(transaction=True)
OLD = ("slack", "0018_shared_slack_source_owner")
NEW = ("slack", "0019_shared_slack_owner_counters")
COUNTERS = {"bindingRevision": 1, "bindingDigest": "a" * 64, "connectionGeneration": 2, "credentialRevision": 3}


def test_upgrade_strips_counters_from_every_stored_owner_and_modal_receipt(
        make_organization_and_user, make_slack_team_identity, make_alert_receive_channel, make_alert_group,
        make_slack_channel, make_slack_message):
    org, user = make_organization_and_user()
    team = make_slack_team_identity(slack_id="T1", cached_app_id="A1", bot_user_id="UB1", bot_access_token="xoxb-test")
    org.slack_team_identity = team
    org.save(update_fields=["slack_team_identity"])
    old_owner = {**source_owner(), **COUNTERS}
    executor = MigrationExecutor(connection)
    assert executor.loader.get_migration(*NEW).dependencies == [OLD]
    executor.migrate([OLD])
    try:
        # 0019 changes data only, so the current models write the 0018 schema.
        SharedSlackInstallation.objects.create(organization=org, team=team, source_owner=old_owner)
        SharedSlackDelivery.objects.create(key="d" * 64, source_owner=old_owner, modal_owners={
            "V1": {"organizationId": org.pk, "sourceOwner": old_owner, "slackUserId": "U1"}})
        group = make_alert_group(make_alert_receive_channel(org))
        message = make_slack_message(make_slack_channel(team, slack_id="C1"), alert_group=group,
                                     slack_id="123.4", source_owner=old_owner)
        SharedSlackPagingSession.objects.create(organization=org, team=team, reservation_token=uuid4(),
            grafana_org_id="1", slack_user_id="U1", grafana_user_id=str(user.user_id), app_id="A1",
            bot_user_id="UB1", source_owner=old_owner, incident_context={}, view_id="V2",
            expires_at=timezone.now() + timedelta(minutes=15))
        MigrationExecutor(connection).migrate([NEW])
        new = SharedSourceOwner.parse(source_owner()).projection()
        assert SharedSlackInstallation.objects.get(organization=org).source_owner == new
        delivery = SharedSlackDelivery.objects.get(key="d" * 64)
        assert delivery.source_owner == new and delivery.modal_owners["V1"]["sourceOwner"] == new
        assert delivery.modal_owners["V1"]["slackUserId"] == "U1"
        assert SlackMessage.objects.get(pk=message.pk).source_owner == new
        assert SharedSlackPagingSession.objects.get(view_id="V2").source_owner == new
    finally:
        MigrationExecutor(connection).migrate([NEW])


def test_populated_reverse_refuses(make_organization, make_slack_team_identity):
    org = make_organization()
    team = make_slack_team_identity()
    SharedSlackInstallation.objects.create(organization=org, team=team, source_owner=source_owner())
    with pytest.raises(RuntimeError, match="cannot be reconstructed"):
        MigrationExecutor(connection).migrate([OLD])
