"""Disposable original Django graph acceptance; operator must stop writers."""
import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.recorder import MigrationRecorder

from apps.slack.models import SharedSlackInstallation
from apps.slack.tests.test_shared_app import source_owner

pytestmark = pytest.mark.django_db(transaction=True)
OLD = ("slack", "0017_shared_slack_paging_command")
NEW = ("slack", "0018_shared_slack_source_owner")


def test_original_chain_cold_upgrade_preserves_token_role_and_unproved_rows(
        make_organization_and_user, make_slack_team_identity):
    org, user = make_organization_and_user()
    team = make_slack_team_identity(slack_id="T1", cached_app_id="A1", bot_user_id="UB1", bot_access_token="xoxb-test")
    org.slack_team_identity = team; org.save(update_fields=["slack_team_identity"])
    old_role = user.role
    executor = MigrationExecutor(connection)
    assert executor.loader.get_migration(*NEW).dependencies == [OLD]
    assert NEW in executor.loader.graph.leaf_nodes("slack")
    executor.migrate([OLD])
    try:
        old_apps = executor.loader.project_state([OLD]).apps
        old_install = old_apps.get_model("slack", "SharedSlackInstallation")
        old_install.objects.create(organization_id=org.pk, team_id=team.pk, assistant_enabled=True)
        MigrationExecutor(connection).migrate([NEW])
        row = SharedSlackInstallation.objects.get(organization_id=org.pk)
        assert row.source_owner is None and row.source_links == {} and row.source_links_revision == 1
        assert not row.source_disconnected
        org.refresh_from_db(); team.refresh_from_db(); user.refresh_from_db()
        assert org.slack_team_identity_id == team.pk and team.bot_access_token == "xoxb-test"
        assert user.role == old_role
    finally:
        MigrationExecutor(connection).migrate([NEW])


def test_populated_reverse_refuses_before_any_provenance_drop(make_organization, make_slack_team_identity):
    org = make_organization(); team = make_slack_team_identity()
    row = SharedSlackInstallation.objects.create(organization=org, team=team, source_owner=source_owner())
    with pytest.raises(RuntimeError, match="provenance"):
        MigrationExecutor(connection).migrate([OLD])
    assert NEW in MigrationRecorder(connection).applied_migrations()
    current = SharedSlackInstallation.objects.get(pk=row.pk)
    assert current.source_owner == source_owner()
    with connection.cursor() as cursor:
        columns = {item.name for item in connection.introspection.get_table_description(cursor, current._meta.db_table)}
    assert {"source_owner", "source_disconnected", "source_links", "source_links_revision"} <= columns


def test_legacy_empty_reverse_is_explicit_and_reversible():
    executor = MigrationExecutor(connection)
    executor.migrate([OLD])
    try:
        assert OLD in MigrationRecorder(connection).applied_migrations()
        assert NEW not in MigrationRecorder(connection).applied_migrations()
    finally:
        MigrationExecutor(connection).migrate([NEW])
