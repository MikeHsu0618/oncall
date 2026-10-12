"""Real native SQL writers for two stacks whose Grafana org IDs are equal."""
import copy
import json

import pytest

from apps.api.permissions import LegacyAccessControlRole
from apps.slack.assistant import assistant_available
from apps.slack.models import SharedSlackInstallation, SlackTeamIdentity
from apps.slack.shared_owner import SharedOwnerError, SharedSourceOwner, local_source_snapshot, shared_org_mapping
from apps.slack.tests.test_shared_app import availability, install_owner_transport, link_receipt, send, source_owner

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def stacks(settings, monkeypatch, make_organization_and_user):
    a, user_a = make_organization_and_user(role=LegacyAccessControlRole.ADMIN)
    b, user_b = make_organization_and_user(role=LegacyAccessControlRole.VIEWER)
    # Numeric identity is also scoped by the existing native Organization.
    for user in (user_a, user_b):
        user.user_id = 7
        user.save(update_fields=["user_id"])
    settings.SHARED_SLACK_BRIDGE_SECRET = "bridge-secret"
    settings.SHARED_SLACK_DEFAULT_STACK_ID = "grafana-apps"
    settings.SHARED_SLACK_ORG_MAP = {"grafana-apps": {"1": a.pk}, "secondary": {"1": b.pk}}
    wire = install_owner_transport(settings, monkeypatch)
    body_a = {"operation": "sync", "orgId": "1", "teamId": "T1", "installation": {
        "teamId": "T1", "teamName": "Test", "appId": "A1", "botToken": "xoxb-test", "botUserId": "UB1", "botId": "B1"},
        "link": link_receipt("7"), "sourceOwner": source_owner()}
    body_b = {**copy.deepcopy(body_a), "sourceOwner": source_owner(stackId="secondary",
        bindingDigest="b" * 64, connectionId="connection-b", installationId="installation-b")}
    return a, user_a, body_a, b, user_b, body_b, wire


def test_equal_org_and_user_ids_keep_distinct_original_native_owners(stacks):
    a, user_a, body_a, b, user_b, body_b, _ = stacks
    for body in (body_a, body_b):
        assert send(body).status_code == 200
    a.refresh_from_db(); b.refresh_from_db(); user_a.refresh_from_db(); user_b.refresh_from_db()
    assert a.slack_team_identity_id == b.slack_team_identity_id
    assert SlackTeamIdentity.objects.count() == 1
    assert SharedSlackInstallation.objects.count() == 2
    assert a.shared_slack_installation.source_owner == body_a["sourceOwner"]
    assert b.shared_slack_installation.source_owner == body_b["sourceOwner"]
    assert user_a.user_id == user_b.user_id == 7
    assert user_a.role == LegacyAccessControlRole.ADMIN
    assert user_b.role == LegacyAccessControlRole.VIEWER
    assert user_a.slack_user_identity_id == user_b.slack_user_identity_id
    assert local_source_snapshot(a.slack_team_identity_id, a.pk)[1].stack_id == "grafana-apps"
    assert local_source_snapshot(b.slack_team_identity_id, b.pk)[1].stack_id == "secondary"
    with pytest.raises(SharedOwnerError):
        local_source_snapshot(a.slack_team_identity_id)


@pytest.mark.parametrize("change", ["unknown_stack", "wrong_org", "missing_owner", "alias_pk", "flat_secondary"])
def test_payload_cannot_pick_a_stack_or_alias_an_existing_owner(stacks, settings, change):
    a, _, body_a, b, _, body_b, wire = stacks
    assert send(body_a).status_code == 200
    body = copy.deepcopy(body_b)
    if change == "unknown_stack":
        body["sourceOwner"]["stackId"] = "unknown"
    elif change == "wrong_org":
        body["orgId"] = "2"
    elif change == "missing_owner":
        body.pop("sourceOwner")
    elif change == "alias_pk":
        settings.SHARED_SLACK_ORG_MAP = {"grafana-apps": {"1": a.pk}, "secondary": {"1": a.pk}}
    else:
        settings.SHARED_SLACK_ORG_MAP = {"1": a.pk}
    before = len(wire.calls)
    assert send(body).status_code in {403, 503}
    assert len(wire.calls) == before
    assert SharedSlackInstallation.objects.count() == 1
    b.refresh_from_db()
    assert b.slack_team_identity_id is None
    assert a.shared_slack_installation.source_owner == body_a["sourceOwner"]


def test_flat_compatibility_requires_explicit_default(stacks, settings):
    a, _, body_a, _, _, _, wire = stacks
    settings.SHARED_SLACK_ORG_MAP = {"1": a.pk}
    settings.SHARED_SLACK_DEFAULT_STACK_ID = ""
    assert send(body_a).status_code == 403
    assert wire.calls == []
    settings.SHARED_SLACK_DEFAULT_STACK_ID = "grafana-apps"
    assert send(body_a).status_code == 200
    assert shared_org_mapping() == {("grafana-apps", "1"): a.pk}


def test_new_peer_cannot_replace_shared_physical_token(stacks):
    a, _, body_a, b, _, body_b, _ = stacks
    assert send(body_a).status_code == 200
    body = copy.deepcopy(body_b)
    body["installation"]["botToken"] = "xoxb-other"
    body["sourceOwner"] = source_owner("xoxb-other", **{
        key: value for key, value in body_b["sourceOwner"].items() if key not in {"tokenSHA256"}})
    assert send(body).status_code == 409
    assert SlackTeamIdentity.objects.get().bot_access_token == "xoxb-test"
    assert SharedSlackInstallation.objects.count() == 1
    b.refresh_from_db()
    assert b.slack_team_identity_id is None


def test_map_change_during_verification_rolls_back_native_sync(stacks, settings):
    a, _, body_a, b, _, body_b, wire = stacks
    assert send(body_a).status_code == 200
    wire.mutate = lambda: setattr(settings, "SHARED_SLACK_ORG_MAP", {"grafana-apps": {"1": a.pk}})
    assert send(body_b).status_code == 503
    b.refresh_from_db()
    assert b.slack_team_identity_id is None
    assert SharedSlackInstallation.objects.count() == 1
    assert SlackTeamIdentity.objects.get().bot_access_token == "xoxb-test"


def test_disconnect_one_stack_preserves_peer_org_user_and_token(stacks):
    a, user_a, body_a, b, user_b, body_b, _ = stacks
    assert send(body_a).status_code == send(body_b).status_code == 200
    disconnect = {"operation": "disconnect", "orgId": "1", "teamId": "T1",
        "sourceOwner": {**body_b["sourceOwner"], "connectionGeneration": 2}}
    assert send(disconnect).status_code == 200
    a.refresh_from_db(); b.refresh_from_db(); user_a.refresh_from_db(); user_b.refresh_from_db()
    assert b.slack_team_identity_id is None
    assert user_b.slack_user_identity_id is None
    assert a.slack_team_identity_id is not None
    assert user_a.slack_user_identity_id is not None
    assert SlackTeamIdentity.objects.get().bot_access_token == "xoxb-test"
    assert b.shared_slack_installation.source_disconnected
    assert not a.shared_slack_installation.source_disconnected


def test_selected_availability_sends_current_original_source_owner(stacks, availability):
    a, _, body_a, b, _, body_b, _ = stacks
    assert send(body_a).status_code == send(body_b).status_code == 200
    for org, body in ((a, body_a), (b, body_b)):
        assert assistant_available(org)
        payload = json.loads(availability.calls[-1][1]["data"])
        assert payload == {"version": 1, "orgId": "1", "teamId": "T1", "appId": "A1",
            "installationFingerprint": body["sourceOwner"]["tokenSHA256"], "sourceOwner": body["sourceOwner"]}
    assert all(reply.closed for reply in availability.responses)


def test_availability_map_change_during_read_refuses_without_default_fallback(stacks, availability, settings):
    a, _, body_a, b, _, body_b, _ = stacks
    assert send(body_a).status_code == send(body_b).status_code == 200
    availability.mutate = lambda: setattr(settings, "SHARED_SLACK_ORG_MAP", {"grafana-apps": {"1": a.pk}})
    assert assistant_available(b) is False
    assert json.loads(availability.calls[-1][1]["data"])["sourceOwner"] == body_b["sourceOwner"]
    before = len(availability.calls)
    assert assistant_available(b) is False
    assert len(availability.calls) == before


def test_ownerless_availability_compatibility_is_only_explicit_default(stacks, availability):
    a, _, body_a, b, _, body_b, _ = stacks
    assert send(body_a).status_code == send(body_b).status_code == 200
    SharedSlackInstallation.objects.update(source_owner=None)
    assert assistant_available(a)
    assert "sourceOwner" not in json.loads(availability.calls[-1][1]["data"])
    before = len(availability.calls)
    assert assistant_available(b) is False
    assert len(availability.calls) == before


def test_existing_owner_rotation_invalidates_peer_until_its_current_sync(stacks):
    a, _, body_a, b, _, body_b, _ = stacks
    assert send(body_a).status_code == send(body_b).status_code == 200
    rotated_a = copy.deepcopy(body_a)
    rotated_a["installation"]["botToken"] = "xoxb-rotated"
    rotated_a["sourceOwner"] = source_owner("xoxb-rotated", credentialRevision=2)
    assert send(rotated_a).status_code == 200
    a.refresh_from_db(); b.refresh_from_db()
    assert local_source_snapshot(a.slack_team_identity_id, a.pk)[1] == SharedSourceOwner.parse(rotated_a["sourceOwner"])
    with pytest.raises(SharedOwnerError):
        local_source_snapshot(b.slack_team_identity_id, b.pk)
    rotated_b = copy.deepcopy(body_b)
    rotated_b["installation"]["botToken"] = "xoxb-rotated"
    rotated_b["sourceOwner"].update(tokenSHA256=rotated_a["sourceOwner"]["tokenSHA256"], credentialRevision=2)
    assert send(rotated_b).status_code == 200
    assert local_source_snapshot(b.slack_team_identity_id, b.pk)[1] == SharedSourceOwner.parse(rotated_b["sourceOwner"])


def test_disconnected_original_owner_rejoins_higher_binding_without_new_physical_identity(stacks):
    a, user_a, body, _, _, _, _ = stacks
    assert send(body).status_code == 200
    old = {**body["sourceOwner"], "connectionGeneration": 2}
    disconnected = send({"operation": "disconnect", "orgId": "1", "teamId": "T1", "sourceOwner": old})
    assert disconnected.status_code == 200
    assert disconnected.data == {"version": 1, "sourceOwner": old, "sourceDisconnected": True, "organizationUnlinked": True}
    assert send({"operation": "disconnect", "orgId": "1", "teamId": "T1", "sourceOwner": old}).data == disconnected.data
    source = SharedSlackInstallation.objects.get(organization=a)
    team_pk = source.team_id
    assert source.source_disconnected
    assert SlackTeamIdentity.objects.get(pk=team_pk).bot_access_token is None
    new = copy.deepcopy(body)
    new["sourceOwner"].update(bindingRevision=2, bindingDigest="c" * 64, connectionGeneration=3)
    assert send(new).status_code == 200
    source.refresh_from_db(); a.refresh_from_db(); user_a.refresh_from_db()
    assert source.source_owner == new["sourceOwner"] and not source.source_disconnected
    assert source.team_id == a.slack_team_identity_id == team_pk
    assert SlackTeamIdentity.objects.get(pk=team_pk).bot_access_token == "xoxb-test"
    assert user_a.role == LegacyAccessControlRole.ADMIN


@pytest.mark.parametrize("failure", ["active", "stack", "org", "connection", "installation", "app",
                                   "token", "incarnation", "credential", "binding_revision", "generation"])
def test_new_binding_never_retargets_active_or_different_native_source(stacks, failure, settings):
    a, _, body, _, _, _, _ = stacks
    assert send(body).status_code == 200
    old = {**body["sourceOwner"], "connectionGeneration": 2}
    if failure != "active":
        assert send({"operation": "disconnect", "orgId": "1", "teamId": "T1", "sourceOwner": old}).status_code == 200
    new = copy.deepcopy(body)
    new["sourceOwner"].update(bindingRevision=2, bindingDigest="c" * 64, connectionGeneration=3)
    changes = {"stack": ("stackId", "secondary"), "org": ("nativeOrgId", "2"),
        "connection": ("connectionId", "foreign"), "installation": ("installationId", "foreign"),
        "app": ("appId", "A2"), "token": ("tokenSHA256", "d" * 64),
        "incarnation": ("installationIncarnation", 2), "credential": ("credentialRevision", 2),
        "binding_revision": ("bindingRevision", 1), "generation": ("connectionGeneration", 2)}
    if failure in changes:
        key, value = changes[failure]
        new["sourceOwner"][key] = value
    if failure == "stack":
        # Explicit operator default/map switch still cannot rebind the old
        # native Organization to another stack, even with a positive verifier.
        settings.SHARED_SLACK_ORG_MAP = {"secondary": {"1": a.pk}}
    elif failure == "org":
        new["orgId"] = "2"
        settings.SHARED_SLACK_ORG_MAP = {"grafana-apps": {"2": a.pk}}
    elif failure == "app":
        new["installation"]["appId"] = "A2"
    elif failure == "token":
        new["installation"]["botToken"] = "xoxb-foreign"
        import hashlib
        new["sourceOwner"]["tokenSHA256"] = hashlib.sha256(b"xoxb-foreign").hexdigest()
    before = list(SharedSlackInstallation.objects.values("organization_id", "team_id", "source_owner", "source_disconnected"))
    token = SlackTeamIdentity.objects.get().bot_access_token
    assert send(new).status_code != 200
    assert list(SharedSlackInstallation.objects.values("organization_id", "team_id", "source_owner", "source_disconnected")) == before
    assert SlackTeamIdentity.objects.get().bot_access_token == token
