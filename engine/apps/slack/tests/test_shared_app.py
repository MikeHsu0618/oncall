import hashlib
import hmac
import json
import time
from unittest.mock import patch

import pytest
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory

from apps.api.permissions import LegacyAccessControlRole
from apps.slack.models import SharedSlackDelivery, SharedSlackInstallation, SlackTeamIdentity
from apps.slack.shared_app import SharedSlackAppView, route_manifest

pytestmark = pytest.mark.django_db(transaction=True)


def send(body, *, secret="bridge-secret", timestamp=None):
    raw = json.dumps({"version": 1, **body}).encode()
    timestamp = str(timestamp or int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    request = APIRequestFactory().post("/slack/shared-app/v1/", raw, content_type="application/json",
        HTTP_X_GRAFANA_SLACK_TIMESTAMP=timestamp, HTTP_X_GRAFANA_SLACK_SIGNATURE=signature)
    return SharedSlackAppView.as_view()(request)


def source_owner(token="xoxb-test", **changes):
    return {"version": 1, "stackId": "grafana-apps", "nativeOrgId": "1", "connectionId": "connection-1",
        "installationId": "installation-1", "installationIncarnation": 1,
        "teamId": "T1", "appId": "A1", "tokenSHA256": hashlib.sha256(token.encode()).hexdigest(), **changes}


def link_receipt(uid, *, slack_user="U1", revision=1):
    return {"version": 1, "slackUserId": slack_user, "grafanaUserId": uid,
        "mappingId": "mapping-1" if uid is not None else None,
        "grafanaLogin": "original-user" if uid is not None else None,
        "mappingLinkRevision": 1 if uid is not None else None, "linkRevision": revision}


def install_owner_transport(settings, monkeypatch):
    """Fake only pure connector HTTP; actual HMAC/JSON/SQL admission remains."""
    from types import SimpleNamespace
    from django.db import transaction
    settings.SHARED_SLACK_PUBLISH_VERIFY_URL = "http://connector/internal/irm/slack/oncall-publish-verify"
    settings.SHARED_SLACK_OWNER_VERIFY_URL = "http://connector/internal/irm/slack/oncall-owner-verify"
    settings.SHARED_SLACK_LINK_VERIFY_URL = "http://connector/internal/irm/slack/oncall-link-verify"
    settings.SHARED_SLACK_LINKS_VERIFY_URL = "http://connector/internal/irm/slack/oncall-links-verify"
    state = SimpleNamespace(calls=[], responses=[], mutate=None, status=200, raw=None, headers=None, chunk_mutate=None)
    class Reply:
        def __init__(self, raw):
            self.status_code = state.status
            self.raw = raw
            self.headers = state.headers if state.headers is not None else {"Content-Length": str(len(raw))}
            self.closed = False
        def iter_content(self, chunk_size):
            assert chunk_size == 1
            for index in range(len(self.raw)):
                if state.chunk_mutate is not None:
                    state.chunk_mutate(index)
                yield self.raw[index:index + 1]
        def close(self):
            self.closed = True
    class Client:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, **kwargs):
            assert not transaction.get_connection().in_atomic_block
            assert self.trust_env is False and kwargs["allow_redirects"] is False
            assert kwargs["timeout"] == (2.5, 2.5)
            raw = kwargs["data"]
            stamp = kwargs["headers"]["X-Grafana-Slack-Timestamp"]
            expected = hmac.new(settings.SHARED_SLACK_BRIDGE_SECRET.encode(), stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
            assert kwargs["headers"]["X-Grafana-Slack-Signature"] == expected
            state.calls.append((url, json.loads(raw)))
            if state.mutate is not None:
                state.mutate()
            result = Reply(state.raw if state.raw is not None else json.dumps({**json.loads(raw), "verified": True}).encode())
            state.responses.append(result)
            return result
    monkeypatch.setattr("apps.slack.shared_owner.requests.Session", Client)
    return state


@pytest.fixture
def connected(settings, make_organization_and_user, monkeypatch):
    organization, user = make_organization_and_user(role=LegacyAccessControlRole.ADMIN)
    settings.SHARED_SLACK_BRIDGE_SECRET = "bridge-secret"
    settings.SHARED_SLACK_DEFAULT_STACK_ID = "grafana-apps"
    settings.SHARED_SLACK_ORG_MAP = {"1": organization.pk}
    install_owner_transport(settings, monkeypatch)
    body = {"operation": "sync", "orgId": "1", "teamId": "T1", "installation": {
        "teamId": "T1", "teamName": "Test", "appId": "A1", "botToken": "xoxb-test", "botUserId": "UB1", "botId": "B1"},
        "link": link_receipt(str(user.user_id)), "sourceOwner": source_owner()}
    return organization, user, body


@pytest.fixture
def availability(settings, monkeypatch):
    """Mock only the signed transport, leaving fresh SQL ownership and rendering intact."""
    from types import SimpleNamespace

    settings.SHARED_SLACK_AVAILABILITY_URL = "http://connector/internal/irm/slack/availability"
    state = SimpleNamespace(enabled=True, calls=[], responses=[], mutate=None, status=200, raw=None, headers=None)

    class Reply:
        def __init__(self, raw):
            self.status_code = state.status
            self.raw = raw
            self.closed = False
            self.headers = state.headers if state.headers is not None else {"Content-Length": str(len(raw))}
            self.read_bytes = 0

        def iter_content(self, chunk_size):
            assert chunk_size == 1
            for offset in range(0, len(self.raw), chunk_size):
                self.read_bytes += chunk_size
                yield self.raw[offset:offset + chunk_size]

        def close(self):
            self.closed = True

    def post(url, **kwargs):
        state.calls.append((url, kwargs))
        if state.mutate:
            state.mutate()
        payload = json.loads(kwargs["data"])
        reply = Reply(state.raw if state.raw is not None else json.dumps({
            **payload, "assistantAvailable": state.enabled}).encode())
        state.responses.append(reply)
        return reply

    monkeypatch.setattr("apps.slack.assistant.requests.post", post)
    return state


def test_bad_signature_stale_and_unmapped_org_have_no_installation(connected):
    _, _, body = connected
    assert send(body, secret="wrong").status_code == 401
    assert send(body, timestamp=int(time.time()) - 301).status_code == 401
    assert send({**body, "orgId": "foreign"}).status_code == 403
    assert SlackTeamIdentity.objects.count() == 0


def test_install_sync_preserves_native_user_role_and_rotates_bot_token(connected):
    organization, user, body = connected
    role = user.role
    assert send(body).status_code == 200
    user.refresh_from_db()
    organization.refresh_from_db()
    assert user.role == role
    assert user.slack_user_identity.slack_id == "U1"
    assert organization.slack_team_identity.bot_access_token == "xoxb-test"
    rotated = {**body, "installation": {**body["installation"], "botToken": "xoxb-rotated"},
        "sourceOwner": source_owner("xoxb-rotated")}
    # Same App, rotated token: no counter is needed, the connector's fresh proof vouches for the digest.
    assert send(rotated).status_code == 200
    assert SlackTeamIdentity.objects.count() == 1
    assert SlackTeamIdentity.objects.get().bot_access_token == "xoxb-rotated"


def test_nonmember_and_different_app_cannot_overwrite_installation(connected):
    organization, user, body = connected
    assert send({**body, "link": link_receipt("999999")}).status_code == 403
    organization.refresh_from_db()
    assert organization.slack_team_identity_id is None
    assert send(body).status_code == 200
    assert send({**body, "installation": {**body["installation"], "appId": "A2"}}).status_code == 422
    assert SlackTeamIdentity.objects.get().cached_app_id == "A1"


def dispatch_body(body):
    return {**body, "operation": "dispatch", "deliveryId": "a" * 64, "payload": {
        "type": "block_actions", "api_app_id": "A1", "team": {"id": "T1"}, "user": {"id": "U1"},
        "trigger_id": "test-trigger",
        "channel": {"id": "C1"}, "message": {"ts": "123.4"},
        "actions": [{"action_id": "AcknowledgeGroupStep", "type": "button", "action_ts": "123.5", "value": "{}"}]}}


def test_repeated_native_delivery_runs_once_and_restores_modal_response(connected):
    organization, user, body = connected
    assert send(body).status_code == 200
    data = dispatch_body(body)
    data["payload"]["command"] = "/grafana"
    response = {"response_action": "errors", "errors": {"title": "Required"}}
    with patch("apps.slack.shared_app.SlackEventApiEndpointView.dispatch_payload", return_value=Response(response)) as native:
        assert send(data).data == response
        assert send(data).data == response
        native.assert_called_once()
        assert native.call_args.kwargs["scoped_organization"].pk == organization.pk


def test_ambiguous_native_dispatch_is_never_replayed(connected):
    _, _, body = connected
    assert send(body).status_code == 200
    data = dispatch_body(body)
    data["payload"]["command"] = "/grafana"
    with patch("apps.slack.shared_app.SlackEventApiEndpointView.dispatch_payload", side_effect=RuntimeError("lost")) as native:
        with pytest.raises(RuntimeError):
            send(data)
        assert send(data).status_code == 200
        native.assert_called_once()
    assert SharedSlackDelivery.objects.get().phase == "uncertain"


def test_unlinked_snapshot_removes_old_link_before_native_dispatch(connected):
    _, user, body = connected
    assert send(body).status_code == 200
    data = dispatch_body(body)
    data["payload"]["command"] = "/grafana"
    with patch("apps.slack.shared_app.SlackEventApiEndpointView.dispatch_payload", return_value=Response()) as native:
        send({**data, "link": link_receipt(None, revision=2)})
        user.refresh_from_db()
        assert user.slack_user_identity_id is None
        native.assert_called_once()


def test_payload_team_and_actor_must_match_service_snapshot(connected):
    _, _, body = connected
    data = dispatch_body(body)
    data["payload"]["team"]["id"] = "T2"
    assert send(data).status_code == 422
    data["payload"]["team"]["id"] = "T1"
    data["link"]["slackUserId"] = "U2"
    assert send(data).status_code == 422
    assert SlackTeamIdentity.objects.count() == 0


def test_disconnect_clears_native_installation_and_link(connected):
    organization, user, body = connected
    assert send(body).status_code == 200
    assert send({"operation": "disconnect", "orgId": "1", "teamId": "T1",
        "sourceOwner": source_owner()}).status_code == 200
    organization.refresh_from_db()
    user.refresh_from_db()
    assert organization.slack_team_identity_id is None
    assert user.slack_user_identity_id is None
    assert SlackTeamIdentity.objects.get().bot_access_token is None


def test_manifest_is_derived_from_native_scenarios():
    manifest = route_manifest()
    assert "AcknowledgeGroupStep" in manifest["actions"]
    assert "ResolveGroupStep" in manifest["actions"]
    assert "/grafana" in manifest["commands"]


@pytest.mark.parametrize("allowed", [True, False])
def test_original_acknowledge_scenario_enforces_native_role(connected, make_alert_receive_channel,
        make_alert_group, make_slack_channel, make_slack_message, allowed):
    from apps.alerts.models import AlertGroup
    organization, user, body = connected
    if not allowed:
        user.role = LegacyAccessControlRole.VIEWER
        user.permissions = []
        user.save(update_fields=["role", "permissions"])
    assert send(body).status_code == 200
    organization.refresh_from_db()
    group = make_alert_group(make_alert_receive_channel(organization))
    channel = make_slack_channel(organization.slack_team_identity, slack_id="C1")
    make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"])
    data = dispatch_body(body)
    data["payload"]["actions"][0]["value"] = json.dumps({"organization_id": organization.pk, "alert_group_pk": group.pk})
    # The real router resolves the native user; only the final side effect is mocked.
    with patch.object(AlertGroup, "acknowledge_by_user_or_backsync") as acknowledge, \
            patch("apps.slack.client.SlackClient.chat_postEphemeral"):
        assert send(data).status_code == 200
        if allowed:
            assert acknowledge.call_args.args[0].pk == user.pk
        else:
            acknowledge.assert_not_called()


def test_native_router_refuses_foreign_organization(connected, make_organization):
    from apps.alerts.models import AlertGroup
    organization, user, body = connected
    data = dispatch_body(body)
    foreign = make_organization()
    assert send(body).status_code == 200
    organization.refresh_from_db()
    foreign.slack_team_identity = organization.slack_team_identity
    foreign.save(update_fields=["slack_team_identity"])
    data["payload"]["command"] = "/grafana"
    data["payload"]["actions"][0]["value"] = json.dumps({"organization_id": foreign.pk})
    with patch.object(AlertGroup, "acknowledge_by_user_or_backsync") as acknowledge:
        assert send(data).status_code == 403
        acknowledge.assert_not_called()


@pytest.fixture
def alert_context(connected, make_alert_receive_channel, make_alert_group, make_alert, make_slack_channel, make_slack_message):
    organization, user, body = connected
    body["installation"]["assistantAvailable"] = True
    assert send(body).status_code == 200
    organization.refresh_from_db()
    group = make_alert_group(make_alert_receive_channel(organization))
    alert = make_alert(group, {"labels": {"service": "checkout"}, "annotations": {"summary": "Errors"}})
    channel = make_slack_channel(organization.slack_team_identity, slack_id="C1")
    make_slack_message(channel, alert_group=group, slack_id="123.4", source_owner=body["sourceOwner"])
    read = {"operation": "alert_context", "orgId": "1", "teamId": "T1", "channelId": "C1",
            "messageTs": "123.4", "alertGroupId": group.public_primary_key,
            "slackUserId": "U1", "grafanaUserId": str(user.user_id),
            "sourceOwner": body["sourceOwner"], "link": body["link"]}
    return organization, user, body, group, alert, read


@pytest.mark.parametrize("rbac", [True, False])
def test_alert_context_reads_fresh_state_as_viewer_without_mutation(alert_context, rbac):
    from apps.api.permissions import GrafanaAPIPermissions, RBACPermission, get_required_permission_values
    organization, user, body, group, alert, read = alert_context
    organization.is_rbac_permissions_enabled = rbac
    organization.save(update_fields=["is_rbac_permissions_enabled"])
    user.role = LegacyAccessControlRole.VIEWER
    user.permissions = GrafanaAPIPermissions.construct_permissions(get_required_permission_values(organization, [
        RBACPermission.Permissions.ALERT_GROUPS_READ, RBACPermission.Permissions.CHATOPS_READ
    ])) if rbac else []
    user.save(update_fields=["role", "permissions"])
    assert send(read).status_code == 200
    group.resolved = True
    group.save(update_fields=["resolved"])
    result = send(read)
    assert result.status_code == 200
    assert result.data["messageTs"] == "123.4"
    assert result.data["alertGroup"]["resolved"] is True
    assert json.loads(result.data["alertGroup"]["lastAlertPayload"])["labels"]["service"] == "checkout"
    assert SharedSlackDelivery.objects.count() == 0
    assert SlackTeamIdentity.objects.count() == 1


@pytest.mark.parametrize("field", ["teamId", "channelId", "messageTs", "alertGroupId", "grafanaUserId"])
def test_alert_context_cannot_read_a_foreign_root_or_user(alert_context, field):
    _, _, _, _, _, read = alert_context
    result = send({**read, field: "999999"})
    assert result.status_code in {403, 404, 503}
    assert result.data is None


def test_alert_context_enforces_native_team_visibility(alert_context, make_team):
    organization, user, _, group, _, read = alert_context
    organization.is_rbac_permissions_enabled = False
    organization.save(update_fields=["is_rbac_permissions_enabled"])
    user.role = LegacyAccessControlRole.VIEWER
    user.permissions = []
    user.save(update_fields=["role", "permissions"])
    team = make_team(organization, is_sharing_resources_to_all=False)
    group.channel.team = team
    group.channel.save(update_fields=["team"])
    assert send(read).status_code == 404
    team.users.add(user)
    assert send(read).status_code == 200


def test_alert_context_enforces_native_rbac_but_not_render_availability_snapshot(alert_context):
    organization, user, body, _, _, read = alert_context
    organization.is_rbac_permissions_enabled = True
    organization.save(update_fields=["is_rbac_permissions_enabled"])
    user.permissions = []
    user.save(update_fields=["permissions"])
    assert send(read).status_code == 403
    organization.is_rbac_permissions_enabled = False
    organization.save(update_fields=["is_rbac_permissions_enabled"])
    body["installation"]["assistantAvailable"] = False
    assert send(body).status_code == 200
    assert send(read).status_code == 200
    assert organization.slack_team_identity_id is not None


def test_alert_context_rejects_wiped_alert_and_bounds_context(alert_context):
    _, _, _, group, alert, read = alert_context
    alert.raw_request_data = {"description": "x" * 20000}
    alert.save(update_fields=["raw_request_data"])
    result = send(read).data["alertGroup"]
    assert len(result["lastAlertPayload"]) == 12000 and result["payloadTruncated"] is True
    from django.utils import timezone
    group.wiped_at = timezone.now()
    group.save(update_fields=["wiped_at"])
    assert send(read).status_code == 404


@pytest.mark.django_db(transaction=True)
def test_native_alert_card_adds_assistant_only_when_available(alert_context, availability):
    from apps.alerts.incident_appearance.renderers.slack_renderer import AlertGroupSlackRenderer
    from apps.slack.assistant import INVESTIGATE_ALERT_ACTION_ID

    organization, _, body, group, _, read = alert_context
    native = AlertGroupSlackRenderer(group)._get_buttons_blocks()[0]["elements"]
    button = next(b for b in native if b["action_id"] == INVESTIGATE_ALERT_ACTION_ID)
    assert button["text"]["text"] == "Investigate this alert"
    assert button["value"] == group.public_primary_key
    assert any(b["action_id"].startswith("AcknowledgeGroupStep") for b in native)
    body["installation"]["assistantAvailable"] = False
    assert send(body).status_code == 200
    availability.enabled = False
    native = AlertGroupSlackRenderer(group)._get_buttons_blocks()[0]["elements"]
    assert all(b["action_id"] != INVESTIGATE_ALERT_ACTION_ID for b in native)
    assert any(b["action_id"].startswith("AcknowledgeGroupStep") for b in native)
    assert send({"operation": "disconnect", "orgId": "1", "teamId": "T1",
        "sourceOwner": source_owner()}).status_code == 200
    assert SharedSlackInstallation.objects.get(organization=organization).source_disconnected is True


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("enabled", [True, False, "outage"])
def test_attached_alert_message_retains_native_actions_and_assistant(
        alert_context, availability, make_alert_group, make_alert, enabled, monkeypatch):
    from apps.alerts.incident_appearance.renderers.slack_renderer import AlertGroupSlackRenderer
    from apps.slack.assistant import INVESTIGATE_ALERT_ACTION_ID

    _, _, _, group, _, _ = alert_context
    parent = make_alert_group(group.channel)
    make_alert(parent, {})
    group.root_alert_group = parent
    group.save(update_fields=["root_alert_group"])
    availability.enabled = enabled is True
    if enabled == "outage":
        import requests
        def timeout(*args, **kwargs):
            raise requests.Timeout()
        monkeypatch.setattr("apps.slack.assistant.requests.post", timeout)
    attachments = AlertGroupSlackRenderer(group).render_alert_group_attachments()
    assert attachments[0]["actions"][0]["text"] == "Unattach"
    elements = [element for attachment in attachments for block in attachment.get("blocks", [])
                for element in block.get("elements", [])]
    assert (any(element["action_id"] == INVESTIGATE_ALERT_ACTION_ID for element in elements)) is (enabled is True)
    if enabled is True:
        assert elements[0]["value"] == group.public_primary_key
