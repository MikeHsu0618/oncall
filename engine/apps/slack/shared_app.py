"""Versioned local adapter for the shared Grafana Slack app.

The connector owns installation and verified linking. This adapter never
creates an OnCall user or changes their role; native scenarios own permission.
"""

import hashlib
import hmac
import json
import time
import re

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.slack.models import SharedSlackDelivery, SharedSlackInstallation, SlackMessage, SlackTeamIdentity, SlackUserIdentity
from apps.slack.views import SCENARIOS_ROUTES, SlackEventApiEndpointView
from apps.slack.shared_owner import (SharedOwnerError, SharedSourceOwner, strict_json, using_shared_owner, verify_source, parse_link,
    verify_link_source, verify_links_source, using_shared_delivery, modal_owner, _verification_config, _identifier, _slack, using_loading_view, selected_loading_view, require_local_source,
    shared_organization_id, default_shared_organization_id)
from apps.user_management.models import Organization

MAX_BODY_BYTES = 512 * 1024



def require_verification_configuration(owner_proof, link_proof=None, links_proof=None):
    for proof, setting in ((owner_proof, "SHARED_SLACK_OWNER_VERIFY_URL"),
                           (link_proof, "SHARED_SLACK_LINK_VERIFY_URL"),
                           (links_proof, "SHARED_SLACK_LINKS_VERIFY_URL")):
        if proof is not None and _verification_config(setting) != proof:
            raise SharedOwnerError()


def route_manifest():
    """Derive routing from the native registry, so new scenarios need no copied list."""
    def values(key):
        result = set()
        for route in SCENARIOS_ROUTES:
            value = route.get(key)
            if isinstance(value, str):
                result.add(value)
            elif isinstance(value, (list, tuple)):
                result.update(value)
        return sorted(result)

    loading = {}
    for route in SCENARIOS_ROUTES:
        operation = getattr(route.get("step"), "shared_loading_operation", None)
        if operation is None:
            continue
        action_ids = route.get("block_action_id")
        for action_id in action_ids if isinstance(action_ids, (list, tuple)) else [action_ids]:
            if isinstance(action_id, str):
                if action_id in loading and loading[action_id] != operation:
                    raise SharedOwnerError()
                loading[action_id] = operation
    return {"version": 1, "actions": values("block_action_id"),
            "loadingActions": [{"actionId": key, "operation": loading[key]} for key in sorted(loading)],
            "loadingCommands": [{"command": "/" + settings.SLACK_IRM_ROOT_COMMAND, "subcommand": "escalate", "operation": "open"}],
            "loadingShortcuts": [],
            "options": values("block_suggestion_action_id"),
            "views": values("view_callback_id"), "shortcuts": values("message_action_callback_id"),
            "events": values("event_type"), "commands": ["/" + settings.SLACK_IRM_ROOT_COMMAND]}


def authenticated(request):
    secret = getattr(settings, "SHARED_SLACK_BRIDGE_SECRET", "")
    timestamp = request.META.get("HTTP_X_GRAFANA_SLACK_TIMESTAMP", "")
    signature = request.META.get("HTTP_X_GRAFANA_SLACK_SIGNATURE", "")
    if (not isinstance(secret, str) or not secret or not isinstance(timestamp, str)
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,18})", timestamp) is None
            or not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{64}", signature) is None):
        return False
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
        expected = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + request.body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except (TypeError, ValueError, UnicodeError):
        return False


def payload_team(payload):
    team = payload.get("team")
    return team.get("id") if isinstance(team, dict) else payload.get("team_id")


def payload_user(payload):
    user = payload.get("user")
    event = payload.get("event") or {}
    return user.get("id") if isinstance(user, dict) else payload.get("user_id") or event.get("user")


class SharedSlackAppView(APIView):
    authentication_classes = ()
    permission_classes = ()

    def post(self, request):
        if len(request.body) > MAX_BODY_BYTES:
            return Response(status=413)
        if not authenticated(request):
            return Response(status=401)
        try:
            data = strict_json(request.body)
        except SharedOwnerError:
            return Response(status=422)
        if not isinstance(data, dict) or type(data.get("version")) is not int or data.get("version") != 1:
            return Response(status=422)
        if data.get("operation") == "origin":
            return self.origin(data)
        if data.get("links") is None and len(request.body) > 64 * 1024:
            return Response(status=413)
        try:
            owner = SharedSourceOwner.parse(data.get("sourceOwner")) if data.get("sourceOwner") is not None else None
        except SharedOwnerError:
            return Response(status=503)
        try:
            if owner is not None:
                if owner.native_org_id != data.get("orgId"):
                    return Response(status=403)
                oncall_id = shared_organization_id(owner)
            elif data.get("operation") == "routes":
                oncall_id = default_shared_organization_id(data.get("orgId"))
            else:
                return Response(status=503)
        except SharedOwnerError:
            return Response(status=403)
        try:
            organization = Organization.objects.get(pk=oncall_id)
        except Organization.DoesNotExist:
            return Response(status=404)
        operation = data.get("operation")
        if operation == "routes":
            return Response(route_manifest())
        if operation == "alert_context":
            return self.alert_context(organization, data)
        if operation not in {"sync", "dispatch", "disconnect", "incident_paging_start"}:
            return Response(status=422)
        team_id = data.get("teamId")
        if not isinstance(team_id, str) or not team_id or len(team_id) > 100:
            return Response(status=422)
        try:
            if owner.native_org_id != str(data.get("orgId")) or owner.team_id != team_id:
                return Response(status=422)
            if operation == "dispatch" and isinstance(data.get("payload"), dict):
                payload = data["payload"]
                if payload_team(payload) != team_id or payload.get("api_app_id") != owner.app_id:
                    return Response(status=422)
                key = hashlib.sha256(json.dumps([organization.pk, team_id, payload], sort_keys=True).encode()).hexdigest()
                completed = SharedSlackDelivery.objects.filter(key=key, phase="completed").first()
                if completed is not None:
                    if completed.source_owner != owner.projection():
                        return Response(status=409)
                    return Response(completed.response_data, status=completed.response_status)
            owner_proof = verify_source(owner, "disconnect" if operation == "disconnect" else "sync")
        except SharedOwnerError:
            return Response(status=503)
        if operation == "disconnect":
            return self.disconnect(organization, team_id, owner, owner_proof)
        installation = data.get("installation")
        if not isinstance(installation, dict) or installation.get("teamId") != team_id:
            return Response(status=422)
        if installation.get("appId") != owner.app_id:
            return Response(status=422)
        token = installation.get("botToken")
        bot_user = installation.get("botUserId")
        if not isinstance(token, str) or not token.startswith("xoxb-") or len(token) > 255:
            return Response(status=422)
        if not _slack(bot_user, "[UW]"):
            return Response(status=422)
        if hashlib.sha256(token.encode()).hexdigest() != owner.token_sha256:
            return Response(status=422)
        assistant_enabled = installation.get("assistantAvailable", False)
        if not isinstance(assistant_enabled, bool):
            return Response(status=422)
        payload = data.get("payload")
        if operation in {"dispatch", "incident_paging_start"} and (not isinstance(payload, dict) or payload_team(payload) != team_id):
            return Response(status=422)
        if operation in {"dispatch", "incident_paging_start"} and payload.get("api_app_id") != owner.app_id:
            return Response(status=422)
        loading_view = data.get("loadingView") if operation == "dispatch" else None
        deferred = data.get("deferredViewSubmission", False)
        if type(deferred) is not bool or deferred and (operation != "dispatch" or payload.get("type") != "view_submission"):
            return Response(status=422)
        link = data.get("link")
        actor = payload_user(payload) if operation in {"dispatch", "incident_paging_start"} else None
        if operation == "dispatch" and not actor:
            event = payload.get("event")
            if (payload.get("type") != "event_callback" or not isinstance(event, dict)
                    or event.get("type") not in {"subteam_created", "subteam_updated", "subteam_members_changed"}):
                return Response(status=403)
        if actor and link is None:
            return Response(status=422)
        links_snapshot = data.get("links")
        links_revision = data.get("linksRevision")
        link_proof = links_proof = None
        try:
            if link is not None:
                link = parse_link(link)
                if actor and link["slackUserId"] != actor:
                    return Response(status=422)
                link_proof = verify_link_source(owner, link)
            if links_snapshot is not None or links_revision is not None:
                if operation != "sync" or link is not None:
                    return Response(status=422)
                links_proof = verify_links_source(owner, links_revision, links_snapshot)
        except SharedOwnerError:
            return Response(status=503)
        if operation in {"dispatch", "incident_paging_start"} and (not isinstance(data.get("deliveryId"), str)
                                         or len(data["deliveryId"]) != 64):
            return Response(status=422)
        # Never silently overwrite an independently installed legacy workspace/app.
        with transaction.atomic():
            organization = Organization.objects.select_for_update().get(pk=organization.pk)
            source = SharedSlackInstallation.objects.select_for_update().filter(organization=organization).first()
            previous = None
            if source is not None and source.source_owner is not None:
                try:
                    previous = SharedSourceOwner.parse(source.source_owner)
                    if (operation == "sync" and source.source_disconnected
                            and (owner.binding_revision, owner.binding_digest) != (previous.binding_revision, previous.binding_digest)):
                        owner.require_reenrollment(previous)
                    else:
                        owner.require_successor(previous)
                    if (operation != "sync" and (owner != previous or source.source_disconnected)
                            or source.source_disconnected and owner.connection_generation <= previous.connection_generation):
                        return Response(status=409)
                except SharedOwnerError:
                    return Response(status=409)
            if operation != "sync" and previous is None:
                return Response(status=409)
            team = organization.slack_team_identity
            if operation == "dispatch" and (team is None or not self.original_payload_owner(organization, team, owner, payload)):
                return Response(status=409)
            if team and (team.slack_id != team_id or
                         (team.bot_user_id and team.bot_user_id != bot_user) or
                         (team.cached_app_id and team.cached_app_id != installation.get("appId") and previous is None)):
                return Response({"detail": "Existing Slack installation requires an explicit migration"}, status=409)
            if source is not None:
                if (link is not None and link["linkRevision"] < source.source_links_revision
                        or links_snapshot is not None and links_revision < source.source_links_revision):
                    return Response(status=409)
                if link is not None:
                    previous_link = source.source_links.get(link["slackUserId"])
                    if (previous_link is not None and previous_link["linkRevision"] == link["linkRevision"]
                            and previous_link != link):
                        return Response(status=409)
            user = None
            if link is not None and link.get("grafanaUserId"):
                user = organization.users.filter(user_id=str(link["grafanaUserId"])).first()
                if user is None:
                    return Response({"detail": "Grafana user is not an OnCall member"}, status=403)
            candidates = list(SlackTeamIdentity.objects.select_for_update().filter(slack_id=team_id)[:2])
            if len(candidates) > 1:
                return Response(status=409)
            team = candidates[0] if candidates else SlackTeamIdentity.objects.create(slack_id=team_id)
            if ((team.cached_app_id and team.cached_app_id != installation.get("appId"))
                    or (team.bot_user_id and team.bot_user_id != bot_user)):
                # A proved current native source may rotate only its own previous
                # physical projection. Independently installed/foreign owners stay conflicts.
                peers = SharedSlackInstallation.objects.filter(team=team).exclude(organization=organization)
                if (previous is None or owner.installation_incarnation <= previous.installation_incarnation
                        or peers.filter(source_disconnected=False).exists()):
                    return Response({"detail": "Slack app identity differs"}, status=409)
            # A new mapped organization may share the original physical App/T,
            # but cannot rewrite another organization's existing credential.
            if (previous is None and SharedSlackInstallation.objects.filter(team=team,
                    source_disconnected=False).exclude(organization=organization).exists()
                    and team.bot_access_token != token):
                return Response(status=409)
            team.bot_access_token = token
            team.bot_user_id = bot_user
            team.cached_bot_id = installation.get("botId")
            team.cached_name = installation.get("teamName")
            team.cached_app_id = installation.get("appId")
            team.oauth_scope = installation.get("scopes") or ""
            team.detected_token_revoked = None
            team.save()
            organization.slack_team_identity = team
            organization.save(update_fields=["slack_team_identity"])
            SharedSlackInstallation.objects.update_or_create(
                organization=organization, defaults={"team": team, "assistant_enabled": assistant_enabled,
                    "source_owner": owner.projection(), "source_disconnected": False}
            )
            source = SharedSlackInstallation.objects.get(organization=organization)
            if links_snapshot is not None:
                new_links = {entry["slackUserId"]: entry for entry in links_snapshot}
                # A complete current SQL snapshot proves removal, not absence in
                # a partial sync. Only exact existing native members are linked.
                organization.users.exclude(slack_user_identity__slack_id__in=new_links).update(slack_user_identity=None)
                for entry in links_snapshot:
                    native_user = organization.users.filter(user_id=entry["grafanaUserId"]).first()
                    if native_user is None:
                        continue
                    identity, _ = SlackUserIdentity.objects.get_or_create(slack_team_identity=team, slack_id=entry["slackUserId"])
                    organization.users.filter(slack_user_identity=identity).exclude(pk=native_user.pk).update(slack_user_identity=None)
                    native_user.slack_user_identity = identity
                    native_user.save(update_fields=["slack_user_identity"])
                source.source_links = new_links
                source.source_links_revision = links_revision
                source.save(update_fields=["source_links", "source_links_revision", "updated_at"])
            if link is not None:
                links = dict(source.source_links)
                links[link["slackUserId"]] = link
                source.source_links = links
                source.source_links_revision = max(source.source_links_revision, link["linkRevision"])
                source.save(update_fields=["source_links", "source_links_revision", "updated_at"])
                slack_id = link["slackUserId"]
                identity, _ = SlackUserIdentity.objects.get_or_create(slack_team_identity=team, slack_id=slack_id)
                # Clear a replaced/unlinked account in this org; preserve other orgs.
                previous = organization.users.filter(slack_user_identity=identity)
                if user is not None:
                    previous = previous.exclude(pk=user.pk)
                previous.update(slack_user_identity=None)
                if user is not None:
                    user.slack_user_identity = identity
                    user.save(update_fields=["slack_user_identity"])
            try:
                require_verification_configuration(owner_proof, link_proof, links_proof)
                if shared_organization_id(owner) != organization.pk:
                    raise SharedOwnerError()
            except SharedOwnerError:
                transaction.set_rollback(True)
                return Response(status=503)
        if operation == "sync":
            return Response({"version": 1, "teamId": team_id, "oncallOrgId": organization.pk})
        if operation == "incident_paging_start":
            from apps.slack.incident_paging import start_incident_paging

            with using_shared_owner(organization.pk, owner):
                return start_incident_paging(organization, team, user, data)
        # Options loads are current reads. Replaying a cached response could
        # expose a catalog after permission revocation; never mint a write receipt.
        if not self.original_payload_owner(organization, team, owner, payload):
            return Response(status=409)
        if payload.get("type") == "block_suggestion":
            with using_shared_owner(organization.pk, owner):
                return SlackEventApiEndpointView().dispatch_payload(payload, request, scoped_organization=organization)
        # Bind the receipt to tenant + payload rather than trusting a caller-supplied key.
        key = hashlib.sha256(json.dumps([organization.pk, team_id, payload], sort_keys=True).encode()).hexdigest()
        receipt, created = SharedSlackDelivery.objects.get_or_create(key=key, defaults={"source_owner": owner.projection()})
        if not created:
            # No existing record is retroactively assigned the new installation.
            if receipt.source_owner != owner.projection():
                return Response(status=409)
            if receipt.phase == "completed":
                return Response(receipt.response_data, status=receipt.response_status)
            # Execution may have taken effect. A duplicate can never invoke it again.
            return Response({"response_type": "ephemeral", "text": "This action may already have taken effect. Check its current state before trying again."})
        try:
            channel = payload.get("channel") or {}
            message = payload.get("message") or {}
            origin = modal_owner(payload, team_id, owner.app_id) if payload.get("view") else None
            channel_id = origin.get("channelId") if origin else channel.get("id") or payload.get("channel_id")
            root_ts = origin.get("rootTS") if origin else message.get("thread_ts") or message.get("ts")
            with using_shared_owner(organization.pk, owner), using_shared_delivery(key, actor, channel_id, root_ts), using_loading_view(loading_view):
                result = SlackEventApiEndpointView().dispatch_payload(payload, request, scoped_organization=organization)
                if deferred and result.status_code == 200:
                    self.deferred_view(organization, team, owner, payload, result)
                loading = selected_loading_view()
                if loading is not None and not loading.get("_filled"):
                    from apps.slack.client import SlackClient
                    result_text = result.data.get("text") if isinstance(result.data, dict) else None
                    text = result_text[:2500] if isinstance(result_text, str) and result_text else "This action has been processed."
                    SlackClient(team, source_owner=owner, source_organization=organization).views_update(
                        view_id=loading["id"], view={"type": "modal", "callback_id": "oncall_loading",
                            "title": {"type": "plain_text", "text": "Grafana OnCall"},
                            "close": {"type": "plain_text", "text": "Close"},
                            "blocks": [{"type": "section", "text": {"type": "plain_text", "text": text}}]})
        except Exception:
            receipt.phase = "uncertain"
            receipt.save(update_fields=["phase"])
            raise
        receipt.phase = "completed"
        receipt.response_status = result.status_code
        receipt.response_data = result.data
        receipt.save(update_fields=["phase", "response_status", "response_data"])
        return result

    @staticmethod
    def deferred_view(organization, team, owner, payload, response):
        """Preserve native validation after a queued submission's loading ACK."""
        import copy
        from apps.slack.client import SlackClient
        view = payload["view"]
        result = response.data if isinstance(response.data, dict) else {}
        action = result.get("response_action")
        if action in {"update", "push"} and isinstance(result.get("view"), dict):
            outgoing = copy.deepcopy(result["view"])
        elif action == "errors" and isinstance(result.get("errors"), dict):
            # Retain original block/action IDs; Slack keeps input values on the
            # same view. Validation is visible and the original form can retry.
            blocks = copy.deepcopy(view.get("blocks"))
            if not isinstance(blocks, list) or len(blocks) > 95:
                raise SharedOwnerError()
            # The queued loading ACK may have temporarily removed inputs.
            # Restore the original submitted values, never a current default.
            states = (view.get("state") or {}).get("values", {})
            if not isinstance(states, dict):
                raise SharedOwnerError()
            fields = {"plain_text_input": ("value", "initial_value"), "number_input": ("value", "initial_value"),
                "static_select": ("selected_option", "initial_option"), "external_select": ("selected_option", "initial_option"),
                "radio_buttons": ("selected_option", "initial_option"), "checkboxes": ("selected_options", "initial_options"),
                "multi_static_select": ("selected_options", "initial_options"), "multi_external_select": ("selected_options", "initial_options"),
                "users_select": ("selected_user", "initial_user"), "multi_users_select": ("selected_users", "initial_users"),
                "channels_select": ("selected_channel", "initial_channel"), "multi_channels_select": ("selected_channels", "initial_channels"),
                "conversations_select": ("selected_conversation", "initial_conversation"),
                "multi_conversations_select": ("selected_conversations", "initial_conversations"),
                "datepicker": ("selected_date", "initial_date"), "timepicker": ("selected_time", "initial_time"),
                "datetimepicker": ("selected_date_time", "initial_date_time")}
            for block in blocks:
                if not isinstance(block, dict):
                    raise SharedOwnerError()
                elements = [block.get("element")] if block.get("type") == "input" else block.get("elements", [])
                if not isinstance(elements, list):
                    raise SharedOwnerError()
                values = states.get(block.get("block_id"), {})
                if not isinstance(values, dict):
                    raise SharedOwnerError()
                for element in elements:
                    if not isinstance(element, dict) or element.get("type") not in fields:
                        continue
                    state = values.get(element.get("action_id"))
                    if state is None:
                        continue
                    source_key, initial_key = fields[element["type"]]
                    if not isinstance(state, dict) or state.get("type") != element["type"] or source_key not in state:
                        raise SharedOwnerError()
                    value = state[source_key]
                    if value is None:
                        element.pop(initial_key, None)
                    else:
                        element[initial_key] = copy.deepcopy(value)
            messages = list(result["errors"].values())
            if any(not isinstance(message, str) or len(message) > 500 for message in messages) or len(messages) > 20:
                raise SharedOwnerError()
            outgoing = {key: copy.deepcopy(view[key]) for key in
                        ("type", "title", "submit", "close", "callback_id", "private_metadata") if key in view}
            outgoing["blocks"] = [{"type": "section", "text": {"type": "plain_text", "text":
                "Please review the form: " + "; ".join(messages)[:2500]}}] + blocks
        else:
            outgoing = {"type": "modal", "callback_id": view.get("callback_id", "oncall_completed"),
                "private_metadata": view.get("private_metadata", ""),
                "title": {"type": "plain_text", "text": "Grafana OnCall"},
                "close": {"type": "plain_text", "text": "Close"},
                "blocks": [{"type": "section", "text": {"type": "plain_text", "text": "This form has been processed."}}]}
        SlackClient(team, source_owner=owner, source_organization=organization).views_update(view_id=view["id"], view=outgoing)

    @staticmethod
    def origin(data):
        """IDs-only original storage lookup, never a grant/default selector."""
        from apps.slack.models import SharedSlackPagingSession
        from uuid import UUID
        if set(data) != {"version", "operation", "teamId", "appId", "origin"}:
            return Response(status=422)
        team, app, origin = data["teamId"], data["appId"], data["origin"]
        if not _slack(team, "T") or not _slack(app, "A") or not isinstance(origin, dict):
            return Response(status=422)
        actor = origin.get("slackUserId")
        if not _slack(actor, "[UW]"):
            return Response(status=422)
        raw_owner = None
        kind = origin.get("kind")
        if kind == "view" and set(origin) == {"kind", "viewId", "slackUserId"} and _identifier(origin["viewId"]):
            rows = list(SharedSlackDelivery.objects.filter(modal_owners__has_key=origin["viewId"])
                        .values_list("modal_owners", flat=True)[:2])
            if len(rows) == 1:
                record = rows[0][origin["viewId"]]
                if isinstance(record, dict) and record.get("slackUserId") == actor:
                    raw_owner = record.get("sourceOwner")
            if raw_owner is None:
                sessions = list(SharedSlackPagingSession.objects.filter(slack_user_id=actor, app_id=app,
                    team__slack_id=team).filter(Q(view_id=origin["viewId"]) |
                    Q(confirmation_view_id=origin["viewId"]))
                    .values_list("source_owner", flat=True)[:2])
                if len(sessions) == 1:
                    raw_owner = sessions[0]
        elif kind == "paging" and set(origin) == {"kind", "sessionId", "slackUserId"}:
            try:
                session_id = UUID(origin["sessionId"])
            except (ValueError, TypeError, AttributeError):
                return Response(status=422)
            raw_owner = SharedSlackPagingSession.objects.filter(pk=session_id, slack_user_id=actor,
                app_id=app, team__slack_id=team).values_list("source_owner", flat=True).first()
        elif kind == "message" and set(origin) == {"kind", "channelId", "messageTS", "slackUserId"}:
            import re
            if not _slack(origin["channelId"], "[CGD]") or not isinstance(origin["messageTS"], str) or not re.fullmatch(r"[0-9]{1,20}\.[0-9]{1,10}", origin["messageTS"]):
                return Response(status=422)
            rows = list(SlackMessage.objects.filter(_slack_team_identity__slack_id=team,
                channel__slack_id=origin["channelId"], slack_id=origin["messageTS"])
                .values_list("source_owner", flat=True)[:2])
            if len(rows) == 1:
                raw_owner = rows[0]
        else:
            return Response(status=422)
        try:
            owner = SharedSourceOwner.parse(raw_owner)
            if owner.team_id != team or owner.app_id != app:
                return Response(status=404)
        except SharedOwnerError:
            return Response(status=404)
        return Response({"version": 1, "sourceOwner": owner.projection(), "origin": origin})

    @staticmethod
    def alert_context(organization, data):
        """Read as the linked requester through the native read/team policy, with an exact Slack root fence."""
        from types import SimpleNamespace

        from apps.api.permissions import RBACPermission, user_is_authorized
        from apps.api.views.alert_group import AlertGroupView
        from apps.slack.assistant import shared_installation_owned

        fields = ("teamId", "channelId", "messageTs", "alertGroupId", "slackUserId", "grafanaUserId")
        if not all(isinstance(data.get(key), str) and 0 < len(data[key]) <= 100 for key in fields):
            return Response(status=422)
        if not data["grafanaUserId"].isdigit():
            return Response(status=422)
        try:
            owner = SharedSourceOwner.parse(data.get("sourceOwner"))
            link = parse_link(data.get("link"))
            if (owner.native_org_id != str(data.get("orgId")) or owner.team_id != data["teamId"]
                    or link["slackUserId"] != data["slackUserId"]
                    or link["grafanaUserId"] != data["grafanaUserId"]):
                return Response(status=403)
            owner_proof = verify_source(owner, "transport")
            link_proof = verify_link_source(owner, link)
            snapshot = require_local_source(organization.slack_team_identity_id, organization.pk, owner)
            source = SharedSlackInstallation.objects.get(organization=organization)
            if source.source_links.get(link["slackUserId"]) != link:
                return Response(status=403)
        except (SharedOwnerError, SharedSlackInstallation.DoesNotExist):
            return Response(status=503)
        if not shared_installation_owned(organization, data["teamId"]):
            return Response(status=403)
        team = SlackTeamIdentity.objects.filter(
            organizations=organization, slack_id=data["teamId"]
        ).first()
        if team is None:
            return Response(status=403)
        user = organization.users.filter(user_id=data["grafanaUserId"],
            slack_user_identity__slack_team_identity=team, slack_user_identity__slack_id=data["slackUserId"]).first()
        if user is None or not user_is_authorized(user, [
            RBACPermission.Permissions.ALERT_GROUPS_READ, RBACPermission.Permissions.CHATOPS_READ
        ]):
            return Response(status=403)
        # Reuse the native API queryset, including resource-sharing/team visibility.
        view = AlertGroupView()
        view.request = SimpleNamespace(user=user, auth=SimpleNamespace(organization=organization))
        group = view._get_queryset(action="retrieve").filter(public_primary_key=data["alertGroupId"]).first()
        if group is None or group.wiped_at is not None:
            return Response(status=404)
        if not SlackMessage.objects.filter(
            alert_group=group, _slack_team_identity=team,
            channel__slack_id=data["channelId"], slack_id=data["messageTs"], source_owner=owner.projection(),
        ).exists():
            return Response(status=404)
        alert = group.alerts.last()
        if alert is None:
            return Response(status=404)
        raw = json.dumps(alert.raw_request_data, ensure_ascii=False, default=str)
        context = {
            "alertGroupId": group.public_primary_key,
            "title": str(alert.title or "Alert")[:500],
            "message": str(alert.message or "")[:4000],
            "resolved": group.resolved, "acknowledged": group.acknowledged, "silenced": group.silenced,
            "startedAt": group.started_at.isoformat(), "alertCount": group.alerts.count(),
            "integration": str(group.channel.verbal_name)[:300],
            "labels": [{"key_name": label["key_name"][:200], "value_name": label["value_name"][:500]}
                       for label in group.labels.values("key_name", "value_name")[:50]],
            "lastAlertAt": alert.created_at.isoformat(), "lastAlertPayload": raw[:12000],
            "payloadTruncated": len(raw) > 12000,
        }
        try:
            require_verification_configuration(owner_proof, link_proof)
            if require_local_source(team.pk, organization.pk, owner) != snapshot:
                raise SharedOwnerError()
            current = SharedSlackInstallation.objects.get(organization=organization)
            if current.source_links.get(link["slackUserId"]) != link:
                raise SharedOwnerError()
        except (SharedOwnerError, SharedSlackInstallation.DoesNotExist):
            return Response(status=503)
        return Response({"version": 1, "orgId": str(data["orgId"]), "teamId": data["teamId"],
                         "channelId": data["channelId"], "messageTs": data["messageTs"],
                         "grafanaUserId": str(user.user_id), "slackUserId": data["slackUserId"],
                         "alertGroup": context})

    @staticmethod
    def original_payload_owner(organization, team, owner, payload):
        """Body org hints are never a root receipt. No legacy root auto-upgrade."""
        kind = payload.get("type")
        if payload.get("command") or kind == "event_callback":
            return True
        if payload.get("view"):
            record = modal_owner(payload, owner.team_id, owner.app_id)
            if record is not None:
                return record["organizationId"] == organization.pk and record["sourceOwner"] == owner.projection()
        if payload.get("view"):
            # Original shared paging views already have a native server session.
            from apps.slack.incident_paging import MARKER, marker
            from apps.slack.models import SharedSlackPagingSession
            data = marker(payload.get("view") or {})
            if not isinstance(data, dict) or set(data) != {MARKER}:
                return False
            try:
                session = SharedSlackPagingSession.objects.filter(pk=data[MARKER], organization=organization,
                    team=team, app_id=owner.app_id).first()
            except (ValueError, TypeError):
                return False
            return (session is not None and session.source_owner == owner.projection()
                    and session.slack_user_id == payload_user(payload))
        channel = payload.get("channel")
        channel_id = channel.get("id") if isinstance(channel, dict) else payload.get("channel_id")
        message = payload.get("message") or {}
        root = message.get("thread_ts") or message.get("ts") or payload.get("message_ts")
        if not channel_id or not root:
            return False
        rows = SlackMessage.objects.filter(_slack_team_identity=team, channel__slack_id=channel_id,
            slack_id=root, alert_group__channel__organization=organization).values_list("source_owner", flat=True)[:2]
        rows = list(rows)
        return len(rows) == 1 and rows[0] == owner.projection()

    @staticmethod
    def disconnect(organization, team_id, owner, proof):
        with transaction.atomic():
            organization = Organization.objects.select_for_update().get(pk=organization.pk)
            source = SharedSlackInstallation.objects.select_for_update().filter(organization=organization).first()
            if source is None or source.source_owner is None:
                return Response(status=409)
            try:
                previous = SharedSourceOwner.parse(source.source_owner)
                owner.require_successor(previous)
            except SharedOwnerError:
                return Response(status=409)
            if (owner.connection_generation <= previous.connection_generation and not source.source_disconnected):
                return Response(status=409)
            team = source.team
            if team.slack_id != team_id:
                return Response(status=409)
            if source.source_disconnected and source.source_owner == owner.projection():
                return SharedSlackAppView.disconnected_source_receipt(organization.pk, owner)
            # Retain the existing original row as a tombstone. It is provenance,
            # not permission, and cannot silently bless a reconnect's old epoch.
            source.source_owner = owner.projection()
            source.source_disconnected = True
            source.save(update_fields=["source_owner", "source_disconnected", "updated_at"])
            organization.users.update(slack_user_identity=None)
            if organization.slack_team_identity_id == team.pk:
                organization.slack_team_identity = None
                organization.save(update_fields=["slack_team_identity"])
            if not team.organizations.exists():
                team.bot_access_token = None
                team.access_token = None
                team.save(update_fields=["bot_access_token", "access_token"])
            try:
                require_verification_configuration(proof)
                if shared_organization_id(owner) != organization.pk:
                    raise SharedOwnerError()
            except SharedOwnerError:
                transaction.set_rollback(True)
                return Response(status=503)
        return SharedSlackAppView.disconnected_source_receipt(organization.pk, owner)

    @staticmethod
    def disconnected_source_receipt(org_id, owner):
        # Fresh SQL proves the written side, including an idempotent retry.
        row = SharedSlackInstallation.objects.filter(organization_id=org_id).values(
            "source_owner", "source_disconnected", "organization__slack_team_identity_id").first()
        if (row is None or row["source_owner"] != owner.projection() or not row["source_disconnected"]
                or row["organization__slack_team_identity_id"] is not None):
            return Response(status=503)
        return Response({"version": 1, "sourceOwner": row["source_owner"],
            "sourceDisconnected": True, "organizationUnlinked": True})
