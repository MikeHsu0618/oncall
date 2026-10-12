"""OSS incident adapter around the original OnCall direct-paging scenarios.

Only an opaque session ID leaves the server. The incident reservation is an
origin receipt, never a permission grant; every interaction rechecks its user.
"""

import copy
import hashlib
import hmac
import json
import re
import time
from uuid import UUID

import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.response import Response

from apps.alerts.paging import direct_paging
from apps.api.permissions import user_is_authorized
from apps.slack.client import SlackClient, SharedMutationUnknown
from apps.slack.shared_owner import SharedOwnerError, SharedSourceOwner, require_local_source, _verification_config
from apps.slack.models import SharedSlackPagingNotification, SharedSlackPagingSession
from apps.slack.scenarios import paging

MARKER = "pagingSessionId"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def marker(view):
    try:
        metadata = json.loads(view.get("private_metadata", "{}"))
        if isinstance(metadata, dict) and MARKER in metadata:
            return metadata
    except (TypeError, ValueError):
        pass
    return None


def _require_session_identity(session):
    from apps.slack.models import SlackTeamIdentity
    organization = type(session.organization).objects.filter(pk=session.organization_id,
        slack_team_identity_id=session.team_id).first()
    team = SlackTeamIdentity.objects.filter(pk=session.team_id, cached_app_id=session.app_id,
        bot_user_id=session.bot_user_id).first()
    if organization is None or team is None or session.phase != "open" or session.expires_at <= timezone.now():
        raise SharedOwnerError()
    user = organization.users.filter(user_id=session.grafana_user_id,
        slack_user_identity__slack_id=session.slack_user_id,
        slack_user_identity__slack_team_identity_id=session.team_id).first()
    if user is None or not user_is_authorized(user, paging.FinishDirectPaging.REQUIRED_PERMISSIONS):
        raise SharedOwnerError()
    if session.source_owner is not None:
        require_local_source(session.team_id, session.organization_id, SharedSourceOwner.parse(session.source_owner))


class SessionClient:
    """Native session CAS before views; no row lock spans provider HTTP."""

    def __init__(self, session, client):
        self.session = session
        self.client = client
        self.expected = _session_dispatch_snapshot(session)
        self.client._admit_request = self.require_current

    def require_current(self):
        if transaction.get_connection().in_atomic_block:
            raise SharedOwnerError()
        current = SharedSlackPagingSession.objects.filter(pk=self.session.pk).first()
        if current is None or _session_dispatch_snapshot(current) != self.expected:
            raise SharedOwnerError()
        _require_session_identity(current)

    def _mutate(self, **changes):
        with transaction.atomic():
            current = SharedSlackPagingSession.objects.select_for_update().get(pk=self.session.pk)
            if _session_dispatch_snapshot(current) != self.expected:
                raise SharedOwnerError()
            _require_session_identity(current)
            for key, value in changes.items():
                setattr(current, key, value)
            current.save(update_fields=list(changes))
            self.session = current
            self.expected = _session_dispatch_snapshot(current)

    def protected_view(self, view, confirmation=False):
        view = copy.deepcopy(view)
        field = "confirmation_metadata" if confirmation else "form_metadata"
        if self.session.view_operation_phase != "ready":
            raise SharedOwnerError()
        self._mutate(**{field: json.loads(view["private_metadata"]), "view_operation_phase": "posting"})
        view["private_metadata"] = canonical({MARKER: str(self.session.pk)})
        return view

    def _hold_uncertain(self):
        # Outcome loss never releases the original view-operation fence.
        # Do not replace a concurrently changed source/session observation.
        with transaction.atomic():
            current = SharedSlackPagingSession.objects.select_for_update().filter(pk=self.session.pk).first()
            if current is not None and _session_dispatch_snapshot(current) == self.expected:
                current.view_operation_phase = "uncertain"
                current.save(update_fields=["view_operation_phase"])

    def views_update(self, **kwargs):
        kwargs["view"] = self.protected_view(kwargs["view"])
        self.require_current()
        try:
            result = self.client.views_update(**kwargs)
        except Exception as error:
            try:
                self._hold_uncertain()
            except Exception:
                raise SharedMutationUnknown() from None
            raise error
        try:
            self._mutate(view_operation_phase="ready")
        except Exception:
            raise SharedMutationUnknown() from None
        return result

    def views_push(self, **kwargs):
        kwargs["view"] = self.protected_view(kwargs["view"], confirmation=True)
        self.require_current()
        try:
            result = self.client.views_push(**kwargs)
        except Exception as error:
            try:
                self._hold_uncertain()
            except Exception:
                raise SharedMutationUnknown() from None
            raise error
        try:
            self._mutate(confirmation_view_id=result["view"]["id"], view_operation_phase="ready")
        except Exception:
            raise SharedMutationUnknown() from None
        return result


def start_incident_paging(organization, team, user, data):
    context = data.get("incidentContext")
    view = data.get("loadingView")
    payload = data["payload"]
    if not user or not user_is_authorized(user, paging.FinishDirectPaging.REQUIRED_PERMISSIONS):
        return Response(status=403)
    if (not isinstance(context, dict) or not isinstance(view, dict)
            or not isinstance(view.get("id"), str) or not 0 < len(view["id"]) <= 100
            or not all(isinstance(context.get(k), str) and 0 < len(context[k]) <= 2000
                       for k in ("reservationToken", "incidentId", "channelId", "title", "sourceUrl", "expiresAt"))
            or payload.get("type") != "block_actions"
            or (payload.get("channel") or {}).get("id") != context["channelId"]
            or len(payload.get("actions", [])) != 1
            or payload["actions"][0].get("action_id") != "irm_incident_escalate"):
        return Response(status=422)
    try:
        reservation = UUID(context["reservationToken"])
        expires = parse_datetime(context["expiresAt"])
        if not reservation.int or not expires or timezone.is_naive(expires) or expires <= timezone.now():
            return Response(status=422)
    except (ValueError, TypeError):
        return Response(status=422)
    with transaction.atomic():
        # Serialize starts for this installation before checking unique nonce.
        type(organization).objects.select_for_update().get(pk=organization.pk)
        session, created = SharedSlackPagingSession.objects.get_or_create(
            reservation_token=reservation, defaults={
                "organization": organization, "team": team, "grafana_org_id": str(data["orgId"]),
                "slack_user_id": user.slack_user_identity.slack_id, "grafana_user_id": str(user.user_id),
                "app_id": team.cached_app_id, "bot_user_id": team.bot_user_id,
                "incident_context": context, "view_id": view["id"], "expires_at": expires,
                "source_owner": data.get("sourceOwner"),
            })
        if not created:
            if (session.organization_id != organization.pk or session.team_id != team.pk
                    or session.grafana_user_id != str(user.user_id) or session.incident_context != context
                    or session.view_id != view["id"] or session.source_owner != data.get("sourceOwner")):
                return Response(status=409)
            if session.phase == "completed" or session.form_metadata and session.view_operation_phase == "ready":
                return Response({"sessionId": str(session.pk), "state": session.phase})
            # A claimed/unknown prior view update may already have happened.
            # No replay posts it again or advertises an initialized dialog.
            return Response({"sessionId": str(session.pk), "state": "uncertain"}, status=503)
        metadata = {"channel_id": context["channelId"], "input_id_prefix": paging._generate_input_id_prefix(),
                    "submit_routing_uid": paging.FinishDirectPaging.routing_uid(),
                    "organization_id": organization.pk, paging.DataKey.USERS: {}}
        native = paging.render_dialog(user.slack_user_identity, team,
                                     {"view": {"private_metadata": canonical(metadata)}}, initial=True)
    # Reserve native session+metadata first; provider calls run only after the
    # transaction closes and each physical send repeats original session CAS.
    client = SessionClient(session, SlackClient(team, source_owner=session.source_owner,
                                                source_organization=organization))
    kwargs = {"view_id": view["id"], "view": native}
    if view.get("hash"):
        kwargs["hash"] = view["hash"]
    client.views_update(**kwargs)
    return Response({"sessionId": str(session.pk), "state": "open"})


def scoped_targets(session, payload, metadata):
    """Reject manipulated native selection values before any original step runs."""
    organization = session.organization
    prefix = metadata["input_id_prefix"]
    team_id, team = paging._get_selected_team_from_payload(payload, prefix)
    if team_id is not None and (team is None or team.organization_id != organization.pk):
        raise ValueError("Team is not currently available for direct paging")
    selected_id = paging._get_select_field_value(payload, prefix, paging.OnPagingUserChange.routing_uid(), paging.DIRECT_PAGING_USER_SELECT_ID)
    selected = paging._get_selected_user_from_payload(payload, prefix)
    if selected_id is not None and (selected is None or selected.organization_id != organization.pk):
        raise ValueError("User belongs to another organization")
    users = []
    for user_id, policy in metadata[paging.DataKey.USERS].items():
        user = organization.users.filter(pk=user_id).first()
        if user is None or policy not in {paging.Policy.DEFAULT, paging.Policy.IMPORTANT}:
            raise ValueError("Responder is no longer available")
        users.append((user, policy == paging.Policy.IMPORTANT))
    # Item policy actions may add a user: validate their ID, key and policy too.
    for action in payload.get("actions", []):
        if action.get("action_id", "").startswith(paging.OnPagingItemActionChange.routing_uid()):
            value = json.loads(action["selected_option"]["value"])
            if (value.get("key") != paging.DataKey.USERS or value.get("action") not in set(paging.Policy)
                    or not organization.users.filter(pk=value.get("id")).exists()):
                raise ValueError("Invalid responder policy")
    return team, users


def finish(session, user, payload, metadata, *, verified_configuration=None):
    team, users = scoped_targets(session, payload, metadata)
    message = paging._get_message_from_payload(payload)
    important = paging._get_team_escalation_severity_from_payload(payload, metadata["input_id_prefix"])
    targets = ([{"kind": "team", "id": team.public_primary_key, "name": team.name, "important": important}]
               if team else [])
    targets += [{"kind": "user", "id": u.public_primary_key, "name": u.username, "important": p}
                for u, p in users]
    if not targets:
        return Response({"response_action": "errors", "errors": {
            paging.DIRECT_PAGING_MESSAGE_INPUT_ID: "Select at least one team or user."}})
    # Validate the receiving contract BEFORE creating a native page. Names are
    # Unicode code points; opaque origin IDs are ASCII on both service seams.
    origin = [session.grafana_org_id, session.team.slack_id, session.incident_context["channelId"],
              session.slack_user_id, session.grafana_user_id, session.incident_context["incidentId"],
              session.app_id, session.bot_user_id]
    if (not all(isinstance(value, str) and value.isascii() and 0 < len(value) <= 128 for value in origin)
            or not re.fullmatch(r"[1-9][0-9]*", session.grafana_user_id)
            or len(targets) > 100
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", target["id"])
                   or not target["name"].strip() or len(target["name"]) > 300 for target in targets)):
        raise ValueError("Paging result exceeds the native receiving contract")
    # Refuse malformed Unicode before any task or page is created.
    canonical(targets).encode("utf-8")
    digest = hashlib.sha256(canonical({"message": message, "targets": sorted(targets, key=lambda t: (t["kind"], t["id"]))}).encode()).hexdigest()
    if session.phase == "completed":
        return Response() if digest == session.semantic_fingerprint else Response(status=409)

    def enqueue(native_user, group, important_policy, force_default_fallback=False):
        SharedSlackPagingNotification.objects.create(session=session, user=native_user,
                                                      alert_group=group, important=important_policy,
                                                      force_default_fallback=force_default_fallback)

    context = session.incident_context
    if verified_configuration is not None:
        try:
            if _verification_config("SHARED_SLACK_PAGING_VERIFY_URL") != verified_configuration:
                return Response(status=503)
        except SharedOwnerError:
            return Response(status=503)
    group = direct_paging(organization=session.organization, from_user=user, message=message,
                          title=context["title"], source_url=context["sourceUrl"],
                          grafana_incident_id=context["incidentId"], team=team, users=users,
                          important_team_escalation=important, notification_enqueue=enqueue)
    result = {"version": 1, "orgId": session.grafana_org_id, "teamId": session.team.slack_id,
              "channelId": context["channelId"], "slackUserId": session.slack_user_id,
              "grafanaUserId": session.grafana_user_id, "reservationToken": str(session.reservation_token),
              "sessionId": str(session.pk), "incidentId": context["incidentId"],
              "alertGroupId": group.public_primary_key, "appId": session.app_id,
              "botUserId": session.bot_user_id, "targets": targets}
    session.phase = "completed"
    session.semantic_fingerprint = digest
    session.result_data = result
    session.result_body = canonical(result)
    if len(session.result_body.encode("utf-8")) > 256 * 1024:
        raise ValueError("Paging result exceeds the native receiving contract")
    session.save(update_fields=["phase", "semantic_fingerprint", "result_data", "result_body"])
    return Response()


def _prepare_session_dispatch(session, organization, team, identity, payload):
    # Re-read original current owners both before preflight and under the final
    # session lock. Caller objects may predate a concurrent unlink/reinstall.
    organization = type(organization).objects.filter(pk=organization.pk).first()
    team = type(team).objects.filter(pk=team.pk).first()
    if organization is None or team is None:
        return Response(status=403)
    identity = type(identity).objects.filter(pk=identity.pk).first()
    user = identity.get_user(organization) if identity is not None else None
    if (session is None or session.organization_id != organization.pk or session.team_id != team.pk
            or identity is None or session.slack_user_id != identity.slack_id or user is None
            or str(user.user_id) != session.grafana_user_id
            or organization.slack_team_identity_id != team.pk
            or identity.slack_team_identity_id != team.pk
            or team.cached_app_id != session.app_id or team.bot_user_id != session.bot_user_id
            or not user_is_authorized(user, paging.FinishDirectPaging.REQUIRED_PERMISSIONS)):
        return Response(status=403)
    if session.source_owner is not None:
        try:
            require_local_source(session.team_id, session.organization_id, SharedSourceOwner.parse(session.source_owner))
        except SharedOwnerError:
            return Response(status=409)
    session.organization = organization
    session.team = team
    view = payload["view"]
    confirmation = view.get("id") == session.confirmation_view_id and bool(session.confirmation_view_id)
    if view.get("id") != session.view_id and not confirmation:
        return Response(status=403)
    if session.phase != "completed" and session.view_operation_phase != "ready":
        return Response(status=409)
    if session.phase != "completed" and session.expires_at <= timezone.now():
        return Response(status=410)
    metadata = copy.deepcopy(session.confirmation_metadata if confirmation else session.form_metadata)
    if payload.get("type") == "block_suggestion":
        if confirmation or session.phase == "completed":
            return Response(status=409)
        return organization, team, identity, user, metadata, None, None
    native_payload = copy.deepcopy(payload)
    native_payload["view"]["private_metadata"] = canonical(metadata)
    validation_payload = native_payload
    if confirmation:
        if view.get("previous_view_id") != session.view_id:
            return Response(status=403)
        validation_payload = {"view": {"state": metadata["state"], "private_metadata": canonical(metadata)}}
    scoped_targets(session, validation_payload, metadata)
    Step = None
    for route in paging.STEPS_ROUTING:
        if route["payload_type"] != payload.get("type"):
            continue
        if payload.get("type") == "view_submission":
            matches = view.get("callback_id", "").startswith(route.get("view_callback_id", "\0"))
        else:
            actions = payload.get("actions", [])
            matches = len(actions) == 1 and actions[0].get("type") == route.get("block_action_type") and actions[0].get("action_id", "").startswith(route.get("block_action_id", "\0"))
        if matches:
            Step = route["step"]
            break
    if Step is None or Step is paging.OnPagingOrgChange:
        return Response(status=422)
    if confirmation != (Step is paging.OnPagingConfirmUserChange):
        return Response(status=403)
    return organization, team, identity, user, metadata, native_payload, Step


def _session_dispatch_snapshot(session):
    fields = {key: getattr(session, key) for key in (
        "organization_id", "team_id", "grafana_org_id", "slack_user_id", "grafana_user_id",
        "app_id", "bot_user_id", "incident_context", "view_id", "confirmation_view_id",
        "form_metadata", "confirmation_metadata", "phase", "source_owner", "view_operation_phase")}
    fields.update(reservationToken=str(session.reservation_token), expiresAt=session.expires_at.isoformat(),
                  slackTeamId=session.team.slack_id)
    return canonical(fields)


def _verify_paging_reservation(session, *, configuration=None):
    """Fresh native reservation read outside SQL transactions; never a saved grant."""
    if transaction.get_connection().in_atomic_block:
        return Response(status=503)
    try:
        captured = _verification_config("SHARED_SLACK_PAGING_VERIFY_URL")
        if configuration is not None and captured != configuration:
            return Response(status=503)
        url, secret = captured
    except SharedOwnerError:
        return Response(status=503)
    context = session.incident_context
    body = {"version": 1, "orgId": session.grafana_org_id, "teamId": session.team.slack_id,
            "channelId": context["channelId"], "slackUserId": session.slack_user_id,
            "grafanaUserId": session.grafana_user_id, "reservationToken": str(session.reservation_token),
            "sessionId": str(session.pk), "incidentId": context["incidentId"], "appId": session.app_id}
    raw = canonical(body).encode("utf-8")
    timestamp = str(int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    response = None
    try:
        with requests.Session() as client:
            client.trust_env = False
            if _verification_config("SHARED_SLACK_PAGING_VERIFY_URL") != captured:
                return Response(status=503)
            response = client.post(url, data=raw, headers={"Content-Type": "application/json",
                "X-Grafana-Slack-Timestamp": timestamp, "X-Grafana-Slack-Signature": signature,
                "X-Grafana-Slack-Delivery-Id": str(session.pk)}, timeout=5, allow_redirects=False, stream=True)
        if response.status_code != 200:
            return Response(status=response.status_code if response.status_code in {403, 404, 409} else 503)
        chunks, size = [], 0
        for chunk in response.iter_content(chunk_size=4096):
            size += len(chunk)
            if size > 16 * 1024:
                return Response(status=503)
            chunks.append(chunk)
        result = json.loads(b"".join(chunks).decode("utf-8"))
        if (not isinstance(result, dict) or result.get("verified") is not True
                or type(result.get("version")) is not int or result["version"] != 1
                or any(result.get(key) != value for key, value in body.items() if key != "version")):
            return Response(status=503)
    except (requests.RequestException, ValueError, UnicodeError, SharedOwnerError):
        return Response(status=503)
    finally:
        if response is not None:
            response.close()
    try:
        if _verification_config("SHARED_SLACK_PAGING_VERIFY_URL") != captured:
            return Response(status=503)
    except SharedOwnerError:
        return Response(status=503)
    return None


def _dispatch_session(organization, team, identity, payload):
    """Return None for ordinary native dialogs; protect only our opaque sessions."""
    marker_data = marker(payload.get("view") or {})
    if marker_data is None:
        return None
    if set(marker_data) != {MARKER} or organization is None or identity is None or team is None:
        return Response(status=403)
    try:
        session_id = UUID(marker_data[MARKER])
    except (ValueError, TypeError, AttributeError):
        return Response(status=422)
    verified_snapshot = None
    verified_configuration = None
    try:
        candidate = SharedSlackPagingSession.objects.filter(pk=session_id).first()
        prepared = _prepare_session_dispatch(candidate, organization, team, identity, payload)
        if isinstance(prepared, Response):
            return prepared
        if prepared[-1] is paging.FinishDirectPaging and candidate.phase != "completed":
            verified_snapshot = _session_dispatch_snapshot(candidate)
            verified_configuration = _verification_config("SHARED_SLACK_PAGING_VERIFY_URL")
            refusal = _verify_paging_reservation(candidate, configuration=verified_configuration)
            if refusal is not None:
                return refusal
    except SharedOwnerError:
        return Response(status=503)
    except (ValueError, KeyError, TypeError, AttributeError):
        return Response(status=422)
    with transaction.atomic():
        session = SharedSlackPagingSession.objects.select_for_update().filter(pk=session_id).first()
        try:
            prepared = _prepare_session_dispatch(session, organization, team, identity, payload)
            if isinstance(prepared, Response):
                return prepared
            current_org, current_team, current_identity, user, metadata, native_payload, Step = prepared
            if payload.get("type") == "block_suggestion":
                from apps.slack.paging_options import dispatch_options
                return dispatch_options(current_org, current_team, current_identity, payload, metadata=metadata)
            if Step is paging.FinishDirectPaging:
                if session.phase != "completed" and (verified_snapshot is None or
                        _session_dispatch_snapshot(session) != verified_snapshot):
                    return Response(status=409)
                if session.phase != "completed":
                    try:
                        if _verification_config("SHARED_SLACK_PAGING_VERIFY_URL") != verified_configuration:
                            return Response(status=503)
                    except SharedOwnerError:
                        return Response(status=503)
                return finish(session, user, native_payload, metadata,
                    verified_configuration=verified_configuration if session.phase != "completed" else None)
            if session.phase == "completed":
                return Response(status=409)
            session_snapshot = _session_dispatch_snapshot(session)
        except (ValueError, KeyError, TypeError, AttributeError):
            transaction.set_rollback(True)
            return Response(status=422)
    # The original nonfinal dialog step owns the view; no transport is called
    # while its session row is locked. SessionClient reserves metadata with CAS.
    if _session_dispatch_snapshot(session) != session_snapshot:
        return Response(status=409)
    step = Step(current_team, current_org, user)
    step._slack_client = SessionClient(session, SlackClient(current_team,
        source_owner=session.source_owner, source_organization=current_org))
    result = step.process_scenario(current_identity, current_team, native_payload, predefined_org=current_org)
    return result or Response()


def dispatch_session(organization, team, identity, payload):
    try:
        return _dispatch_session(organization, team, identity, payload)
    except Exception:
        # Original OnCall on_commit signal publication can fail AFTER the page
        # and our result committed. Read the persisted fact before answering;
        # replay performs fresh authorization and semantic comparison, no page.
        metadata = marker(payload.get("view") or {})
        if metadata and set(metadata) == {MARKER}:
            try:
                session_id = UUID(metadata[MARKER])
            except (ValueError, TypeError, AttributeError):
                raise
            if SharedSlackPagingSession.objects.filter(pk=session_id, phase="completed").exists():
                return _dispatch_session(organization, team, identity, payload)
        raise
