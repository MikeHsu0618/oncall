"""Fresh Assistant availability for original OnCall cards; native controls are independent."""

import hashlib
import hmac
import json
import re
import time

import requests
from django.conf import settings
from django.db import connection
from django.db.models import F

from apps.slack.models import SharedSlackInstallation
from apps.slack.shared_owner import (
    SharedOwnerError, SharedSourceOwner, shared_org_mapping, shared_organization_id,
)

INVESTIGATE_ALERT_ACTION_ID = "irm_investigate_alert"


def _installation_snapshot(organization):
    # Read scalar SQL values, never a caller's cached organization/team relationship.
    rows = list(SharedSlackInstallation.objects.filter(
        organization_id=organization.pk, source_disconnected=False,
        team_id=F("organization__slack_team_identity_id"),
    ).values_list(
        "pk", "organization_id", "organization__slack_team_identity_id", "team_id",
        "team__slack_id", "team__cached_app_id", "team__bot_access_token", "team__detected_token_revoked",
        "source_owner", "source_disconnected",
    )[:2])
    row = rows[0] if len(rows) == 1 else None
    if (row is None or row[2] != row[3] or row[7] is not None or row[9]
            or not isinstance(row[6], str) or not row[6]
            or not isinstance(row[4], str) or re.fullmatch(r"T[A-Z0-9]{1,63}", row[4]) is None
            or not isinstance(row[5], str) or re.fullmatch(r"A[A-Z0-9]{1,63}", row[5]) is None):
        return None
    return row


def shared_installation_owned(organization, team_id=None):
    """Pure current local ownership, for execution already gated by the connector."""
    snapshot = _installation_snapshot(organization)
    return snapshot is not None and (team_id is None or snapshot[4] == team_id)


def _grafana_org_id(organization):
    try:
        mapping = shared_org_mapping()
    except SharedOwnerError:
        return None
    default = getattr(settings, "SHARED_SLACK_DEFAULT_STACK_ID", "")
    matches = [org for (stack, org), value in mapping.items()
               if stack == default and value == organization.pk]
    if len(matches) != 1:
        return None
    return matches[0]


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response key")
        result[key] = value
    return result


def assistant_available(organization):
    """No availability cache: an unknown or changed owner hides only the AI button."""
    if connection.in_atomic_block:
        return False
    response = None
    try:
        url = getattr(settings, "SHARED_SLACK_AVAILABILITY_URL", "")
        secret = getattr(settings, "SHARED_SLACK_BRIDGE_SECRET", "")
        snapshot = _installation_snapshot(organization)
        owner = SharedSourceOwner.parse(snapshot[8]) if snapshot is not None and snapshot[8] is not None else None
        if owner is not None:
            if (shared_organization_id(owner) != organization.pk or owner.team_id != snapshot[4]
                    or owner.app_id != snapshot[5]
                    or owner.token_sha256 != hashlib.sha256(snapshot[6].encode()).hexdigest()):
                return False
            org_id = owner.native_org_id
        else:
            org_id = _grafana_org_id(organization)
        if not url or not secret or snapshot is None or org_id is None:
            return False
        payload = {"version": 1, "orgId": org_id, "teamId": snapshot[4], "appId": snapshot[5],
                   "installationFingerprint": hashlib.sha256(snapshot[6].encode()).hexdigest()}
        if owner is not None:
            payload["sourceOwner"] = owner.projection()
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        timestamp = str(int(time.time()))
        signature = hmac.new(secret.encode(), b"v1:" + timestamp.encode() + b":" + raw,
                             hashlib.sha256).hexdigest()
        deadline = time.monotonic() + 2.5
        response = requests.post(url, data=raw, headers={"Content-Type": "application/json", "Accept-Encoding": "identity",
            "X-Oncall-Timestamp": timestamp, "X-Oncall-Signature": "v1=" + signature},
            timeout=(2.5, 2.5), allow_redirects=False, stream=True)
        # Requests timeouts bound inactivity, not DNS/header receipt or the whole
        # call. Avoid aggregated/compressed body reads; check each received byte.
        if time.monotonic() >= deadline or response.status_code != 200:
            return False
        length = response.headers.get("Content-Length")
        if (response.headers.get("Content-Encoding", "identity").lower() != "identity"
                or "Transfer-Encoding" in response.headers
                or not isinstance(length, str) or re.fullmatch(r"[1-9][0-9]{0,3}", length) is None
                or int(length) > 4096):
            return False
        expected_length = int(length)
        body = bytearray()
        for chunk in response.iter_content(chunk_size=1):
            if time.monotonic() >= deadline or len(body) + len(chunk) > expected_length:
                return False
            body.extend(chunk)
        if time.monotonic() >= deadline or len(body) != expected_length:
            return False
        result = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object)
        if (not isinstance(result, dict) or set(result) != set(payload) | {"assistantAvailable"}
                or type(result.get("version")) is not int
                or type(result.get("assistantAvailable")) is not bool
                or any(result.get(key) != value for key, value in payload.items())):
            return False
        return (result["assistantAvailable"] and _installation_snapshot(organization) == snapshot
                and (shared_organization_id(owner) == organization.pk if owner is not None
                     else _grafana_org_id(organization) == org_id))
    except Exception:
        # Optional rendering must never interrupt native alert publication, including
        # malformed headers, database availability, and transport decoding failures.
        return False
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


def investigation_button(alert_group):
    return {
        "type": "button",
        "action_id": INVESTIGATE_ALERT_ACTION_ID,
        "text": {"type": "plain_text", "text": "Investigate this alert"},
        # A reference only. The receiver re-reads tenant, caller and original Slack root.
        "value": alert_group.public_primary_key,
    }
