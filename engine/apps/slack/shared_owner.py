"""Original shared-installation provenance and fresh transport admission.

This is an OSS service contract, not a permission grant. The original OnCall
organization, token projection, scenarios and delivery records remain owners.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import time
from urllib.parse import urlsplit

import requests
from django.conf import settings
from django.db import transaction

MAX_COUNTER = 2**63 - 1
_SOURCE = ContextVar("oncall_shared_source", default=None)
_FIELDS = frozenset(("version", "stackId", "nativeOrgId", "bindingRevision", "bindingDigest",
                     "connectionId", "connectionGeneration", "installationId", "installationIncarnation",
                     "credentialRevision", "teamId", "appId", "tokenSHA256"))


class SharedOwnerError(RuntimeError):
    """Coarse pre-send refusal; it never contains tokens or provider bodies."""

    def __init__(self):
        super().__init__("Shared Slack source owner is unavailable")


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) is not None


def _positive(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,18}", value) is not None and int(value) <= MAX_COUNTER


def _counter(value):
    return type(value) is int and 1 <= value <= MAX_COUNTER


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _slack(value, prefix):
    return isinstance(value, str) and re.fullmatch(prefix + r"[A-Z0-9]{1,63}", value) is not None


def shared_org_mapping():
    """Explicit deployment mapping; a numeric org never selects a stack."""
    raw = getattr(settings, "SHARED_SLACK_ORG_MAP", {})
    if not isinstance(raw, dict):
        raise SharedOwnerError()
    if not raw:
        return {}
    if all(_positive(key) and type(value) is int for key, value in raw.items()):
        default = getattr(settings, "SHARED_SLACK_DEFAULT_STACK_ID", "")
        if not _identifier(default) or default == "local":
            raise SharedOwnerError()
        raw = {default: raw}
    result = {}
    for stack, orgs in raw.items():
        if not _identifier(stack) or stack == "local" or not isinstance(orgs, dict):
            raise SharedOwnerError()
        for org, native_pk in orgs.items():
            if not _positive(org) or type(native_pk) is not int or not 1 <= native_pk <= MAX_COUNTER:
                raise SharedOwnerError()
            result[(stack, org)] = native_pk
    if len(set(result.values())) != len(result):
        raise SharedOwnerError()
    return result


def shared_organization_id(owner):
    if not isinstance(owner, SharedSourceOwner):
        raise SharedOwnerError()
    value = shared_org_mapping().get((owner.stack_id, owner.native_org_id))
    if value is None:
        raise SharedOwnerError()
    return value


def default_shared_organization_id(org_id):
    default = getattr(settings, "SHARED_SLACK_DEFAULT_STACK_ID", "")
    if not _identifier(default) or default == "local" or not _positive(org_id):
        raise SharedOwnerError()
    value = shared_org_mapping().get((default, org_id))
    if value is None:
        raise SharedOwnerError()
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SharedOwnerError()
            result[key] = value
        return result
    try:
        text = raw.decode("utf-8")
        if any(0xD800 <= ord(c) <= 0xDFFF for c in text):
            raise SharedOwnerError()
        result = json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(SharedOwnerError()))
        def valid(value):
            if isinstance(value, str):
                return not any(0xD800 <= ord(c) <= 0xDFFF for c in value)
            if isinstance(value, dict):
                return all(valid(k) and valid(v) for k, v in value.items())
            if isinstance(value, list):
                return all(valid(v) for v in value)
            return True
        if not valid(result):
            raise SharedOwnerError()
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise SharedOwnerError() from None


@dataclass(frozen=True, repr=False)
class SharedSourceOwner:
    version: int
    stack_id: str
    native_org_id: str
    binding_revision: int
    binding_digest: str
    connection_id: str
    connection_generation: int
    installation_id: str
    installation_incarnation: int
    credential_revision: int
    team_id: str
    app_id: str
    token_sha256: str

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict) or set(value) != _FIELDS or type(value.get("version")) is not int or value["version"] != 1:
            raise SharedOwnerError()
        if (not _identifier(value["stackId"]) or value["stackId"] == "local" or not _positive(value["nativeOrgId"])
                or not all(_identifier(value[k]) for k in ("connectionId", "installationId"))
                or not all(_counter(value[k]) for k in ("bindingRevision", "connectionGeneration", "installationIncarnation", "credentialRevision"))
                or not _digest(value["bindingDigest"]) or not _digest(value["tokenSHA256"])
                or not _slack(value["teamId"], "T") or not _slack(value["appId"], "A")):
            raise SharedOwnerError()
        return cls(*(value[k] for k in ("version", "stackId", "nativeOrgId", "bindingRevision", "bindingDigest", "connectionId",
                    "connectionGeneration", "installationId", "installationIncarnation", "credentialRevision", "teamId", "appId", "tokenSHA256")))

    def projection(self):
        return dict(zip(("version", "stackId", "nativeOrgId", "bindingRevision", "bindingDigest", "connectionId",
                        "connectionGeneration", "installationId", "installationIncarnation", "credentialRevision", "teamId", "appId", "tokenSHA256"),
                        (self.version, self.stack_id, self.native_org_id, self.binding_revision, self.binding_digest,
                         self.connection_id, self.connection_generation, self.installation_id, self.installation_incarnation,
                         self.credential_revision, self.team_id, self.app_id, self.token_sha256)))

    def require_successor(self, previous):
        # A new approved route needs explicit original-owner enrollment. Never
        # turn a default change into a native organization's new source owner.
        if ((self.stack_id, self.native_org_id, self.binding_revision, self.binding_digest, self.connection_id, self.installation_id)
                != (previous.stack_id, previous.native_org_id, previous.binding_revision, previous.binding_digest,
                    previous.connection_id, previous.installation_id)
                or self.connection_generation < previous.connection_generation
                or self.installation_incarnation < previous.installation_incarnation
                or self.credential_revision < previous.credential_revision
                or self.team_id != previous.team_id
                or (self.app_id != previous.app_id and (self.installation_incarnation <= previous.installation_incarnation
                    or self.credential_revision <= previous.credential_revision))
                or (self.token_sha256 != previous.token_sha256 and self.credential_revision <= previous.credential_revision)):
            raise SharedOwnerError()


    def require_reenrollment(self, previous):
        """Fresh join of the SAME disconnected physical owner, never a retarget."""
        same = ("stack_id", "native_org_id", "connection_id", "installation_id", "installation_incarnation",
                "credential_revision", "team_id", "app_id", "token_sha256")
        if (any(getattr(self, key) != getattr(previous, key) for key in same)
                or self.binding_revision <= previous.binding_revision
                or self.connection_generation <= previous.connection_generation):
            raise SharedOwnerError()


def _verification_config(setting="SHARED_SLACK_OWNER_VERIFY_URL"):
    url = getattr(settings, setting, "")
    secret = getattr(settings, "SHARED_SLACK_BRIDGE_SECRET", "")
    try:
        parsed = urlsplit(url)
        if (not isinstance(secret, str) or not secret or not isinstance(url, str) or len(url) > 2048
                or parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password
                or parsed.query or parsed.fragment or any(c.isspace() for c in url)):
            raise SharedOwnerError()
        _ = parsed.port
        secret.encode("utf-8")
    except (ValueError, UnicodeError):
        raise SharedOwnerError() from None
    return url, secret


def verify_source(owner, purpose):
    """One fixed authenticated pure read, outside every native SQL transaction.

    Requests inactivity timeout plus per-byte elapsed checks are not an absolute
    DNS/response-header wall-clock guarantee. No redirect/retry/proxy is used.
    """
    if not isinstance(owner, SharedSourceOwner) or purpose not in {"sync", "disconnect", "transport"}:
        raise SharedOwnerError()
    return _verified_call({"version": 1, "purpose": purpose, "owner": owner.projection()}, "SHARED_SLACK_OWNER_VERIFY_URL")


def _verified_call(body, setting):
    if transaction.get_connection().in_atomic_block:
        raise SharedOwnerError()
    url, secret = _verification_config(setting)
    max_bytes = 512 * 1024 if setting == "SHARED_SLACK_LINKS_VERIFY_URL" else 4096
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    start = time.monotonic()
    response = None
    try:
        with requests.Session() as client:
            client.trust_env = False
            response = client.post(url, data=raw, headers={"Content-Type": "application/json", "Accept-Encoding": "identity",
                "X-Grafana-Slack-Timestamp": timestamp, "X-Grafana-Slack-Signature": signature},
                timeout=(2.5, 2.5), allow_redirects=False, stream=True)
            length = response.headers.get("Content-Length", "")
            if (response.status_code != 200 or time.monotonic() - start > 2.5
                    or response.headers.get("Content-Encoding", "identity").lower() != "identity"
                    or response.headers.get("Transfer-Encoding") is not None
                    or not isinstance(length, str) or re.fullmatch(r"[1-9][0-9]{0,5}", length) is None
                    or int(length) > max_bytes):
                raise SharedOwnerError()
            result = bytearray()
            for chunk in response.iter_content(chunk_size=1):
                if time.monotonic() - start > 2.5 or len(result) + len(chunk) > int(length):
                    raise SharedOwnerError()
                result.extend(chunk)
            if time.monotonic() - start > 2.5 or len(result) != int(length):
                raise SharedOwnerError()
            answer = strict_json(bytes(result))
            expected = {**body, "verified": True}
            if (not isinstance(answer, dict) or set(answer) != set(expected)
                    or type(answer.get("version")) is not int or answer["version"] != 1 or answer.get("verified") is not True
                    or SharedSourceOwner.parse(answer.get("owner")) != SharedSourceOwner.parse(body["owner"])
                    or json.dumps(answer, sort_keys=True, separators=(",", ":")) != json.dumps(expected, sort_keys=True, separators=(",", ":"))
                    or _verification_config(setting) != (url, secret)):
                raise SharedOwnerError()

    except (requests.RequestException, ValueError, UnicodeError):
        raise SharedOwnerError() from None
    finally:
        if response is not None:
            response.close()

    if _verification_config(setting) != (url, secret):
        raise SharedOwnerError()
    return url, secret


@contextmanager
def using_shared_owner(organization_id, owner):
    token = _SOURCE.set((organization_id, owner))
    try:
        yield
    finally:
        _SOURCE.reset(token)


def selected_shared_owner():
    return _SOURCE.get()


def local_source_snapshot(team_pk, organization_id=None):
    from apps.slack.models import SharedSlackInstallation, SlackTeamIdentity
    rows = SharedSlackInstallation.objects.filter(team_id=team_pk)
    if organization_id is not None:
        rows = rows.filter(organization_id=organization_id)
    values = list(rows.values("organization_id", "source_owner", "source_disconnected", "organization__slack_team_identity_id")[:2])
    if not values:
        return None
    if len(values) != 1:
        raise SharedOwnerError()
    row = values[0]
    owner = SharedSourceOwner.parse(row["source_owner"])
    if shared_organization_id(owner) != row["organization_id"]:
        raise SharedOwnerError()
    physical = SlackTeamIdentity.objects.filter(pk=team_pk).values(
        "slack_id", "cached_app_id", "bot_user_id", "bot_access_token", "detected_token_revoked").first()
    if (physical is None or row["source_disconnected"] or row["organization__slack_team_identity_id"] != team_pk
            or physical["slack_id"] != owner.team_id or physical["cached_app_id"] != owner.app_id
            or not isinstance(physical["bot_access_token"], str) or not physical["bot_access_token"]
            or physical["detected_token_revoked"] is not None
            or hashlib.sha256(physical["bot_access_token"].encode()).hexdigest() != owner.token_sha256):
        raise SharedOwnerError()
    # No raw token leaves this private local scalar snapshot.
    return row["organization_id"], owner, physical["bot_user_id"]


def require_local_source(team_pk, organization_id, owner):
    current = local_source_snapshot(team_pk, organization_id)
    if current is None or current[1] != owner:
        raise SharedOwnerError()
    return current


_LINK_FIELDS = {"version", "slackUserId", "grafanaUserId", "mappingId", "grafanaLogin", "mappingLinkRevision", "linkRevision"}


def parse_link(value):
    if (not isinstance(value, dict) or set(value) != _LINK_FIELDS or type(value.get("version")) is not int
            or value["version"] != 1 or not _slack(value["slackUserId"], "[UW]") or not _counter(value["linkRevision"])):
        raise SharedOwnerError()
    linked = (value["grafanaUserId"], value["mappingId"], value["grafanaLogin"], value["mappingLinkRevision"])
    if all(item is None for item in linked):
        return dict(value)
    login = value["grafanaLogin"]
    try:
        login_size = len(login.encode("utf-8")) if isinstance(login, str) else 0
    except UnicodeError:
        raise SharedOwnerError() from None
    if (not _positive(value["grafanaUserId"]) or not _identifier(value["mappingId"])
            or not _counter(value["mappingLinkRevision"]) or not isinstance(login, str) or not login
            or login_size > 512 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in login)):
        raise SharedOwnerError()
    return dict(value)


def verify_link_source(owner, link):
    parsed = parse_link(link)
    return _verified_call({"version": 1, "owner": owner.projection(), "link": parsed}, "SHARED_SLACK_LINK_VERIFY_URL")


@dataclass(frozen=True, repr=False)
class SharedNotificationRecipient:
    """Original native recipient/link provenance, never a saved permission."""
    owner: SharedSourceOwner
    user_id: int
    message_id: str
    snapshot: tuple
    link_json: str
    initial_im_channel: str | None

    @staticmethod
    def _snapshot(owner, user_id, message_id):
        from apps.slack.models import SharedSlackInstallation, SlackMessage
        from apps.user_management.models import User
        if transaction.get_connection().in_atomic_block:
            raise SharedOwnerError()
        user = User.objects.filter(pk=user_id).select_related("organization", "slack_user_identity").first()
        message = SlackMessage.objects.filter(pk=message_id).values(
            "created_at", "source_owner", "slack_id", "channel__slack_id", "_slack_team_identity_id",
            "alert_group_id", "channel_id", "alert_group__channel__organization_id").first()
        if user is None or message is None or user.slack_user_identity_id is None:
            raise SharedOwnerError()
        identity = user.slack_user_identity
        if (not _positive(str(user.user_id)) or not user.is_notification_allowed
                or message["alert_group__channel__organization_id"] != user.organization_id
                or message["_slack_team_identity_id"] != identity.slack_team_identity_id
                or message["source_owner"] != owner.projection()):
            raise SharedOwnerError()
        require_local_source(identity.slack_team_identity_id, user.organization_id, owner)
        source = SharedSlackInstallation.objects.filter(organization_id=user.organization_id).values(
            "source_links").first()
        if source is None or not isinstance(source["source_links"], dict):
            raise SharedOwnerError()
        link = parse_link(source["source_links"].get(identity.slack_id))
        if link["grafanaUserId"] != str(user.user_id) or link["slackUserId"] != identity.slack_id:
            raise SharedOwnerError()
        canonical_link = json.dumps(link, sort_keys=True, separators=(",", ":"))
        return (user.pk, user.public_primary_key, user.organization_id, str(user.user_id), identity.pk,
            identity.slack_id, identity.slack_team_identity_id, identity.counter, str(message_id),
            message["created_at"].isoformat(), message["slack_id"], message["channel__slack_id"],
            message["alert_group_id"], message["channel_id"], canonical_link)

    @classmethod
    def capture(cls, owner, user, message):
        snapshot = cls._snapshot(owner, user.pk, str(message.pk))
        identity = user.slack_user_identity
        # Compare the actual caller objects used to render mentions/coordinates,
        # rather than replacing stale same-PK objects with a fresh recipient.
        if (user.public_primary_key != snapshot[1] or user.organization_id != snapshot[2]
                or str(user.user_id) != snapshot[3] or user.slack_user_identity_id != snapshot[4]
                or (identity.pk, identity.slack_id, identity.slack_team_identity_id, identity.counter) != snapshot[4:8]
                or (str(message.pk), message.created_at.isoformat(), message.slack_id,
                    message.channel.slack_id, message.alert_group_id) != snapshot[8:13]
                or message.channel_id != snapshot[13]
                or message.source_owner != owner.projection()
                or message._slack_team_identity_id != identity.slack_team_identity_id):
            raise SharedOwnerError()
        from apps.slack.models import SlackUserIdentity
        cached = SlackUserIdentity.objects.filter(pk=identity.pk).values_list("cached_im_channel_id").first()
        if cached is None or cached[0] != identity.cached_im_channel_id:
            raise SharedOwnerError()
        return cls(owner, user.pk, str(message.pk), snapshot, snapshot[-1], cached[0])

    def require_current(self):
        if self._snapshot(self.owner, self.user_id, self.message_id) != self.snapshot:
            raise SharedOwnerError()
        proof = verify_link_source(self.owner, strict_json(self.link_json.encode()))
        if (self._snapshot(self.owner, self.user_id, self.message_id) != self.snapshot
                or _verification_config("SHARED_SLACK_LINK_VERIFY_URL") != proof):
            raise SharedOwnerError()


@dataclass(frozen=True, repr=False)
class SharedCompletionRecipient:
    """Original asking user's completion address; no notification-role grant."""
    owner: SharedSourceOwner
    user_id: int
    snapshot: tuple
    link_json: str

    @staticmethod
    def _snapshot(owner, user_id):
        from apps.slack.models import SharedSlackInstallation
        from apps.user_management.models import User
        if transaction.get_connection().in_atomic_block:
            raise SharedOwnerError()
        user = User.objects.filter(pk=user_id).select_related("slack_user_identity").first()
        if user is None or user.slack_user_identity_id is None or not _positive(str(user.user_id)):
            raise SharedOwnerError()
        identity = user.slack_user_identity
        require_local_source(identity.slack_team_identity_id, user.organization_id, owner)
        source = SharedSlackInstallation.objects.filter(organization_id=user.organization_id).values("source_links").first()
        if source is None or not isinstance(source["source_links"], dict):
            raise SharedOwnerError()
        link = parse_link(source["source_links"].get(identity.slack_id))
        if link["slackUserId"] != identity.slack_id or link["grafanaUserId"] != str(user.user_id):
            raise SharedOwnerError()
        return (user.pk, user.public_primary_key, user.organization_id, str(user.user_id), identity.pk,
            identity.slack_id, identity.slack_team_identity_id, identity.counter,
            json.dumps(link, sort_keys=True, separators=(",", ":")))

    @classmethod
    def capture(cls, owner, user, identity):
        snapshot = cls._snapshot(owner, user.pk)
        if ((user.pk, user.public_primary_key, user.organization_id, str(user.user_id),
                user.slack_user_identity_id) != snapshot[:5]
                or (identity.pk, identity.slack_id, identity.slack_team_identity_id, identity.counter) != snapshot[4:8]):
            raise SharedOwnerError()
        return cls(owner, user.pk, snapshot, snapshot[-1])

    def require_current(self):
        if self._snapshot(self.owner, self.user_id) != self.snapshot:
            raise SharedOwnerError()
        proof = verify_link_source(self.owner, strict_json(self.link_json.encode()))
        if (self._snapshot(self.owner, self.user_id) != self.snapshot
                or _verification_config("SHARED_SLACK_LINK_VERIFY_URL") != proof):
            raise SharedOwnerError()


_PAGING_COMPLETION_SEAL = object()


@dataclass(frozen=True, repr=False, init=False)
class SharedPagingCompletion:
    """In-memory proof of this original FinishDirectPaging committed outcome."""
    owner: SharedSourceOwner
    recipient: SharedCompletionRecipient
    delivery: tuple
    origin_json: str
    group_id: int
    outcome: tuple
    text: str
    channel_id: str
    _view_id: str
    _seal: object

    @staticmethod
    def _outcome(group_id, user_id):
        from apps.alerts.models import AlertGroup, AlertGroupLogRecord, AlertReceiveChannel
        from apps.user_management.models import User
        if transaction.get_connection().in_atomic_block:
            raise SharedOwnerError()
        user = User.objects.filter(pk=user_id).first()
        group = AlertGroup.objects.filter(pk=group_id).select_related("channel__organization").first()
        if (user is None or group is None or group.channel.organization_id != user.organization_id
                or group.channel.integration != AlertReceiveChannel.INTEGRATION_DIRECT_PAGING
                or group.wiped_at is not None):
            raise SharedOwnerError()
        alerts = list(group.alerts.order_by("pk").values("pk", "created_at", "raw_request_data", "integration_unique_data")[:2])
        if len(alerts) != 1:
            raise SharedOwnerError()
        alert = alerts[0]
        raw = alert["raw_request_data"]
        creator = alert["integration_unique_data"]
        oncall = raw.get("oncall") if isinstance(raw, dict) else None
        if (not isinstance(creator, dict) or creator.get("created_by") != user.username
                or not isinstance(oncall, dict) or oncall.get("author_username") != user.username):
            raise SharedOwnerError()
        from uuid import UUID
        try:
            if str(UUID(oncall.get("uid"))) != oncall.get("uid"):
                raise SharedOwnerError()
        except (ValueError, TypeError, AttributeError):
            raise SharedOwnerError() from None
        logs = list(group.log_records.filter(type=AlertGroupLogRecord.TYPE_DIRECT_PAGING)
            .order_by("pk").values_list("pk", "author_id", "created_at", "step_specific_info")[:1001])
        if len(logs) > 1000 or any(log[1] != user.pk for log in logs):
            raise SharedOwnerError()
        # Empty-team direct paging has no responder log. Its original Alert
        # creator/UID is still mandatory; no synthetic audit record is added.
        return (group.pk, group.public_primary_key, group.started_at.isoformat(), group.channel_id,
            group.channel.organization_id, alert["pk"], alert["created_at"].isoformat(),
            hashlib.sha256(json.dumps([raw, creator], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            tuple((log[0], log[1], log[2].isoformat(), json.dumps(log[3], sort_keys=True, separators=(",", ":"))) for log in logs),
            group.web_link)

    @classmethod
    def _from_original_finish(cls, owner, user, identity, group, payload, writer_started):
        from apps.slack.models import SharedSlackDelivery
        delivery = selected_shared_delivery()
        origin = modal_owner(payload, owner.team_id, owner.app_id)
        if (delivery is None or origin is None or delivery[1] != identity.slack_id
                or origin.get("sourceOwner") != owner.projection()
                or origin.get("organizationId") != user.organization_id
                or origin.get("callbackId") != "FinishDirectPaging"
                or origin.get("channelId") != delivery[2] or origin.get("slackUserId") != delivery[1]
                or origin.get("rootTS") != delivery[3] or not _slack(delivery[2], "[CGD]")):
            raise SharedOwnerError()
        accepted = SharedSlackDelivery.objects.filter(pk=delivery[0], phase="dispatching",
            source_owner=owner.projection()).exists()
        outcome = cls._outcome(group.pk, user.pk)
        if (not accepted or group.started_at < writer_started or group.pk != outcome[0]
                or group.public_primary_key != outcome[1] or group.started_at.isoformat() != outcome[2]
                or group.channel_id != outcome[3]):
            raise SharedOwnerError()
        recipient = SharedCompletionRecipient.capture(owner, user, identity)
        receipt = object.__new__(cls)
        values = dict(owner=owner, recipient=recipient, delivery=delivery,
            origin_json=json.dumps(origin, sort_keys=True, separators=(",", ":")), group_id=group.pk,
            outcome=outcome, text=f":white_check_mark: Escalation created: {outcome[-1]}",
            channel_id=delivery[2], _view_id=payload["view"]["id"], _seal=_PAGING_COMPLETION_SEAL)
        for name, value in values.items():
            object.__setattr__(receipt, name, value)
        receipt.require_current()
        return receipt

    def _require_outcome(self):
        from apps.slack.models import SharedSlackDelivery
        if getattr(self, "_seal", None) is not _PAGING_COMPLETION_SEAL:
            raise SharedOwnerError()
        if (selected_shared_delivery() != self.delivery or self.owner != self.recipient.owner
                or self.channel_id != self.delivery[2]
                or self.text != f":white_check_mark: Escalation created: {self.outcome[-1]}"):
            raise SharedOwnerError()
        record = SharedSlackDelivery.objects.filter(pk=self.delivery[0], phase="dispatching",
            source_owner=self.owner.projection()).first()
        if record is None or self._outcome(self.group_id, self.recipient.user_id) != self.outcome:
            raise SharedOwnerError()
        origin = strict_json(self.origin_json.encode())
        # The original modal must survive unchanged; never select a new default
        # or reuse only a caller-supplied channel/text after paging succeeds.
        rows = list(SharedSlackDelivery.objects.filter(modal_owners__has_key=self._view_id)
            .values_list("modal_owners", flat=True)[:2])
        if len(rows) != 1 or rows[0].get(self._view_id) != origin:
            raise SharedOwnerError()

    def require_current(self):
        self._require_outcome()
        self.recipient.require_current()
        # The original group/creator/modal may change during the link HTTP.
        self._require_outcome()



def verify_links_source(owner, revision, links):
    if not _counter(revision) or not isinstance(links, list) or len(links) > 1000:
        raise SharedOwnerError()
    parsed = [parse_link(link) for link in links]
    if (len({link["slackUserId"] for link in parsed}) != len(parsed)
            or any(link["grafanaUserId"] is None or link["linkRevision"] > revision for link in parsed)):
        raise SharedOwnerError()
    return _verified_call({"version": 1, "owner": owner.projection(), "linksRevision": revision, "links": parsed},
                          "SHARED_SLACK_LINKS_VERIFY_URL")


_DELIVERY = ContextVar("oncall_shared_delivery", default=None)


@contextmanager
def using_shared_delivery(key, actor, channel_id, root_ts):
    token = _DELIVERY.set((key, actor, channel_id, root_ts))
    try:
        yield
    finally:
        _DELIVERY.reset(token)


def selected_shared_delivery():
    return _DELIVERY.get()


def remember_modal(owner, organization_id, method, request, response):
    """Attach real provider view coordinates to the original delivery record."""
    from apps.slack.models import SharedSlackDelivery
    delivery = _DELIVERY.get()
    if delivery is None:
        return
    key, actor, channel, root = delivery
    if not _slack(actor, "[UW]"):
        raise SharedOwnerError()
    view = response.get("view")
    if not isinstance(view, dict) or not isinstance(view.get("id"), str) or not _identifier(view["id"]):
        raise SharedOwnerError()
    outgoing = request.get("view")
    if isinstance(outgoing, str):
        outgoing = strict_json(outgoing.encode())
    if not isinstance(outgoing, dict) or not isinstance(outgoing.get("callback_id", ""), str):
        raise SharedOwnerError()
    metadata = outgoing.get("private_metadata", "")
    if not isinstance(metadata, str) or len(metadata.encode()) > 3000:
        raise SharedOwnerError()
    record = {"organizationId": organization_id, "sourceOwner": owner.projection(), "slackUserId": actor,
        "channelId": channel, "rootTS": root, "callbackId": outgoing.get("callback_id", ""), "privateMetadata": metadata}
    from django.db.models import Q
    with transaction.atomic():
        receipts = list(SharedSlackDelivery.objects.select_for_update().filter(
            Q(key=key) | Q(modal_owners__has_key=view["id"])).order_by("key")[:3])
        current = next((receipt for receipt in receipts if receipt.key == key), None)
        existing = [receipt for receipt in receipts if view["id"] in receipt.modal_owners]
        if (current is None or current.source_owner != owner.projection() or current.phase != "dispatching"
                or len(existing) > 1):
            raise SharedOwnerError()
        receipt = existing[0] if existing else current
        if existing:
            previous = receipt.modal_owners[view["id"]]
            if any(previous.get(k) != record[k] for k in ("organizationId", "sourceOwner", "slackUserId", "channelId", "rootTS")):
                raise SharedOwnerError()
        views = dict(receipt.modal_owners)
        if len(views) >= 20 and view["id"] not in views:
            raise SharedOwnerError()
        views[view["id"]] = record
        receipt.modal_owners = views
        receipt.save(update_fields=["modal_owners"])


def modal_owner(payload, team_id, app_id):
    """Pure original-receipt lookup; the UI's org hint does not select a route."""
    from apps.slack.models import SharedSlackDelivery
    view = payload.get("view")
    if not isinstance(view, dict) or not _identifier(view.get("id")):
        return None
    # A provider view ID is indexed by the original receipt JSON key. At most
    # two matches is sufficient to reject ambiguous historical ownership.
    records = list(SharedSlackDelivery.objects.filter(modal_owners__has_key=view["id"]).values_list("modal_owners", flat=True)[:2])
    if len(records) != 1:
        return None
    record = records[0].get(view["id"])
    if not isinstance(record, dict):
        return None
    owner = SharedSourceOwner.parse(record.get("sourceOwner"))
    user = payload.get("user")
    actor = user.get("id") if isinstance(user, dict) else payload.get("user_id")
    if (owner.team_id != team_id or owner.app_id != app_id or actor != record.get("slackUserId")
            or view.get("callback_id", "") != record.get("callbackId")
            or view.get("private_metadata", "") != record.get("privateMetadata")):
        return None
    return record


_LOADING = ContextVar("oncall_shared_loading_view", default=None)


@contextmanager
def using_loading_view(view):
    if view is not None and (not isinstance(view, dict) or set(view) - {"id", "hash"}
            or not _identifier(view.get("id")) or "hash" in view and
            (not isinstance(view["hash"], str) or not 0 < len(view["hash"]) <= 100)):
        raise SharedOwnerError()
    token = _LOADING.set(dict(view) if view is not None else None)
    try:
        yield
    finally:
        _LOADING.reset(token)


def selected_loading_view():
    return _LOADING.get()


def verify_publication(owner):
    """Fresh IRM enabled read for new publication; identity remains separate."""
    if not isinstance(owner, SharedSourceOwner):
        raise SharedOwnerError()
    return _verified_call({"version": 1, "owner": owner.projection()}, "SHARED_SLACK_PUBLISH_VERIFY_URL")


def mark_loading_filled():
    loading = _LOADING.get()
    if loading is not None:
        loading["_filled"] = True
