"""Typed Slack escalation targets, executed by the original OnCall engine."""

import hashlib
import json
import re
import shlex

from django.db import transaction
from django.db.models import Q
from rest_framework.response import Response

from apps.alerts.paging import direct_paging
from apps.api.permissions import RBACPermission, user_is_authorized
from apps.slack.models import SharedSlackPagingCommand, SharedSlackPagingNotification

USER_MENTION = re.compile(r"<@([A-Z0-9]+)(?:\|[^<>]+)?>\Z")


def command_target(payload):
    """One exact target, including quoted team names; never fuzzy-match a page."""
    from apps.slack.slash_command import SlashCommand

    text = payload.get("text", "")
    if not isinstance(text, str) or len(text) > 1000 or any(ord(char) < 32 for char in text):
        raise ValueError("Invalid escalation target. Use /grafana escalate @user or a team name.")
    if not payload.get("command"):
        return ""
    command = SlashCommand.parse(payload)
    text = text.strip()
    tail = text.split(maxsplit=1)[1] if command.is_root_command and len(text.split(maxsplit=1)) == 2 else ("" if command.is_root_command else text)
    if not tail:
        return ""
    if USER_MENTION.fullmatch(tail):
        return tail
    parts = shlex.split(tail)
    if len(parts) != 1:
        # An unquoted multiword target may still be an exact full team name.
        if any(char in tail for char in (chr(34), chr(39))):
            raise ValueError("Specify one user or team. Quote a team name that contains spaces.")
        return tail
    return parts[0]


def resolve_target(organization, slack_team, target):
    mention = USER_MENTION.fullmatch(target)
    if mention:
        users = list(organization.users.filter(slack_user_identity__slack_team_identity=slack_team,
                                              slack_user_identity__slack_id=mention[1])[:2])
        teams = []
    else:
        name = target.removeprefix("@")
        if target.startswith("<") or not name:
            raise ValueError("Escalation target was not found in this stack.")
        user_filter = Q(username__iexact=name) | Q(public_primary_key=target)
        user_filter |= Q(slack_user_identity__slack_team_identity=slack_team,
                         slack_user_identity__cached_slack_login__iexact=name)
        users = list(organization.users.filter(user_filter).distinct()[:2])
        teams = [] if target.startswith("@") else list(organization.teams.filter(
            Q(name__iexact=target) | Q(public_primary_key=target))[:2])
    if len(users) + len(teams) != 1:
        raise ValueError("Escalation target is missing or ambiguous. Select it in /grafana escalate instead.")
    return (None, users[0]) if users else (teams[0], None)


def execute_target(organization, slack_team, identity, payload, target):
    """Persist native command result and notification intents with its one page."""
    key = hashlib.sha256(json.dumps([organization.pk, slack_team.slack_id, payload], sort_keys=True).encode()).hexdigest()

    def execute():
        with transaction.atomic():
            type(organization).objects.select_for_update().get(pk=organization.pk)
            user = identity.get_user(organization)
            if user is None or not user_is_authorized(user, [RBACPermission.Permissions.ALERT_GROUPS_DIRECT_PAGING]):
                return Response({"response_type": "ephemeral", "text": "You do not have permission to escalate alerts."}, status=403)
            receipt, created = SharedSlackPagingCommand.objects.get_or_create(key=key, defaults={
                "organization": organization, "team": slack_team, "slack_user_id": identity.slack_id,
                "grafana_user_id": str(user.user_id)})
            if not created:
                if (receipt.organization_id != organization.pk or receipt.team_id != slack_team.pk
                        or receipt.slack_user_id != identity.slack_id or receipt.grafana_user_id != str(user.user_id)):
                    return Response(status=403)
                if receipt.phase == "completed":
                    return Response(receipt.response_data)
            team, responder = resolve_target(organization, slack_team, target)
            users = [(responder, organization.direct_paging_prefer_important_policy)] if responder else []

            def enqueue(native_user, group, important, force_default_fallback=False):
                SharedSlackPagingNotification.objects.create(command=receipt, user=native_user, alert_group=group,
                    important=important, force_default_fallback=force_default_fallback)

            group = direct_paging(organization=organization, from_user=user, message="", team=team, users=users,
                                  notification_enqueue=enqueue)
            receipt.phase = "completed"
            receipt.alert_group_id = group.public_primary_key
            receipt.response_data = {"response_type": "ephemeral", "text": f":white_check_mark: Escalation created: {group.web_link}"}
            receipt.save(update_fields=["phase", "alert_group_id", "response_data"])
            return Response(receipt.response_data)

    try:
        return execute()
    except Exception:
        # Original alert on_commit signals can fail after commit. Its completed
        # receipt is the authority; reread it, never create another page.
        if SharedSlackPagingCommand.objects.filter(key=key, phase="completed").exists():
            return execute()
        raise
