"""Authorized, bounded native paging searches for Slack external selects."""

import json

from django.db.models import Case, IntegerField, Q, Value, When
from rest_framework.response import Response

from apps.slack.chatops_proxy_routing import make_value
from apps.slack.types import PayloadType


def target_option(target, organization):
    label = (getattr(target, "name", None) or getattr(target, "username", "") or target.public_primary_key).strip() or target.public_primary_key
    # Slack labels admit 75 characters. Keep a stable ID for distinct long names.
    if len(label) > 75:
        suffix = "… " + target.public_primary_key
        label = label[:75 - len(suffix)] + suffix
    username = getattr(target, "username", "")
    suffix = " · " + target.public_primary_key if username else target.public_primary_key
    description = username[:75 - len(suffix)] + suffix if username else suffix
    return {"text": {"type": "plain_text", "text": label, "emoji": True},
            "description": {"type": "plain_text", "text": description},
            "value": make_value({"id": target.pk}, organization)}


def search_targets(organization, payload):
    from apps.slack.scenarios import paging
    query = payload.get("value")
    if not isinstance(query, str) or len(query) > 300 or any(ord(char) < 32 for char in query):
        raise ValueError("Invalid paging search")
    query = query.strip()
    if payload["action_id"] == paging.OnPagingTeamChange.routing_uid():
        targets = organization.teams.all()
        match = Q(name__icontains=query) | Q(public_primary_key__iexact=query)
        exact = Q(name__iexact=query) | Q(public_primary_key__iexact=query)
        order = "name"
    else:
        targets = organization.users.all()
        match = Q(username__icontains=query) | Q(name__icontains=query) | Q(public_primary_key__iexact=query)
        exact = Q(username__iexact=query) | Q(name__iexact=query) | Q(public_primary_key__iexact=query)
        order = "username"
    targets = (targets.filter(match)
               .annotate(search_rank=Case(When(exact, then=Value(0)), default=Value(1), output_field=IntegerField()))
               .order_by("search_rank", order, "pk")[:100])
    return {"options": [target_option(target, organization) for target in targets]}


def dispatch_options(organization, team, identity, payload, *, metadata=None):
    from apps.slack.scenarios import paging
    if payload.get("type") != PayloadType.BLOCK_SUGGESTION:
        return None
    if identity is None or payload.get("api_app_id") != team.cached_app_id:
        return Response(status=403)
    try:
        if metadata is None:
            metadata = json.loads(payload["view"]["private_metadata"])
            selected = paging._get_predefined_org_from_private_metadata(metadata, team)
            if selected is None:
                selected = paging._get_selected_org_from_payload(payload, metadata["input_id_prefix"], team, identity)
            if organization is not None and (selected is None or selected.pk != organization.pk):
                return Response(status=403)
            organization = selected
        if organization is None or not paging._get_available_organizations(team, identity).filter(pk=organization.pk).exists():
            return Response(status=403)
        routes = [r for r in paging.STEPS_ROUTING if r["payload_type"] == PayloadType.BLOCK_SUGGESTION
                  and r["block_suggestion_action_id"] == payload.get("action_id")]
        if len(routes) != 1:
            return Response(status=422)
        field = (paging.DIRECT_PAGING_TEAM_SELECT_ID if payload["action_id"] == paging.OnPagingTeamChange.routing_uid()
                 else paging.DIRECT_PAGING_USER_SELECT_ID)
        if payload.get("block_id") != metadata["input_id_prefix"] + field:
            return Response(status=422)
        user = identity.get_user(organization)
        step = routes[0]["step"](team, organization, user)
        if not step.is_authorized():
            return Response(status=403)
        return step.process_scenario(identity, team, payload)
    except (ValueError, KeyError, TypeError, AttributeError):
        return Response(status=422)
