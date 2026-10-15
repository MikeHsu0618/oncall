import logging

import requests
from django.core.cache import cache
from rest_framework.exceptions import PermissionDenied, Throttled

from .config import Unavailable, load_binding, positive_int
from .tokens import mint_pair

logger = logging.getLogger(__name__)


def actor_snapshot(user, token, binding):
    if (user is None or user.is_active is not True or token is None
            or user.organization_id != token.organization_id
            or token.organization_id != binding.oncall_org_id):
        raise PermissionDenied("WebSession pairing does not match organization")
    external_id = positive_int(user.user_id, "User.user_id")
    if not isinstance(user.username, str) or not user.username or not isinstance(user.email, str) or not user.email:
        raise PermissionDenied("WebSession pairing needs a current login and email")
    return (user.pk, token.pk, token.organization_id, external_id, user.username, user.email)


def rate_limit(snapshot):
    # Atomic add on the deployment's shared cache; no process-local throttle state.
    key = f"web-session:mint:{snapshot[2]}:{snapshot[0]}"
    try:
        allowed = cache.add(key, True, timeout=10)
    except Exception:
        logger.warning("WebSession mint cache unavailable")
        raise Unavailable("WebSession rate limit unavailable") from None
    if not allowed:
        raise Throttled(wait=10)


def fetch_json(session, url, headers):
    try:
        # Never propagate cookies set by the previous probe, caller headers or netrc.
        session.cookies.clear()
        response = session.get(url, headers=headers, allow_redirects=False, timeout=(3, 5), verify=True)
        if response.status_code != 200:
            raise PermissionDenied("Grafana identity validation failed")
        payload = response.json()
    except (requests.RequestException, ValueError):
        logger.warning("WebSession Grafana validation transport or JSON failed")
        raise Unavailable("Grafana identity validation unavailable") from None
    if not isinstance(payload, dict):
        raise PermissionDenied("Grafana identity validation failed")
    return payload


def validate_identity(binding, snapshot):
    probe = mint_pair(binding, snapshot[3], validation=True)
    headers = {"X-Access-Token": probe["access_token"], "X-Grafana-Id": probe["id_token"]}
    session = requests.Session()
    session.trust_env = False
    session.auth = None
    session.headers.clear()
    try:
        user = fetch_json(session, binding.internal_origin + "/api/user", headers)
        org = fetch_json(session, binding.internal_origin + "/api/org", headers)
    finally:
        session.close()
    # Exact login AND email policy. Legitimate changes require re-sync/re-pairing.
    if (type(user.get("id")) is not int or user["id"] != snapshot[3]
            or type(user.get("orgId")) is not int or user["orgId"] != binding.grafana_org_id
            or type(org.get("id")) is not int or org["id"] != binding.grafana_org_id
            or user.get("login") != snapshot[4] or user.get("email") != snapshot[5]
            or any(user.get(flag, False) is not False for flag in ("isDisabled", "isServiceAccount"))):
        raise PermissionDenied("Grafana identity or organization changed; re-sync pairing")


def issue_session(request):
    from apps.mobile_app.auth import MobileAppAuthTokenAuthentication

    binding = load_binding()
    snapshot = actor_snapshot(request.user, request.auth, binding)
    rate_limit(snapshot)
    validate_identity(binding, snapshot)
    # Reuse the real token validator and fresh active User query after both probes.
    fresh = MobileAppAuthTokenAuthentication().authenticate(request)
    if fresh is None:
        raise PermissionDenied("Mobile pairing changed during Grafana validation")
    current = load_binding()
    if current != binding or actor_snapshot(*fresh, current) != snapshot:
        raise PermissionDenied("Mobile pairing or binding changed during Grafana validation")
    return {**mint_pair(current, snapshot[3]), "grafana_url": current.public_origin}
