"""[code] Maintained Incident actor service; routed via local_incident/views.py behind MOBILE_APP_LOCAL_INCIDENT_ENABLED (default OFF).

[code] Positive operations release the finite transport result only after fresh
identity probes and final authentication/binding/gate/organization checks.
A failed release check discards the result, not any already committed write.
[code] Pre/post checks cannot make distributed revocation atomic or undo committed
writes. Transport failures retain an unknown write outcome; never retry here.
"""

from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed, NotFound, PermissionDenied

from apps.mobile_app.auth import MobileAppAuthTokenAuthentication
from apps.mobile_app.web_session import service as web_service, tokens
from apps.mobile_app.web_session.config import Unavailable, load_binding
from apps.user_management.models import Organization

from . import contracts, transport


def _require_local_enabled():
    if getattr(settings, "MOBILE_APP_LOCAL_INCIDENT_ENABLED", False) is not True:
        raise Unavailable("Local incident unavailable")


def _validate_operation(request, path, raw_body, http_method):
    if request is None:
        raise AuthenticationFailed("Mobile authentication required")
    method = contracts.resolve_method(path, http_method)
    contracts.resolve_method(path, getattr(request, "method", None))
    # [code] Validate before any probes/mints; preserve the original native bytes
    # for transport's independent finite contract check, not a generic proxy.
    contracts.validate_request(method, contracts.decode_body(raw_body))


def _authenticate(request):
    try:
        authenticated = MobileAppAuthTokenAuthentication().authenticate(request)
    except (AttributeError, TypeError, UnicodeError):
        # [code] The real authenticator decodes the raw Authorization header.
        # Malformed headers expose only this static DRF boundary message.
        raise AuthenticationFailed("Invalid mobile authentication") from None
    if authenticated is None:
        raise AuthenticationFailed("Mobile authentication required")
    return authenticated


def _actor_snapshot(user, token, binding):
    try:
        return web_service.actor_snapshot(user, token, binding)
    except (AttributeError, TypeError):
        raise AuthenticationFailed("Invalid mobile authentication") from None


def _capture_actor(request, binding):
    authenticated = _authenticate(request)
    snapshot = _actor_snapshot(*authenticated, binding)
    cached = _actor_snapshot(request.user, request.auth, binding)
    if cached != snapshot:
        raise PermissionDenied("Mobile pairing does not match authenticated actor")
    return snapshot


def _require_incident_organization(binding):
    # [code] The default manager excludes deleted rows. Only the bound OnCall PK
    # selects this fresh row; external/Grafana/stack IDs and cached relations do not.
    organization = Organization.objects.filter(pk=binding.oncall_org_id).first()
    if organization is None or organization.is_grafana_incident_enabled is not True:
        raise NotFound("Local incident organization unavailable")


def _revalidate_local_state(request, binding, snapshot):
    authenticated = _authenticate(request)
    current = load_binding()
    if current != binding or _actor_snapshot(*authenticated, current) != snapshot:
        raise PermissionDenied("Mobile pairing or binding changed during validation")
    _require_local_enabled()
    _require_incident_organization(binding)


def perform_local_incident(request, path: str, raw_body: bytes, *, http_method: str = "POST") -> dict:
    """[code] Dispatch once with real prechecks; release only after real postchecks."""
    _require_local_enabled()
    _validate_operation(request, path, raw_body, http_method)
    binding = load_binding()
    snapshot = _capture_actor(request, binding)
    _require_incident_organization(binding)
    web_service.validate_identity(binding, snapshot)
    _revalidate_local_state(request, binding, snapshot)
    pair = tokens.mint_local_incident_pair(binding, snapshot[3])
    result = transport.call_incident(binding, pair, path, raw_body, http_method=http_method)
    # [code] Reuse captured authority/destination, never follow a changed binding.
    # Safe typed failures discard the body without compensation or write retry.
    web_service.validate_identity(binding, snapshot)
    _revalidate_local_state(request, binding, snapshot)
    return result
