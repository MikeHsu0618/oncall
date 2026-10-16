"""[code] Native Incident gateway route: request-time local/legacy selector + strict local view.

[code] Local mode (MOBILE_APP_LOCAL_INCIDENT_ENABLED is True) handles every suffix
below gateway/incident/ itself and never falls back to the legacy proxy. Every
local response is no-store; every non-200 body is exactly {"error": <static>}.
"""

import logging
import math
import re

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http.request import RawPostDataException
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import (
    AuthenticationFailed,
    MethodNotAllowed,
    NotAuthenticated,
    NotFound,
    PermissionDenied,
    Throttled,
)
from rest_framework.negotiation import BaseContentNegotiation
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import set_rollback

from apps.mobile_app.views import MobileAppGatewayView
from apps.mobile_app.web_session.config import Unavailable
from apps.mobile_app.web_session.views import NoStoreView, WebSessionAuthentication

from . import admission, contracts, service
from .json_inputs import MAX_BODY_BYTES, ContractError
from .responses import UpstreamResponseError
from .transport import IncidentTransportError

logger = logging.getLogger(__name__)

# [code] Explicit literal list of the 13 native write RPCs (admission scope flag only).
WRITE_METHODS = frozenset((
    "CommentsService.AddReaction",
    "CommentsService.RemoveReaction",
    "IncidentContextService.AddIncidentContext",
    "IncidentsService.AssignLabelByUUID",
    "IncidentsService.UnassignLabelByUUID",
    "IncidentsService.AssignRole",
    "IncidentsService.UnassignRole",
    "IncidentsService.CreateIncident",
    "IncidentsService.UpdateDescription",
    "IncidentsService.UpdateSeverity",
    "IncidentsService.UpdateStatus",
    "IncidentsService.UpdateTitle",
    "KeyUpdatesService.CreateKeyUpdate",
))

_DIGITS = re.compile(r"[0-9]+")
_INVALID_REQUEST = "invalid native incident request"
_STATUS_MESSAGES = {
    400: _INVALID_REQUEST,
    401: "authentication required",
    403: "permission denied",
    404: "not found",
    405: "method not allowed",
    409: "conflict",
    411: "content length required",
    413: "request too large",
    429: "too many requests",
    500: "internal error",
    502: "upstream incident request failed",
    503: "service unavailable",
}
# [code] Upstream statuses that are safe to surface; 401 and everything else -> 502
# so a server-to-server credential failure never looks like a dead mobile token.
_UPSTREAM_PASSTHROUGH = frozenset((400, 403, 404, 409, 413, 429))


class _Reject(Exception):
    """Local pre-check failure with a static status; carries no request data."""

    def __init__(self, status_code, message=None):
        super().__init__(status_code)
        self.status_code = status_code
        self.message = message


_ADMISSION_LOST = "local incident admission lost"


def _release_ok(permit):
    try:
        permit.release()
    except Exception as exc:
        # [code] Type name only; an unprovable release is reported as admission lost.
        logger.warning("Local incident admission release raised: type=%s", type(exc).__name__)
        return False
    return getattr(permit, "ok", None) is True


class _JSONOnlyNegotiation(BaseContentNegotiation):
    """Ignore Accept/format so negotiation can never raise or pick another renderer."""

    def select_parser(self, request, parsers):
        return None

    def select_renderer(self, request, renderers, format_suffix=None):
        return (renderers[0], renderers[0].media_type)


def _resolve_suffix(downstream_path):
    if type(downstream_path) is not str or not downstream_path.startswith("api/"):
        raise NotFound()
    method = downstream_path[len("api/"):]
    if method not in contracts.METHODS:
        raise NotFound()
    return method


def _declared_length(meta):
    value = meta.get("CONTENT_LENGTH")
    if value is None or value == "":
        raise _Reject(411)
    if type(value) is not str or not _DIGITS.fullmatch(value):
        raise _Reject(400)
    length = int(value)
    if length > MAX_BODY_BYTES:
        raise _Reject(413)
    return length


def _read_body(request, length):
    try:
        raw = request._request.body
    except RequestDataTooBig:
        raise _Reject(413) from None
    except RawPostDataException:
        raise _Reject(400) from None
    # [code] Defense-only: WSGI LimitedStream normally makes these lengths agree.
    if type(raw) is not bytes or len(raw) != length:
        raise _Reject(400)
    return raw


def _prevalidate(method, raw):
    # [code] Client contract errors are decided here, before admission. A ContractError
    # escaping perform_local_incident is treated as upstream/server-side (502): it comes
    # mostly from upstream response decoding/validation, though transport re-encoding
    # limits can rarely trip on an accepted body.
    try:
        contracts.validate_request(method, contracts.decode_body(raw))
    except ContractError:
        raise _Reject(400) from None


def _map_exception(exc):
    if isinstance(exc, _Reject):
        return exc.status_code
    if isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
        return 401
    if isinstance(exc, PermissionDenied):
        return 403
    if isinstance(exc, NotFound):
        return 404
    if isinstance(exc, MethodNotAllowed):
        return 405
    if isinstance(exc, Throttled):
        return 429
    if isinstance(exc, Unavailable):
        return 503
    if isinstance(exc, UpstreamResponseError):
        status = exc.http_status
        return status if type(status) is int and status in _UPSTREAM_PASSTHROUGH else 502
    if isinstance(exc, (IncidentTransportError, ContractError)):
        return 502
    # [code] Type name only: messages/tracebacks may carry tokens or request data.
    logger.error("Local incident gateway failed: type=%s", type(exc).__name__)
    return 500


def _is_envelope(data):
    return type(data) is dict and set(data) == {"error"} and type(data["error"]) is str


class LocalIncidentGatewayView(NoStoreView):
    authentication_classes = (WebSessionAuthentication,)
    permission_classes = (IsAuthenticated,)
    http_method_names = ("post",)
    parser_classes = ()
    renderer_classes = (JSONRenderer,)
    content_negotiation_class = _JSONOnlyNegotiation

    def post(self, request, downstream_path=""):
        method = _resolve_suffix(downstream_path)
        if request.META.get("QUERY_STRING"):
            raise NotFound()
        raw = _read_body(request, _declared_length(request.META))
        _prevalidate(method, raw)
        # [code] Scope comes only from the authenticated token/user, never the body.
        scope = (request.auth.organization_id, request.user.pk, method in WRITE_METHODS)
        permit = admission.acquire(scope)
        try:
            result = service.perform_local_incident(request, "/api/" + method, raw, http_method="POST")
        except BaseException:
            # [code] Release still runs; the original exception's mapping wins.
            _release_ok(permit)
            raise
        if not _release_ok(permit):
            # [code] Discard the result. Never retry or replay the operation: a write
            # may already be committed upstream, so its outcome is reported as unknown.
            raise _Reject(503, _ADMISSION_LOST)
        return Response(result, status=200)

    def handle_exception(self, exc):
        # [code] View-local replacement for DRF's handler: no 401->403 rewrite,
        # no exception detail echo, never re-raise.
        status_code = _map_exception(exc)
        set_rollback()
        message = exc.message if isinstance(exc, _Reject) and exc.message else _STATUS_MESSAGES[status_code]
        response = Response({"error": message}, status=status_code)
        if status_code == 401:
            auth_header = self.get_authenticate_header(self.request)
            if auth_header:
                response["WWW-Authenticate"] = auth_header
        elif isinstance(exc, Throttled) and exc.wait is not None:
            response["Retry-After"] = str(math.ceil(exc.wait))
        response.exception = True
        return response

    def finalize_response(self, request, response, *args, **kwargs):
        if response.status_code != 200 and not _is_envelope(getattr(response, "data", None)):
            status_code = response.status_code if response.status_code in _STATUS_MESSAGES else 500
            response = Response({"error": _STATUS_MESSAGES[status_code]}, status=status_code)
        # NoStoreView adds Cache-Control: no-store and Pragma: no-cache to every response.
        return super().finalize_response(request, response, *args, **kwargs)


@csrf_exempt
def incident_gateway_selector(request, downstream_path):
    """Request-time selector; CsrfViewMiddleware inspects this outer view."""
    if getattr(settings, "MOBILE_APP_LOCAL_INCIDENT_ENABLED", False) is True:
        return LocalIncidentGatewayView.as_view()(request, downstream_path=downstream_path)
    return MobileAppGatewayView.as_view()(
        request, downstream_backend="incident", downstream_path=downstream_path,
    )
