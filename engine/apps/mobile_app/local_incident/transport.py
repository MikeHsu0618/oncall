"""[code] Unrouted, finite server-to-server Incident transport; no actor authority.

[code] The service supplies an already validated frozen WebSession Binding and an
in-memory mint_pair result. Only the numeric binding.grafana_org_id selects the
Core organization; neither the OnCall PK, namespace nor request data can select it.
[code] Existing origin-only configuration policy applies unchanged. The resource
paths reserve a new Go entry point, not the existing generic dispatcher.
[code] Connect/read timeouts bound socket waits, not total elapsed time or immediate
cancellation. A failed write has an unknown outcome and is never retried here.
"""

import json
import logging
from types import MappingProxyType

import requests
from urllib3.exceptions import HTTPError

from apps.mobile_app.web_session.config import Binding, origin

from .contracts import resolve_method, validate_request
from .json_inputs import MAX_BODY_BYTES, decode_body, fail
from .responses import validate_response

logger = logging.getLogger(__name__)

# [code] Compile-time finite map, independent of client plugin/path selection.
METHOD_PATHS = MappingProxyType({
    "ActivityService.FilterActivity":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/ActivityService.FilterActivity",
    "ActivityService.QueryActivity":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/ActivityService.QueryActivity",
    "CommentsService.AddReaction":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/CommentsService.AddReaction",
    "CommentsService.RemoveReaction":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/CommentsService.RemoveReaction",
    "FieldsService.GetFields":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/FieldsService.GetFields",
    "IncidentContextService.AddIncidentContext":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentContextService.AddIncidentContext",
    "IncidentContextService.QueryIncidentContext":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentContextService.QueryIncidentContext",
    "IncidentsService.AssignLabelByUUID":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.AssignLabelByUUID",
    "IncidentsService.AssignRole":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.AssignRole",
    "IncidentsService.CreateIncident":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.CreateIncident",
    "IncidentsService.GetIncident":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.GetIncident",
    "IncidentsService.QueryIncidentPreviews":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.QueryIncidentPreviews",
    "IncidentsService.UnassignLabelByUUID":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UnassignLabelByUUID",
    "IncidentsService.UnassignRole":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UnassignRole",
    "IncidentsService.UpdateDescription":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateDescription",
    "IncidentsService.UpdateSeverity":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateSeverity",
    "IncidentsService.UpdateStatus":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateStatus",
    "IncidentsService.UpdateTitle":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/IncidentsService.UpdateTitle",
    "KeyUpdatesService.CreateKeyUpdate":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/KeyUpdatesService.CreateKeyUpdate",
    "KeyUpdatesService.GetLastKeyUpdate":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/KeyUpdatesService.GetLastKeyUpdate",
    "KeyUpdatesService.QueryKeyUpdates":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/KeyUpdatesService.QueryKeyUpdates",
    "OrgService.GetOrg":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/OrgService.GetOrg",
    "OrgService.GetOrgStatus":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/OrgService.GetOrgStatus",
    "SeveritiesService.GetOrgSeverities":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/SeveritiesService.GetOrgSeverities",
    "StatusService.QueryOrgStatuses":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/StatusService.QueryOrgStatuses",
    "UsersService.AutocompleteUsers":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.AutocompleteUsers",
    "UsersService.GetSession":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.GetSession",
    "UsersService.GetUser":
        "/api/plugins/grafana-irm-app/resources/mobile/incident/api/UsersService.GetUser",
})


class IncidentTransportError(ValueError):
    """Static boundary error, without upstream diagnostic values in its arguments."""

    def __init__(self):
        super().__init__("incident transport unavailable")


def _destination(binding, method):
    if not isinstance(binding, Binding):
        fail("binding", "a validated server binding is required")
    numeric_org_id = binding.grafana_org_id
    if type(numeric_org_id) is not int or not 0 < numeric_org_id < 2 ** 63:
        fail("grafana_org_id", "must be a positive int64")
    return origin(binding.internal_origin, "internal_origin") + METHOD_PATHS[method]


def _headers(binding, pair):
    if type(pair) is not dict or set(pair) != {"access_token", "id_token"}:
        fail("pair", "a server token pair is required")
    for value in pair.values():
        if type(value) is not str or not value or any(ord(char) <= 32 or ord(char) >= 127 for char in value):
            fail("pair", "token headers must be nonempty ASCII without whitespace or controls")
    return {
        "X-Access-Token": pair["access_token"],
        "X-Grafana-Id": pair["id_token"],
        "X-Grafana-Org-Id": str(binding.grafana_org_id),
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }


def _bounded_body(response):
    encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        raise IncidentTransportError()
    chunks = []
    size = 0
    while True:
        chunk = response.raw.read(min(65536, MAX_BODY_BYTES + 1 - size), decode_content=False)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise IncidentTransportError()
        chunks.append(chunk)


def _encoded_body(body):
    # [code] requests' json= uses ensure_ascii and can expand a valid UTF-8 input
    # beyond the byte cap. Serialize the validated object once and dispatch bytes.
    wire = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(wire) > MAX_BODY_BYTES:
        fail("body", "encoded request exceeds byte limit")
    return wire


def _no_redirects(*_args, **_kwargs):
    # [code] Requests still invokes resolve_redirects with allow_redirects=False
    # to populate Response.next, consuming/decompressing the response on that path.
    # This policy belongs only to the fresh owned Session: never prepare a redirect,
    # inspect Location or touch the response body, even for yield_requests=True.
    return iter(())


def _cleanup(action):
    try:
        action()
    except Exception:
        # [code] Only the cleanup operation is normalized, never model validation
        # or BaseException/control flow. Outer finally blocks still run later cleanup.
        raise IncidentTransportError() from None


def _request(method, url, headers, body):
    session = requests.Session()
    try:
        # [code] requests sessions are mutation-based APIs; this instance is private
        # to this call. No incoming request/session/header object is accepted.
        session.trust_env = False
        session.auth = None
        session.cert = None
        session.headers.clear()
        session.cookies.clear()
        session.proxies.clear()
        session.params.clear()
        session.hooks = {"response": []}
        session.resolve_redirects = _no_redirects
        response = session.post(url, data=body, headers=headers, timeout=(3, 5),
                                allow_redirects=False, stream=True, verify=True)
        try:
            payload = decode_body(_bounded_body(response))
            return validate_response(method, payload, http_status=response.status_code)
        finally:
            _cleanup(response.close)
    finally:
        try:
            _cleanup(session.cookies.clear)
        finally:
            _cleanup(session.close)


def call_incident(binding: Binding, pair: dict[str, str], path: str, raw_body: bytes,
                  *, http_method: str = "POST") -> dict:
    """Return only an independent validated HTTP-200 body; no response headers.

    Authentication, minting, numeric-org proof and feature/limiter decisions remain
    the service's responsibility. Domain user IDs never confer caller authority.
    """
    method = resolve_method(path, http_method)
    body = _encoded_body(validate_request(method, decode_body(raw_body)))
    url = _destination(binding, method)
    headers = _headers(binding, pair)
    try:
        return _request(method, url, headers, body)
    except (requests.RequestException, HTTPError, OSError, IncidentTransportError):
        # [code] Both fields are static/allowlisted; raw I/O exceptions contain secrets.
        logger.warning("Local incident transport failed: phase=http method=%s", method)
        raise IncidentTransportError() from None
