"""[code] Exact, unrouted native Incidents request contract; no auth or I/O logic.

[code] Source: /private/tmp/mobile-incident-wire.abLgfs/contract.json, SHA256
2e425c76142d36745d979271623f9807e71ba0d20a6e19feca0cef61ff099c5e.
[code] Serializer key sets and synthetic native examples are not server requiredness.
Only existing Go operation mandatory fields are enforced below; absent optional
members and explicit native nulls survive unchanged. All bounds are local policy
unless an existing Go validation source is cited.
"""

from urllib.parse import urlsplit

from .json_inputs import ContractError, copy_json_object, decode_body, fail, field_path

__all__ = ("METHODS", "ContractError", "decode_body", "resolve_method", "validate_request")

MAX_QUERY_LIMIT = 100


def _fields(names):
    return frozenset(names.split())


_METHOD_FIELDS = {
    "ActivityService.FilterActivity": _fields("cursor filter"),
    "ActivityService.QueryActivity": _fields("query cursor"),
    "CommentsService.AddReaction": _fields("incidentID targetKind targetID reaction"),
    "CommentsService.RemoveReaction": _fields("incidentID targetKind targetID reaction"),
    "FieldsService.GetFields": _fields("domainName"),
    "IncidentContextService.AddIncidentContext": _fields(
        "incidentID title description type payload metadata status syncResponse origin alertGroupID"),
    "IncidentContextService.QueryIncidentContext": _fields("query cursor"),
    "IncidentsService.AssignLabelByUUID": _fields("incidentID keyUUID valueUUID"),
    "IncidentsService.AssignRole": _fields("incidentID userID role invite"),
    "IncidentsService.CreateIncident": _fields(
        "title severity severityID status statusID incidentType labels roomPrefix isDrill refs "
        "attachCaption attachURL fieldGroupID fieldGroupUUID description initialStatusUpdate "
        "startedAt fieldValues alertGroupID"),
    "IncidentsService.GetIncident": _fields("incidentID"),
    "IncidentsService.QueryIncidentPreviews": _fields(
        "query cursor includeCustomFieldValues includeMembershipPreview includeIncidentChannels"),
    "IncidentsService.UnassignLabelByUUID": _fields("incidentID keyUUID valueUUID"),
    "IncidentsService.UnassignRole": _fields("incidentID userID role"),
    "IncidentsService.UpdateDescription": _fields("incidentID description"),
    "IncidentsService.UpdateSeverity": _fields("incidentID severityID severity"),
    "IncidentsService.UpdateStatus": _fields("incidentID status statusID"),
    "IncidentsService.UpdateTitle": _fields("incidentID title"),
    "KeyUpdatesService.CreateKeyUpdate": _fields(
        "incidentID title content contentType statusID severityID scope color"),
    "KeyUpdatesService.GetLastKeyUpdate": _fields("incidentID contentType"),
    "KeyUpdatesService.QueryKeyUpdates": _fields("query cursor"),
    "OrgService.GetOrg": _fields(""),
    "OrgService.GetOrgStatus": _fields("withHealthcheck"),
    "SeveritiesService.GetOrgSeverities": _fields(""),
    "StatusService.QueryOrgStatuses": _fields("incidentType"),
    "UsersService.AutocompleteUsers": _fields("text"),
    "UsersService.GetSession": _fields(""),
    "UsersService.GetUser": _fields("userID"),
}
METHODS = frozenset(_METHOD_FIELDS)

_QUERY_FIELDS = {
    "ActivityService.FilterActivity": ("filter", _fields("filter incidentID limit orderDirection")),
    "ActivityService.QueryActivity": ("query", _fields(
        "activityKind incidentID limit orderDirection tag withBodyFormat")),
    "IncidentContextService.QueryIncidentContext": ("query", _fields(
        "alertGroupID incidentID limit orderDirection orderField payload status type")),
    "IncidentsService.QueryIncidentPreviews": ("query", _fields(
        "limit orderDirection orderField queryString")),
    "KeyUpdatesService.QueryKeyUpdates": ("query", _fields(
        "contentType incidentID limit orderDirection orderField scope")),
}
_BOOLEAN_FIELDS = _fields(
    "withHealthcheck invite isDrill syncResponse includeCustomFieldValues "
    "includeMembershipPreview includeIncidentChannels")
_LABEL_FIELDS = _fields("colorHex description key keyUUID label labelUUID")
_REF_FIELDS = _fields("key ref url")

# [code] pkg/irm/{handler.go,rpc_comments.go,rpc_context.go,rpc_keyupdates.go,
# rpc_incidents_extra.go}: actual operation checks, not generated response DTOs.
_REQUIRED_STRINGS = {
    "IncidentsService.CreateIncident": ("title",),
    "IncidentsService.UpdateTitle": ("title",),
    "IncidentsService.AssignRole": ("incidentID", "userID", "role"),
    "IncidentsService.UnassignRole": ("incidentID", "userID", "role"),
    "CommentsService.AddReaction": ("incidentID", "targetID", "targetKind", "reaction"),
    "CommentsService.RemoveReaction": ("incidentID", "targetID", "targetKind", "reaction"),
    "IncidentContextService.AddIncidentContext": ("incidentID", "type", "payload"),
    "KeyUpdatesService.CreateKeyUpdate": ("incidentID", "content"),
}
_REQUIRED_QUERY_METHODS = frozenset((
    "IncidentContextService.QueryIncidentContext", "KeyUpdatesService.QueryKeyUpdates"))


def resolve_method(path, http_method="POST"):
    """Resolve only the exact path remaining below the incident gateway mount."""
    if type(http_method) is not str or http_method != "POST":
        fail("http_method", "native methods require POST")
    if type(path) is not str or not path.startswith("/api/"):
        fail("path", "unsupported native method path")
    method = path[len("/api/"):]
    if method not in METHODS:
        fail("path", "unsupported native method path")
    return method


def _object(value, allowed, path, nullable=False):
    if value is None and nullable:
        return
    if type(value) is not dict:
        fail(path, "must be an object")
    for key in value:
        if key not in allowed:
            fail(field_path(path, key), "unknown field")


def _string(value, path):
    if value is not None and type(value) is not str:
        fail(path, "must be a string or null")


def _boolean(value, path):
    if value is not None and type(value) is not bool:
        fail(path, "must be a boolean or null")


def _require_strings(value, fields, path=""):
    for key in fields:
        member = value.get(key)
        if type(member) is not str or not member.strip():
            fail(field_path(path, key, fields), "a nonempty string is required")


def _cursor(value):
    _object(value, _fields("nextValue hasMore"), "cursor", nullable=True)
    if value is not None:
        for key, item in value.items():
            validator = _boolean if key == "hasMore" else _string
            validator(item, field_path("cursor", key, _fields("nextValue hasMore")))


def _activity_kinds(value, path):
    if value is None:
        return
    if type(value) is not list:
        fail(path, "must be an array or null")
    for index, item in enumerate(value):
        # [code] The native primitive-string list converter admits null members.
        _string(item, f"{path}[{index}]")


def _query(method, value):
    wrapper, allowed = _QUERY_FIELDS[method]
    _object(value, allowed, wrapper)
    for key, item in value.items():
        path = field_path(wrapper, key, allowed)
        if key == "limit":
            if item is None and method == "IncidentContextService.QueryIncidentContext":
                continue
            if type(item) is not int or not 1 <= item <= MAX_QUERY_LIMIT:
                fail(path, "must be a positive integer within query limit")
        elif key == "activityKind":
            _activity_kinds(item, path)
        else:
            _string(item, path)
    if method == "KeyUpdatesService.QueryKeyUpdates":
        _require_strings(value, ("incidentID",), wrapper)


def _object_list(value, allowed, path):
    if value is None:
        return []
    if type(value) is not list:
        fail(path, "must be an array or null")
    for index, item in enumerate(value):
        child_path = f"{path}[{index}]"
        _object(item, allowed, child_path)
        for key, member in item.items():
            _string(member, field_path(child_path, key, allowed))
    return value


def _length(value, key, maximum, path="", trim=False):
    member = value.get(key)
    if member is not None:
        text = member.strip() if trim else member
        if len(text.encode("utf-8")) > maximum:
            fail(field_path(path, key, (key,)), "exceeds operation byte limit")


def _labels(value):
    for index, label in enumerate(_object_list(value, _LABEL_FIELDS, "labels")):
        path = f"labels[{index}]"
        # [code] pkg/irm/incident_mutation.go:140-149 requires label text.
        _require_strings(label, ("label",), path)
        for key, maximum in (("label", 256), ("key", 256), ("description", 2000), ("colorHex", 100)):
            _length(label, key, maximum, path)


def _refs(value):
    refs = _object_list(value, _REF_FIELDS, "refs")
    # [code] pkg/irm/incident_mutation.go:11,102-103,271-284.
    if len(refs) > 100:
        fail("refs", "exceeds operation item limit")
    for index, ref in enumerate(refs):
        path = f"refs[{index}]"
        _require_strings(ref, ("key", "ref"), path)
        for key, maximum in (("key", 100), ("ref", 500), ("url", 2000)):
            _length(ref, key, maximum, path)
        if ref.get("url"):
            try:
                parsed = urlsplit(ref["url"])
            except ValueError:
                fail(field_path(path, "url", ("url",)), "must be an absolute HTTP or HTTPS URL")
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                fail(field_path(path, "url", ("url",)), "must be an absolute HTTP or HTTPS URL")


def _member(method, key, value):
    if key == "cursor":
        _cursor(value)
    elif method in _QUERY_FIELDS and key == _QUERY_FIELDS[method][0]:
        _query(method, value)
    elif key in _BOOLEAN_FIELDS:
        _boolean(value, key)
    elif key == "labels":
        _labels(value)
    elif key == "refs":
        _refs(value)
    elif key not in ("fieldValues", "metadata"):
        _string(value, key)
    # [code] These explicit opaque fields are bounded JSON, already deeply checked
    # by copy_json_object; no guessed generic binding or routing interpretation.


def _operation_checks(method, body):
    _require_strings(body, _REQUIRED_STRINGS.get(method, ()))
    if method in _REQUIRED_QUERY_METHODS and "query" not in body:
        fail("query", "an object is required")
    if method in ("CommentsService.AddReaction", "CommentsService.RemoveReaction"):
        if body["targetKind"] not in ("activityItem", "comment"):
            fail("targetKind", "unsupported reaction target kind")
    if method in ("IncidentsService.CreateIncident", "IncidentsService.UpdateTitle"):
        _length(body, "title", 300, trim=True)
    if method in ("IncidentsService.CreateIncident", "IncidentsService.UpdateDescription"):
        _length(body, "description", 50_000)
    if method == "KeyUpdatesService.CreateKeyUpdate":
        _length(body, "content", 50_000, trim=True)


def _error_field_labels(method):
    # [code] Labels derive only from the selected static request schema. Opaque
    # fields deliberately have no child labels, even for schema-looking keys.
    labels = dict.fromkeys(_METHOD_FIELDS[method])
    if "cursor" in labels:
        labels["cursor"] = dict.fromkeys(_fields("nextValue hasMore"))
    if method in _QUERY_FIELDS:
        wrapper, fields = _QUERY_FIELDS[method]
        labels[wrapper] = dict.fromkeys(fields)
    if "labels" in labels:
        labels["labels"] = dict.fromkeys(_LABEL_FIELDS)
    if "refs" in labels:
        labels["refs"] = dict.fromkeys(_REF_FIELDS)
    return labels


def validate_request(method, payload):
    """Validate a finite logical method and return an independent JSON object.

    No defaults, coercion, selection, identity lookup or payload rewriting occurs.
    A legal userID is a domain target only; caller authority is outside this module.
    """
    if type(method) is not str or method not in METHODS:
        fail("method", "unsupported native method")
    body = copy_json_object(payload, _error_field_labels(method))
    _object(body, _METHOD_FIELDS[method], "")
    for key, value in body.items():
        _member(method, key, value)
    _operation_checks(method, body)
    return body
