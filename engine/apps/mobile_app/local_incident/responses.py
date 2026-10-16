"""[code] Bounded native Incidents response parser compatibility, with no I/O.

[code] Schema source: /private/tmp/mobile-incident-wire.abLgfs/contract.json,
SHA256 2e425c76142d36745d979271623f9807e71ba0d20a6e19feca0cef61ff099c5e.
The static model data below projects exact parser field names/types/nullability;
it is not server schema, authorization, readiness or semantic-success evidence.
[code] validate_response(method, payload, *, http_status=200) returns an independent
JSON dict ONLY for HTTP 200. Nullable body.error is application data, not a
transport error. A valid non-200 Error envelope raises a safe UpstreamResponseError;
invalid input raises the shared ContractError, never a fabricated HTTP-200 result.
[code] Shared json_inputs limits apply before model validation to all known,
opaque and additive data. Bounds are local safety policy, not native API limits.
[UNVERIFIED] ActivityItem.fieldValues/ImportantActivityMatcher.fieldValues generic
bindings are unresolved; bounded JSON is retained without invented type arguments.
"""

from .json_inputs import ContractError, copy_json_object, fail, field_path

__all__ = ("METHODS", "ContractError", "UpstreamResponseError", "validate_response")

# [code] Exact logical RPC names; shared DTOs do not merge distinct methods.
_RESPONSE_MODELS = {
    'ActivityService.FilterActivity': 'FilterActivityResponse',
    'ActivityService.QueryActivity': 'QueryActivityResponse',
    'CommentsService.AddReaction': 'AddReactionResponse',
    'CommentsService.RemoveReaction': 'RemoveReactionResponse',
    'FieldsService.GetFields': 'GetFieldsResponse',
    'IncidentContextService.AddIncidentContext': 'AddIncidentContextResponse',
    'IncidentContextService.QueryIncidentContext': 'QueryIncidentContextResponse',
    'IncidentsService.AssignLabelByUUID': 'AssignLabelByUUIDResponse',
    'IncidentsService.AssignRole': 'AssignRoleResponse',
    'IncidentsService.CreateIncident': 'CreateIncidentResponse',
    'IncidentsService.GetIncident': 'GetIncidentResponse',
    'IncidentsService.QueryIncidentPreviews': 'QueryIncidentPreviewsResponse',
    'IncidentsService.UnassignLabelByUUID': 'UnassignLabelByUUIDResponse',
    'IncidentsService.UnassignRole': 'UnassignRoleResponse',
    'IncidentsService.UpdateDescription': 'UpdateDescriptionResponse',
    'IncidentsService.UpdateSeverity': 'UpdateSeverityResponse',
    'IncidentsService.UpdateStatus': 'UpdateStatusResponse',
    'IncidentsService.UpdateTitle': 'UpdateTitleResponse',
    'KeyUpdatesService.CreateKeyUpdate': 'CreateKeyUpdateResponse',
    'KeyUpdatesService.GetLastKeyUpdate': 'GetLastKeyUpdateResponse',
    'KeyUpdatesService.QueryKeyUpdates': 'QueryKeyUpdatesResponse',
    'OrgService.GetOrg': 'GetOrgResponse',
    'OrgService.GetOrgStatus': 'GetOrgStatusResponse',
    'SeveritiesService.GetOrgSeverities': 'GetOrgSeveritiesResponse',
    'StatusService.QueryOrgStatuses': 'QueryOrgStatusesResponse',
    'UsersService.AutocompleteUsers': 'AutocompleteUsersResponse',
    'UsersService.GetSession': 'GetSessionResponse',
    'UsersService.GetUser': 'GetUserResponse',
}
METHODS = frozenset(_RESPONSE_MODELS)

# [code] Compact static schema: trailing ? means null OR missing is accepted.
# All other fields are required only when their containing model is non-null.
# object is the unresolved generic boundary, not a guessed homogeneous map.
_MODEL_FIELDS = {
    'ActionEvent': 'description:string? event:string?',
    'ActivityFilter': 'filter:string? incidentID:string? limit:int orderDirection:string',
    'ActivityItem': (
        'activityItemID:string? activityKind:string? attachments:Attachment[]? body:string? '
        'bodyFormat:string? bodyJSON:string? createdTime:string? eventTime:string? fieldValues:object? '
        'immutable:bool? incidentID:string? reactionsOverview:ReactionsOverview? '
        'recentComments:CommentsPreview? relevance:string? subjectUser:UserPreview? tags:string[]? '
        'url:string? user:UserPreview?'
    ),
    'ActivityQuery': (
        'activityKind:string[]? incidentID:string? limit:int orderDirection:string tag:string? '
        'withBodyFormat:string?'
    ),
    'AddIncidentContextResponse': 'error:string? incidentContext:IncidentContext?',
    'AddReactionResponse': 'didChange:bool? error:string? reactionsOverview:ReactionsOverview?',
    'AssignLabelByUUIDResponse': 'error:string? labels:IncidentKeyValueLabel[]?',
    'AssignRoleResponse': 'didChange:bool? error:string? incident:Incident? role:string? userID:string?',
    'Assignment': 'role:Role? roleID:int? user:UserPreview?',
    'AssignmentPreview': 'roleID:int? user:UserPreview?',
    'Attachment': (
        'attachedByUserID:string? attachmentErr:string? attachmentID:string? contentLength:int? '
        'contentType:string? deletedTime:string? displayType:string? downloadURL:string? ext:string? '
        'fileType:string? hasThumbnail:bool? path:string? sHA512:string? sourceURL:string? '
        'thumbnailURL:string? title:string? uploadTime:string? useSourceURL:bool?'
    ),
    'AutocompleteUsersResponse': 'cacheStatus:string? error:string? users:UserPreview[]?',
    'Comment': (
        'authors:UserPreviewList? body:string? bodyHTML:string? commentID:string createdTime:string? '
        'deleted:bool? edited:bool? incidentID:string modifiedTime:string? originalAuthor:UserPreview? '
        'reactionsOverview:ReactionsOverview? targetID:string targetKind:string'
    ),
    'CommentsPreview': 'comments:Comment[]? cursor:Cursor? query:CommentsQuery?',
    'CommentsQuery': (
        'incidentID:string limit:int onlyDeleted:bool? orderDirection:string targetID:string '
        'targetKind:string'
    ),
    'CreateIncidentResponse': 'error:string? incident:Incident?',
    'CreateKeyUpdateResponse': 'error:string? keyUpdate:KeyUpdate?',
    'Cursor': 'hasMore:bool? nextValue:string?',
    'CustomMetadataField': (
        'archived:bool? color:string? defaultValue:string? description:string? domainName:string '
        'exportAsMetric:bool? externalID:string? icon:string? immutable:bool? name:string '
        'promptCompletion:bool? required:bool? selectoptions:CustomMetadataFieldSelectOption[]? '
        'slug:string source:string? type:string uuid:string? version:int?'
    ),
    'CustomMetadataFieldSelectOption': (
        'archived:bool? color:string? description:string? externalID:string? icon:string? label:string '
        'source:string? uuid:string? value:string'
    ),
    'CustomMetadataFieldValue': 'fieldUUID:string? value:string?',
    'Error': 'error:string',
    'Field': (
        'checked:bool? description:string? hidden:bool? key:string secret:bool? type:string '
        'value:string?'
    ),
    'FilterActivityResponse': (
        'activityItems:ActivityItem[]? cursor:Cursor? error:string? filter:ActivityFilter?'
    ),
    'GetFieldsResponse': 'error:string? fields:CustomMetadataField[]?',
    'GetIncidentResponse': 'error:string? incident:Incident?',
    'GetLastKeyUpdateResponse': 'error:string? keyUpdate:KeyUpdate? keyUpdateCount:int?',
    'GetOrgResponse': 'error:string? org:Org?',
    'GetOrgSeveritiesResponse': 'error:string? severities:Severity[]?',
    'GetOrgStatusResponse': 'error:string? isEnabled:bool? isHealthy:bool? isSetup:bool? orgID:string?',
    'GetSessionResponse': 'error:string? user:User?',
    'GetUserResponse': 'error:string? user:User?',
    'HookMetadata': 'explanation:string? fields:Field[]? title:string? url:string?',
    'HookRun': (
        'enabledHookID:string error:string? eventKind:string? eventName:string? hookID:string '
        'integrationID:string lastRun:string? lastUpdate:string? metadata:HookMetadata? status:string? '
        'updateError:string? updateStatus:string?'
    ),
    'ImportantActivityMatcher': 'activityKind:string? fieldValues:object?',
    'Incident': (
        'closedTime:string? createdByUser:UserPreview? createdTime:string? description:string? '
        'descriptionModifiedTime:string? descriptionUser:UserPreview? durationSeconds:int? '
        'fieldGroupUUID:string? fieldValues:CustomMetadataFieldValue[]? '
        'incidentChannels:IncidentChannel[]? incidentEnd:string? incidentHookRuns:IncidentHookRuns? '
        'incidentID:string? incidentMembership:IncidentMembership? incidentStart:string? '
        'incidentType:string? isDrill:bool? labels:IncidentLabel[]? modifiedTime:string? '
        'overviewURL:string? prefix:string? refs:IncidentRef[]? severity:string? severityID:string? '
        'slug:string? state:string? status:string? statusID:string? statusModifiedByUser:UserPreview? '
        'statusModifiedTime:string? summary:string? taskList:TaskList? title:string? version:int?'
    ),
    'IncidentChannel': 'channelID:string? provider:string? teamID:string?',
    'IncidentContext': (
        'alertGroupID:string? contextID:string? createdByUser:UserPreview? createdTime:string? '
        'description:string? incidentID:string? lastRun:string? metadata:Field[]? modifiedTime:string? '
        'payload:string? processError:string? processStatus:string? processorInfo:string? '
        'status:string? title:string? type:string?'
    ),
    'IncidentContextQuery': (
        'alertGroupID:string? incidentID:string? limit:int? orderDirection:string? orderField:string? '
        'payload:string? status:string? type:string?'
    ),
    'IncidentHookRuns': 'hookRuns:HookRun[]?',
    'IncidentKeyValueLabel': (
        'colorHex:string? description:string? key:string? keyUUID:string? value:string? '
        'valueUUID:string?'
    ),
    'IncidentLabel': (
        'colorHex:string? description:string? key:string? keyUUID:string? label:string? '
        'labelUUID:string?'
    ),
    'IncidentMembership': 'assignments:Assignment[]? totalAssignments:int? totalParticipants:int?',
    'IncidentMembershipPreview': (
        'importantAssignments:AssignmentPreview[]? totalAssignments:int? totalParticipants:int?'
    ),
    'IncidentPreview': (
        'closedTime:string? createdByUser:UserPreview? createdTime:string? description:string? '
        'fieldValues:CustomMetadataFieldValue[]? incidentChannels:IncidentChannel[]? '
        'incidentEnd:string? incidentID:string? incidentMembershipPreview:IncidentMembershipPreview? '
        'incidentStart:string? incidentType:string? isDrill:bool? labels:IncidentLabel[]? '
        'modifiedTime:string? severityID:string? severityLabel:string? slug:string? state:string? '
        'status:string? statusID:string? summary:string? title:string? version:int?'
    ),
    'IncidentPreviewsQuery': 'limit:int orderDirection:string? orderField:string? queryString:string?',
    'IncidentRef': 'key:string? ref:string? url:string?',
    'IncidentRoomPrefix': 'description:string? prefix:string?',
    'IncidentStatusOption': 'description:string? label:string? status:string?',
    'KeyUpdate': (
        'color:string? content:string? contentType:string createdBy:UserPreview? createdTime:string? '
        'id:string incidentID:string lastModifiedBy:UserPreview? modifiedTime:string? orgID:string '
        'scope:string severityID:string? statusID:string? title:string?'
    ),
    'KeyUpdatesQuery': (
        'contentType:string? incidentID:string limit:int orderDirection:string orderField:string? '
        'scope:string?'
    ),
    'Org': (
        'actionEvents:ActionEvent[]? canSelfDestruct:bool? chatopsStatus:string? createdAt:string? '
        'defaultSeverityID:string? grafanaOrgID:string? grafanaOrgSlug:string? grafanaStack:string? '
        'grafanaURL:string? importantActivities:ImportantActivityMatcher[]? '
        'incidentLabels:IncidentLabel[]? incidentRoomPrefixes:IncidentRoomPrefix[]? '
        'incidentStatuses:IncidentStatusOption[]? isSlackConnected:bool? limited:bool? orgID:string '
        'ready:bool? roles:Role[]? slackTeamID:string? updatedAt:string?'
    ),
    'QueryActivityResponse': 'activityItems:ActivityItem[]? cursor:Cursor? error:string? query:ActivityQuery?',
    'QueryIncidentContextResponse': (
        'cursor:Cursor? error:string? incidentContexts:IncidentContext[]? query:IncidentContextQuery?'
    ),
    'QueryIncidentPreviewsResponse': (
        'cursor:Cursor? error:string? incidentPreviews:IncidentPreview[]? query:IncidentPreviewsQuery?'
    ),
    'QueryKeyUpdatesResponse': 'cursor:Cursor? error:string? keyUpdates:KeyUpdate[]? query:KeyUpdatesQuery?',
    'QueryOrgStatusesResponse': 'configurations:StatusConfiguration[]? error:string?',
    'ReactionCount': 'count:int? people:UserPreview[]? reaction:string?',
    'ReactionsOverview': 'reactionCounts:ReactionCount[]?',
    'RemoveReactionResponse': 'didChange:bool? error:string? reactionsOverview:ReactionsOverview?',
    'Role': (
        'archived:bool? createdAt:string? description:string? hidden:bool? important:bool? '
        'mandatory:bool? name:string? orgID:string? roleID:int? updatedAt:string?'
    ),
    'Severity': (
        'archivedAt:string? archivedByUserID:string? createdAt:string? darkColor:string? '
        'deletedAt:string? deletedByUserID:string? description:string? displayLabel:string? '
        'iconName:string? level:int? lightColor:string? orgID:string? severityID:string? '
        'updatedAt:string?'
    ),
    'Status': (
        'archivedTime:string? category:string? color:string createdTime:string? description:string '
        'icon:string immutable:bool? incidentType:string? kind:string? modifiedTime:string? '
        'name:string orgID:string position:int slug:string statusID:string'
    ),
    'StatusConfiguration': 'default:bool? incidentType:string? statuses:Status[]?',
    'Task': (
        'assignedUser:UserPreview? authorUser:UserPreview? context:IncidentContext? '
        'createdTime:string? immutable:bool modifiedTime:string? order:int? status:string? '
        'statusKind:string? taskID:string text:string?'
    ),
    'TaskList': 'doneCount:int? tasks:Task[]? todoCount:int? totalCount:int?',
    'UnassignLabelByUUIDResponse': 'error:string? labels:IncidentKeyValueLabel[]?',
    'UnassignRoleResponse': 'didChange:bool? error:string? incident:Incident?',
    'UpdateDescriptionResponse': 'error:string? incident:Incident?',
    'UpdateSeverityResponse': 'error:string? incident:Incident?',
    'UpdateStatusResponse': 'error:string? incident:Incident?',
    'UpdateTitleResponse': 'error:string? incident:Incident?',
    'User': (
        'chatbotOrgID:string? chatbotUserID:string? email:string? grafanaLogin:string? '
        'internalUserID:string? modifiedTime:string? msTeamsUserID:string? name:string? '
        'photoURL:string? slackTeamID:string? slackUserID:string? userID:string?'
    ),
    'UserPreview': (
        'chatbotUserID:string? email:string? grafanaLogin:string? msTeamsUserID:string? name:string? '
        'photoURL:string? slackUserID:string? userID:string?'
    ),
    'UserPreviewList': 'userPreviews:UserPreview[]?',
}


def _parse_fields(description):
    fields = {}
    for entry in description.split():
        name, kind = entry.split(":", 1)
        fields[name] = (kind.removesuffix("?"), kind.endswith("?"))
    return fields


_MODELS = {name: _parse_fields(fields) for name, fields in _MODEL_FIELDS.items()}


class UpstreamResponseError(ValueError):
    """A transport failure with no retained upstream error text or payload."""

    def __init__(self, http_status):
        super().__init__("upstream incident request failed")
        self.http_status = http_status


def _field_labels(model):
    # [code] Only static schema names may enter an error path. Opaque and additive
    # descendants have no labels, even if their keys resemble another model field.
    return {key: _field_labels(kind.removesuffix("[]")) if kind.removesuffix("[]") in _MODELS else None
            for key, (kind, _nullable) in _MODELS[model].items()}


def _validate_list(kind, value, path):
    if type(value) is not list:
        fail(path, "must be an array")
    member_kind = kind.removesuffix("[]")
    for index, member in enumerate(value):
        member_path = f"{path}[{index}]"
        if member_kind == "string":
            # [code] The native primitive-string mapper filters null members. Keep
            # source JSON unchanged; object-list mappers do not share this rule.
            if member is not None and type(member) is not str:
                fail(member_path, "must be a string or null")
        else:
            _validate_model(member_kind, member, member_path)


def _validate_value(kind, value, path):
    primitive = {"string": str, "int": int, "bool": bool}.get(kind)
    if primitive is not None:
        if type(value) is not primitive:
            fail(path, f"must be a {kind}")
    elif kind.endswith("[]"):
        _validate_list(kind, value, path)
    elif kind in _MODELS:
        _validate_model(kind, value, path)
    elif kind == "object":
        # [UNVERIFIED] The two object* fields deliberately have no semantic
        # validator; copy_json_object already bounded and independently copied JSON.
        return
    else:
        fail(path, "unsupported static model field type")


def _validate_model(model, value, path=""):
    if type(value) is not dict:
        fail(path, "must be an object")
    fields = _MODELS[model]
    for key, (kind, nullable) in fields.items():
        member_path = field_path(path, key, fields)
        if key not in value or value[key] is None:
            if not nullable:
                fail(member_path, "a non-null field is required")
            continue
        _validate_value(kind, value[key], member_path)
    # [code] Additive upstream fields are intentionally retained, not interpreted.


def validate_response(method, payload, *, http_status=200):
    """Validate bounded parser compatibility; never infer semantic success.

    No defaults/coercion/selection/identity lookup or payload rewriting occurs.
    HTTP status is a caller-supplied transport observation, never read from body.
    """
    if type(method) is not str or method not in METHODS:
        fail("method", "unsupported native method")
    if type(http_status) is not int or not 100 <= http_status <= 599:
        fail("http_status", "must be an integer HTTP status within 100..599")
    model = _RESPONSE_MODELS[method] if http_status == 200 else "Error"
    body = copy_json_object(payload, _field_labels(model))
    _validate_model(model, body)
    if http_status != 200:
        raise UpstreamResponseError(http_status) from None
    return body
