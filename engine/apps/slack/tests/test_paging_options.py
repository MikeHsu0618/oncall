import json
from unittest.mock import patch

import pytest

from apps.alerts.models import AlertGroup
from apps.api.permissions import LegacyAccessControlRole
from apps.slack.models import SharedSlackDelivery
from apps.slack.scenarios import paging
from apps.slack.tests.test_incident_paging import paging_verification, started, submit
from apps.slack.tests.test_shared_app import connected, send, link_receipt

pytestmark = pytest.mark.django_db(transaction=True)


def suggestion(session, *, users=False, query=""):
    field = paging.DIRECT_PAGING_USER_SELECT_ID if users else paging.DIRECT_PAGING_TEAM_SELECT_ID
    action = paging.OnPagingUserChange if users else paging.OnPagingTeamChange
    return {"type": "block_suggestion", "team": {"id": session.team.slack_id},
            "user": {"id": session.slack_user_id}, "api_app_id": session.app_id,
            "action_id": action.routing_uid(), "block_id": session.form_metadata["input_id_prefix"] + field,
            "value": query, "view": {"id": session.view_id,
                "private_metadata": json.dumps({"pagingSessionId": str(session.pk)})}}


def shared(data, payload):
    # Real signed interactions carry the physical App, and each new opener's
    # loading view is separately reserved; never copy the initial start loader.
    result = {**data, "operation": "dispatch", "deliveryId": "b" * 64,
              "payload": {"api_app_id": data["installation"]["appId"], **payload}}
    result.pop("loadingView", None)
    return result


def option_ids(response):
    return [json.loads(o["value"])["id"] for o in response.data["options"]]


def test_search_reaches_team_after_first_hundred_and_prefills_exact_selected_team(started, make_team):
    org, actor, data, session = started
    for i in range(105):
        make_team(org, name=f"Alpha {i:03}")
    target = make_team(org, name="Zulu Platform")
    result = send(shared(data, suggestion(session, query="Zulu")))
    assert result.status_code == 200 and option_ids(result) == [target.pk]
    assert len(send(shared(data, suggestion(session))).data["options"]) == 100
    blocks = paging._get_team_select_blocks(actor.slack_user_identity, org, True, target, False, "prefix")
    assert blocks[0]["element"]["initial_option"] == result.data["options"][0]
    assert SharedSlackDelivery.objects.count() == 0 and AlertGroup.objects.count() == 0


def test_user_search_is_org_scoped_and_matches_name_and_public_id(started, make_user_for_organization, make_organization_and_user):
    org, actor, data, session = started
    for i in range(105):
        make_user_for_organization(org, username=f"aaa{i:03}", name=f"Alpha {i:03}")
    target = make_user_for_organization(org, username="zulu", name="國際維運")
    _, foreign = make_organization_and_user()
    foreign.username = "foreign-zulu"; foreign.save()
    for query in ("zulu", "國際", target.public_primary_key):
        response = send(shared(data, suggestion(session, users=True, query=query)))
        assert response.status_code == 200 and option_ids(response) == [target.pk]
    assert option_ids(send(shared(data, suggestion(session, users=True, query=foreign.public_primary_key)))) == []
    assert len(send(shared(data, suggestion(session, users=True))).data["options"]) == 100
    assert SharedSlackDelivery.objects.count() == 0


@pytest.mark.parametrize("change", ["permission", "unlinked", "session", "view", "block", "app", "query", "completed", "expired"])
def test_search_refuses_stolen_stale_or_malformed_session_without_catalog(started, make_team, change):
    org, actor, data, session = started
    make_team(org, name="Private Catalog")
    payload = suggestion(session)
    if change == "permission":
        actor.role = LegacyAccessControlRole.VIEWER; actor.permissions = []; actor.save()
    elif change == "unlinked":
        data = {**data, "link": link_receipt(None, revision=2)}
    elif change == "session":
        payload["view"]["private_metadata"] = '{"pagingSessionId":"00000000-0000-0000-0000-000000000001"}'
    elif change == "view":
        payload["view"]["id"] = "stolen"
    elif change == "block":
        payload["block_id"] = "stale-prefix" + paging.DIRECT_PAGING_TEAM_SELECT_ID
    elif change == "app":
        payload["api_app_id"] = "FOREIGN"
    elif change == "query":
        payload["value"] = "x" * 301
    elif change == "expired":
        from datetime import timedelta
        from django.utils import timezone
        session.expires_at = timezone.now() - timedelta(seconds=1); session.save()
    else:
        session.phase = "completed"; session.save()
    response = send(shared(data, payload))
    assert response.status_code in {403, 409, 410, 422}
    assert not response.data or "options" not in response.data
    assert SharedSlackDelivery.objects.count() == 0 and AlertGroup.objects.count() == 0


def test_identical_search_rechecks_permission_and_reads_updated_catalog(started, make_team):
    org, actor, data, session = started
    team = make_team(org, name="Operations")
    payload = shared(data, suggestion(session, query="Operations"))
    assert option_ids(send(payload)) == [team.pk]
    team.name = "Retired"; team.save()
    assert option_ids(send(payload)) == []
    actor.role = LegacyAccessControlRole.VIEWER; actor.permissions = []; actor.save()
    assert send(payload).status_code == 403
    assert SharedSlackDelivery.objects.count() == 0


def test_original_metadata_options_use_current_link_and_retained_modal_origin(connected, make_team, monkeypatch):
    org, actor, data = connected
    send(data); org.refresh_from_db(); actor.refresh_from_db()
    team = make_team(org)
    metadata = {"organization_id": org.pk, "input_id_prefix": "legacy", "users": {}}
    from apps.slack.client import SlackClient
    from apps.slack.shared_owner import SharedSourceOwner, using_shared_owner, using_shared_delivery
    from apps.slack.tests.test_shared_owner import physical, SlackReply
    source = SharedSourceOwner.parse(data["sourceOwner"])
    original = SharedSlackDelivery.objects.create(key="c" * 64, source_owner=source.projection())
    wire = physical(monkeypatch, response=SlackReply({"ok": True, "view": {"id": "VL"}}))
    with using_shared_owner(org.pk, source), using_shared_delivery(original.pk, "U1", "C1", "123.4"):
        SlackClient(org.slack_team_identity, source_organization=org).views_open(trigger_id="signed-trigger",
            view={"type": "modal", "title": {"type": "plain_text", "text": "Original"}, "blocks": [],
                  "callback_id": "FinishDirectPaging", "private_metadata": json.dumps(metadata)})
    assert len(wire.calls) == 1
    payload = {"type": "block_suggestion", "team": {"id": "T1"}, "user": {"id": "U1"},
        "api_app_id": "A1", "action_id": paging.OnPagingTeamChange.routing_uid(),
        "block_id": "legacy" + paging.DIRECT_PAGING_TEAM_SELECT_ID, "value": team.name,
        "view": {"id": "VL", "callback_id": "FinishDirectPaging", "private_metadata": json.dumps(metadata)}}
    assert option_ids(send(shared(data, payload))) == [team.pk]
    assert SharedSlackDelivery.objects.count() == 1  # search creates no new write receipt


def test_long_unicode_option_labels_fit_slack_without_altering_native_name(started, make_team):
    org, actor, data, session = started
    team = make_team(org, name="維運" * 150)
    result = send(shared(data, suggestion(session, query=team.public_primary_key)))
    option = result.data["options"][0]
    assert len(option["text"]["text"]) <= 75 and option["text"]["text"].endswith(team.public_primary_key)
    assert len(option["value"]) <= 150 and option_ids(result) == [team.pk]
    team.refresh_from_db(); assert team.name == "維運" * 150


@pytest.mark.django_db(transaction=True)
def test_external_team_selection_pages_through_original_session(started, make_team, paging_verification):
    org, actor, data, session = started
    team = make_team(org, name="Platform")
    option = send(shared(data, suggestion(session, query="Platform"))).data["options"][0]
    prefix = session.form_metadata["input_id_prefix"]
    payload = {"type": "block_actions", "team": {"id": "T1"}, "user": {"id": "U1"},
        "trigger_id": "unused", "view": {"id": session.view_id,
            "private_metadata": json.dumps({"pagingSessionId": str(session.pk)}),
            "state": {"values": {prefix + paging.DIRECT_PAGING_TEAM_SELECT_ID: {
                paging.OnPagingTeamChange.routing_uid(): {"selected_option": option}}}}},
        "actions": [{"type": "external_select", "action_id": paging.OnPagingTeamChange.routing_uid(),
                     "block_id": prefix + paging.DIRECT_PAGING_TEAM_SELECT_ID, "selected_option": option}]}
    with patch("apps.slack.incident_paging.SlackClient") as client:
        assert send(shared(data, payload)).status_code == 200
        assert client.return_value.views_update.called
    session.refresh_from_db()
    final = submit(session)
    final["view"]["state"]["values"][session.form_metadata["input_id_prefix"] + paging.DIRECT_PAGING_TEAM_SELECT_ID] = {
        paging.OnPagingTeamChange.routing_uid(): {"selected_option": option}}
    assert send(shared(data, final)).status_code == 200
    assert AlertGroup.objects.get().channel.team_id == team.pk



@pytest.mark.django_db(transaction=True)
def test_external_user_selection_retains_original_offcall_confirmation(started, make_user_for_organization, paging_verification):
    org, actor, data, session = started
    responder = make_user_for_organization(org, username="offcall-user")
    option = send(shared(data, suggestion(session, users=True, query=responder.public_primary_key))).data["options"][0]
    prefix = session.form_metadata["input_id_prefix"]
    payload = {"type": "block_actions", "team": {"id": "T1"}, "user": {"id": "U1"}, "trigger_id": "unused",
        "view": {"id": session.view_id, "private_metadata": json.dumps({"pagingSessionId": str(session.pk)}),
                 "state": {"values": {prefix + paging.DIRECT_PAGING_USER_SELECT_ID: {
                    paging.OnPagingUserChange.routing_uid(): {"selected_option": option}},
                    paging.DIRECT_PAGING_MESSAGE_INPUT_ID: {paging.FinishDirectPaging.routing_uid(): {"value": None}}}}},
        "actions": [{"type": "external_select", "action_id": paging.OnPagingUserChange.routing_uid(),
                     "block_id": prefix + paging.DIRECT_PAGING_USER_SELECT_ID, "selected_option": option}]}
    with patch("apps.slack.incident_paging.SlackClient") as client:
        client.return_value.views_push.return_value = {"view": {"id": "VC-SEARCH"}}
        assert send(shared(data, payload)).status_code == 200
        client.return_value.views_push.assert_called_once()
        session.refresh_from_db()
        confirmation = {"type": "view_submission", "trigger_id": "confirm-trigger", "team": {"id": "T1"}, "user": {"id": "U1"},
            "view": {"id": "VC-SEARCH", "previous_view_id": session.view_id,
                     "callback_id": paging.OnPagingConfirmUserChange.routing_uid(),
                     "private_metadata": json.dumps({"pagingSessionId": str(session.pk)})}}
        assert send(shared(data, confirmation)).status_code == 200
    session.refresh_from_db()
    assert str(responder.pk) in session.form_metadata["users"]
    assert AlertGroup.objects.count() == 0
    assert send(shared(data, submit(session))).status_code == 200
    session.refresh_from_db()
    assert session.result_data["targets"][0]["id"] == responder.public_primary_key


def test_actual_native_search_modal_exports_for_public_schema_validation(started, make_team):
    import os
    from pathlib import Path
    org, actor, _, session = started
    team = make_team(org, name="維運" * 150)
    payload = {"view": {"private_metadata": json.dumps(session.form_metadata)}}
    view = paging.render_dialog(actor.slack_user_identity, session.team, payload, initial=True)
    selectors = [b["element"] for b in view["blocks"] if b.get("type") == "input" and b["element"]["type"] == "external_select"]
    assert {s["action_id"] for s in selectors} == {paging.OnPagingTeamChange.routing_uid(), paging.OnPagingUserChange.routing_uid()}
    from apps.slack.paging_options import target_option
    team_select = next(s for s in selectors if s["action_id"] == paging.OnPagingTeamChange.routing_uid())
    team_select["initial_option"] = target_option(team, org)
    assert len(json.dumps(view).encode()) < 64 * 1024
    if path := os.environ.get("IRM_PAGING_VIEW_FIXTURE_FILE"):
        Path(path).write_text(json.dumps(view))
