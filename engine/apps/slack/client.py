import logging
import typing
import hashlib
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, build_opener
from typing import Optional, Tuple

from django.utils import timezone
from django.db import transaction
from apps.slack.shared_owner import (SharedOwnerError, SharedSourceOwner, local_source_snapshot,
                                     require_local_source, selected_shared_owner, verify_source, _verification_config, remember_modal, strict_json, selected_loading_view, verify_publication, mark_loading_filled, _slack)
from rest_framework import status
from slack_sdk.errors import SlackApiError as SlackSDKApiError
from slack_sdk.http_retry import HttpRequest, HttpResponse, RetryHandler, RetryState, default_retry_handlers
from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler
from slack_sdk.web import SlackResponse, WebClient

from apps.slack.errors import SlackAPIRatelimitError, SlackAPIServerError, SlackAPITokenError, get_error_class

if typing.TYPE_CHECKING:
    from apps.slack.models import SlackTeamIdentity

logger = logging.getLogger(__name__)


class SlackServerErrorRetryHandler(RetryHandler):
    """Retry failed Slack API calls on Slack server errors"""

    def _can_retry(
        self,
        *,
        state: RetryState,
        request: HttpRequest,
        response: Optional[HttpResponse] = None,
        error: Optional[Exception] = None,
    ) -> bool:
        # Retry Slack API call on 5xx errors
        if response and response.status_code in [
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            status.HTTP_503_SERVICE_UNAVAILABLE,
            status.HTTP_504_GATEWAY_TIMEOUT,
        ]:
            return True

        # Retry Slack API call on "internal_error" and "fatal_error" errors
        if response and response.body and response.body.get("error") in SlackAPIServerError.errors:
            return True

        return False


# retries when HTTP status 429 is returned using the Retry-After header information
rate_limit_handler = RateLimitErrorRetryHandler(max_retry_count=1)
server_error_retry_handler = SlackServerErrorRetryHandler(max_retry_count=2)


class SharedMutationUnknown(RuntimeError):
    def __init__(self):
        super().__init__("Shared Slack operation outcome is uncertain")

    def __reduce__(self):
        # Celery serializes terminal failures. Preserve this exact exclusion
        # class without forwarding provider bodies or exception constructor args.
        return type(self), ()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_UNSET = object()


class SlackClient(WebClient):
    def __init__(
        self, slack_team_identity: "SlackTeamIdentity", enable_ratelimit_retry=False, timeout: int = 30,
        *, source_owner=_UNSET, source_organization=None,
    ) -> None:
        self._shared_owner = None
        self._shared_snapshot = None
        self._shared_org_id = getattr(source_organization, "pk", source_organization)
        self._shared_refused = False
        selected = selected_shared_owner()
        if selected is not None:
            selected_org, selected_owner = selected
            if self._shared_org_id is not None and self._shared_org_id != selected_org:
                self._shared_refused = True
            self._shared_org_id = selected_org
            if source_owner is _UNSET:
                source_owner = selected_owner
        try:
            snapshot = local_source_snapshot(slack_team_identity.pk, self._shared_org_id)
            if snapshot is not None:
                self._shared_snapshot = snapshot
                self._shared_org_id = snapshot[0]
                if source_owner is _UNSET:
                    self._shared_owner = snapshot[1]
                else:
                    self._shared_owner = source_owner if isinstance(source_owner, SharedSourceOwner) else SharedSourceOwner.parse(source_owner)
                    if self._shared_owner != snapshot[1]:
                        self._shared_refused = True
            elif source_owner is not _UNSET and source_owner is not None:
                self._shared_refused = True
        except SharedOwnerError:
            self._shared_refused = True
        self._shared = self._shared_owner is not None or self._shared_refused
        self._admit_request = None
        self._notification_recipient = None
        self._completion_recipient = None
        self._completion_notice = None
        self._completion_outcome = None
        self._recipient_address_check = None
        self._captured_token = slack_team_identity.bot_access_token
        retry_handlers = [] if self._shared else default_retry_handlers() + [server_error_retry_handler]
        if enable_ratelimit_retry and not self._shared:
            retry_handlers += [rate_limit_handler]
        # Suppress SDK request/response logging for the private shared transport.
        private_logger = logging.Logger("oncall.shared_slack_transport", logging.CRITICAL) if self._shared else None
        super().__init__(token=self._captured_token, timeout=timeout, retry_handlers=retry_handlers,
                         **({"logger": private_logger, "proxy": None, "base_url": "https://slack.com/api/"} if self._shared else {}))
        self.slack_team_identity = slack_team_identity

    def shared_source_owner(self):
        if self._shared_refused:
            raise SharedOwnerError()
        return self._shared_owner.projection() if self._shared_owner is not None else None

    def bind_notification_recipient(self, user, message):
        if not self._shared:
            return
        from apps.slack.shared_owner import SharedNotificationRecipient
        if self._shared_refused or self._shared_owner is None or user.organization_id != self._shared_org_id:
            raise SharedOwnerError()
        if self._notification_recipient is not None:
            if (self._notification_recipient.user_id != user.pk
                    or self._notification_recipient.message_id != str(message.pk)):
                raise SharedOwnerError()
            compared = SharedNotificationRecipient.capture(self._shared_owner, user, message)
            if compared != self._notification_recipient:
                raise SharedOwnerError()
            self._notification_recipient.require_current()
            return
        recipient = SharedNotificationRecipient.capture(self._shared_owner, user, message)
        recipient.require_current()
        previous = self._admit_request
        def admission():
            if previous is not None:
                previous()
            recipient.require_current()
        self._notification_recipient = recipient
        self._admit_request = admission

    def bind_completion_recipient(self, completion):
        from apps.slack.shared_owner import SharedPagingCompletion
        if not self._shared:
            return
        if (type(completion) is not SharedPagingCompletion or self._shared_refused
                or self._shared_owner is None or getattr(completion, "owner", None) != self._shared_owner):
            raise SharedOwnerError()
        completion.require_current()
        recipient = completion.recipient
        if self._completion_recipient is not None:
            raise SharedOwnerError()
        previous = self._admit_request
        def admission():
            if previous is not None:
                previous()
            completion.require_current()
        self._completion_recipient = recipient
        self._completion_outcome = completion
        self._completion_notice = (recipient.snapshot[5], completion.text, {completion.channel_id})
        self._admit_request = admission

    def require_shared_admission(self, *, new_publication=False):
        if not self._shared:
            return
        if self._shared_refused or self._shared_owner is None or transaction.get_connection().in_atomic_block:
            raise SharedOwnerError()
        if require_local_source(self.slack_team_identity.pk, self._shared_org_id, self._shared_owner) != self._shared_snapshot:
            raise SharedOwnerError()
        if (not isinstance(self._captured_token, str)
                or hashlib.sha256(self._captured_token.encode()).hexdigest() != self._shared_owner.token_sha256):
            raise SharedOwnerError()
        proof_config = verify_source(self._shared_owner, "transport")
        publication_proof = verify_publication(self._shared_owner) if new_publication else None
        if require_local_source(self.slack_team_identity.pk, self._shared_org_id, self._shared_owner) != self._shared_snapshot:
            raise SharedOwnerError()
        if self._admit_request is not None:
            self._admit_request()
        if (_verification_config() != proof_config or publication_proof is not None and
                _verification_config("SHARED_SLACK_PUBLISH_VERIFY_URL") != publication_proof):
            raise SharedOwnerError()
        if require_local_source(self.slack_team_identity.pk, self._shared_org_id, self._shared_owner) != self._shared_snapshot:
            raise SharedOwnerError()

    def _perform_urllib_http_request_internal(self, url, req):
        if not self._shared:
            # An old independently constructed client is not retroactively
            # blessed when the workspace enters shared-owner mode.
            if local_source_snapshot(self.slack_team_identity.pk, self._shared_org_id) is not None:
                raise SharedOwnerError()
            return super()._perform_urllib_http_request_internal(url, req)
        parsed = urlsplit(url)
        if (url != req.full_url or parsed.scheme != "https" or parsed.netloc != "slack.com"
                or parsed.query or parsed.fragment or re.fullmatch(r"/api/[A-Za-z][A-Za-z0-9_.]*", parsed.path) is None
                or req.get_method() != "POST" or req.get_header("Authorization") != "Bearer " + (self._captured_token or "")):
            raise SharedOwnerError()
        # Runs AFTER all SDK encoding and immediately before each physical call.
        new_publication = parsed.path in {"/api/chat.postMessage", "/api/chat.postEphemeral", "/api/chat.scheduleMessage"}
        if self._completion_notice is not None and parsed.path == "/api/chat.postEphemeral":
            # Narrow original committed-page notice, never an arbitrary new send.
            outgoing = strict_json(req.data)
            user_id, text, channels = self._completion_notice
            if (not isinstance(outgoing, dict) or outgoing.get("user") != user_id
                    or outgoing.get("text") != text or outgoing.get("channel") not in channels
                    or set(outgoing) - {"user", "text", "channel"}):
                raise SharedOwnerError()
            new_publication = False
        self.require_shared_admission(new_publication=new_publication)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=self.ssl), _NoRedirect())
        response = None
        try:
            try:
                response = opener.open(req, timeout=self.timeout)
            except HTTPError as error:
                response = error
            size = 0
            chunks = []
            while True:
                chunk = response.read(65536)
                size += len(chunk)
                if size > 2 * 1024 * 1024:
                    raise SharedMutationUnknown()
                if not chunk:
                    break
                chunks.append(chunk)
            body = b"".join(chunks).decode("utf-8")
            status_code = getattr(response, "status", None) or response.code
            if 300 <= status_code < 400 or status_code >= 500:
                raise SharedMutationUnknown()
            try:
                parsed_body = strict_json(body.encode("utf-8"))
                if not isinstance(parsed_body, dict) or type(parsed_body.get("ok")) is not bool:
                    raise SharedOwnerError()
            except SharedOwnerError:
                raise SharedMutationUnknown() from None
            return {"status": status_code, "headers": response.headers, "body": body}
        except (URLError, TimeoutError, OSError, UnicodeError):
            # No automatic physical repeat after an ambiguous response/loss.
            raise SharedMutationUnknown() from None
        finally:
            if response is not None:
                response.close()

    def paginated_api_call(self, method: str, paginated_key: str, **kwargs):
        """
        `paginated_key` represents a key from the response which is paginated. For example "users" or "channels"
        """
        api_method = getattr(self, method)

        response = api_method(**kwargs)
        cumulative_response = response.data

        while (
            "response_metadata" in response
            and "next_cursor" in response["response_metadata"]
            and response["response_metadata"]["next_cursor"] != ""
        ):
            kwargs["cursor"] = response["response_metadata"]["next_cursor"]
            response = api_method(**kwargs).data
            cumulative_response[paginated_key] += response[paginated_key]

        return cumulative_response

    def paginated_api_call_with_ratelimit(
        self, method: str, paginated_key: str, **kwargs
    ) -> Tuple[dict, Optional[str], bool]:
        """
        This method does paginated api calls and handle slack rate limit errors in order to return collected data
        and have the ability to continue doing paginated requests from the last successful cursor.

        Return last successful cursor instead of next cursor to avoid data loss during delay time.

        `paginated_key` represents a key from the response which is paginated. For example "users" or "channels"
        """
        api_method = getattr(self, method)

        cumulative_response = {}
        cursor = kwargs["cursor"]
        rate_limited = False

        try:
            response = api_method(**kwargs).data
            cumulative_response = response
            cursor = response["response_metadata"]["next_cursor"]

            while (
                "response_metadata" in response
                and "next_cursor" in response["response_metadata"]
                and response["response_metadata"]["next_cursor"] != ""
            ):
                next_cursor = response["response_metadata"]["next_cursor"]
                kwargs["cursor"] = next_cursor
                response = api_method(**kwargs).data
                cumulative_response[paginated_key] += response[paginated_key]
                cursor = next_cursor

        except SlackAPIRatelimitError:
            rate_limited = True

        return cumulative_response, cursor, rate_limited

    def api_call(self, *args, **kwargs) -> SlackResponse:
        """Wrap Slack SDK api_call with more granular error handling and logging"""

        method = args[0] if args else kwargs.get("api_method")
        loading = selected_loading_view() if self._shared else None
        if method in {"views.open", "views.push"} and loading is not None:
            # The connector opened this original loading view within Slack's
            # trigger deadline. Fill it through the same native modal writer.
            request = dict(kwargs.get("json") or kwargs.get("params") or {})
            request.pop("trigger_id", None)
            request["view_id"] = loading["id"]
            if loading.get("hash"):
                request["hash"] = loading["hash"]
            kwargs.pop("params", None)
            kwargs["json"] = request
            if args:
                args = ("views.update", *args[1:])
            else:
                kwargs["api_method"] = "views.update"
        try:
            response = super().api_call(*args, **kwargs)
            effective = args[0] if args else kwargs.get("api_method")
            outgoing = kwargs.get("json") or kwargs.get("params") or {}
            if self._shared and effective == "views.update" and outgoing.get("view_id"):
                actual_view = response.get("view")
                if not isinstance(actual_view, dict) or actual_view.get("id") != outgoing["view_id"]:
                    raise SharedMutationUnknown()
            if loading is not None and method in {"views.open", "views.push"}:
                mark_loading_filled()
            try:
                if self._shared and require_local_source(self.slack_team_identity.pk, self._shared_org_id, self._shared_owner) != self._shared_snapshot:
                    raise SharedOwnerError()
                if self._notification_recipient is not None:
                    self._notification_recipient.require_current()
                if self._completion_outcome is not None:
                    self._completion_outcome.require_current()
                if self._recipient_address_check is not None:
                    self._recipient_address_check()
                self._unmark_token_revoked()  # unmark token as revoked if the API call was successful
                method = args[0] if args else kwargs.get("api_method")
                if self._shared_owner is not None and method in {"views.open", "views.push", "views.update"}:
                    remember_modal(self._shared_owner, self._shared_org_id, method,
                        kwargs.get("json") or kwargs.get("params") or {}, response)
            except Exception:
                if self._shared:
                    # The physical operation succeeded; a lost local receipt or
                    # changed source cannot authorize an automatic repeat.
                    raise SharedMutationUnknown() from None
                raise
            return response
        except SlackSDKApiError as e:
            if self._shared:
                error = e.response.get("error")
                if not isinstance(error, str) or re.fullmatch(r"[a-z_]{1,64}", error) is None:
                    raise SharedMutationUnknown() from None
                if error in SlackAPIServerError.errors:
                    raise SharedMutationUnknown() from None
                headers = {}
                delay = e.response.headers.get("Retry-After") if e.response.headers else None
                if isinstance(delay, str) and re.fullmatch(r"[0-9]{1,6}", delay):
                    headers["Retry-After"] = delay
                safe_response = SlackResponse(client=None, http_verb="POST", api_url="shared-slack",
                    req_args={}, data={"ok": False, "error": error}, headers=headers, status_code=e.response.status_code)
                error_class = get_error_class(safe_response)
                if error_class is SlackAPITokenError:
                    self._mark_token_revoked()
                else:
                    self._unmark_token_revoked()
                raise error_class(safe_response) from None
            logger.error(
                "Slack API call error! slack_team_identity={} args={} kwargs={} status={} error={} response={}".format(
                    self.slack_team_identity.pk,
                    args,
                    kwargs,
                    e.response["status"] if isinstance(e.response, dict) else e.response.status_code,
                    e.response.get("error"),
                    e.response,
                )
            )

            # narrow down the error
            error_class = get_error_class(e.response)

            # mark / unmark token as revoked
            if error_class is SlackAPITokenError:
                self._mark_token_revoked()
            else:
                self._unmark_token_revoked()

            # raise the narrowed down error class
            raise error_class(e.response) from e

    def _mark_token_revoked(self) -> None:
        if self._shared:
            from apps.slack.models import SlackTeamIdentity
            try:
                if require_local_source(self.slack_team_identity.pk, self._shared_org_id, self._shared_owner) != self._shared_snapshot:
                    raise SharedOwnerError()
            except SharedOwnerError:
                return
            from apps.slack.models import SharedSlackInstallation
            exact_receipt = SharedSlackInstallation.objects.filter(organization_id=self._shared_org_id,
                team_id=self.slack_team_identity.pk, source_owner=self._shared_owner.projection(),
                source_disconnected=False, organization__slack_team_identity_id=self.slack_team_identity.pk).values("team_id")
            SlackTeamIdentity.objects.filter(pk=self.slack_team_identity.pk, pk__in=exact_receipt,
                bot_access_token=self._captured_token, cached_app_id=self._shared_owner.app_id,
                slack_id=self._shared_owner.team_id).update(detected_token_revoked=timezone.now())
            return
        if not self.slack_team_identity.detected_token_revoked:
            self.slack_team_identity.detected_token_revoked = timezone.now()
            self.slack_team_identity.save(update_fields=["detected_token_revoked"])

    def _unmark_token_revoked(self) -> None:
        if self._shared:
            from apps.slack.models import SlackTeamIdentity
            try:
                if require_local_source(self.slack_team_identity.pk, self._shared_org_id, self._shared_owner) != self._shared_snapshot:
                    raise SharedOwnerError()
            except SharedOwnerError:
                return
            from apps.slack.models import SharedSlackInstallation
            exact_receipt = SharedSlackInstallation.objects.filter(organization_id=self._shared_org_id,
                team_id=self.slack_team_identity.pk, source_owner=self._shared_owner.projection(),
                source_disconnected=False, organization__slack_team_identity_id=self.slack_team_identity.pk).values("team_id")
            SlackTeamIdentity.objects.filter(pk=self.slack_team_identity.pk, pk__in=exact_receipt,
                bot_access_token=self._captured_token, cached_app_id=self._shared_owner.app_id,
                slack_id=self._shared_owner.team_id).update(detected_token_revoked=None)
            return
        if self.slack_team_identity.detected_token_revoked:
            self.slack_team_identity.detected_token_revoked = None
            self.slack_team_identity.save(update_fields=["detected_token_revoked"])
