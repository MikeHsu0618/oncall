import re
import typing

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.permissions import RBACPermission
from apps.auth_token.auth import PluginAuthentication
from apps.base.utils import live_settings
from apps.mobile_app.auth import MobileAppAuthTokenAuthentication
from apps.twilioapp.models import TwilioPhoneCallSender, TwilioSmsSender

TWILIO_PROVIDER = "twilio"
SOURCE_PHONE_NUMBER_FRIENDLY_NAME = "Grafana IRM"
# Only dialable E.164 numbers make sense in a device contact; SMS short codes and alphanumeric sender ids are skipped.
_E164_RE = re.compile(r"^\+[1-9]\d{6,14}$")


def _normalize(number: typing.Optional[str]) -> typing.Optional[str]:
    if not number:
        return None
    candidate = re.sub(r"[\s\-()]", "", str(number))
    return candidate if _E164_RE.match(candidate) else None


def _active_phone_provider() -> str:
    # Mirrors apps.phone_notifications.phone_provider.get_phone_provider's fallback to the default provider.
    provider = live_settings.PHONE_PROVIDER
    if provider not in settings.PHONE_PROVIDERS:
        return settings.DEFAULT_PHONE_PROVIDER
    return provider


def get_source_phone_numbers() -> typing.List[dict]:
    """
    Caller IDs OnCall uses for calls/SMS. These are instance-wide (live settings + Twilio sender tables are global,
    not per organization). Only the Twilio provider exposes its from-numbers; other providers yield an empty list.
    """
    if _active_phone_provider() != TWILIO_PROVIDER:
        return []

    capabilities: typing.Dict[str, typing.Dict[str, bool]] = {}

    def _add(number: typing.Optional[str], voice: bool, sms: bool) -> None:
        normalized = _normalize(number)
        if normalized is None:
            return
        current = capabilities.get(normalized, {"voice": False, "sms": False})
        capabilities[normalized] = {"voice": current["voice"] or voice, "sms": current["sms"] or sms}

    # The default Twilio client places calls and sends SMS from TWILIO_NUMBER when no per-country sender matches.
    _add(live_settings.TWILIO_NUMBER, voice=True, sms=True)
    for number in TwilioPhoneCallSender.objects.order_by("id").values_list("number", flat=True):
        _add(number, voice=True, sms=False)
    for sender in TwilioSmsSender.objects.order_by("id").values_list("sender", flat=True):
        _add(sender, voice=False, sms=True)

    return [
        {
            "phone_number": number,
            "friendly_name": SOURCE_PHONE_NUMBER_FRIENDLY_NAME,
            "status": "in-use",
            "capabilities": {"voice": caps["voice"], "sms": caps["sms"], "mms": False, "fax": False},
        }
        for number, caps in capabilities.items()
    ]


class SourcePhoneNumbersView(APIView):
    """
    `GET api/internal/v1/source_phone_numbers`, used by the mobile app to keep the "Grafana IRM" device contact in
    sync with the numbers OnCall calls/texts from. The app treats a number as eligible only when
    status == "in-use" and at least one capability is true; capabilities must be real booleans.
    """

    authentication_classes = (MobileAppAuthTokenAuthentication, PluginAuthentication)
    permission_classes = (IsAuthenticated, RBACPermission)
    rbac_permissions = {
        "get": [RBACPermission.Permissions.USER_SETTINGS_READ],
    }

    def get(self, request):
        return Response({"phone_numbers": get_source_phone_numbers()}, status=status.HTTP_200_OK)
