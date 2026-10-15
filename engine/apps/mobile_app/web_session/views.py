from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.mobile_app.auth import MobileAppAuthTokenAuthentication

from .config import load_binding
from .service import issue_session
from .tokens import public_jwk


class NoStoreView(APIView):
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        return response


class WebSessionAuthentication(MobileAppAuthTokenAuthentication):
    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except UnicodeDecodeError:
            # WSGI headers may contain arbitrary Latin-1 bytes. Keep the existing
            # shared authenticator untouched; DRF will finalize this as no-store.
            raise AuthenticationFailed("Invalid token") from None


class WebSessionView(NoStoreView):
    authentication_classes = (WebSessionAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response(issue_session(request))


class WebSessionJWKSView(NoStoreView):
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def get(self, request):
        return Response({"keys": [public_jwk(load_binding())]})
