"""[code] TESTS FIRST: HTTP lifecycle regressions omitted by the original send stub.

[code] This suite preserves test_local_incident_transport.py and transport.py at
main's accepted baseline until main observes RED. Real requests Session.prepare_request
and Session.send remain unmodified; only HTTPAdapter.send supplies offline responses.
No redirect target, proxy, credential source or socket is contacted.
[code] Fault injection covers ordinary ValueError/RuntimeError at response.close,
session.close and the second cookies.clear invocation (the transport cleanup seam).
Cookie-clear faults are injected at the real jar method boundary, not a claim that
normal zero-argument RequestsCookieJar.clear commonly raises those exceptions.
Control-flow/BaseException handling is deliberately outside this specification.
[code] Gzip and malformed Latin-1 Location fixtures exercise real Requests redirect
preparation even with allow_redirects=False; raw reads must remain bounded/undecoded.
[code] A legitimate bounded Unicode request must also remain <=1 MiB on the wire,
not expand through requests' default ensure_ascii serialization or lose its content.
[code] Main owns pinned-image RED/GREEN; this file itself performs no environment setup.
"""

import gzip
import io
import json
import logging
import traceback
import unittest
from unittest.mock import patch

import requests
from requests.structures import CaseInsensitiveDict
from urllib3.exceptions import ProtocolError
from urllib3.response import HTTPResponse

from apps.mobile_app.local_incident import responses, transport
from apps.mobile_app.tests import test_local_incident_transport as fixtures


CANARY = "synthetic-cleanup-and-location-secret"


class CleanupResponse(fixtures.ResponseProbe):
    def __init__(self, *, close_error=None, **options):
        super().__init__(**options)
        self.close_error = close_error
        self.close_attempts = 0

    def close(self):
        self.close_attempts += 1
        super().close()
        if self.close_error is not None:
            raise self.close_error


class LifecycleSession(fixtures.RealSession):
    """[code] No send/prepare override: actual Requests lifecycle reaches the adapter."""

    def __init__(self, *, close_error=None, cookie_error=None):
        super().__init__()
        self.close_error = close_error
        self.cookie_error = cookie_error
        self.close_attempts = 0
        self.cookie_clear_attempts = 0
        original_clear = self.cookies.clear

        def clear_cookies(*args, **kwargs):
            self.cookie_clear_attempts += 1
            if self.cookie_clear_attempts > 1 and self.cookie_error is not None:
                raise self.cookie_error
            return original_clear(*args, **kwargs)

        # [code] Inject only the cleanup call; initial credential clearing is real.
        self.cookies.clear = clear_cookies

    def close(self):
        self.close_attempts += 1
        super().close()
        if self.close_error is not None:
            raise self.close_error


class ObservedGzipRaw:
    """[code] Real urllib3 gzip decoding, observed rather than reimplemented."""

    def __init__(self, expanded):
        self.inner = HTTPResponse(
            body=io.BytesIO(gzip.compress(expanded)),
            headers={"Content-Encoding": "gzip"},
            preload_content=False,
            decode_content=False,
        )
        self.stream_calls = []
        self.read_calls = []
        self.decoded_bytes = 0
        self.close_attempts = 0

    def stream(self, amt=65536, decode_content=None):
        self.stream_calls.append((amt, decode_content))
        for chunk in self.inner.stream(amt, decode_content=decode_content):
            self.decoded_bytes += len(chunk)
            yield chunk

    def read(self, amt=None, decode_content=None):
        self.read_calls.append((amt, decode_content))
        return self.inner.read(amt, decode_content=decode_content)

    def close(self):
        self.close_attempts += 1
        self.inner.close()

    def release_conn(self):
        return self.inner.release_conn()


class LocalIncidentTransportCleanupTests(unittest.TestCase):
    def setUp(self):
        self.binding = fixtures.config.Binding(
            oncall_org_id=100, grafana_org_id=1, internal_origin=fixtures.BASE,
            public_origin="https://grafana.example.invalid", namespace="synthetic",
            issuer="synthetic-issuer", key_id="synthetic-key-id", ttl_seconds=60,
            private_key_file="/never/read/synthetic-key.pem", public_der=b"synthetic", key=fixtures.PRIVATE,
        )
        self.pair = {"access_token": fixtures.ACCESS, "id_token": fixtures.IDENTITY}
        self.logs = fixtures.LogProbe()
        logging.getLogger().addHandler(self.logs)
        self.addCleanup(logging.getLogger().removeHandler, self.logs)
        for target in ("socket.create_connection", "socket.socket.connect", "socket.getaddrinfo"):
            self.enterContext(patch(target, side_effect=AssertionError("real network forbidden")))

    def call(self, session, response, *, method="UsersService.GetSession", payload=None):
        attempts = []
        factory_calls = []

        def session_factory():
            factory_calls.append(True)
            if len(factory_calls) != 1:
                raise AssertionError("unexpected retry/failover session")
            return session

        def adapter_send(_adapter, request, **options):
            attempts.append((request, options))
            if len(attempts) != 1:
                raise AssertionError("unexpected redirect/retry/failover request")
            response.request = request
            response.url = request.url
            return response

        with patch.object(transport.requests, "Session", session_factory), patch.object(
            requests.adapters.HTTPAdapter, "send", adapter_send
        ):
            result = transport.call_incident(
                self.binding, self.pair, "/api/" + method, fixtures.encoded(payload or {}))
        return result, attempts

    def assert_private(self, error):
        disclosure = str(error) + repr(error) + repr(vars(error)) + "".join(traceback.format_exception(error))
        for record in self.logs.records:
            disclosure += record.getMessage() + repr(record.__dict__)
            if record.exc_info:
                disclosure += "".join(traceback.format_exception(*record.exc_info))
        for secret in (CANARY, fixtures.ACCESS, fixtures.IDENTITY, fixtures.PRIVATE,
                       fixtures.CLIENT_SECRET, fixtures.BASE, "cloud.invalid"):
            self.assertNotIn(secret, disclosure)

    def assert_cleanup_error(self, session, response):
        # [code] Observe all ordinary failures for assertions; never swallow control flow.
        observed = None
        try:
            self.call(session, response)
        except Exception as error:
            observed = error
        self.assertGreaterEqual(response.close_attempts, 1)
        self.assertEqual(session.close_attempts, 1, "session close must be attempted after response cleanup fails")
        self.assertIsInstance(observed, transport.IncidentTransportError)
        self.assertEqual(str(observed), fixtures.TRANSPORT_MESSAGE)
        self.assert_private(observed)

    def test_ordinary_cleanup_failures_are_private_after_success_protocol_and_read_failures(self):
        for seam in ("response-close", "session-close", "cookie-clear"):
            for error_type in (ValueError, RuntimeError):
                for outcome in ("success", "protocol-failure", "read-timeout"):
                    with self.subTest(seam=seam, error_type=error_type.__name__, outcome=outcome):
                        options = {}
                        if outcome != "success":
                            error = (ProtocolError(CANARY) if outcome == "protocol-failure"
                                     else requests.ReadTimeout(CANARY))
                            options = {"data": b'{"user":null}', "fragment": 3,
                                       "failure": error, "fail_after": 3}
                        response = CleanupResponse(
                            close_error=error_type(CANARY) if seam == "response-close" else None, **options)
                        session = LifecycleSession(
                            close_error=error_type(CANARY) if seam == "session-close" else None,
                            cookie_error=error_type(CANARY) if seam == "cookie-clear" else None,
                        )
                        self.assert_cleanup_error(session, response)
                        self.assertGreaterEqual(session.cookie_clear_attempts, 2)

    def test_real_session_send_never_prepares_redirect_or_consumes_redirect_body_implicitly(self):
        response = CleanupResponse(data=b'{"error":"synthetic redirect"}', status=302, headers={
            "Location": "https://cloud.invalid/" + CANARY,
        })
        session = LifecycleSession()
        with self.assertRaises(responses.UpstreamResponseError) as raised:
            self.call(session, response)
        self.assertEqual(raised.exception.http_status, 302)
        self.assertIsNone(response.next, "no redirected PreparedRequest may retain server credentials")
        self.assertTrue(response.raw.reads, "transport must validate the bounded Error envelope")
        self.assertTrue(all(decode is False for _amount, decode in response.raw.reads))
        self.assertGreaterEqual(response.close_attempts, 1)
        self.assertEqual(session.close_attempts, 1)
        self.assert_private(raised.exception)

    def test_real_session_send_does_not_decompress_gzip_302_before_transport_checks(self):
        response = requests.Response()
        response.status_code = 302
        response.headers = CaseInsensitiveDict({
            "Content-Type": "application/json", "Content-Encoding": "gzip",
            "Location": "https://cloud.invalid/" + CANARY,
        })
        raw = ObservedGzipRaw(b'{"error":"' + b"x" * fixtures.MAX_BODY_BYTES + b'"}')
        response.raw = raw
        session = LifecycleSession()
        with self.assertRaises(transport.IncidentTransportError) as raised:
            self.call(session, response)
        self.assertEqual(str(raised.exception), fixtures.TRANSPORT_MESSAGE)
        self.assertEqual(raw.stream_calls, [], "Requests must not implicitly decode a redirect response")
        self.assertEqual(raw.read_calls, [], "unexpected encoding is rejected before reading any bytes")
        self.assertEqual(raw.decoded_bytes, 0)
        self.assertIsNone(response.next)
        self.assertGreaterEqual(raw.close_attempts, 1)
        self.assertEqual(session.close_attempts, 1)
        self.assert_private(raised.exception)

    def test_invalid_latin1_location_cannot_escape_static_error_or_leave_stream_open(self):
        response = CleanupResponse(data=b'{"error":"synthetic redirect"}', status=302, headers={
            "Location": "https://cloud.invalid/\xff/" + CANARY,
        })
        session = LifecycleSession()
        with self.assertRaises(responses.UpstreamResponseError) as raised:
            self.call(session, response)
        self.assertEqual(raised.exception.http_status, 302)
        self.assertIsNone(response.next)
        self.assertGreaterEqual(response.close_attempts, 1)
        self.assertTrue(response.raw.closed)
        self.assertEqual(session.close_attempts, 1)
        self.assert_private(raised.exception)

    def test_valid_unicode_request_stays_utf8_and_bounded_on_actual_prepared_wire(self):
        payload = {"title": "Synthetic UTF8", "fieldValues": {
            "one": "é" * 131060, "two": "é" * 131060, "three": "é" * 131060,
        }}
        inbound = fixtures.encoded(payload)
        ascii_expansion = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
        self.assertLess(len(inbound), fixtures.MAX_BODY_BYTES)
        self.assertGreater(len(ascii_expansion), fixtures.MAX_BODY_BYTES)
        response = CleanupResponse()
        session = LifecycleSession()
        result, attempts = self.call(session, response, method="IncidentsService.CreateIncident", payload=payload)
        self.assertEqual(result, {})
        self.assertEqual(len(attempts), 1)
        request, options = attempts[0]
        self.assertIs(type(request.body), bytes)
        self.assertLessEqual(len(request.body), fixtures.MAX_BODY_BYTES)
        self.assertEqual(request.body, inbound, "serialize the accepted JSON once as bounded compact UTF8")
        self.assertEqual(json.loads(request.body.decode("utf-8")), payload)
        self.assertIn("é".encode("utf-8"), request.body)
        self.assertEqual(int(request.headers["Content-Length"]), len(request.body))
        self.assertEqual(request.headers["X-Grafana-Org-Id"], "1")
        self.assertIs(options["stream"], True)
        self.assertEqual(session.close_attempts, 1)
        self.assertGreaterEqual(response.close_attempts, 1)
