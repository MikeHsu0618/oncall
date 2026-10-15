"""Operator-pinned, single-organization WebSession configuration; disabled by default."""
import ipaddress
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from rest_framework.exceptions import APIException


class Unavailable(APIException):
    status_code = 503
    default_detail = "WebSession unavailable"


def bad(field_name):
    raise Unavailable(f"Invalid WebSession field: {field_name}")


def positive_int(value, field_name):
    if type(value) is not int or value <= 0:
        bad(field_name)
    return value


def text(value, field_name):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        bad(field_name)
    return value


def origin(value, field_name, public=False):
    value = text(value, field_name)
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        bad(field_name)
    if (parsed.scheme not in (("https",) if public else ("http", "https"))
            or not host or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment or "?" in value or "#" in value
            or any(c.isspace() or c == "\\" for c in value)
            or (port is not None and not 0 < port <= 65535)):
        bad(field_name)
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", host) or host.endswith("."):
        bad(field_name)
    if public:
        if host.lower() == "localhost" or host.lower().endswith(".localhost") or "." not in host:
            bad(field_name)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass  # A DNS hostname, not an IP literal, is required for the public origin.
        else:
            bad(field_name)
        if all(c in "0123456789.xXaAbBcCdDeEfF" for c in host) or host.startswith("127."):
            bad(field_name)
    return value


def private_key(filename):
    filename = text(filename, "private_key_file")
    try:
        path = Path(filename)
        if not path.is_absolute() or path.is_symlink():
            bad("private_key_file")
        with path.open("rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 16384:
                bad("private_key_file")
            key = serialization.load_pem_private_key(handle.read(16385), password=None)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        bad("private_key_file")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        bad("private_key_file")
    return key


@dataclass(frozen=True)
class Binding:
    oncall_org_id: int
    grafana_org_id: int
    internal_origin: str
    public_origin: str
    namespace: str
    issuer: str
    key_id: str
    ttl_seconds: int
    private_key_file: str
    public_der: bytes
    key: object = field(compare=False, repr=False)


def load_binding():
    if getattr(settings, "WEB_SESSION_ENABLED", False) is not True:
        raise Unavailable()
    raw = getattr(settings, "WEB_SESSION_BINDING", None)
    if not isinstance(raw, dict):
        bad("WEB_SESSION_BINDING")
    ttl = positive_int(raw.get("ttl_seconds", 60), "ttl_seconds")
    if not 15 <= ttl <= 120:
        bad("ttl_seconds")
    namespace = text(raw.get("namespace"), "namespace")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}", namespace):
        bad("namespace")
    key = private_key(raw.get("private_key_file"))
    return Binding(
        oncall_org_id=positive_int(raw.get("oncall_org_id"), "oncall_org_id"),
        grafana_org_id=positive_int(raw.get("grafana_org_id"), "grafana_org_id"),
        internal_origin=origin(raw.get("internal_origin"), "internal_origin"),
        public_origin=origin(raw.get("public_origin"), "public_origin", public=True),
        namespace=namespace, issuer=text(raw.get("issuer"), "issuer"),
        key_id=text(raw.get("key_id"), "key_id"), ttl_seconds=ttl,
        private_key_file=raw["private_key_file"], key=key,
        public_der=key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
    )


def public_status(organization_id, call_status):
    if getattr(settings, "WEB_SESSION_ENABLED", False) is not True:
        return call_status
    # Advertising a public URL is independent of mint/JWKS signer readiness.
    # Validate only this optional mapping; never turn connection health into 503.
    try:
        raw = getattr(settings, "WEB_SESSION_BINDING", None)
        if not isinstance(raw, dict):
            bad("WEB_SESSION_BINDING")
        if positive_int(raw.get("oncall_org_id"), "oncall_org_id") != organization_id:
            return call_status
        positive_int(raw.get("grafana_org_id"), "grafana_org_id")
        public_origin = origin(raw.get("public_origin"), "public_origin", public=True)
    except Unavailable as exc:
        # Validation details contain field names only, never operator values/keys.
        logging.getLogger(__name__).warning(
            "WebSession status URL ignored: organization_id=%s reason=%s", organization_id, exc.detail
        )
        return call_status
    return {**call_status, "url": public_origin + "/api/org"}
