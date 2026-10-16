"""[code] Fail-closed renewing-lease admission for the local Incident gateway.

[code] Per (organization, user) scope, Redis holds a lease ZSET (nonce -> expiry ms)
bounding concurrency and per-kind ZSETs (nonce -> admit ms) bounding admitted
requests in a sliding 60 s window. All clocks are Redis TIME, never worker clocks.
Any store/config failure is 503; there is no in-process or unlimited fallback.
[code] A holder renews its lease from a daemon thread; a crashed worker's slot is
reclaimed after the lease TTL. Release removes only the holder's own nonce.
"""

import logging
import math
import re
import secrets
import threading
from dataclasses import dataclass
from types import SimpleNamespace

from django.conf import settings
from django_redis import get_redis_connection
from redis.exceptions import RedisError
from rest_framework.exceptions import Throttled

from apps.mobile_app.web_session.config import Unavailable

logger = logging.getLogger(__name__)

WINDOW_MS = 60_000
RATE_WAIT_SECONDS = 60
_UNAVAILABLE = "Local incident admission unavailable"
_STORE_ERRORS = (RedisError, OSError)
_POSITIVE_DIGITS = re.compile(r"[1-9][0-9]{0,8}")
_MAX_SETTING = 999_999_999

# [code] Effects replication makes TIME legal before writes on Redis < 5; it is a
# no-op (deprecated, always on) for Redis >= 7.
_NOW = """
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
-- Key expiry only ever extends; PTTL -1/-2 (no TTL / missing) is below any want.
local function extend_expiry(key, want)
  if redis.call('PTTL', key) < want then redis.call('PEXPIRE', key, want) end
end
"""

ACQUIRE_LUA = _NOW + """
local limit = tonumber(ARGV[2])
local concurrency = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local window = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - window)
if redis.call('ZCARD', KEYS[2]) >= limit then return {0, 'rate'} end
if redis.call('ZCARD', KEYS[1]) >= concurrency then return {0, 'concurrency'} end
redis.call('ZADD', KEYS[1], now + ttl, ARGV[1])
redis.call('ZADD', KEYS[2], now, ARGV[1])
extend_expiry(KEYS[1], ttl * 2)
extend_expiry(KEYS[2], window)
return {1, 'ok'}
"""

RENEW_LUA = _NOW + """
local ttl = tonumber(ARGV[2])
local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if (not score) or tonumber(score) <= now then
  redis.call('ZREM', KEYS[1], ARGV[1])
  return 0
end
redis.call('ZADD', KEYS[1], 'XX', now + ttl, ARGV[1])
extend_expiry(KEYS[1], ttl * 2)
return 1
"""

RELEASE_LUA = """
return redis.call('ZREM', KEYS[1], ARGV[1])
"""


@dataclass(frozen=True)
class Config:
    read_per_minute: int
    write_per_minute: int
    concurrency: int
    lease_ttl_ms: int
    lease_renew_ms: int


def _positive_int(value):
    # [code] Strict: an int, or a raw env string of ASCII digits without sign/space/
    # leading zero. Never echo the value; any other input fails closed.
    if type(value) is int and 0 < value <= _MAX_SETTING:
        return value
    if type(value) is str and _POSITIVE_DIGITS.fullmatch(value):
        return int(value)
    raise Unavailable(_UNAVAILABLE)


def _config():
    values = [getattr(settings, name, None) for name in (
        "MOBILE_APP_LOCAL_INCIDENT_READ_PER_MINUTE",
        "MOBILE_APP_LOCAL_INCIDENT_WRITE_PER_MINUTE",
        "MOBILE_APP_LOCAL_INCIDENT_CONCURRENCY",
        "MOBILE_APP_LOCAL_INCIDENT_LEASE_TTL_MS",
        "MOBILE_APP_LOCAL_INCIDENT_LEASE_RENEW_MS",
    )]
    config = Config(*(_positive_int(value) for value in values))
    if config.lease_renew_ms * 2 >= config.lease_ttl_ms:
        raise Unavailable(_UNAVAILABLE)
    return config


def _keys(scope):
    """Lease and rate keys from server-derived ints only; one hash tag per scope."""
    if type(scope) is not tuple or len(scope) != 3:
        raise Unavailable(_UNAVAILABLE)
    organization_id, user_pk, write = scope
    if (type(organization_id) is not int or organization_id <= 0
            or type(user_pk) is not int or user_pk <= 0 or type(write) is not bool):
        raise Unavailable(_UNAVAILABLE)
    prefix = f"oncall:li:adm:{{{organization_id}:{user_pk}}}"
    return f"{prefix}:lease", f"{prefix}:rate:{'w' if write else 'r'}"


def _connection():
    try:
        return get_redis_connection("default")
    except Exception:
        # [code] Includes NotImplementedError for non-Redis (e.g. LocMem) caches.
        logger.warning("Local incident admission store unavailable")
        raise Unavailable(_UNAVAILABLE) from None


def _scripts(client):
    return SimpleNamespace(
        acquire=client.register_script(ACQUIRE_LUA),
        renew=client.register_script(RENEW_LUA),
        release=client.register_script(RELEASE_LUA),
    )


def _text(value):
    return value.decode("ascii", "replace") if isinstance(value, bytes) else value


def _parse(result):
    if type(result) not in (list, tuple) or len(result) != 2:
        return None
    admitted, reason = result
    if admitted not in (0, 1) or type(admitted) is bool:
        return None
    return admitted == 1, _text(reason)


class Permit:
    """Holder of one lease nonce; renews in background until released or lost."""

    def __init__(self, scripts, lease_key, nonce, config):
        self._scripts = scripts
        self._lease_key = lease_key
        self._nonce = nonce
        self._ttl_ms = config.lease_ttl_ms
        self._renew_seconds = config.lease_renew_ms / 1000
        # [code] A permit is a mutable one-shot resource handle by design.
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._released = False
        self.lost = False
        self.ok = None
        self._thread = threading.Thread(target=self._renew_loop, name="local-incident-lease", daemon=True)

    def _start(self):
        self._thread.start()

    def _renew_loop(self):
        while not self._stop.wait(self._renew_seconds):
            try:
                renewed = self._scripts.renew(keys=[self._lease_key], args=[self._nonce, self._ttl_ms])
            except Exception:
                # [code] Background thread: any failure means the lease can no longer
                # be proven held; record loss instead of dying silently.
                logger.warning("Local incident admission lease renewal failed")
                renewed = 0
            if renewed != 1:
                self.lost = True
                return

    def release(self):
        """Idempotent; returns True only if the lease was held to the end and removed."""
        with self._lock:
            if self._released:
                return self.ok
            self._released = True
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self._renew_seconds + 1.0)
        renewing = self._thread.is_alive()
        try:
            removed = self._scripts.release(keys=[self._lease_key], args=[self._nonce])
        except _STORE_ERRORS:
            logger.warning("Local incident admission release failed")
            removed = 0
        self.ok = removed == 1 and not self.lost and not renewing
        return self.ok


def _best_effort_release(scripts, lease_key, nonce):
    try:
        scripts.release(keys=[lease_key], args=[nonce])
    except _STORE_ERRORS:
        # [code] Outcome already ambiguous and reported as 503; the lease TTL
        # reclaims the slot if this cleanup could not run.
        logger.warning("Local incident admission cleanup failed")


def acquire(scope):
    """Return a started Permit; raise Throttled (429) or Unavailable (503)."""
    config = _config()
    lease_key, rate_key = _keys(scope)
    scripts = _scripts(_connection())
    nonce = secrets.token_hex(16)
    limit = config.write_per_minute if scope[2] else config.read_per_minute
    try:
        result = scripts.acquire(
            keys=[lease_key, rate_key],
            args=[nonce, limit, config.concurrency, config.lease_ttl_ms, WINDOW_MS],
        )
    except _STORE_ERRORS:
        result = None
    parsed = _parse(result)
    if parsed is None:
        # [code] Ambiguous: the script may have run. Never retry acquire.
        logger.warning("Local incident admission acquire failed")
        _best_effort_release(scripts, lease_key, nonce)
        raise Unavailable(_UNAVAILABLE)
    admitted, reason = parsed
    if not admitted:
        if reason == "rate":
            raise Throttled(wait=RATE_WAIT_SECONDS)
        if reason == "concurrency":
            raise Throttled(wait=math.ceil(config.lease_ttl_ms / 1000))
        raise Unavailable(_UNAVAILABLE)
    permit = Permit(scripts, lease_key, nonce, config)
    try:
        permit._start()
    except Exception:
        # [code] Admitted but cannot renew: give the slot back and fail closed (503).
        logger.warning("Local incident admission renewal start failed")
        _best_effort_release(scripts, lease_key, nonce)
        raise Unavailable(_UNAVAILABLE) from None
    return permit
