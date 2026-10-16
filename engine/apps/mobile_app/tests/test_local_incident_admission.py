"""[code] Unit tests for the renewing-lease admission seam; Redis and scripts are faked.

[code] Real Lua/Redis semantics are covered by test_local_incident_admission_redis.py.
"""

import re
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from django.core.exceptions import ImproperlyConfigured
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, TimeoutError as RedisTimeoutError
from rest_framework.exceptions import Throttled

from apps.mobile_app.local_incident import admission
from apps.mobile_app.web_session.config import Unavailable

READ_SCOPE = (12, 34, False)
WRITE_SCOPE = (12, 34, True)
LEASE_KEY = "oncall:li:adm:{12:34}:lease"
SETTING_NAMES = (
    "MOBILE_APP_LOCAL_INCIDENT_READ_PER_MINUTE",
    "MOBILE_APP_LOCAL_INCIDENT_WRITE_PER_MINUTE",
    "MOBILE_APP_LOCAL_INCIDENT_CONCURRENCY",
    "MOBILE_APP_LOCAL_INCIDENT_LEASE_TTL_MS",
    "MOBILE_APP_LOCAL_INCIDENT_LEASE_RENEW_MS",
)


def configure(settings, read=60, write=20, concurrency=4, ttl=15000, renew=5000):
    for name, value in zip(SETTING_NAMES, (read, write, concurrency, ttl, renew)):
        setattr(settings, name, value)


@pytest.fixture
def store(settings, monkeypatch):
    configure(settings)
    scripts = SimpleNamespace(
        acquire=Mock(return_value=[1, b"ok"]),
        renew=Mock(return_value=1),
        release=Mock(return_value=1),
    )
    connection = Mock(name="redis-connection")
    get_connection = Mock(return_value=connection)
    monkeypatch.setattr(admission, "get_redis_connection", get_connection)
    monkeypatch.setattr(admission, "_scripts", Mock(return_value=scripts))
    return SimpleNamespace(scripts=scripts, connection=connection, get_connection=get_connection)


def acquired_nonce(store, index=0):
    return store.scripts.acquire.call_args_list[index].kwargs["args"][0]


# --- configuration ---------------------------------------------------------------------


@pytest.mark.parametrize("name", SETTING_NAMES)
@pytest.mark.parametrize("value", [
    "600/min", "four", " 4", "4 ", "-1", "0", "+4", "04", "", "\u0664", "1_0", "1234567890",
    0, -1, True, 4.0, 1.5, None, 1_000_000_000,
])
def test_invalid_setting_is_503_before_store_access(store, settings, name, value):
    setattr(settings, name, value)
    with pytest.raises(Unavailable):
        admission.acquire(READ_SCOPE)
    store.get_connection.assert_not_called()
    store.scripts.acquire.assert_not_called()


@pytest.mark.parametrize("raw,parsed", [("60", 60), (60, 60), ("15000", 15000)])
def test_strict_setting_accepts_digit_strings_and_ints(store, settings, raw, parsed):
    settings.MOBILE_APP_LOCAL_INCIDENT_READ_PER_MINUTE = raw
    permit = admission.acquire(READ_SCOPE)
    try:
        assert store.scripts.acquire.call_args.kwargs["args"][1] == parsed
        assert type(store.scripts.acquire.call_args.kwargs["args"][1]) is int
    finally:
        permit.release()


def test_base_settings_defaults_are_raw_strings_that_parse():
    # [code] base.py keeps env strings; the defaults must satisfy the strict parser.
    config = admission._config()
    assert (config.read_per_minute, config.write_per_minute, config.concurrency,
            config.lease_ttl_ms, config.lease_renew_ms) == (60, 20, 4, 15000, 5000)


@pytest.mark.parametrize("ttl,renew", [(10000, 5000), (10000, 6000), (100, 100)])
def test_renew_interval_must_be_less_than_half_ttl(store, settings, ttl, renew):
    configure(settings, ttl=ttl, renew=renew)
    with pytest.raises(Unavailable):
        admission.acquire(READ_SCOPE)
    store.get_connection.assert_not_called()


@pytest.mark.parametrize("scope", [
    ("12", 34, False), (12, "34", False), (0, 34, False), (12, -1, True),
    (12, 34, "yes"), (True, 34, False), (12, 34), [12, 34, False], None,
])
def test_scope_must_be_server_ints_and_bool(store, scope):
    with pytest.raises(Unavailable):
        admission.acquire(scope)
    store.get_connection.assert_not_called()


# --- store availability ----------------------------------------------------------------


@pytest.mark.parametrize("error", [
    NotImplementedError("This backend does not support this feature"),
    RedisConnectionError("synthetic"), ImproperlyConfigured("synthetic"),
])
def test_connection_failure_is_503(store, error):
    store.get_connection.side_effect = error
    with pytest.raises(Unavailable):
        admission.acquire(READ_SCOPE)
    store.scripts.acquire.assert_not_called()


def test_locmem_test_cache_cannot_admit(settings):
    # [code] Real django_redis lookup against the LocMem test cache: fail closed.
    configure(settings)
    assert "redis" not in settings.CACHES["default"]["BACKEND"].lower()
    with pytest.raises(Unavailable):
        admission.acquire(READ_SCOPE)


def test_scripts_register_the_three_lua_sources():
    client = Mock()
    admission._scripts(client)
    sources = [call.args[0] for call in client.register_script.call_args_list]
    assert sources == [admission.ACQUIRE_LUA, admission.RENEW_LUA, admission.RELEASE_LUA]
    for source in (admission.ACQUIRE_LUA, admission.RENEW_LUA):
        assert "redis.call('TIME')" in source


# --- keys / nonce ----------------------------------------------------------------------


@pytest.mark.parametrize("scope,rate_key,limit", [
    (READ_SCOPE, "oncall:li:adm:{12:34}:rate:r", 60),
    (WRITE_SCOPE, "oncall:li:adm:{12:34}:rate:w", 20),
])
def test_keys_and_limits_come_only_from_server_scope(store, scope, rate_key, limit):
    permit = admission.acquire(scope)
    try:
        call = store.scripts.acquire.call_args
        assert call.kwargs["keys"] == [LEASE_KEY, rate_key]
        assert call.kwargs["args"][1:] == [limit, 4, 15000, admission.WINDOW_MS]
        assert admission.WINDOW_MS == 60000
    finally:
        permit.release()


def test_nonce_is_fresh_csprng_hex_per_acquire(store):
    permits = [admission.acquire(READ_SCOPE), admission.acquire(READ_SCOPE)]
    for permit in permits:
        permit.release()
    nonces = [acquired_nonce(store, 0), acquired_nonce(store, 1)]
    assert nonces[0] != nonces[1]
    assert all(re.fullmatch(r"[0-9a-f]{32}", nonce) for nonce in nonces)


# --- denials / ambiguity ---------------------------------------------------------------


@pytest.mark.parametrize("reply,ttl,wait", [
    ([0, b"rate"], 15000, 60),
    ([0, "rate"], 15000, 60),
    ([0, b"concurrency"], 15000, 15),
    ([0, b"concurrency"], 1500, 2),
])
def test_rate_and_concurrency_denials_are_429(store, settings, reply, ttl, wait):
    configure(settings, ttl=ttl, renew=min(5000, ttl // 3))
    store.scripts.acquire.return_value = reply
    with pytest.raises(Throttled) as caught:
        admission.acquire(WRITE_SCOPE)
    assert caught.value.wait == wait
    store.scripts.acquire.assert_called_once()
    store.scripts.release.assert_not_called()
    store.scripts.renew.assert_not_called()


@pytest.mark.parametrize("outcome", [
    RedisTimeoutError("synthetic"), RedisConnectionError("synthetic"), OSError("synthetic"),
    None, [1], [2, b"ok"], [True, b"ok"], "ok", [0, b"other"],
])
def test_ambiguous_acquire_is_503_with_best_effort_release_and_no_retry(store, outcome):
    if isinstance(outcome, Exception):
        store.scripts.acquire.side_effect = outcome
    else:
        store.scripts.acquire.return_value = outcome
    with pytest.raises(Unavailable):
        admission.acquire(READ_SCOPE)
    store.scripts.acquire.assert_called_once()
    if outcome == [0, b"other"]:
        # [code] A definite non-admission (script ran, nothing added) needs no cleanup.
        store.scripts.release.assert_not_called()
        return
    store.scripts.release.assert_called_once_with(keys=[LEASE_KEY], args=[acquired_nonce(store)])


def test_ambiguous_acquire_cleanup_failure_is_still_503(store):
    store.scripts.acquire.side_effect = RedisTimeoutError("synthetic")
    store.scripts.release.side_effect = RedisError("synthetic")
    with pytest.raises(Unavailable):
        admission.acquire(READ_SCOPE)
    store.scripts.acquire.assert_called_once()


# --- permit lifecycle ------------------------------------------------------------------


def test_release_is_idempotent_and_reports_ok(store):
    permit = admission.acquire(READ_SCOPE)
    assert permit.release() is True
    assert permit.release() is True
    assert permit.ok is True
    store.scripts.release.assert_called_once_with(keys=[LEASE_KEY], args=[acquired_nonce(store)])
    assert not permit._thread.is_alive()


@pytest.mark.parametrize("removed,error", [(0, None), (None, RedisError("synthetic")), (None, OSError("x"))])
def test_release_not_removing_own_nonce_is_not_ok(store, removed, error):
    store.scripts.release.return_value = removed
    store.scripts.release.side_effect = error
    permit = admission.acquire(READ_SCOPE)
    assert permit.release() is False
    assert permit.ok is False


def test_renewal_extends_own_lease_until_released(store, settings):
    configure(settings, ttl=300, renew=20)
    renewed = threading.Event()

    def renew(**kwargs):
        if store.scripts.renew.call_count >= 2:
            renewed.set()
        return 1

    store.scripts.renew.side_effect = renew
    permit = admission.acquire(READ_SCOPE)
    assert renewed.wait(timeout=2)
    assert permit.release() is True
    assert permit.lost is False
    assert store.scripts.renew.call_args.kwargs == {"keys": [LEASE_KEY], "args": [acquired_nonce(store), 300]}


@pytest.mark.parametrize("renew_outcome", [0, RedisError("synthetic"), RuntimeError("synthetic")])
def test_renewal_loss_marks_lost_and_release_not_ok(store, settings, renew_outcome):
    configure(settings, ttl=300, renew=20)
    if isinstance(renew_outcome, Exception):
        store.scripts.renew.side_effect = renew_outcome
    else:
        store.scripts.renew.return_value = renew_outcome
    permit = admission.acquire(READ_SCOPE)
    permit._thread.join(timeout=2)
    assert not permit._thread.is_alive()
    assert permit.lost is True
    assert store.scripts.renew.call_count == 1  # stops renewing after loss
    assert permit.release() is False
    assert permit.ok is False
    store.scripts.release.assert_called_once()


def test_renewal_thread_start_failure_releases_slot_and_is_503(store, monkeypatch):
    def fail_start(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(admission.Permit, "_start", fail_start)
    with pytest.raises(Unavailable):
        admission.acquire(WRITE_SCOPE)
    store.scripts.acquire.assert_called_once()
    store.scripts.release.assert_called_once_with(keys=[LEASE_KEY], args=[acquired_nonce(store)])
