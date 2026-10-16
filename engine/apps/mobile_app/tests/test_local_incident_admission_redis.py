"""[code] Real-Redis integration tests for the renewing-lease admission limiter.

[code] Requires LOCAL_INCIDENT_TEST_REDIS_URL (a disposable Redis DB; it is FLUSHDB'd).
Without it every test skips; the dedicated CI stage must set it and require zero skips.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import redis
from rest_framework.exceptions import Throttled

from apps.mobile_app.local_incident import admission

URL_ENV = "LOCAL_INCIDENT_TEST_REDIS_URL"
READ_SCOPE = (101, 202, False)
WRITE_SCOPE = (101, 202, True)
WORKER_SCRIPT = Path(__file__).resolve().with_name("local_incident_admission_redis_worker.py")

pytestmark = pytest.mark.enable_socket


def configure(settings, read=1000, write=1000, concurrency=4, ttl=15000, renew=5000):
    settings.MOBILE_APP_LOCAL_INCIDENT_READ_PER_MINUTE = read
    settings.MOBILE_APP_LOCAL_INCIDENT_WRITE_PER_MINUTE = write
    settings.MOBILE_APP_LOCAL_INCIDENT_CONCURRENCY = concurrency
    settings.MOBILE_APP_LOCAL_INCIDENT_LEASE_TTL_MS = ttl
    settings.MOBILE_APP_LOCAL_INCIDENT_LEASE_RENEW_MS = renew


@pytest.fixture
def real(settings, monkeypatch):
    url = os.environ.get(URL_ENV)
    if not url:
        pytest.skip(f"{URL_ENV} is not set")
    client = redis.Redis.from_url(url)
    client.flushdb()
    monkeypatch.setattr(admission, "_connection", lambda: client)
    configure(settings)
    permits = []
    yield SimpleNamespace(client=client, url=url, permits=permits)
    for permit in permits:
        permit.release()
    client.flushdb()
    client.close()


def take(real, scope=READ_SCOPE):
    permit = admission.acquire(scope)
    real.permits.append(permit)
    return permit


def wait_until(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_concurrency_limit_and_slot_reuse_with_redis_clock(real, settings):
    configure(settings, concurrency=4)
    held = [take(real) for _ in range(4)]
    with pytest.raises(Throttled) as caught:
        admission.acquire(READ_SCOPE)
    assert caught.value.wait == 15
    lease_key = admission._keys(READ_SCOPE)[0]
    seconds, micros = real.client.time()
    now_ms = seconds * 1000 + micros // 1000
    score = real.client.zscore(lease_key, held[0]._nonce)
    assert now_ms + 15000 - 2000 <= score <= now_ms + 15000 + 2000
    assert held[0].release() is True
    replacement = take(real)
    assert real.client.zcard(lease_key) == 4
    assert all(permit.release() is True for permit in held[1:] + [replacement])
    assert real.client.zcard(lease_key) == 0


def test_rate_limit_counts_admissions_and_is_not_refunded(real, settings):
    configure(settings, read=3, concurrency=10)
    for _ in range(3):
        assert take(real).release() is True
    with pytest.raises(Throttled) as caught:
        admission.acquire(READ_SCOPE)
    assert caught.value.wait == 60
    # [code] Denials do not consume; writes use their own window.
    with pytest.raises(Throttled):
        admission.acquire(READ_SCOPE)
    assert take(real, WRITE_SCOPE).release() is True
    assert real.client.zcard(admission._keys(READ_SCOPE)[1]) == 3


def test_crashed_holder_slot_is_reclaimed_after_ttl(real, settings):
    configure(settings, concurrency=1, ttl=300, renew=100)
    crashed = take(real)
    # [code] Simulate a dead worker: stop renewing without releasing.
    crashed._stop.set()
    crashed._thread.join(timeout=2)
    with pytest.raises(Throttled):
        admission.acquire(READ_SCOPE)
    time.sleep(0.4)
    successor = take(real)
    assert successor.release() is True
    assert crashed.release() is False


def test_renewal_keeps_slot_past_ttl(real, settings):
    configure(settings, concurrency=1, ttl=300, renew=100)
    holder = take(real)
    deadline = time.monotonic() + 1.0
    attempts = 0
    while time.monotonic() < deadline:
        with pytest.raises(Throttled):
            admission.acquire(READ_SCOPE)
        attempts += 1
        time.sleep(0.1)
    assert attempts >= 5
    assert holder.lost is False
    assert holder.release() is True


def test_release_with_foreign_nonce_does_not_remove_holder(real, settings):
    holder = take(real)
    lease_key = admission._keys(READ_SCOPE)[0]
    scripts = admission._scripts(real.client)
    assert scripts.release(keys=[lease_key], args=["f" * 32]) == 0
    assert real.client.zscore(lease_key, holder._nonce) is not None
    assert holder.release() is True


def test_redis_reset_while_held_marks_lease_lost(real, settings):
    configure(settings, concurrency=1, ttl=300, renew=100)
    holder = take(real)
    real.client.flushdb()
    assert wait_until(lambda: holder.lost, timeout=1.0)
    assert holder.release() is False
    assert holder.ok is False


def test_key_expiry_is_only_extended_never_shortened(real, settings):
    configure(settings, concurrency=4, ttl=300, renew=100)
    lease_key, read_rate_key = admission._keys(READ_SCOPE)
    write_rate_key = admission._keys(WRITE_SCOPE)[1]
    far_future = 9_999_999_999_999
    real.client.zadd(lease_key, {"placeholder": far_future})
    real.client.pexpire(lease_key, 60000)
    real.client.zadd(read_rate_key, {"placeholder": far_future})
    real.client.pexpire(read_rate_key, 120000)
    holder = take(real)
    assert real.client.pttl(lease_key) > 50000
    assert real.client.pttl(read_rate_key) > 110000
    time.sleep(0.25)  # [code] At least one RENEW has run with ttl=300.
    assert holder.lost is False
    assert real.client.pttl(lease_key) > 50000
    # [code] A fresh key (PTTL -2) still receives its expiry.
    writer = take(real, WRITE_SCOPE)
    assert 0 < real.client.pttl(write_rate_key) <= admission.WINDOW_MS
    assert writer.release() is True
    assert holder.release() is True


def _diagnostics(processes):
    details = []
    for process in processes:
        if process.poll() is None:
            process.kill()
        _out, err = process.communicate(timeout=5)
        details.append(err.decode("utf-8", "replace")[-500:])
    return details


def test_multi_process_contention_never_exceeds_concurrency(real):
    count, concurrency = 12, 4
    lease_key, rate_key = admission._keys(READ_SCOPE)
    keys = {name: f"oncall:li:test:{name}" for name in ("ready", "start", "attempted", "release")}
    config = json.dumps({
        "acquire_lua": admission.ACQUIRE_LUA, "release_lua": admission.RELEASE_LUA,
        "lease_key": lease_key, "rate_key": rate_key, "rate_limit": 1000,
        "concurrency": concurrency, "ttl_ms": 10000, "window_ms": admission.WINDOW_MS,
        **{f"{name}_key": key for name, key in keys.items()},
    })
    # [code] Separate interpreters (not multiprocessing) so the runner's __main__ is
    # never re-imported; -I keeps project/env paths out, the worker needs only redis.
    command = [sys.executable, "-I", "-B", str(WORKER_SCRIPT), config]
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", URL_ENV: real.url}
    processes = []
    try:
        for _ in range(count):
            processes.append(subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, cwd=str(WORKER_SCRIPT.parent),
            ))
        for _ in range(count):
            assert real.client.blpop([keys["ready"]], timeout=15) is not None, _diagnostics(processes)
        real.client.rpush(keys["start"], *(["go"] * count))
        for _ in range(count):
            assert real.client.blpop([keys["attempted"]], timeout=10) is not None, _diagnostics(processes)
        holding = real.client.zcard(lease_key)
        real.client.rpush(keys["release"], *(["go"] * count))
        outputs = [process.communicate(timeout=15) for process in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    assert all(process.returncode == 0 for process in processes), [err[-500:] for _, err in outputs]
    results = [json.loads(out.decode("utf-8").strip().splitlines()[-1]) for out, _ in outputs]
    assert [r for r in results if r["status"] != "ok"] == []
    admitted = [r for r in results if r["admitted"] == 1]
    assert holding == concurrency
    assert len(admitted) == concurrency
    assert all(r["first"] <= concurrency for r in admitted)
    assert all(r["removed"] == 1 for r in admitted)
    assert real.client.zcard(lease_key) == 0
