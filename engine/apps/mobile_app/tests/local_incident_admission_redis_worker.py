"""[code] Standalone worker script for the real-Redis admission contention test.

[code] Run as `python -I -B <this file> <json-config>`; imports only stdlib + redis
(no project/Django modules). The parent passes the production ACQUIRE/RELEASE Lua
source text from admission.py in the config, so the exact same scripts execute.
Barriers are Redis lists: ready -> start -> attempted -> release. Prints one JSON line.
"""

import json
import os
import secrets
import sys

import redis


def _wait(client, key):
    if client.blpop([key], timeout=10) is None:
        raise RuntimeError("barrier timeout")


def run(config, url):
    client = redis.Redis.from_url(url)
    try:
        acquire = client.register_script(config["acquire_lua"])
        release = client.register_script(config["release_lua"])
        lease_key, rate_key = config["lease_key"], config["rate_key"]
        nonce = secrets.token_hex(16)
        client.rpush(config["ready_key"], nonce)
        _wait(client, config["start_key"])
        admitted, _reason = acquire(
            keys=[lease_key, rate_key],
            args=[nonce, config["rate_limit"], config["concurrency"], config["ttl_ms"], config["window_ms"]],
        )
        first = client.zcard(lease_key) if admitted == 1 else None
        client.rpush(config["attempted_key"], nonce)
        # [code] Hold until the parent has measured the lease set with everyone attempted.
        _wait(client, config["release_key"])
        removed = release(keys=[lease_key], args=[nonce]) if admitted == 1 else None
        return {"status": "ok", "admitted": int(admitted), "first": first, "removed": removed}
    except Exception as exc:
        return {"status": "error", "type": type(exc).__name__}
    finally:
        client.close()


def main(argv):
    config = json.loads(argv[1])
    result = run(config, os.environ["LOCAL_INCIDENT_TEST_REDIS_URL"])
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main(sys.argv)
