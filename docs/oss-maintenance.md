# OSS maintenance branch

This checkout is the maintained OnCall engine used by the source-restored
`grafana-irm-app` OSS runtime.

## Baseline and upstream history

- Maintenance branch: `oss-maintenance`
- Baseline: the final formal OSS release tag, `v1.16.11`
- Read-only archive reference: `archived-dev` at the official archived `dev`
  head
- License: AGPL-3.0; redistributed source and images must preserve the license
  and corresponding-source obligations

The archived `dev` head is not a descendant of `v1.16.11`. It contains the
repository-archive notice and a small number of dependency/CI commits, while
the release branch contains additional release and packaging history. Do not
rebase the maintenance branch onto `dev` or assume that `dev` is a newer
release. Review and cherry-pick individual upstream changes only when they are
applicable and tested.

## IRM 0.114 compatibility contract

The official Grafana IRM 0.114 frontend and OnCall 1.16.11 have version-skewed
internal APIs. The Grafana app backend marks those requests with:

```text
X-Grafana-IRM-API-Contract: 0.114.0
```

OnCall must keep its legacy responses unchanged when the header is absent.
Contract-specific behavior currently includes:

- page-number responses for escalation-chain list calls, while preserving the
  unpaginated legacy list and `filters=true` response;
- `is_user_allowed_to_update` on schedule resources, derived from existing
  OnCall RBAC/legacy-role authorization rather than browser input;
- IRM alert list/detail contracts with organization, team, and RBAC isolation;
- alert-group label mutations and label dropdown/name lookup contracts;
- escalation-next preview and execution, which skips pending wait policies,
  rotates OnCall's active Celery task ID, and then resumes the existing
  escalation task state machine without delivering notifications in HTTP;
- administrator-only manual verification of a pending phone number, with a
  native resource insight-log record;
- current-user mobile-device listing and disconnect, backed by the existing
  FCM device table while deliberately omitting registration tokens;
- parent-scoped outgoing-webhook response detail.

The maintained exporter also restores the application-metric contract promised
by the archived OnCall documentation but absent from the final OSS source:

- `oncall_alert_groups_resolution_time_seconds_{bucket,sum,count}` uses
  `resolved_at - started_at` for alert groups resolved in the rolling seven-day
  window;
- it keeps the same integration, team, stack, and `service_name` labels as the
  response-time histogram;
- resolve updates the cache immediately, while reopen/restart removes the old
  sample by alert-group ID; the daily calculation rebuilds the cache from the
  database as the durability backstop.

The self-hosted installation path now refreshes all configured organization
identity fields, rather than updating only the Grafana token and URL. The
idempotent `sync_self_hosted_identity` command applies the same reconciliation
to an existing volume and immediately recalculates exporter caches when the
identity changes. This keeps Prometheus tenant labels aligned with the official
IRM local Insights scene without dropping its stack selector.

The sibling IRM repository audits every recovered static REST route plus
explicit expansions for its dynamic template/path callsites. The current
0.114.0 audit classifies 204 unique routes: 190 in this engine, 8 in the
Grafana Go bridge, and 6 intentionally Cloud-only. The six Cloud-only routes
are Grafana-hosted LCR number provisioning and the hosted Microsoft Teams
connector; there are no unclassified routes.

Compatibility belongs in the engine when it represents real OnCall state or
authorization. The Grafana Go bridge retains fallbacks so the same IRM plugin
can still run against the untouched official `grafana/oncall:v1.16.11` image.
It must not invent schedules, escalation state, alert groups, or delivery
results.

## Build and test

Build the maintained engine from the repository root:

```sh
docker build --target prod \
  -t mikehsu0618/grafana-oncall:1.16.11-oss.2 engine
```

Run the focused contract and regression suite with a development image that
contains the test dependencies:

```sh
docker run --rm \
  -e DATABASE_TYPE=sqlite3 \
  -e DATABASE_NAME=/tmp/oncall-test.db \
  -v "$PWD/engine:/etc/app" \
  -v "$PWD/grafana-plugin:/etc/grafana-plugin:ro" \
  -w /etc/app \
  mikehsu0618/grafana-oncall:1.16.11-oss.1-dev \
  pytest --ds=settings.ci_test apps/api/tests -q
```

The focused exporter regression suite is:

```sh
docker run --rm \
  -e DJANGO_SETTINGS_MODULE=settings.ci_test \
  -e DATABASE_TYPE=sqlite3 \
  -e DATABASE_NAME=/tmp/oncall-test.db \
  -v "$PWD/engine:/etc/app" \
  -v "$PWD/grafana-plugin:/etc/grafana-plugin:ro" \
  grafana-oncall-tests:oss-maintenance \
  pytest -q \
    apps/grafana_plugin/tests/test_self_hosted_install.py \
    apps/grafana_plugin/tests/test_sync_self_hosted_identity_command.py \
    apps/metrics_exporter/tests
```

The sibling `grafana-irm-app` repository provides the integrated clean-Grafana
runtime:

```sh
cd ../grafana-irm-app
npm run runtime:up
```

It builds this checkout, reuses the persistent OnCall/Redis volumes, and loads
the separately packaged IRM plugin ZIP into an unmodified Grafana image.

## Optional mobile WebSession configuration

[code] Production `settings.helm` inherits these environment mappings from
`settings.base`. The feature is disabled by default; set `WEB_SESSION_ENABLED=True`
(or `1`) explicitly to enable it. `WEB_SESSION_BINDING` is one JSON object, not an
inline signing key. Example values below are illustrative, not a live deployment:

```sh
WEB_SESSION_ENABLED=True
WEB_SESSION_BINDING='{"oncall_org_id":42,"grafana_org_id":1,"internal_origin":"http://grafana:3000","public_origin":"https://grafana.example.test","namespace":"default","issuer":"https://oncall.example.test","key_id":"oncall-web-session","ttl_seconds":60,"private_key_file":"/run/secrets/oncall-web-session.pem"}'
```

[code] Supply every binding field shown above. IDs must be positive JSON integers,
not strings or booleans. `internal_origin` is the operator-pinned probe origin;
`public_origin` must be an HTTPS DNS origin with no credentials, path, query or
fragment. Namespace, issuer, key ID, TTL and key-file validation run before minting
or publishing JWKS. TTL defaults to 60 seconds when omitted and must be an integer
from 15 through 120 seconds. Malformed JSON is logged by field name and disables
binding use without preventing production startup; invalid bindings fail closed.

[code] Deliver the ES256 P-256 PEM private key out of band as a **read-only mounted,
protected regular file** at the absolute `private_key_file` path. The OnCall process
must be able to read it; use owner-only permissions such as `0400` (no group/other
access), a protected parent directory, and no symlink at the file path. Do not put
private key bytes in environment JSON, Helm values, source, logs or this repository.
Provision and rotate the file through your deployment's secret-file mechanism;
this example contains no real key. Protect file replacement/rotation from writers.

[code] StatusV2 substitutes only the enabled matching organization's validated
public URL; signer failures do not mask existing connection health. Unusable
optional URL/mapping values leave the original status intact and log safe field
and organization context. Mint/JWKS still reject unavailable signing material.
[UNVERIFIED] This private candidate's mocked/SQLite tests are not real native
Grafana, mobile-app, distributed-cache or deployment acceptance.

[code] `MOBILE_APP_STATUS_LICENSE` (optional, default unset) changes only the
`license` string StatusV2 reports to callers authenticated with a
`MobileAppAuthToken`. Unset or blank reports the engine `ONCALL_LICENSE` value;
plugin-token callers always receive the engine license, and `LICENSE` /
`IS_OPEN_SOURCE` are unchanged. It is intended for the official Grafana mobile
app, which force-logs-out OpenSource-licensed engines, e.g.
`MOBILE_APP_STATUS_LICENSE=SelfHosted`.

[code] The WebSession access token delegates exactly these actions (the
validation pair delegates only `orgs:read`); service `permissions` stay empty and
delegation caps, never widens, the user's own Grafana permissions:
`orgs:read`, `dashboards:read`, `folders:read`, `datasources:read`,
`datasources:query`, `plugins.app:access`, `annotations:read`,
`dashboard.grafana.app/dashboards:get`, `folder.grafana.app/folders:get`,
`preferences.grafana.app/preferences:get`, `alert.rules:read`. All verbs are
read/get/query/access, but `plugins.app:access` also reaches authorized apps' own
mutable APIs, so the list is not a read-only confinement boundary.

## Maintenance policy

1. Add a failing engine-level contract test before changing a response.
2. Prove the headerless legacy response remains compatible.
3. Rebuild the local engine image and exercise the official recovered IRM UI.
4. Verify schedule, rotation, escalation-chain, integration, and alert-group
   persistence after restarting the engine and Redis.
5. Keep Grafana Cloud entitlements, hosted mobile push, hosted SMS/voice, and
   billing out of the OSS compatibility contract. Use self-hosted notification
   providers where OnCall already supports them.

The engine is a maintained backend building block. It does not replace the
source-restored IRM frontend and no hand-written IRM screens belong here.
