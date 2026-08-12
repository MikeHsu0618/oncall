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

The sibling `grafana-irm-app` repository provides the integrated clean-Grafana
runtime:

```sh
cd ../grafana-irm-app
npm run runtime:up:oncall-source
```

It builds this checkout, reuses the persistent OnCall/Redis volumes, and loads
the separately packaged IRM plugin ZIP into an unmodified Grafana image.

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
