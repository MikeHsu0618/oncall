"""Native ES256 tokens; service permissions are always empty.

plugins.app:access also permits authorized apps' own mutable APIs. This is neither
an Assistant-only credential nor a read-only confinement boundary.
"""
import json
import time

import jwt

# Grafana 13 page render and dashboard view also read through the K8s APIs, which check
# their own delegated actions; only read verbs are granted. Delegation caps, never widens,
# the user's own permissions.
ACTIONS = ("orgs:read", "dashboards:read", "folders:read", "datasources:read",
           "datasources:query", "plugins.app:access", "annotations:read",
           "dashboard.grafana.app/dashboards:get", "folder.grafana.app/folders:get",
           "preferences.grafana.app/preferences:get", "alert.rules:read")
# Immutable fixed profile; the signer copies it into each token's claim payload.
LOCAL_INCIDENT_ACTIONS = ("orgs:read", "plugins.app:access")


def _mint_pair_with_permissions(binding, external_id, delegated_permissions):
    now = int(time.time())
    common = {"iss": binding.issuer, "aud": ["grafana"], "iat": now, "nbf": now,
              "exp": now + binding.ttl_seconds, "namespace": binding.namespace}
    identity = {**common, "sub": f"user:{external_id}", "type": "user", "identifier": str(external_id)}
    access = {**common, "sub": "access-policy:oncall-web-session", "permissions": [],
              "delegatedPermissions": list(delegated_permissions)}
    return {
        "access_token": jwt.encode(access, binding.key, algorithm="ES256",
                                   headers={"kid": binding.key_id, "typ": "at+jwt"}),
        "id_token": jwt.encode(identity, binding.key, algorithm="ES256",
                               headers={"kid": binding.key_id, "typ": "jwt"}),
    }


def mint_pair(binding, external_id, validation=False):
    delegated_permissions = ("orgs:read",) if validation else ACTIONS
    return _mint_pair_with_permissions(binding, external_id, delegated_permissions)


def mint_local_incident_pair(binding, external_id):
    """Mint for a prevalidated actor; this token is not an authorization proof.

    It does not bind requests to an RPC or establish confinement. Actor validation
    and exact-operation dispatch remain server-layer responsibilities.
    """
    if type(external_id) is not int or external_id <= 0:
        raise ValueError("external_id must be a positive integer")
    return _mint_pair_with_permissions(binding, external_id, LOCAL_INCIDENT_ACTIONS)


def public_jwk(binding):
    # Serialize the public key, never the private key (which would include d).
    key = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(binding.key.public_key()))
    return {**key, "kid": binding.key_id, "use": "sig", "alg": "ES256"}
