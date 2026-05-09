#!/usr/bin/env python3
"""
Sätter upp alla Token Exchange-behörigheter i realm-management authz-server.

Keycloak 25 med admin-fine-grained-authz kontrollerar BÅDA behörigheterna via
realm-management — inte via klienternas egna authz-servrar:

  canExchangeTo()   — får vs1-client använda vs2-idp som källa?
  canExchangeWith() — får vs1-client begära tokens med audience=vs2-resource?

Steg:
  1. Aktivera IDP fine-grained permissions på vs2-idp
     → skapar token-exchange.permission.idp.<UUID> i realm-management
  2. Aktivera client management permissions på vs2-resource
     → skapar token-exchange.permission.client.<UUID> i realm-management
  3. Skapa client-policy för vs1-client i realm-management
  4. Koppla policyn till båda permissions
"""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

KEYCLOAK_URL = "http://localhost:8080"
REALM = "token-lab"


def http(method, url, body=None, token=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode("utf-8", errors="replace")


def get_token():
    data = urllib.parse.urlencode({
        "client_id": "admin-cli",
        "username": "admin",
        "password": "admin",
        "grant_type": "password",
    }).encode()
    with urllib.request.urlopen(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token", data
    ) as r:
        return json.loads(r.read())["access_token"]


def get_client_uuid(token, client_id_str):
    status, data = http(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={urllib.parse.quote(client_id_str)}",
        token=token,
    )
    return data[0]["id"] if status == 200 and data else None


def ensure_client_policy(token, rm_uid, vs1_uid):
    """Hämtar eller skapar client-policy för vs1-client i realm-management."""
    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_uid}/authz/resource-server"
    policy_name = "allow-vs1-exchange"
    status, all_policies = http("GET", f"{base}/policy?max=100", token=token)
    existing = next((p for p in (all_policies or []) if p.get("name") == policy_name), None)
    if existing:
        print(f"    Policy '{policy_name}' finns redan: {existing['id']}")
        return existing["id"]
    status, policy = http("POST", f"{base}/policy/client", body={
        "name": policy_name,
        "logic": "POSITIVE",
        "clients": [vs1_uid],
    }, token=token)
    assert status in (200, 201), f"Misslyckades skapa policy: {status} {policy}"
    print(f"    Policy skapad: {policy['id']}")
    return policy["id"]


def link_policy_to_permission(token, rm_uid, perm_id, policy_id):
    """Uppdaterar en scope-permission i realm-management med given policy."""
    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_uid}/authz/resource-server"

    # Hämta befintliga scope- och resource-IDs
    scope_ids = []
    status, scopes = http("GET", f"{base}/permission/{perm_id}/scopes", token=token)
    if status == 200:
        scope_ids = [s["id"] for s in scopes]

    resource_ids = []
    status, resources = http("GET", f"{base}/permission/{perm_id}/resources", token=token)
    if status == 200:
        resource_ids = [r.get("_id") or r.get("id", "") for r in resources]

    # Om scope saknas, hämta "token-exchange" scope från realm-management
    if not scope_ids:
        status, all_scopes = http("GET", f"{base}/scope?max=100", token=token)
        te_scope = next((s for s in (all_scopes or []) if s.get("name") == "token-exchange"), None)
        if te_scope:
            scope_ids = [te_scope["id"]]

    status, perm_detail = http("GET", f"{base}/permission/scope/{perm_id}", token=token)
    perm_name = perm_detail.get("name", "") if status == 200 else ""

    update_body = {
        "id": perm_id,
        "name": perm_name,
        "type": "scope",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "scopes": scope_ids,
        "policies": [policy_id],
    }
    if resource_ids:
        update_body["resources"] = resource_ids

    status, _ = http("PUT", f"{base}/permission/scope/{perm_id}", body=update_body, token=token)
    if status not in (200, 201, 204):
        print(f"    VARNING: PUT permission returnerade {status}")
    else:
        print(f"    Permission {perm_id[:8]}… kopplad till policy ✓")


def main():
    print("Hämtar admin-token ...")
    token = get_token()

    vs1_uid = get_client_uuid(token, "vs1-client")
    vs2_uid = get_client_uuid(token, "vs2-resource")
    rm_uid  = get_client_uuid(token, "realm-management")
    print(f"vs1-client UUID:       {vs1_uid}")
    print(f"vs2-resource UUID:     {vs2_uid}")
    print(f"realm-management UUID: {rm_uid}")

    if not all([vs1_uid, vs2_uid, rm_uid]):
        print("FEL: Kunde inte hitta alla klienter. Kör setup_keycloak.py först.")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # 1. Aktivera IDP fine-grained permissions (canExchangeTo)
    # -----------------------------------------------------------------------
    print("\n[1] Aktiverar IDP fine-grained permissions på vs2-idp ...")
    status, idp_perms = http(
        "PUT",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/vs2-idp/management/permissions",
        body={"enabled": True},
        token=token,
    )
    assert status in (200, 201, 204), f"Misslyckades aktivera IDP permissions: {status} {idp_perms}"
    idp_te_perm_id = (idp_perms.get("scopePermissions") or {}).get("token-exchange")
    print(f"    IDP token-exchange permission ID: {idp_te_perm_id}")

    # -----------------------------------------------------------------------
    # 2. Aktivera client management permissions (canExchangeWith)
    # -----------------------------------------------------------------------
    print("\n[2] Aktiverar client management permissions på vs2-resource ...")
    status, client_perms = http(
        "PUT",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{vs2_uid}/management/permissions",
        body={"enabled": True},
        token=token,
    )
    assert status in (200, 201, 204), f"Misslyckades aktivera client permissions: {status} {client_perms}"
    client_te_perm_id = (client_perms.get("scopePermissions") or {}).get("token-exchange")
    print(f"    Client token-exchange permission ID: {client_te_perm_id}")

    # -----------------------------------------------------------------------
    # 3. Skapa (eller hämta) client-policy för vs1-client i realm-management
    # -----------------------------------------------------------------------
    print("\n[3] Hämtar/skapar client-policy för vs1-client i realm-management ...")
    policy_id = ensure_client_policy(token, rm_uid, vs1_uid)

    # -----------------------------------------------------------------------
    # 4. Koppla policyn till båda permissions
    # -----------------------------------------------------------------------
    print("\n[4] Kopplar policy till IDP token-exchange permission ...")
    if idp_te_perm_id:
        link_policy_to_permission(token, rm_uid, idp_te_perm_id, policy_id)
    else:
        print("    VARNING: Kunde inte hitta IDP permission ID.")

    print("\n[5] Kopplar policy till client token-exchange permission ...")
    if client_te_perm_id:
        link_policy_to_permission(token, rm_uid, client_te_perm_id, policy_id)
    else:
        print("    VARNING: Kunde inte hitta client permission ID.")

    print("\n=== Behörigheter konfigurerade! ===")


if __name__ == "__main__":
    main()
