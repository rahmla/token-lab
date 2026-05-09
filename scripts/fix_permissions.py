#!/usr/bin/env python3
"""
Sätter upp token-exchange permission på vs2-resource så att vs1-client
får lov att göra Token Exchange mot den.

Keycloak kräver:
  1. En "token-exchange" scope på vs2-resource authorization server
  2. En client-policy som pekar på vs1-client
  3. En scope-permission som kopplar ihop policyn med scopet
"""
import json
import urllib.request
import urllib.parse
import urllib.error

KEYCLOAK_URL = "http://localhost:8080"
REALM = "token-lab"

def http(method, url, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else {}

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

def get_client_id(token, client_name):
    status, data = http("GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={client_name}", token=token)
    return data[0]["id"] if status == 200 and data else None

def main():
    print("Hämtar admin-token ...")
    token = get_token()

    vs1_uid = get_client_id(token, "vs1-client")
    vs2_uid = get_client_id(token, "vs2-resource")
    print(f"vs1-client id: {vs1_uid}")
    print(f"vs2-resource id: {vs2_uid}")

    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{vs2_uid}/authz/resource-server"

    # 1. Skapa token-exchange scope
    print("\n[1] Skapar token-exchange scope ...")
    status, all_scopes = http("GET", f"{base}/scope?max=100", token=token)
    existing_scope = next((s for s in (all_scopes or []) if s.get("name") == "token-exchange"), None)
    if existing_scope:
        scope_id = existing_scope["id"]
        print(f"    Finns redan: {scope_id}")
    else:
        status, scope = http("POST", f"{base}/scope", body={"name": "token-exchange"}, token=token)
        assert status in (200, 201), f"Misslyckades skapa scope: {status} {scope}"
        scope_id = scope["id"]
        print(f"    Skapad: {scope_id}")

    # 2. Skapa/uppdatera token-exchange resource med scopet
    print("\n[2] Skapar token-exchange resource ...")
    status, all_resources = http("GET", f"{base}/resource?max=100", token=token)
    existing_resource = next((r for r in (all_resources or []) if r.get("name") == "token-exchange"), None)
    if existing_resource:
        resource_id = existing_resource.get("_id") or existing_resource.get("id")
        print(f"    Finns redan: {resource_id}")
    else:
        status, resource = http("POST", f"{base}/resource", body={
            "name": "token-exchange",
            "type": "urn:token-exchange:resources:default",
            "scopes": [{"id": scope_id, "name": "token-exchange"}],
        }, token=token)
        assert status in (200, 201), f"Misslyckades skapa resource: {status} {resource}"
        resource_id = resource.get("_id") or resource.get("id")
        print(f"    Skapad: {resource_id}")

    # 3. Skapa client-policy för vs1-client
    print("\n[3] Skapar client-policy för vs1-client ...")
    policy_name = "allow-vs1-exchange"
    status, all_policies = http("GET", f"{base}/policy?max=100", token=token)
    existing_policy = next((p for p in (all_policies or []) if p.get("name") == policy_name), None)
    if existing_policy:
        policy_id = existing_policy["id"]
        print(f"    Finns redan: {policy_id}")
    else:
        status, policy = http("POST", f"{base}/policy/client", body={
            "name": policy_name,
            "logic": "POSITIVE",
            "clients": [vs1_uid],
        }, token=token)
        assert status in (200, 201), f"Misslyckades skapa policy: {status} {policy}"
        policy_id = policy["id"]
        print(f"    Skapad: {policy_id}")

    # 4. Skapa scope-permission
    print("\n[4] Skapar token-exchange permission ...")
    perm_name = "token-exchange-permission"
    status, all_perms = http("GET", f"{base}/permission?max=100", token=token)
    existing_perm = next((p for p in (all_perms or []) if p.get("name") == perm_name), None)
    if existing_perm:
        print(f"    Finns redan, uppdaterar ...")
        perm_id = existing_perm["id"]
        status, _ = http("PUT", f"{base}/permission/scope/{perm_id}", body={
            "id": perm_id,
            "name": perm_name,
            "type": "scope",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "scopes": [scope_id],
            "resources": [resource_id],
            "policies": [policy_id],
        }, token=token)
        print(f"    Uppdaterad: {status}")
    else:
        status, perm = http("POST", f"{base}/permission/scope", body={
            "name": perm_name,
            "type": "scope",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "scopes": [scope_id],
            "resources": [resource_id],
            "policies": [policy_id],
        }, token=token)
        assert status in (200, 201), f"Misslyckades skapa permission: {status} {perm}"
        print(f"    Skapad: {perm['id']}")

    print("\nKlart! Kör nu: python scripts/exchange_token.py")

if __name__ == "__main__":
    main()
