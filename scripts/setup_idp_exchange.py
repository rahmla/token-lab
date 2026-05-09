#!/usr/bin/env python3
"""
Sätter upp IDP fine-grained permissions för external token exchange.

För extern token exchange kontrollerar Keycloak INTE vs2-resources authz-server
utan IDPns egna permissions i realm-managements authz-server.

Flöde:
  1. PUT identity-provider/instances/vs2-idp/management/permissions  → enabled:true
     → Skapar IDP-resurs + token-exchange scope i realm-management authz
  2. Skapa client-policy för vs1-client i realm-management authz
  3. Uppdatera token-exchange permission med policyn
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


def main():
    print("Hämtar admin-token ...")
    token = get_token()

    vs1_uid = get_client_uuid(token, "vs1-client")
    rm_uid = get_client_uuid(token, "realm-management")
    print(f"vs1-client UUID:       {vs1_uid}")
    print(f"realm-management UUID: {rm_uid}")

    if not vs1_uid or not rm_uid:
        print("FEL: Kunde inte hitta klient-UUIDs. Kör setup_keycloak.py först.")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # 1. Aktivera IDP fine-grained permissions
    # -----------------------------------------------------------------------
    print("\n[1] Aktiverar IDP fine-grained permissions på vs2-idp ...")
    status, perm_info = http(
        "PUT",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/vs2-idp/management/permissions",
        body={"enabled": True},
        token=token,
    )
    if status not in (200, 201, 204):
        print(f"    FEL: HTTP {status}: {perm_info}")
        sys.exit(1)
    print(f"    OK. Svar: {json.dumps(perm_info, indent=4)}")

    te_perm_id = (perm_info.get("scopePermissions") or {}).get("token-exchange")
    print(f"\n    token-exchange permission ID: {te_perm_id}")

    base_rm = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{rm_uid}/authz/resource-server"

    # Om vi inte fick permission-ID från svaret, leta i realm-management
    if not te_perm_id:
        print("    Letar efter permission manuellt ...")
        status, all_perms = http("GET", f"{base_rm}/permission?max=100", token=token)
        print(f"    Alla permissions: {json.dumps(all_perms, indent=2)}")
        te_perm = next(
            (p for p in (all_perms or []) if "token-exchange" in p.get("name", "").lower()
             or "vs2-idp" in p.get("name", "").lower()),
            None
        )
        if te_perm:
            te_perm_id = te_perm["id"]
            print(f"    Hittad: {te_perm_id} ({te_perm['name']})")
        else:
            print("    FEL: Ingen token-exchange permission hittad i realm-management.")
            sys.exit(1)

    # -----------------------------------------------------------------------
    # 2. Skapa client-policy för vs1-client i realm-management
    # -----------------------------------------------------------------------
    print("\n[2] Skapar client-policy för vs1-client i realm-management ...")
    policy_name = "allow-vs1-idp-exchange"
    status, all_policies = http("GET", f"{base_rm}/policy?max=100", token=token)
    existing_policy = next(
        (p for p in (all_policies or []) if p.get("name") == policy_name), None
    )
    if existing_policy:
        policy_id = existing_policy["id"]
        print(f"    Finns redan: {policy_id}")
    else:
        status, policy = http("POST", f"{base_rm}/policy/client", body={
            "name": policy_name,
            "logic": "POSITIVE",
            "clients": [vs1_uid],
        }, token=token)
        if status not in (200, 201):
            print(f"    FEL: HTTP {status}: {policy}")
            sys.exit(1)
        policy_id = policy["id"]
        print(f"    Skapad: {policy_id}")

    # -----------------------------------------------------------------------
    # 3. Uppdatera token-exchange permission med policyn
    # -----------------------------------------------------------------------
    print(f"\n[3] Hämtar befintlig permission {te_perm_id} ...")
    status, perm_detail = http("GET", f"{base_rm}/permission/scope/{te_perm_id}", token=token)
    if status != 200:
        print(f"    FEL: HTTP {status}: {perm_detail}")
        sys.exit(1)
    print(f"    Permission: {json.dumps(perm_detail, indent=4)}")

    # Hämta existerande scope-IDs
    existing_scope_ids = []
    for s in perm_detail.get("scopes", []):
        if isinstance(s, dict):
            existing_scope_ids.append(s.get("id", s.get("name", "")))
        else:
            existing_scope_ids.append(s)

    # Hämta existerande resource-IDs
    existing_resource_ids = []
    for r in perm_detail.get("resources", []):
        if isinstance(r, dict):
            existing_resource_ids.append(r.get("_id") or r.get("id", ""))
        else:
            existing_resource_ids.append(r)

    # Om inga scope-IDs hittades, hämta via scope-namn
    if not existing_scope_ids:
        print("    Hämtar scope-ID för 'token-exchange' ...")
        status, all_scopes = http("GET", f"{base_rm}/scope?max=100", token=token)
        te_scope = next(
            (s for s in (all_scopes or []) if s.get("name") == "token-exchange"), None
        )
        if te_scope:
            existing_scope_ids = [te_scope["id"]]
            print(f"    Scope ID: {te_scope['id']}")

    update_body = {
        "id": te_perm_id,
        "name": perm_detail.get("name", ""),
        "type": "scope",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "scopes": existing_scope_ids,
        "policies": [policy_id],
    }
    if existing_resource_ids:
        update_body["resources"] = existing_resource_ids

    print(f"\n    Uppdaterar permission med body:\n{json.dumps(update_body, indent=4)}")
    status, result = http("PUT", f"{base_rm}/permission/scope/{te_perm_id}", body=update_body, token=token)
    if status not in (200, 201, 204):
        print(f"    FEL: HTTP {status}: {result}")
        sys.exit(1)
    print(f"    OK: HTTP {status}")

    print("\n=== Klart! Kör nu: python scripts/exchange_token.py ===")


if __name__ == "__main__":
    main()
