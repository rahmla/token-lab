#!/usr/bin/env python3
"""
Steg 2: Automatisk Keycloak-konfiguration via Admin REST API.

Skapar:
  - Realm: token-lab
  - Identity Provider (JWT / External IdP): vs2-idp
      Issuer:   http://localhost:9000
      JWKS URL: http://jwks-server:9000/jwks   (inom Docker-nätverket)
  - Klient: vs1-client  (konfidentiell, token-exchange aktiverat)
  - Klient: vs2-resource (publik resurs som vs1 begär access till)
  - Token Exchange-policy: vs1-client får exchangea tokens mot vs2-resource

Väntar automatiskt tills Keycloak är redo innan den börjar.

Kör: python scripts/setup_keycloak.py
"""

import sys
import time
import json
import urllib.request
import urllib.parse
import urllib.error

KEYCLOAK_URL = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
REALM = "token-lab"

# JWKS URL som Keycloak använder inifrån Docker-nätverket
JWKS_URL_INTERNAL = "http://jwks-server:9000/jwks"
# Issuer i JWT:erna från VS2 (matchar issue_token.py)
VS2_ISSUER = "http://localhost:9000"


# ---------------------------------------------------------------------------
# Hjälpfunktioner
# ---------------------------------------------------------------------------

def http(method: str, url: str, body=None, token: str = None) -> tuple[int, dict | list | str]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode("utf-8", errors="replace")


def get_admin_token() -> str:
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
    }).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["access_token"]


def wait_for_keycloak(max_wait: int = 120):
    print("Väntar på Keycloak ...", end="", flush=True)
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{KEYCLOAK_URL}/realms/master", timeout=3) as r:
                if r.status == 200:
                    print(" redo!")
                    return
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(3)
    print("\nKeycloak svarade inte inom timeout.")
    sys.exit(1)


def realm_exists(token: str) -> bool:
    status, _ = http("GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}", token=token)
    return status == 200


def get_client_id(token: str, client_id_str: str) -> str | None:
    """Returnerar intern UUID för en klient givet dess clientId."""
    status, clients = http(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={urllib.parse.quote(client_id_str)}",
        token=token,
    )
    if status == 200 and clients:
        return clients[0]["id"]
    return None


def get_idp_alias(token: str, alias: str) -> bool:
    status, _ = http("GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/{alias}", token=token)
    return status == 200


# ---------------------------------------------------------------------------
# Konfigurationssteg
# ---------------------------------------------------------------------------

def create_realm(token: str):
    if realm_exists(token):
        print(f"  Realm '{REALM}' finns redan, hoppar över.")
        return
    status, _ = http("POST", f"{KEYCLOAK_URL}/admin/realms", body={
        "realm": REALM,
        "enabled": True,
        "displayName": "Token Lab",
    }, token=token)
    _check(status, f"Skapa realm '{REALM}'")


def create_idp(token: str):
    """Skapar en Identity Provider av typen 'jwt' (oidc utan discovery)."""
    alias = "vs2-idp"
    if get_idp_alias(token, alias):
        print(f"  Identity Provider '{alias}' finns redan, hoppar över.")
        return

    body = {
        "alias": alias,
        "providerId": "oidc",
        "enabled": True,
        "trustEmail": True,
        "config": {
            "issuer": VS2_ISSUER,
            "jwksUrl": JWKS_URL_INTERNAL,
            "validateSignature": "true",
            "useJwksUrl": "true",
            "clientAuthMethod": "client_secret_post",
            "syncMode": "FORCE",
            # KC 26 token-exchange:v2 validerar JWT-signaturen direkt mot JWKS.
            # UserInfo behövs inte — VS2 är en token translator, inte en IdP med user store.
            "disableUserInfoService": "true",
        },
    }
    status, resp = http(
        "POST",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances",
        body=body, token=token,
    )
    _check(status, f"Skapa Identity Provider '{alias}'")


def create_client(token: str, client_id: str, secret: str | None, public_client: bool = False) -> str:
    existing = get_client_id(token, client_id)
    if existing:
        print(f"  Klient '{client_id}' finns redan (id={existing}), hoppar över.")
        return existing

    body = {
        "clientId": client_id,
        "enabled": True,
        "publicClient": public_client,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": not public_client,
        "authorizationServicesEnabled": not public_client,
        "standardFlowEnabled": False,
        "attributes": {
            "token.exchange.grant.enabled": "true",
        },
    }
    if secret and not public_client:
        body["secret"] = secret
        body["clientAuthenticatorType"] = "client-secret"

    status, resp = http(
        "POST", f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients",
        body=body, token=token,
    )
    _check(status, f"Skapa klient '{client_id}'")

    # Hämta nytt UUID
    uid = get_client_id(token, client_id)
    return uid


def enable_token_exchange_permission(token: str, target_client_uid: str, requester_client_uid: str):
    """
    Aktiverar token-exchange permission på target_client och lägger till
    en policy som tillåter requester_client att exchangea.
    """
    base = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{target_client_uid}"

    # 1. Aktivera fine-grained authorization på target
    status, _ = http("GET", f"{base}", token=token)

    # 2. Hämta authz resource server
    status, authz = http("GET", f"{base}/authz/resource-server", token=token)
    if status != 200:
        print(f"  Authz resource server saknas på target-klienten (status={status}). Kontrollera att klienten har authorizationServicesEnabled=true.")
        return

    # 3. Hämta token-exchange scope
    status, scopes = http("GET", f"{base}/authz/resource-server/scope?name=token-exchange", token=token)
    if status != 200 or not scopes:
        print("  Kunde inte hitta token-exchange scope.")
        return
    scope_id = scopes[0]["id"]

    # 4. Hämta token-exchange resource
    status, resources = http("GET", f"{base}/authz/resource-server/resource?name=token-exchange", token=token)
    resource_id = resources[0]["id"] if status == 200 and resources else None

    # 5. Skapa client policy för requester
    policy_name = f"allow-{requester_client_uid[:8]}-exchange"
    status, existing_policies = http(
        "GET", f"{base}/authz/resource-server/policy?name={urllib.parse.quote(policy_name)}", token=token
    )
    if status == 200 and existing_policies:
        print(f"  Policy '{policy_name}' finns redan.")
        policy_id = existing_policies[0]["id"]
    else:
        policy_body = {
            "type": "client",
            "name": policy_name,
            "logic": "POSITIVE",
            "clients": [requester_client_uid],
        }
        status, policy_resp = http(
            "POST", f"{base}/authz/resource-server/policy/client",
            body=policy_body, token=token,
        )
        _check(status, f"Skapa client policy '{policy_name}'")
        policy_id = policy_resp["id"]

    # 6. Skapa permission
    perm_name = "token-exchange-permission"
    status, existing_perms = http(
        "GET", f"{base}/authz/resource-server/permission?name={urllib.parse.quote(perm_name)}", token=token
    )
    if status == 200 and existing_perms:
        print(f"  Permission '{perm_name}' finns redan.")
        return

    perm_body = {
        "type": "scope",
        "name": perm_name,
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "scopes": [scope_id],
        "policies": [policy_id],
    }
    if resource_id:
        perm_body["resources"] = [resource_id]

    status, _ = http(
        "POST", f"{base}/authz/resource-server/permission/scope",
        body=perm_body, token=token,
    )
    _check(status, f"Skapa token-exchange permission")


def _check(status: int, action: str):
    ok = status in (200, 201, 204)
    symbol = "OK" if ok else "FEL"
    print(f"  [{symbol}] {action} (HTTP {status})")
    if not ok:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    wait_for_keycloak()

    print("\nHämtar admin-token ...")
    token = get_admin_token()

    print(f"\nKonfigurerar realm '{REALM}' ...")
    create_realm(token)

    # Uppdatera token efter att realm skapats
    token = get_admin_token()

    print("\nSkapar Identity Provider (VS2) ...")
    create_idp(token)

    print("\nSkapar klienter ...")
    vs1_uid = create_client(token, "vs1-client", secret="vs1-secret", public_client=False)
    vs2_uid = create_client(token, "vs2-resource", secret=None, public_client=False)

    print("\nKonfigurerar Token Exchange-behörighet ...")
    if vs1_uid and vs2_uid:
        enable_token_exchange_permission(token, vs2_uid, vs1_uid)
    else:
        print("  Kunde inte hämta klient-ID:n, hoppar över permission-steg.")

    print("\nKeycloak-konfiguration klar!")
    print(f"""
Sammanfattning:
  Realm:              {REALM}
  Identity Provider:  vs2-idp  (issuer={VS2_ISSUER}, jwks={JWKS_URL_INTERNAL})
  vs1-client:         konfidentiell, secret=vs1-secret
  vs2-resource:       resurs som vs1 får exchangea tokens mot

Nästa steg: kör  python scripts/exchange_token.py
""")


if __name__ == "__main__":
    main()
