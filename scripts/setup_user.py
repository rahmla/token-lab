#!/usr/bin/env python3
"""
Skapar KC-användare som motsvarar VS2:s löpnummer 123456.

Steg:
  0. Deklarerar phone_number och employee_id i realm User Profile-schemat
     (KC 25 ignorerar attribut som inte är deklarerade)
  1. Skapar realm-rollen 'Supervisor'
  2. Skapar användaren med namn, e-post och attribut (phone_number, employee_id)
  3. Tilldelar rollen Supervisor
  4. Skapar federated identity-länk → vs2-idp:123456
  5. Lägger till protocol mappers på vs1-client så att KC-tokenet innehåller:
       phone_number  — användarattribut
       employee_id   — användarattribut (=löpnumret från VS2)
       roles         — platt array med realm-roller
"""
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

KEYCLOAK_URL = "http://localhost:8080"
REALM = "token-lab"

# Användardata — motsvarar VS2-subjektet "123456"
EMPLOYEE_ID  = "123456"
FIRST_NAME   = "Alice"
LAST_NAME    = "Svensson"
EMAIL        = "alice.svensson@example.com"
PHONE        = "+46701234567"
ROLE_NAME    = "Supervisor"
IDP_ALIAS    = "vs2-idp"


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


# ---------------------------------------------------------------------------
# 0. User Profile — deklarera anpassade attribut
# ---------------------------------------------------------------------------

CUSTOM_ATTRIBUTES = ["phone_number", "employee_id"]

def ensure_user_profile_attributes(token):
    """
    KC 25 kräver att anpassade attribut är deklarerade i realm User Profile
    innan de kan sparas på en användare. Lägger till saknade attribut och
    aktiverar ADMIN_EDIT för övriga (okonfigurerade) attribut.
    """
    url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/profile"
    status, profile = http("GET", url, token=token)
    assert status == 200, f"Kunde inte hämta user profile: {status}"

    existing_names = {a["name"] for a in profile.get("attributes", [])}
    added = []
    for attr_name in CUSTOM_ATTRIBUTES:
        if attr_name not in existing_names:
            profile["attributes"].append({
                "name": attr_name,
                "displayName": attr_name.replace("_", " ").title(),
                "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
                "multivalued": False,
            })
            added.append(attr_name)

    profile["unmanagedAttributePolicy"] = "ADMIN_EDIT"

    status, _ = http("PUT", url, body=profile, token=token)
    assert status == 200, f"Kunde inte uppdatera user profile: {status}"
    if added:
        print(f"    Attribut deklarerade: {', '.join(added)} ✓")
    else:
        print(f"    Alla attribut redan deklarerade.")


# ---------------------------------------------------------------------------
# 1. Realm-roll
# ---------------------------------------------------------------------------

def ensure_role(token):
    status, existing = http(
        "GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles/{ROLE_NAME}", token=token
    )
    if status == 200:
        print(f"    Roll '{ROLE_NAME}' finns redan: {existing['id']}")
        return existing["id"]
    status, _ = http(
        "POST", f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles",
        body={"name": ROLE_NAME, "description": "Supervisor-roll tilldelad av VS2-systemet"},
        token=token,
    )
    assert status in (200, 201), f"Misslyckades skapa roll: {status}"
    status, role = http(
        "GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles/{ROLE_NAME}", token=token
    )
    print(f"    Roll skapad: {role['id']}")
    return role["id"]


# ---------------------------------------------------------------------------
# 2. Användare
# ---------------------------------------------------------------------------

def find_user(token):
    status, users = http(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={urllib.parse.quote(EMPLOYEE_ID)}&exact=true",
        token=token,
    )
    return users[0]["id"] if status == 200 and users else None


def ensure_user(token):
    user_id = find_user(token)
    if user_id:
        print(f"    Användare '{EMPLOYEE_ID}' finns redan: {user_id}")
    else:
        status, _ = http(
            "POST", f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
            body={
                "username":      EMPLOYEE_ID,
                "firstName":     FIRST_NAME,
                "lastName":      LAST_NAME,
                "email":         EMAIL,
                "enabled":       True,
                "emailVerified": True,
            },
            token=token,
        )
        assert status in (200, 201), f"Misslyckades skapa användare: {status}"
        user_id = find_user(token)
        print(f"    Användare skapad: {user_id}")

    # Spara attribut via PUT (kräver att user profile-schemat är konfigurerat)
    user_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}"
    _, user_repr = http("GET", user_url, token=token)
    user_repr["attributes"] = {"phone_number": [PHONE], "employee_id": [EMPLOYEE_ID]}
    status, _ = http("PUT", user_url, body=user_repr, token=token)
    assert status in (200, 201, 204), f"Misslyckades spara attribut: {status}"
    print(f"    Attribut phone_number={PHONE}, employee_id={EMPLOYEE_ID} sparade ✓")
    return user_id


# ---------------------------------------------------------------------------
# 3. Rolltilldelning
# ---------------------------------------------------------------------------

def assign_role(token, user_id, role_id):
    # Kontrollera om rollen redan är tilldelad
    status, assigned = http(
        "GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
        token=token,
    )
    if status == 200 and any(r.get("name") == ROLE_NAME for r in assigned):
        print(f"    Roll '{ROLE_NAME}' redan tilldelad.")
        return
    status, _ = http(
        "POST",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
        body=[{"id": role_id, "name": ROLE_NAME}],
        token=token,
    )
    assert status in (200, 201, 204), f"Misslyckades tilldela roll: {status}"
    print(f"    Roll '{ROLE_NAME}' tilldelad ✓")


# ---------------------------------------------------------------------------
# 4. Federated identity-länk
# ---------------------------------------------------------------------------

def ensure_federated_identity(token, user_id):
    status, links = http(
        "GET",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/federated-identity",
        token=token,
    )
    if status == 200 and any(f.get("identityProvider") == IDP_ALIAS for f in links):
        print(f"    Federated identity för '{IDP_ALIAS}' finns redan.")
        return
    status, resp = http(
        "POST",
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/federated-identity/{IDP_ALIAS}",
        body={
            "identityProvider": IDP_ALIAS,
            "userId":           EMPLOYEE_ID,
            "userName":         EMPLOYEE_ID,
        },
        token=token,
    )
    assert status in (200, 201, 204), f"Misslyckades länka federated identity: {status} {resp}"
    print(f"    Federated identity länkad: {IDP_ALIAS}:{EMPLOYEE_ID} → KC-user {user_id} ✓")


# ---------------------------------------------------------------------------
# 5. Protocol mappers på vs1-client
# ---------------------------------------------------------------------------

# KC 25 token-exchange:v1 evaluerar bara realm-default client scopes vid extern
# token exchange (profile, email, roles, ...). Anpassade mappers måste läggas
# i de inbyggda scopena för att inkluderas i det utfärdade tokenet.
#
# Mappers och vilket inbyggt scope de tillhör:
SCOPE_MAPPERS = {
    "profile": [
        {
            "name": "phone_number",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "consentRequired": False,
            "config": {
                "claim.name":        "phone_number",
                "user.attribute":    "phone_number",
                "id.token.claim":    "true",
                "access.token.claim":"true",
                "jsonType.label":    "String",
                "multivalued":       "false",
            },
        },
        {
            "name": "employee_id",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "consentRequired": False,
            "config": {
                "claim.name":        "employee_id",
                "user.attribute":    "employee_id",
                "id.token.claim":    "true",
                "access.token.claim":"true",
                "jsonType.label":    "String",
                "multivalued":       "false",
            },
        },
    ],
    "roles": [
        {
            "name": "roles-flat",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "consentRequired": False,
            "config": {
                "claim.name":        "roles",
                "multivalued":       "true",
                "id.token.claim":    "true",
                "access.token.claim":"true",
                "jsonType.label":    "String",
            },
        },
    ],
}


def find_scope_id(token, scope_name):
    status, scopes = http(
        "GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes", token=token
    )
    match = next((s for s in (scopes or []) if s.get("name") == scope_name), None)
    return match["id"] if match else None


def ensure_protocol_mappers(token, _client_uuid=None):
    """Lägger till anpassade mappers i de inbyggda realm-default client scopes."""
    for scope_name, mappers in SCOPE_MAPPERS.items():
        scope_id = find_scope_id(token, scope_name)
        if not scope_id:
            print(f"    VARNING: Scope '{scope_name}' hittades inte.")
            continue

        base = f"{KEYCLOAK_URL}/admin/realms/{REALM}/client-scopes/{scope_id}/protocol-mappers"
        status, existing = http("GET", f"{base}/models", token=token)
        existing_names = {m["name"] for m in (existing or [])}

        for mapper in mappers:
            if mapper["name"] in existing_names:
                print(f"    Mapper '{mapper['name']}' (scope: {scope_name}) finns redan.")
                continue
            status, resp = http("POST", f"{base}/models", body=mapper, token=token)
            assert status in (200, 201), \
                f"Misslyckades skapa mapper '{mapper['name']}': {status} {resp}"
            print(f"    Mapper '{mapper['name']}' → scope '{scope_name}' ✓")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Hämtar admin-token ...")
    token = get_token()

    vs1_uuid = get_client_uuid(token, "vs1-client")
    if not vs1_uuid:
        print("FEL: vs1-client saknas. Kör setup_keycloak.py först.")
        sys.exit(1)
    print(f"vs1-client UUID: {vs1_uuid}")

    print("\n[0] Deklarerar anpassade attribut i realm User Profile ...")
    ensure_user_profile_attributes(token)

    print(f"\n[1] Skapar realm-roll '{ROLE_NAME}' ...")
    role_id = ensure_role(token)

    print(f"\n[2] Skapar användare '{EMPLOYEE_ID}' ({FIRST_NAME} {LAST_NAME}) ...")
    user_id = ensure_user(token)

    print(f"\n[3] Tilldelar roll '{ROLE_NAME}' till användaren ...")
    assign_role(token, user_id, role_id)

    print(f"\n[4] Skapar federated identity-länk ({IDP_ALIAS}:{EMPLOYEE_ID}) ...")
    ensure_federated_identity(token, user_id)

    print(f"\n[5] Lägger till protocol mappers i realm client scopes ...")
    ensure_protocol_mappers(token)

    print(f"""
=== Användarkonfiguration klar! ===

  Användare:    {FIRST_NAME} {LAST_NAME} (KC username: {EMPLOYEE_ID})
  E-post:       {EMAIL}
  Telefon:      {PHONE}
  employee_id:  {EMPLOYEE_ID}
  Roll:         {ROLE_NAME}
  IDP-länk:     {IDP_ALIAS} → sub={EMPLOYEE_ID}

KC-tokenet kommer innehålla:
  name, email, phone_number, employee_id, roles: ["{ROLE_NAME}", ...]
""")


if __name__ == "__main__":
    main()
