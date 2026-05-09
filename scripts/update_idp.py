#!/usr/bin/env python3
"""Uppdaterar vs2-idp med userInfoUrl och aktiverar UserInfo-service."""
import json
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

def main():
    token = get_token()

    # Hämta befintlig IDP-konfiguration
    status, idp = http("GET", f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/vs2-idp", token=token)
    print(f"Befintlig IDP: {json.dumps(idp, indent=2)}")

    # Uppdatera config
    idp["config"]["userInfoUrl"] = "http://jwks-server:9000/userinfo"
    idp["config"]["disableUserInfoService"] = "false"

    status, result = http("PUT", f"{KEYCLOAK_URL}/admin/realms/{REALM}/identity-provider/instances/vs2-idp", body=idp, token=token)
    print(f"PUT IDP: HTTP {status}")
    if status not in (200, 201, 204):
        print(f"Fel: {result}")

if __name__ == "__main__":
    main()
