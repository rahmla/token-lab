#!/usr/bin/env python3
"""
Steg 4: Token Exchange mot Keycloak — simulerar VS1.

Skickar subject_token (JWT från VS2) till Keycloak Token Exchange-endpointen
och skriver ut det utfärdade Keycloak-tokenet.

RFC 8693 Token Exchange:
  grant_type            = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token         = <JWT från VS2>
  subject_token_type    = urn:ietf:params:oauth:token-type:access_token
  requested_token_type  = urn:ietf:params:oauth:token-type:access_token
  audience              = <target klient i Keycloak>

Kör: python scripts/exchange_token.py [--subject-token <jwt>]
"""

import sys
import json
import argparse
import subprocess
import urllib.request
import urllib.parse
import urllib.error

# Keycloak-inställningar (matcha din konfiguration)
KEYCLOAK_URL = "http://localhost:8080"
REALM = "token-lab"
CLIENT_ID = "vs1-client"
CLIENT_SECRET = "vs1-secret"          # sätts i Keycloak (se README steg 5)
TARGET_AUDIENCE = "vs2-resource"      # den klient vars access vi begär


def exchange(subject_token: str) -> dict:
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"

    data = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "subject_issuer": "vs2-idp",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": TARGET_AUDIENCE,
            "scope": "profile email employee-claims",
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)


def decode_jwt_payload(token: str) -> dict:
    """Dekoderar payload-delen av en JWT utan verifiering (för visning)."""
    import base64
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def main():
    parser = argparse.ArgumentParser(description="Token Exchange mot Keycloak")
    parser.add_argument(
        "--subject-token",
        help="JWT från VS2. Om ej angiven körs issue_token.py automatiskt.",
    )
    args = parser.parse_args()

    if args.subject_token:
        subject_token = args.subject_token.strip()
    else:
        print("Genererar subject_token via issue_token.py ...")
        result = subprocess.run(
            [sys.executable, "scripts/issue_token.py"],
            capture_output=True,
            text=True,
            cwd=str(__import__("pathlib").Path(__file__).parent.parent),
        )
        if result.returncode != 0:
            print(f"Fel vid generering av token: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        subject_token = result.stdout.strip()
        print(f"Subject token: {subject_token[:60]}...\n")

    print("Skickar Token Exchange-begäran till Keycloak ...")
    response = exchange(subject_token)

    access_token = response.get("access_token")
    if not access_token:
        print("Oväntat svar:", json.dumps(response, indent=2))
        sys.exit(1)

    print("\n=== Token Exchange lyckades! ===")
    print(f"\nAccess token (rå): {access_token[:80]}...")

    payload = decode_jwt_payload(access_token)
    print("\nToken payload:")
    print(json.dumps(payload, indent=2))

    print(f"\nIssued for: {payload.get('azp', 'N/A')}")
    print(f"Audience:   {payload.get('aud', 'N/A')}")
    print(f"Subject:    {payload.get('sub', 'N/A')}")


if __name__ == "__main__":
    main()
