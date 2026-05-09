#!/usr/bin/env python3
"""
Steg 5: Verifiera att Keycloak avvisar ogiltiga tokens.

Testar tre scenarion:
  1. Token signerad med fel nyckel (ny tillfällig nyckel)
  2. Utgången token (exp i förfluten tid)
  3. Token med fel issuer

Förväntat resultat: alla tre ska ge HTTP 400 / invalid_token från Keycloak.
"""

import sys
import json
import time
import base64
import urllib.request
import urllib.parse
import urllib.error

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEYCLOAK_URL = "http://localhost:8080"
REALM = "token-lab"
CLIENT_ID = "vs1-client"
CLIENT_SECRET = "vs1-secret"
TARGET_AUDIENCE = "vs2-resource"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(payload: dict, private_key, kid: str = "vs2-key-1") -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url(sig)}"


def do_exchange(subject_token: str, client_secret: str = CLIENT_SECRET) -> tuple[int, dict]:
    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": CLIENT_ID,
        "client_secret": client_secret,
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_issuer": "vs2-idp",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": TARGET_AUDIENCE,
    }).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": f"HTTP {e.code}"}


def load_real_key() -> object:
    key_path = Path(__file__).parent.parent / "keys" / "private_key.pem"
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def new_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def run_test(name: str, token: str, expect_success: bool = False, client_secret: str = CLIENT_SECRET):
    print(f"\n--- Test: {name} ---")
    status, body = do_exchange(token, client_secret=client_secret)
    if expect_success:
        if "access_token" in body:
            print(f"  PASS  HTTP {status} — token utfärdat som förväntat")
        else:
            print(f"  FAIL  HTTP {status} — förväntade access_token men fick: {body.get('error', body)}")
    else:
        if status >= 400 and "error" in body:
            print(f"  PASS  HTTP {status} — avslagen som förväntat: {body['error']}")
        else:
            print(f"  FAIL  HTTP {status} — borde ha avslagits! Svar: {body}")


def main():
    now = int(time.time())

    # Test 0: Giltig token (kontroll)
    real_key = load_real_key()
    valid_payload = {
        "iss": "http://localhost:9000",
        "sub": "alice@example.com",
        "aud": "keycloak-client",
        "iat": now, "exp": now + 300,
    }
    run_test("Giltig token (bör lyckas)", make_jwt(valid_payload, real_key), expect_success=True)

    # Test 1: Signerad med fel nyckel
    wrong_key = new_rsa_key()
    run_test(
        "Signerad med fel nyckel",
        make_jwt(valid_payload, wrong_key, kid="vs2-key-1"),
    )

    # Test 2: Utgången token
    expired_payload = {**valid_payload, "iat": now - 600, "exp": now - 300}
    run_test("Utgången token (exp i förfluten tid)", make_jwt(expired_payload, real_key))

    # Test 3: Fel issuer
    wrong_issuer_payload = {**valid_payload, "iss": "http://evil.example.com"}
    run_test("Fel issuer", make_jwt(wrong_issuer_payload, real_key))

    # Test 4: Rätt VS2-token men fel client_secret (angripare är inte VS1)
    # Simulerar en aktör som snappat upp ett giltigt VS2-token men saknar VS1:s hemlighet.
    # KC avvisar på klientautentisering — VS2:s /userinfo anropas aldrig ens.
    run_test(
        "Giltig VS2-token men fel client_secret (inte VS1)",
        make_jwt(valid_payload, real_key),
        client_secret="fel-hemlighet",
    )

    print("\nKlar.")


if __name__ == "__main__":
    main()
