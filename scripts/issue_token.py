#!/usr/bin/env python3
"""
Steg 3: Utfärda en signerad JWT — simulerar VS2.

Skapar en JWT signerad med VS2:s privata RSA-nyckel.
Printar token till stdout (används sedan av exchange_token.py).

Viktiga claims:
  iss  — måste matcha Keycloak-klientens "Issuer" i Identity Provider-konfigurationen
  aud  — valfritt i subject_token, men bra att ha
  sub  — identiteten som exchangeas
  kid  — måste matcha kid i JWKS-svaret

Kör: python scripts/issue_token.py
"""

import json
import time
import base64
import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_PATH = Path(__file__).parent.parent / "keys" / "private_key.pem"

# Dessa värden måste matcha Keycloak-konfigurationen (se README)
ISSUER = "http://localhost:9000"          # VS2:s "identitet" — matchar KC Identity Provider Issuer
SUBJECT = "123456"                        # 6-siffrigt löpnummer — primärnyckeln i VS2:s system
AUDIENCE = "keycloak-client"
KEY_ID = "vs2-key-1"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_jwt(payload: dict, private_key_pem: bytes) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": KEY_ID}

    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    private_key = load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    return f"{header_b64}.{payload_b64}.{b64url(signature)}"


def main():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key_pem = f.read()

    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,  # giltig 5 minuter
        "jti": hashlib.sha256(struct.pack(">Q", now)).hexdigest()[:16],
    }

    token = sign_jwt(payload, private_key_pem)
    print(token)


if __name__ == "__main__":
    main()
