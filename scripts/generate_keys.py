#!/usr/bin/env python3
"""
Steg 1: Generera RSA-nyckelpar för VS2.

Skapar:
  keys/private_key.pem  — används av issue_token.py för att signera JWT
  keys/public_key.pem   — exponeras via JWKS-servern för Keycloak att verifiera mot

Kör en gång innan du startar Docker Compose.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = Path(__file__).parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def generate():
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Spara privat nyckel (ej krypterad — labbmiljö)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"Privat nyckel sparad: {PRIVATE_KEY_PATH}")

    # Spara publik nyckel
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print(f"Publik nyckel sparad: {PUBLIC_KEY_PATH}")


if __name__ == "__main__":
    generate()
    print("\nNycklar genererade. Starta nu Docker Compose.")
