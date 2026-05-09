"""
JWKS Server — simulerar VS2 APM:s publika nyckelendpoint.

KC 26 token-exchange:v2 validerar JWT-signaturen direkt mot denna JWKS-endpoint.
Ingen UserInfo-endpoint behövs — VS2 är en token translator, inte en IdP med user store.

Exponerar:
  GET /jwks    — JWKS med RSA-publik nyckel (kid: vs2-key-1)
  GET /health  — hälsokontroll
"""

import base64
import os

from flask import Flask, jsonify
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

app = Flask(__name__)

KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "/keys/public_key.pem")
KEY_ID = "vs2-key-1"


def _int_to_base64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    raw = n.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_jwks() -> dict:
    with open(KEY_PATH, "rb") as f:
        pub_key: RSAPublicKey = load_pem_public_key(f.read())
    pub_numbers = pub_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": _int_to_base64url(pub_numbers.n),
                "e": _int_to_base64url(pub_numbers.e),
            }
        ]
    }


@app.route("/jwks", methods=["GET"])
def jwks():
    try:
        return jsonify(build_jwks())
    except FileNotFoundError:
        return jsonify({"error": "Public key not found. Run generate_keys.py first."}), 503


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print(f"JWKS Server startar på port 9000. Läser nyckel från {KEY_PATH}")
    app.run(host="0.0.0.0", port=9000)
