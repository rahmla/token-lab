"""
JWKS Server — simulerar VS2:s publika nyckelendpoint.

Läser den publika RSA-nyckeln från /keys/public_key.pem och
exponerar den som en JWKS på http://0.0.0.0:9000/jwks.

Keycloak konfigureras att hämta JWKS från denna URL när den
validerar inkommande tokens under Token Exchange.
"""

import json
import os
import base64

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

app = Flask(__name__)

KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "/keys/public_key.pem")
KEY_ID = "vs2-key-1"


def _int_to_base64url(n: int) -> str:
    """Konverterar ett stort heltal till base64url-kodat bytestring utan padding."""
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


@app.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    """Simulerar VS2:s UserInfo-endpoint för Keycloaks externa token exchange.
    Verifierar JWT-signaturen mot den konfigurerade publika nyckeln.
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return jsonify({"error": "unauthorized"}), 401
    token = auth[7:]

    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("not a JWT")
        header_b64, payload_b64, sig_b64 = parts

        # Dekoda payload
        padded_payload = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_payload))

        # Verifiera signatur
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        with open(KEY_PATH, "rb") as f:
            pub_key = load_pem_public_key(f.read())
        pub_key.verify(sig_bytes, signing_input, asym_padding.PKCS1v15(), hashes.SHA256())

        # Kontrollera utgångstid
        import time
        if payload.get("exp", 0) < time.time():
            return jsonify({"error": "token_expired"}), 401

        # Kontrollera issuer
        expected_issuer = os.environ.get("JWT_ISSUER", "http://localhost:9000")
        if payload.get("iss") != expected_issuer:
            return jsonify({"error": "invalid_issuer"}), 401

    except (InvalidSignature, ValueError, Exception):
        return jsonify({"error": "invalid_token"}), 401

    return jsonify({
        "sub": payload.get("sub", "unknown"),
        "email": payload.get("sub", "unknown"),
        "name": payload.get("sub", "unknown"),
        "preferred_username": payload.get("sub", "unknown"),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print(f"JWKS Server startar på port 9000. Läser nyckel från {KEY_PATH}")
    app.run(host="0.0.0.0", port=9000)
