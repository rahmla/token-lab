#!/usr/bin/env python3
"""
Token Exchange Lab — fullständig demo med backend-validering.

Kör hela flödet steg för steg och avslutar med att simulera
hur en backend validerar det Keycloak-utfärdade tokenet mot KC:s JWKS.
"""
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from pathlib import Path

KEYCLOAK_URL   = "http://localhost:8080"
REALM          = "token-lab"
CLIENT_ID      = "vs1-client"
CLIENT_SECRET  = "vs1-secret"
AUDIENCE       = "vs2-resource"
ISSUER_VS2     = "http://localhost:9000"
ISSUER_KC      = f"{KEYCLOAK_URL}/realms/{REALM}"


# ─── Hjälpfunktioner ────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def decode_jwt_parts(token: str):
    parts = token.split(".")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def hr(title: str):
    width = 66
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


def ok(msg: str):
    print(f"  ✓  {msg}")


def info(msg: str):
    print(f"     {msg}")


def fetch(url: str) -> dict:
    with urllib.request.urlopen(url) as r:
        return json.loads(r.read())


# ─── Steg 1: VS2 utfärdar JWT ───────────────────────────────────────────────

def step1_issue_vs2_token() -> str:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    import hashlib, struct

    hr("STEG 1 — VS2 utfärdar en signerad JWT")
    info("VS2 är det externa systemet (t.ex. F5). Det har ett eget RSA-nyckelpar.")
    info("Tokenet representerar en autentiserad user med löpnummer 123456.")

    key_path = Path(__file__).parent.parent / "keys" / "private_key.pem"
    with open(key_path, "rb") as f:
        priv_key = load_pem_private_key(f.read(), password=None)

    now = int(time.time())
    payload = {
        "iss": ISSUER_VS2,
        "sub": "123456",
        "aud": "keycloak-client",
        "iat": now,
        "exp": now + 300,
        "jti": hashlib.sha256(struct.pack(">Q", now)).hexdigest()[:16],
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": "vs2-key-1"}

    h = base64.urlsafe_b64encode(json.dumps(header, separators=(",",":")).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload, separators=(",",":")).encode()).rstrip(b"=").decode()
    sig_input = f"{h}.{p}".encode()
    sig = priv_key.sign(sig_input, asym_padding.PKCS1v15(), hashes.SHA256())
    token = f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

    ok(f"Token utfärdat (RS256, kid=vs2-key-1)")
    info(f"iss  = {payload['iss']}")
    info(f"sub  = {payload['sub']}  ← löpnummer, VS2:s primarykey")
    info(f"exp  = om {payload['exp']-now}s")
    info(f"JWT  = {token[:60]}…")
    return token


# ─── Steg 2: Visa JWKS-endpointen ───────────────────────────────────────────

def step2_show_jwks():
    hr("STEG 2 — VS2:s JWKS-endpoint (publik nyckel)")
    info("Keycloak hämtar den publika nyckeln härifrån för att validera VS2:s token.")
    info(f"URL: {ISSUER_VS2}/jwks")

    jwks = fetch(f"{ISSUER_VS2}/jwks")
    key = jwks["keys"][0]
    ok(f"JWKS svarar med 1 nyckel:")
    info(f"  kty = {key['kty']}, alg = {key['alg']}, kid = {key['kid']}")
    info(f"  n   = {key['n'][:40]}…")


# ─── Steg 3: Token Exchange ──────────────────────────────────────────────────

def step3_token_exchange(subject_token: str) -> str:
    hr("STEG 3 — VS1 skickar Token Exchange till Keycloak  (RFC 8693)")
    info(f"POST {KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token")
    info(f"  grant_type        = urn:ietf:params:oauth:grant-type:token-exchange")
    info(f"  client_id         = {CLIENT_ID}")
    info(f"  subject_token     = <VS2-token>")
    info(f"  subject_token_type = urn:…:access_token")
    info(f"  subject_issuer    = vs2-idp")
    info(f"  audience          = {AUDIENCE}")

    print()
    info("Keycloak gör nu:")
    info("  a) Slår upp IDP-alias 'vs2-idp'")
    info("  b) Kontrollerar IDP-behörighet  (realm-management authz) → PERMIT")
    info("  c) Anropar VS2/F5 APM:s /userinfo med tokenet som Bearer")
    info("  d) Extraherar sub=123456 direkt ur JWT-payloaden")
    info("  e) Slår upp KC-user via federated identity vs2-idp:123456")
    info("  f) Kontrollerar audience-behörighet (realm-management authz) → PERMIT")
    info("  g) Utfärdar nytt KC-token med aud=vs2-resource")

    url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type":          "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id":           CLIENT_ID,
        "client_secret":       CLIENT_SECRET,
        "subject_token":       subject_token,
        "subject_token_type":  "urn:ietf:params:oauth:token-type:access_token",
        "subject_issuer":      "vs2-idp",
        "requested_token_type":"urn:ietf:params:oauth:token-type:access_token",
        "audience":            AUDIENCE,
        "scope":               "profile email employee-claims",
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        print(f"\n  ✗  HTTP {e.code}: {err}", file=sys.stderr)
        sys.exit(1)

    token = body["access_token"]
    ok(f"KC utfärdade ett nytt access token!")
    return token


# ─── Steg 4: Backend validerar KC-tokenet ───────────────────────────────────

def step4_backend_validate(kc_token: str):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    hr("STEG 4 — Backend validerar KC-tokenet  (som backenden ser det)")

    info(f"Backend hämtar KC:s JWKS: {ISSUER_KC}/protocol/openid-connect/certs")
    jwks_url = f"{ISSUER_KC}/protocol/openid-connect/certs"
    kc_jwks = fetch(jwks_url)
    ok(f"KC:s JWKS hämtat ({len(kc_jwks['keys'])} nyckel/ar)")

    # Dekoda JWT
    header, payload, sig_b64 = decode_jwt_parts(kc_token)
    kid = header.get("kid")
    info(f"JWT kid = {kid}")

    # Hitta rätt nyckel
    key_data = next((k for k in kc_jwks["keys"] if k.get("kid") == kid), None)
    if not key_data:
        print("  ✗  Nyckel med matchande kid hittades inte i JWKS!", file=sys.stderr)
        sys.exit(1)
    ok(f"Nyckel hittad i KC:s JWKS (alg={key_data['alg']})")

    # Bygg RSA publik nyckel från n och e
    def b64int(s):
        return int.from_bytes(b64url_decode(s), "big")

    pub_numbers = RSAPublicNumbers(b64int(key_data["e"]), b64int(key_data["n"]))
    pub_key = pub_numbers.public_key(default_backend())

    # Verifiera signatur
    h_part, p_part, s_part = kc_token.split(".")
    signing_input = f"{h_part}.{p_part}".encode()
    sig_bytes = b64url_decode(s_part)
    try:
        pub_key.verify(sig_bytes, signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
        ok("Signaturen är GILTIG — token utfärdat av KC ✓")
    except InvalidSignature:
        print("  ✗  Signaturen är OGILTIG!", file=sys.stderr)
        sys.exit(1)

    # Validera claims
    now = int(time.time())
    assert payload["iss"] == ISSUER_KC,     f"Fel issuer: {payload['iss']}"
    assert AUDIENCE in (payload.get("aud") or []), f"Audience saknas: {payload.get('aud')}"
    assert payload["exp"] > now,            "Token har gått ut!"
    ok(f"iss  = {payload['iss']}")
    ok(f"aud  inkluderar '{AUDIENCE}' ✓")
    ok(f"exp  om {payload['exp'] - now}s ✓")

    # Visa alla claims som backenden ser
    hr("VERIFIERADE CLAIMS  (backend ser detta efter validering)")

    fields = [
        ("sub",               "KC-intern UUID för usern"),
        ("azp",               "Klienten som begärde utbytet"),
        ("preferred_username","KC-username = VS2-löpnummer"),
        ("name",              "Fullständigt namn"),
        ("given_name",        "Förnamn"),
        ("family_name",       "Efternamn"),
        ("email",             "E-postadress"),
        ("phone_number",      "Telefonnummer"),
        ("employee_id",       "VS2-löpnummer (6-siffror)"),
        ("roles",             "Realm-roller (platt lista)"),
        ("realm_access",      "Realm-roller (strukturerat)"),
        ("email_verified",    "E-post verifierad"),
        ("scope",             "Beviljade scopes"),
        ("exp",               "Utgångstid (epoch)"),
        ("iss",               "Utfärdare"),
        ("aud",               "Tillåtna audiences"),
    ]

    max_key = max(len(k) for k, _ in fields)
    for key, desc in fields:
        val = payload.get(key)
        if val is None:
            continue
        val_str = json.dumps(val, ensure_ascii=False) if isinstance(val, (list, dict)) else str(val)
        print(f"  {key:<{max_key}}  {val_str}")
        print(f"  {'':>{max_key}}  ↳ {desc}")

    print(f"\n{'─' * 66}")
    print(f"  Backenden kan nu lita på att:")
    print(f"    • Usern är autentiserad av KC (signaturkontroll passerade)")
    print(f"    • employee_id={payload.get('employee_id')} → VS2-löpnummer 123456")
    print(f"    • Usern har rollen {[r for r in payload.get('roles',[]) if r=='Supervisor']}")
    print(f"    • Tokenet är utfärdat för audience '{AUDIENCE}'")
    print(f"{'─' * 66}\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║        Token Exchange Lab — RFC 8693 med Keycloak 26            ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    vs2_token = step1_issue_vs2_token()
    step2_show_jwks()
    kc_token  = step3_token_exchange(vs2_token)
    step4_backend_validate(kc_token)


if __name__ == "__main__":
    main()
