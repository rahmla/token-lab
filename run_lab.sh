#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_lab.sh — Kör hela Token Exchange-labbet i rätt ordning
#
# Förutsättningar:
#   - Docker Desktop körs
#   - Python 3.11+ installerat med pip
#   - pip install cryptography (körs automatiskt nedan om det saknas)
# ---------------------------------------------------------------------------
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB_DIR"

# Lägg till Docker Desktop i PATH
export PATH="/Applications/Docker.app/Contents/Resources/bin:/Applications/Docker.app/Contents/Resources/cli-plugins:$PATH"
mkdir -p ~/.docker/cli-plugins
# Länka compose-pluginen till rätt plats om den saknas
if [ ! -f ~/.docker/cli-plugins/docker-compose ]; then
  ln -sf /Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose ~/.docker/cli-plugins/docker-compose
fi
if ! command -v docker &>/dev/null; then
  echo "Fel: docker hittades inte. Är Docker Desktop igång?"
  exit 1
fi

echo "=== Token Exchange Lab ==="
echo ""

# Hitta python
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then echo "Fel: python3 saknas"; exit 1; fi

# Skapa virtuell miljö om den inte finns
if [ ! -d ".venv" ]; then
    echo "Skapar virtuell miljö (.venv) ..."
    $PYTHON -m venv .venv
fi

# Använd venv-Python direkt (undviker PEP 668 och source-problem)
PYTHON="$LAB_DIR/.venv/bin/python"

# 1. Installera Python-beroenden
echo "[1/5] Installerar Python-beroenden ..."
$PYTHON -m pip install --quiet cryptography flask requests

# 2. Generera RSA-nycklar
echo "[2/5] Genererar RSA-nyckelpar ..."
$PYTHON scripts/generate_keys.py

# 3. Starta Docker Compose
echo "[3/5] Startar Docker Compose (Keycloak + JWKS-server) ..."
docker compose up -d --build

echo "      Väntar på att tjänster ska starta (max 90s) ..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8080/realms/master > /dev/null 2>&1; then
        echo "      Keycloak är redo."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "      TIMEOUT: Keycloak svarade inte. Kontrollera: docker compose logs keycloak"
        exit 1
    fi
    sleep 3
done

for i in $(seq 1 10); do
    if curl -sf http://localhost:9000/health > /dev/null 2>&1; then
        echo "      JWKS-server är redo."
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "      TIMEOUT: JWKS-server svarade inte. Kontrollera: docker compose logs jwks-server"
        exit 1
    fi
    sleep 2
done

# 4. Konfigurera Keycloak (realm, IDP, klienter)
echo "[4/7] Konfigurerar Keycloak (realm, IDP, klienter) ..."
$PYTHON scripts/setup_keycloak.py

# 5. Sätt upp Token Exchange-behörigheter i realm-management
echo "[5/7] Konfigurerar Token Exchange-behörigheter ..."
$PYTHON scripts/setup_permissions.py

# 6. Skapa användare, roll och protocol mappers
echo "[6/7] Skapar användare med attribut och protocol mappers ..."
$PYTHON scripts/setup_user.py

# 7. Kör Token Exchange
echo "[7/7] Kör Token Exchange ..."
$PYTHON scripts/exchange_token.py

echo ""
echo "=== Labb klart! ==="
echo ""
echo "Vill du testa avvisning av ogiltiga tokens?"
echo "  .venv/bin/python scripts/verify_rejection.py"
