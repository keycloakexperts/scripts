#!/usr/bin/env python3
"""
Listet alle Nutzer eines Keycloak-Realms auf.

Auth: Client Credentials Grant (Service Account des Clients muss die
Client-Rollen "view-users" bzw. "query-users" des Clients "realm-management"
im Ziel-Realm zugewiesen bekommen haben, sonst liefert die Admin-API 403).

Konfiguration wird aus einer .env-Datei geladen (siehe .env.example).
"""

import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

KEYCLOAK_HOST = os.environ.get("KEYCLOAK_HOST", "").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM")
CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET")
VERIFY_SSL = os.environ.get("KEYCLOAK_VERIFY_SSL", "true").lower() not in ("false", "0", "no")

PAGE_SIZE = 100


def require_config():
    missing = [
        name
        for name, val in [
            ("KEYCLOAK_HOST", KEYCLOAK_HOST),
            ("KEYCLOAK_REALM", REALM),
            ("KEYCLOAK_CLIENT_ID", CLIENT_ID),
            ("KEYCLOAK_CLIENT_SECRET", CLIENT_SECRET),
        ]
        if not val
    ]
    if missing:
        print(f"Fehlende .env-Variablen: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

def get_access_token() -> str:
    token_url = f"{KEYCLOAK_HOST}/realms/{REALM}/protocol/openid-connect/token"
    resp = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        verify=VERIFY_SSL,
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"Token-Request fehlgeschlagen ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()["access_token"]


def fetch_all_users(token: str) -> list[dict]:
    users_url = f"{KEYCLOAK_HOST}/admin/realms/{REALM}/users"
    headers = {"Authorization": f"Bearer {token}"}

    all_users = []
    first = 0
    while True:
        resp = requests.get(
            users_url,
            headers=headers,
            params={"first": first, "max": PAGE_SIZE, "briefRepresentation": True},
            verify=VERIFY_SSL,
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"Nutzer-Request fehlgeschlagen ({resp.status_code}): {resp.text}", file=sys.stderr)
            sys.exit(1)

        page = resp.json()
        if not page:
            break

        all_users.extend(page)
        first += PAGE_SIZE

        if len(page) < PAGE_SIZE:
            break

    return all_users

def main():
    require_config()
    token = get_access_token()
    users = fetch_all_users(token)

    if not users:
        print("Keine Nutzer gefunden.")
        return

    print(f"{len(users)} Nutzer in Realm '{REALM}':\n")
    for u in users:
        username = u.get("username", "-")
        email = u.get("email", "-")
        enabled = "aktiv" if u.get("enabled") else "deaktiviert"
        print(f"{username:<30} {email:<40} {enabled}")


if __name__ == "__main__":
    main()


