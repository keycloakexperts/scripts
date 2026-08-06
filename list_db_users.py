#!/usr/bin/env python3
"""
Listet Nutzer direkt aus der Keycloak-Postgres-DB (Tabelle user_entity).

Anders als die Admin-REST-API zeigt das hier zuverlässig, welche Nutzer
wirklich eine Zeile in der Keycloak-DB haben - egal ob nativ angelegt oder
per LDAP importiert. Rein virtuelle LDAP-Passthrough-Nutzer (Import=false,
kein Login/keine lokalen Daten bisher) tauchen hier NICHT auf, weil sie
keine user_entity-Zeile besitzen.

federation_link:
  NULL      -> nativ angelegt (manuell / via Admin API)
  gesetzt   -> aus einem User-Storage-Provider (z.B. AD/LDAP) importiert
               bzw. mit lokalen Daten (Credentials, Rollen, ...) verknüpft

Konfiguration über .env (siehe .env.example):
  KC_DB_URL       - JDBC-URL wie aus der systemd-Unit, z.B.
                     jdbc:postgresql://host1:5432,host2:5432/keycloak
  KC_DB_USERNAME
  KC_DB_PASSWORD
  KC_DB_SSLMODE   - optional, Default "prefer"
  KEYCLOAK_REALM  - Name des Realms, dessen Nutzer angezeigt werden sollen
"""

import os
import re
import sys

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

KC_DB_URL = os.environ.get("KC_DB_URL")
KC_DB_USERNAME = os.environ.get("KC_DB_USERNAME")
KC_DB_PASSWORD = os.environ.get("KC_DB_PASSWORD")
KC_DB_SSLMODE = os.environ.get("KC_DB_SSLMODE", "prefer")
REALM = os.environ.get("KEYCLOAK_REALM")

# jdbc:postgresql://host1:port1,host2:port2/dbname?param1=val1&param2=val2
JDBC_RE = re.compile(
    r"^jdbc:postgresql://(?P<hosts>[^/]+)/(?P<dbname>[^?]+)(?:\?(?P<params>.*))?$"
)

def require_config():
    missing = [
        name
        for name, val in [
            ("KC_DB_URL", KC_DB_URL),
            ("KC_DB_USERNAME", KC_DB_USERNAME),
            ("KC_DB_PASSWORD", KC_DB_PASSWORD),
            ("KEYCLOAK_REALM", REALM),
        ]
        if not val
    ]
    if missing:
        print(f"Fehlende .env-Variablen: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def parse_jdbc_url(url: str) -> dict:
    match = JDBC_RE.match(url.strip())
    if not match:
        print(f"Konnte KC_DB_URL nicht parsen (erwartet jdbc:postgresql://...): {url}", file=sys.stderr)
        sys.exit(1)

    hosts = []
    ports = []
    for entry in match.group("hosts").split(","):
        if ":" in entry:
            h, p = entry.split(":", 1)
        else:
            h, p = entry, "5432"
        hosts.append(h)
        ports.append(p)

    return {
        "host": ",".join(hosts),
        "port": ",".join(ports),
        "dbname": match.group("dbname"),
    }

    def get_connection():
    conn_info = parse_jdbc_url(KC_DB_URL)
    try:
        return psycopg2.connect(
            host=conn_info["host"],
            port=conn_info["port"],
            dbname=conn_info["dbname"],
            user=KC_DB_USERNAME,
            password=KC_DB_PASSWORD,
            sslmode=KC_DB_SSLMODE,
            connect_timeout=10,
        )
    except psycopg2.OperationalError as exc:
        print(f"DB-Verbindung fehlgeschlagen: {exc}", file=sys.stderr)
        sys.exit(1)


# f:<storage-provider-component-id>:<external-id-aus-ldap>
FED_USER_ID_RE = re.compile(r"^f:(?P<provider>[^:]+):(?P<external>.*)$")


def get_realm_id(conn, realm_name: str) -> str:
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM realm WHERE name = %s;", (realm_name,))
        row = cur.fetchone()
    if not row:
        print(f"Realm '{realm_name}' nicht gefunden.", file=sys.stderr)
        sys.exit(1)
    return row[0]


def fetch_users(conn, realm_id: str) -> list[dict]:
    query = """
        SELECT id, username, email, enabled, federation_link, created_timestamp
        FROM user_entity
        WHERE realm_id = %s
        ORDER BY username;
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, (realm_id,))
        return cur.fetchall()

def fetch_credentials_for_users(conn, user_ids: list[str]) -> dict[str, list[str]]:
    """
    Credential-Typen (password, otp, recovery-authn-codes, webauthn, ...) fuer
    Nutzer MIT user_entity-Zeile (nativ oder importiert). Liegt in der normalen
    credential-Tabelle, nicht in fed_user_credential.
    """
    if not user_ids:
        return {}

    query = "SELECT user_id, type FROM credential WHERE user_id = ANY(%s);"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, (user_ids,))
        rows = cur.fetchall()

    grouped: dict[str, list[str]] = {}
    for row in rows:
        grouped.setdefault(row["user_id"], []).append(row["type"])
    return grouped

def fetch_federated_storage_users(conn, realm_id: str) -> list[dict]:
    """
    Nutzer, die NUR in den FED_USER_*-Tabellen existieren (kein user_entity-Eintrag).
    Das sind rein virtuelle LDAP-Nutzer (Import=false), denen aber bereits lokale
    Keycloak-Daten zugeordnet wurden (z.B. Recovery Codes, Rollen, Gruppen, Attribute).
    """
    query = """
        SELECT user_id, storage_provider_id, 'credential' AS kind
            FROM fed_user_credential WHERE realm_id = %(realm_id)s
        UNION ALL
        SELECT user_id, storage_provider_id, 'role'
            FROM fed_user_role_mapping WHERE realm_id = %(realm_id)s
        UNION ALL
        SELECT user_id, storage_provider_id, 'group'
            FROM fed_user_group_membership WHERE realm_id = %(realm_id)s
        UNION ALL
        SELECT user_id, storage_provider_id, 'attribute'
            FROM fed_user_attribute WHERE realm_id = %(realm_id)s
        UNION ALL
        SELECT user_id, storage_provider_id, 'required_action'
            FROM fed_user_required_action WHERE realm_id = %(realm_id)s;
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, {"realm_id": realm_id})
        rows = cur.fetchall()

        # Provider-Namen (z.B. "Active Directory") auflösen
        cur.execute("SELECT id, name FROM component WHERE realm_id = %s;", (realm_id,))
        provider_names = {r["id"]: r["name"] for r in cur.fetchall()}

    grouped: dict[str, dict] = {}
    for row in rows:
        user_id = row["user_id"]
        entry = grouped.setdefault(
            user_id,
            {
                "user_id": user_id,
                "provider_name": provider_names.get(row["storage_provider_id"], row["storage_provider_id"]),
                "kinds": set(),
            },
        )
        entry["kinds"].add(row["kind"])

    return sorted(grouped.values(), key=lambda e: e["user_id"])

def main():
    require_config()
    conn = get_connection()
    try:
        realm_id = get_realm_id(conn, REALM)
        users = fetch_users(conn, realm_id)
        credentials_by_user = fetch_credentials_for_users(conn, [u["id"] for u in users])
        fed_storage_users = fetch_federated_storage_users(conn, realm_id)
    finally:
        conn.close()

    native = [u for u in users if not u["federation_link"]]
    federated = [u for u in users if u["federation_link"]]

    print(f"{len(users)} Nutzer physisch in der Keycloak-DB (user_entity), Realm '{REALM}':\n")

    print(f"-- Nativ angelegt ({len(native)}) --")
    for u in native:
        enabled = "aktiv" if u["enabled"] else "deaktiviert"
        creds = ", ".join(credentials_by_user.get(u["id"], [])) or "-"
        print(f"{u['username']:<30} {(u['email'] or '-'):<40} {enabled:<12} Credentials: {creds}")

    print(f"\n-- Importiert / mit lokalen Daten aus Federation ({len(federated)}) --")
    for u in federated:
        enabled = "aktiv" if u["enabled"] else "deaktiviert"
        creds = ", ".join(credentials_by_user.get(u["id"], [])) or "-"
        print(f"{u['username']:<30} {(u['email'] or '-'):<40} {enabled:<12} Credentials: {creds}  (federation_link={u['federation_link']})")

    print(f"\n-- Federated Storage, kein user_entity-Eintrag ({len(fed_storage_users)}) --")
    if not fed_storage_users:
        print("(keine)")
    for u in fed_storage_users:
        match = FED_USER_ID_RE.match(u["user_id"])
        external_id = match.group("external") if match else u["user_id"]
        kinds = ", ".join(sorted(u["kinds"]))
        print(f"{external_id:<30} Provider: {u['provider_name']:<25} Daten: {kinds}")


if __name__ == "__main__":
    main()