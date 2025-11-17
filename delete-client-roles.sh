#!/bin/bash

# =============================================================================
# Skript: Löscht alle Client-Rollen eines Keycloak-Clients
#
# Verwendung:
#   - Hilfreich, wenn Rollen z. B. per AD/LDAP synchronisiert wurden und
#     man sie alle auf einmal löschen möchte.
#   - In der Keycloak-Admin-GUI müsste jede Rolle einzeln gelöscht werden.
#
# Voraussetzungen:
#   - Ein Benutzer mit "realm-admin"-Berechtigung im Ziel-Realm.
#     **Wichtig:**
#     - Der Benutzer muss **vollständig konfiguriert** sein:
#       - Vor- und Nachname müssen gesetzt sein.
#       - E-Mail-Adresse muss vergeben **und verifiziert** sein.
#       - Sonst lehnt Keycloak die API-Anfragen ab, selbst wenn die Rolle korrekt zugewiesen ist.
#   - Der Benutzer muss im **gleichen Realm** liegen wie der Client.
#   - Grant Type "password" für einfache Authentifizierung.
#
# Hinweis:
#   - Das Skript löscht **NUR Client-Rollen**, keine Realm-Rollen!
#   - Rollen-Namen mit Leerzeichen oder Sonderzeichen werden URL-encoded.
# =============================================================================

KEYCLOAK_URL="http://<dein-keycloak-server>"
REALM="dein-realm-name"                      # Realm, in dem der Client liegt
CLIENT_ID="sampleapp01"                      # Client, dessen Rollen gelöscht werden sollen
USERNAME="<dein-admin-benutzername>"         # Benutzer mit realm-admin-Rechten
PASSWORD="<dein-admin-passwort>"             # Passwort des Benutzers

# 1. Access Token abrufen
echo "1. Rufe Access Token ab..."
ACCESS_TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=admin-cli" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "grant_type=password" \
  "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Fehler: Access Token konnte nicht abgerufen werden."
  exit 1
fi
echo "Access Token erfolgreich abgerufen."

# 2. Client UUID abrufen (mit Debugging)
echo "2. Suche Client '$CLIENT_ID' im Realm '$REALM'..."
CLIENT_RESPONSE=$(curl -s -X GET \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID")

echo "API-Antwort (Client-Suche):"
echo "$CLIENT_RESPONSE" | jq

# Prüfe, ob die Antwort ein Array ist und der Client existiert
if echo "$CLIENT_RESPONSE" | jq -e 'type == "array" and length > 0' > /dev/null; then
  CLIENT_UUID=$(echo "$CLIENT_RESPONSE" | jq -r '.[0].id')
  echo "Client UUID: $CLIENT_UUID"
else
  echo "Fehler: Client '$CLIENT_ID' nicht gefunden oder API-Fehler."
  echo "Rohantwort: $CLIENT_RESPONSE"
  exit 1
fi

# 3. Alle Rollen des Clients abrufen und löschen
echo "3. Lösche Rollen für Client '$CLIENT_ID'..."
ROLES_RESPONSE=$(curl -s -X GET \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_UUID/roles")

echo "API-Antwort (Rollen):"
echo "$ROLES_RESPONSE" | jq

# Prüfe, ob Rollen vorhanden sind
if echo "$ROLES_RESPONSE" | jq -e 'type == "array" and length > 0' > /dev/null; then
  for ROLE_NAME in $(echo "$ROLES_RESPONSE" | jq -r '.[] | .name'); do
    echo "Lösche Rolle: $ROLE_NAME"
    ROLE_NAME_ENCODED=$(jq -rn --arg name "$ROLE_NAME" '$name | @uri')
    curl -s -X DELETE \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_UUID/roles/$ROLE_NAME_ENCODED"
  done
else
  echo "Keine Rollen gefunden."
fi

echo "Fertig."
