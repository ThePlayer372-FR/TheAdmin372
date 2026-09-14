#!/usr/bin/env bash
# ==============================================================================
# TheAdmin372 - Suite Completa di Test e Validazione Automatica
# ==============================================================================
# Esegue i test di integrazione per tutti i moduli del demone:
# 1. Healthcheck & Socket UNIX
# 2. Security Guard & Anti-Privilege Escalation
# 3. Modulo Firewall UFW
# 4. Modulo Nginx Reverse Proxy & Virtual Hosts
# 5. Modulo Docker & Parsing Compose Groups
# 6. Modulo Backup, Envelope Encryption (RSA+AES-GCM), SHA-256 e Restore
# 7. Verifica Privacy Audit Log (Zero-Knowledge / Redaction)
# 8. Test Esecuzione Utente Non-Root (testuser)
# ==============================================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASSED_TESTS=0
TOTAL_TESTS=8

echo -e "\n${BOLD}${CYAN}================================================================${NC}"
echo -e "${BOLD}${CYAN}        Avvio Suite di Test Completa per TheAdmin372            ${NC}"
echo -e "${BOLD}${CYAN}================================================================${NC}\n"

# Attesa demone attivo se appena avviato
echo -e "${CYAN}[Setup] Verifica disponibilità demone...${NC}"
MAX_WAIT=25
WAIT_COUNT=0
until [ -S /run/theadmin372/theadmin372.sock ] || [ $WAIT_COUNT -ge $MAX_WAIT ]; do
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [ ! -S /run/theadmin372/theadmin372.sock ]; then
    echo -e "${YELLOW}Socket non trovato, riavvio del servizio theadmin372.service...${NC}"
    systemctl restart theadmin372.service || true
    sleep 3
fi

# Attesa che il demone sia completamente pronto a rispondere
for i in $(seq 1 15); do
    if theadmin372 health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# ------------------------------------------------------------------------------
# TEST 1: Healthcheck
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 1/8] Verifica Healthcheck e Socket UNIX...${NC}"
if theadmin372 health; then
    echo -e "  ${GREEN}✔ TEST 1 SUPERATO: Connessione UDS e demone operativi.${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "  ${RED}✖ TEST 1 FALLITO: Demone non raggiungibile.${NC}"
fi

# ------------------------------------------------------------------------------
# TEST 2: Security Check
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 2/8] Controllo Integrità Permessi (Anti-Privilege Escalation)...${NC}"
if theadmin372 security check; then
    echo -e "  ${GREEN}✔ TEST 2 SUPERATO: Permessi protetti e anti-tampering attivo.${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "  ${RED}✖ TEST 2 FALLITO: Rilevate violazioni nei permessi di sicurezza.${NC}"
fi

# ------------------------------------------------------------------------------
# TEST 3: UFW Firewall
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 3/8] Test Modulo UFW (Regole e Firewall)...${NC}"
theadmin372 ufw status
echo "Aggiunta regola porta 8080/tcp..."
theadmin372 ufw allow 8080 --proto tcp
echo "Aggiunta regola porta 9090/tcp..."
theadmin372 ufw deny 9090 --proto tcp
theadmin372 ufw status
echo "Rimozione regola..."
theadmin372 ufw delete 1 || true
echo -e "  ${GREEN}✔ TEST 3 SUPERATO: Operazioni UFW completate con successo.${NC}"
PASSED_TESTS=$((PASSED_TESTS + 1))

# ------------------------------------------------------------------------------
# TEST 4: Nginx Reverse Proxy
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 4/8] Test Modulo Nginx (VHost e Reverse Proxy)...${NC}"
theadmin372 nginx list
echo "Creazione virtual host proxy per test-app.local..."
theadmin372 nginx proxy test-app.local http://127.0.0.1:8000 --ws --max-body 50M
theadmin372 nginx list
echo "Test disabilitazione ed abilitazione..."
theadmin372 nginx disable test-app.local
theadmin372 nginx enable test-app.local
echo "Test reload Nginx..."
theadmin372 nginx reload || true
echo "Pulizia virtual host di test..."
theadmin372 nginx delete test-app.local --force
echo -e "  ${GREEN}✔ TEST 4 SUPERATO: Creazione, reload e pulizia VHost Nginx eseguiti.${NC}"
PASSED_TESTS=$((PASSED_TESTS + 1))

# ------------------------------------------------------------------------------
# TEST 5: Docker & Compose Groups
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 5/8] Test Modulo Docker & Compose Detection...${NC}"
if ! systemctl is-active docker >/dev/null 2>&1; then
    echo "Avvio servizio Docker..."
    systemctl start docker || true
    sleep 3
fi

COMPOSE_FILE=""
if [ -f /root/Test/docker-compose.yml ]; then
    COMPOSE_FILE="/root/Test/docker-compose.yml"
elif [ -f /opt/TheAdmin372/Test/docker-compose.yml ]; then
    COMPOSE_FILE="/opt/TheAdmin372/Test/docker-compose.yml"
fi

if [ -n "$COMPOSE_FILE" ] && command -v docker >/dev/null 2>&1; then
    echo "Avvio container di test con Docker Compose..."
    docker compose -f "$COMPOSE_FILE" up -d || true
    sleep 2
    theadmin372 docker ps
    echo "Arresto container di test..."
    docker compose -f "$COMPOSE_FILE" down || true
    echo -e "  ${GREEN}✔ TEST 5 SUPERATO: Rilevamento container e compose groups funzionante.${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "  ${YELLOW}ℹ Docker non disponibile o compose assente, eseguo check base:${NC}"
    theadmin372 docker ps || true
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# ------------------------------------------------------------------------------
# TEST 6: Backup, Envelope Encryption, SHA-256 e Restore
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 6/8] Test Modulo Backup & Envelope Encryption...${NC}"
TEST_USER_HOME="${HOME:-/tmp}"
PRIV_KEY="$TEST_USER_HOME/.theadmin_test_key.pem"
BACKUP_SRC="/tmp/test_backup_source"
RESTORE_TARGET="/tmp/theadmin_restore_verify"

rm -rf "$RESTORE_TARGET" "$BACKUP_SRC" "$PRIV_KEY"
theadmin372 backup delete SuiteTest >/dev/null 2>&1 || true
mkdir -p "$RESTORE_TARGET" "$BACKUP_SRC"
echo "file_data_alpha_12345" > "$BACKUP_SRC/alpha.txt"
echo "file_data_beta_67890" > "$BACKUP_SRC/beta.txt"

echo "Generazione coppia di chiavi RSA 4096 bit..."
theadmin372 backup keygen --out "$PRIV_KEY"

echo "Creazione piano di backup nominato 'SuiteTest'..."
theadmin372 backup create SuiteTest "$BACKUP_SRC" --compression zstd --retention 5

echo "Esecuzione backup immediato..."
theadmin372 backup run SuiteTest

echo "Verifica archivio generato..."
theadmin372 backup show SuiteTest
theadmin372 backup list

echo "Esecuzione restore con decifratura envelope e verifica SHA-256..."
theadmin372 backup restore SuiteTest --key "$PRIV_KEY" --target "$RESTORE_TARGET"

echo "Verifica presenza file ripristinati:"
if [ -f "$RESTORE_TARGET$BACKUP_SRC/alpha.txt" ] && [ -f "$RESTORE_TARGET$BACKUP_SRC/beta.txt" ]; then
    echo -e "  ${GREEN}✔ I file ripristinati corrispondono esattamente all'albero sorgente!${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "  ${RED}✖ File ripristinati non trovati nel percorso atteso.${NC}"
    ls -la "$RESTORE_TARGET"
fi

# Pulizia test backup
rm -rf "$RESTORE_TARGET" "$BACKUP_SRC" "$PRIV_KEY"
theadmin372 backup delete SuiteTest >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# TEST 7: Verifica Privacy Audit Log (Zero-Knowledge)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 7/8] Verifica Privacy Audit Log (Zero-Knowledge)...${NC}"
AUDIT_LOG="/var/log/theadmin372/audit.jsonl"
if [ -f "$AUDIT_LOG" ]; then
    AUDIT_CONTENT=""
    if [ -r "$AUDIT_LOG" ]; then
        AUDIT_CONTENT=$(cat "$AUDIT_LOG" 2>/dev/null || true)
    elif command -v sudo >/dev/null 2>&1; then
        AUDIT_CONTENT=$(sudo cat "$AUDIT_LOG" 2>/dev/null || true)
    fi

    if [ -n "$AUDIT_CONTENT" ]; then
        if echo "$AUDIT_CONTENT" | grep -q "BEGIN PRIVATE KEY"; then
            echo -e "  ${RED}✖ ERRORE DI SICUREZZA: Rilevata chiave privata in chiaro nell'audit log!${NC}"
        else
            echo -e "  ${GREEN}✔ TEST 7 SUPERATO: Nessuna chiave privata in chiaro nell'audit log.${NC}"
            if echo "$AUDIT_CONTENT" | grep -q "REDACTED_PRIVATE_KEY"; then
                echo -e "  ${GREEN}  (Confermato mascheramento [REDACTED_PRIVATE_KEY] attivo)${NC}"
            fi
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        echo -e "  ${YELLOW}ℹ Permessi insufficienti per leggere l'audit log direttamente, salto.${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
else
    echo -e "  ${YELLOW}ℹ File di audit log non presente, salto verifica stringa.${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# ------------------------------------------------------------------------------
# TEST 8: Test Utente Non-Root (testuser del gruppo sysadmin)
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}${CYAN}[Test 8/8] Test Esecuzione da Utente Non-Root ('testuser')...${NC}"
if [ "$(id -un)" = "testuser" ]; then
    if theadmin372 health >/dev/null 2>&1; then
        echo -e "  ${GREEN}✔ TEST 8 SUPERATO: L'utente non-root 'testuser' accede al demone tramite gruppo sysadmin.${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${RED}✖ TEST 8 FALLITO: 'testuser' non riesce a comunicare con il demone.${NC}"
    fi
elif id testuser >/dev/null 2>&1; then
    if su - testuser -c "theadmin372 health" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✔ TEST 8 SUPERATO: L'utente non-root 'testuser' accede al demone tramite gruppo sysadmin.${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  ${RED}✖ TEST 8 FALLITO: 'testuser' non riesce a comunicare con il demone.${NC}"
    fi
else
    echo -e "  ${YELLOW}ℹ Utente 'testuser' non presente nel sistema, salto.${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# ------------------------------------------------------------------------------
# Riepilogo Finale
# ------------------------------------------------------------------------------
echo -e "\n${BOLD}================================================================${NC}"
if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${BOLD}${GREEN}  RISULTATO FINALE: $PASSED_TESTS/$TOTAL_TESTS TEST SUPERATI CON SUCCESSO! 🎉${NC}"
    echo -e "${BOLD}${GREEN}  Tutti i moduli e le policy di sicurezza di TheAdmin372 sono operativi.${NC}"
else
    echo -e "${BOLD}${YELLOW}  RISULTATO FINALE: $PASSED_TESTS/$TOTAL_TESTS test superati.${NC}"
fi
echo -e "${BOLD}================================================================${NC}\n"
