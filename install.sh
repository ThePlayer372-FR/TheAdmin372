#!/usr/bin/env bash
# ==============================================================================
# TheAdmin372 - Script di Installazione Completo di Sistema
# ==============================================================================
# Questo script automatizza:
# 1. Verifica dei privilegi di root
# 2. Creazione del gruppo di sistema 'sysadmin'
# 3. Installazione/Verifica delle dipendenze di sistema (Python 3, Git, Curl, UV)
# 4. Download/Clonazione da repository Git in /opt/TheAdmin372
# 5. Configurazione degli ambienti virtuali separati per Demone e CLI
# 6. Installazione del comando universale 'theadmin372' in /usr/local/bin
# 7. Applicazione delle policy di sicurezza e hardening dei permessi
# 8. Installazione, abilitazione e avvio del servizio systemd
# ==============================================================================

set -e

# Colori per l'output nel terminale
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "\n${BOLD}${CYAN}================================================================${NC}"
echo -e "${BOLD}${CYAN}          Installazione del Demone e della CLI TheAdmin372      ${NC}"
echo -e "${BOLD}${CYAN}================================================================${NC}\n"

# ------------------------------------------------------------------------------
# 1. Verifica Privilegi di Root
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}✖ Errore: Questo script richiede privilegi di amministratore (root).${NC}"
    echo -e "  Esegui: ${YELLOW}sudo $0${NC}\n"
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Creazione del Gruppo di Sistema 'sysadmin'
# ------------------------------------------------------------------------------
echo -e "${CYAN}[1/8] Configurazione gruppo di sistema 'sysadmin'...${NC}"
if ! getent group sysadmin >/dev/null 2>&1; then
    groupadd -r sysadmin
    echo -e "  ${GREEN}✔ Gruppo di sistema 'sysadmin' creato con successo.${NC}"
else
    echo -e "  ${GREEN}✔ Gruppo 'sysadmin' già presente nel sistema.${NC}"
fi

# Se eseguito tramite sudo da un utente normale, aggiungilo a sysadmin
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    echo -e "  Aggiunta dell'utente corrente (${BOLD}$SUDO_USER${NC}) al gruppo 'sysadmin'..."
    usermod -aG sysadmin "$SUDO_USER"
    echo -e "  ${GREEN}✔ Utente '$SUDO_USER' abilitato all'interazione con il socket del demone.${NC}"
fi

# ------------------------------------------------------------------------------
# 3. Verifica / Installazione Dipendenze di Sistema
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[2/8] Verifica dei pacchetti e prerequisiti di sistema...${NC}"
MISSING_PKGS=()
for pkg in python3 python3-venv git curl; do
    if ! command -v "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo -e "  Installazione pacchetti mancanti: ${MISSING_PKGS[*]}..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        # Non bloccare l'installazione se repository o PPA esterni di terze parti falliscono
        apt-get update -qq 2>/dev/null || true
        apt-get install -y -qq "${MISSING_PKGS[@]}" || apt-get install -y "${MISSING_PKGS[@]}"
    else
        echo -e "${YELLOW}  Attenzione: Package manager apt-get non rilevato. Assicurati che ${MISSING_PKGS[*]} siano installati.${NC}"
    fi
fi

# Verifica o installazione di uv (astral.sh/uv) a livello di sistema
if ! command -v uv >/dev/null 2>&1; then
    echo -e "  Installazione di 'uv' in /usr/local/bin..."
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
    chmod +x /usr/local/bin/uv || true
    echo -e "  ${GREEN}✔ 'uv' installato con successo in /usr/local/bin/uv.${NC}"
else
    echo -e "  ${GREEN}✔ 'uv' già presente ($(uv --version)).${NC}"
fi

# Configurazione directory Python globale per uv condivisa con tutti gli utenti
export UV_PYTHON_INSTALL_DIR="/opt/uv-python"
mkdir -p /opt/uv-python
chmod 0755 /opt/uv-python

# ------------------------------------------------------------------------------
# 4. Download / Clonazione da Repository Git in /opt/TheAdmin372
# ------------------------------------------------------------------------------
INSTALL_DIR="/opt/TheAdmin372"
GIT_REPO_URL="${THEADMIN_GIT_URL:-https://github.com/ThePlayer372-FR/TheAdmin372.git}"

echo -e "\n${CYAN}[3/8] Download e sincronizzazione sorgenti in $INSTALL_DIR...${NC}"
CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "  Repository Git esistente in $INSTALL_DIR, sincronizzazione aggiornamenti..."
    git -C "$INSTALL_DIR" pull || true
elif [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/daemon/main.py" ]; then
    echo -e "  Directory $INSTALL_DIR già presente con i sorgenti del demone."
else
    echo -e "  Tentativo di clonazione da repository Git: ${YELLOW}$GIT_REPO_URL${NC}..."
    if git clone "$GIT_REPO_URL" "$INSTALL_DIR"; then
        echo -e "  ${GREEN}✔ Clonazione da Git completata con successo in $INSTALL_DIR.${NC}"
    else
        # Fallback se lo script è eseguito all'interno della cartella dei sorgenti locali
        if [ -f "$CURRENT_DIR/daemon/main.py" ] && [ "$CURRENT_DIR" != "$INSTALL_DIR" ]; then
            echo -e "  ${YELLOW}ℹ Git clone non riuscito, fallback sui sorgenti locali da '$CURRENT_DIR'...${NC}"
            mkdir -p "$INSTALL_DIR"
            cp -a "$CURRENT_DIR/." "$INSTALL_DIR/"
            echo -e "  ${GREEN}✔ Sorgenti locali installati con successo in $INSTALL_DIR.${NC}"
        else
            echo -e "\n${RED}✖ Errore critico: Impossibile clonare il repository da '$GIT_REPO_URL'.${NC}"
            echo -e "  Verifica che il repository esista e sia accessibile, oppure imposta:"
            echo -e "  ${YELLOW}export THEADMIN_GIT_URL='<url_repository>'${NC}\n"
            exit 1
        fi
    fi
fi

# ------------------------------------------------------------------------------
# 5. Configurazione Virtual Environment Demone & CLI
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[4/8] Configurazione degli ambienti virtuali Python (.venv)...${NC}"

# Demone
echo -e "  Sincronizzazione ambiente demone ($INSTALL_DIR/daemon)..."
cd "$INSTALL_DIR/daemon"
uv sync

# CLI
echo -e "  Sincronizzazione ambiente CLI ($INSTALL_DIR/cli)..."
cd "$INSTALL_DIR/cli"
uv sync

echo -e "  ${GREEN}✔ Ambienti virtuali sincronizzati correttamente.${NC}"

# ------------------------------------------------------------------------------
# 6. Installazione Comando Globale 'theadmin372' in /usr/local/bin
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[5/8] Installazione eseguibile globale 'theadmin372'...${NC}"
cat << 'EOF' > /usr/local/bin/theadmin372
#!/bin/sh
# ==============================================================================
# TheAdmin372 - Wrapper Globale CLI
# Eseguibile da tutti gli utenti del sistema (root e membri del gruppo sysadmin)
# ==============================================================================
export UV_PYTHON_INSTALL_DIR="/opt/uv-python"
export PYTHONDONTWRITEBYTECODE=1

if [ ! -x /opt/TheAdmin372/cli/.venv/bin/python ] && [ "$(id -u)" -eq 0 ]; then
    /usr/local/bin/uv sync --frozen --project /opt/TheAdmin372/cli >/dev/null 2>&1 || true
    chmod -R a+rX /opt/TheAdmin372/cli/.venv 2>/dev/null || true
fi

if [ -x /opt/TheAdmin372/cli/.venv/bin/python ]; then
    PYTHONPATH=/opt/TheAdmin372/cli exec /opt/TheAdmin372/cli/.venv/bin/python -m cli.main "$@"
else
    echo "Errore: ambiente TheAdmin372 CLI in /opt/TheAdmin372/cli/.venv non inizializzato." >&2
    echo "Esegui una volta theadmin372 come root oppure avvia theadmin372.service." >&2
    exit 1
fi
EOF

chmod 0755 /usr/local/bin/theadmin372
echo -e "  ${GREEN}✔ Comando 'theadmin372' installato con permessi 0755 in /usr/local/bin/theadmin372.${NC}"

# Configurazione Autocompletamento Bash di Sistema
mkdir -p /etc/bash_completion.d
/usr/local/bin/theadmin372 completion bash > /etc/bash_completion.d/theadmin372 2>/dev/null || true
chmod 0644 /etc/bash_completion.d/theadmin372 2>/dev/null || true
echo -e "  ${GREEN}✔ Autocompletamento Bash di sistema configurato in /etc/bash_completion.d/theadmin372.${NC}"

# ------------------------------------------------------------------------------
# 7. Struttura Directory di Sistema e Hardening dei Permessi
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[6/8] Creazione directory di sistema e applicazione Hardening...${NC}"

# Creazione cartelle di sistema
mkdir -p /etc/theadmin372/keys
mkdir -p /etc/theadmin372/backups/configs
mkdir -p /var/backups/theadmin372/archives
mkdir -p /var/backups/theadmin372/snapshots
mkdir -p /var/log/theadmin372
mkdir -p /run/theadmin372

# Hardening Anti-Privilege Escalation:
# Tutti i file del demone devono appartenere a root e NON essere modificabili da non-root
chown -R root:root "$INSTALL_DIR" /etc/theadmin372 /var/backups/theadmin372 /opt/uv-python 2>/dev/null || true

# Rendiamo file e cartelle leggibili ed eseguibili per consentire a tutti gli utenti di eseguire la CLI,
# ma rimuoviamo tassativamente i bit di scrittura per gruppo e altri (go-w)
chmod -R u=rwX,go=rX "$INSTALL_DIR" /opt/uv-python 2>/dev/null || true
chmod -R go-w "$INSTALL_DIR" /etc/theadmin372 /opt/uv-python 2>/dev/null || true

# Socket e log directory con accesso riservato a root e gruppo sysadmin
chown -R root:sysadmin /run/theadmin372 /var/log/theadmin372
chmod 0770 /run/theadmin372
chmod 0750 /var/log/theadmin372

# Se esistono file di log audit, proteggili con permessi 0600
if [ -f /var/log/theadmin372/audit.jsonl ]; then
    chmod 0600 /var/log/theadmin372/audit.jsonl
fi

echo -e "  ${GREEN}✔ Hardening dei permessi applicato (Owner: root, no non-root write).${NC}"

# ------------------------------------------------------------------------------
# 8. Installazione e Avvio Servizio Systemd
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[7/8] Configurazione e avvio del servizio di sistema systemd...${NC}"
SERVICE_SRC="$INSTALL_DIR/daemon/service/theadmin372.service"
SERVICE_DST="/etc/systemd/system/theadmin372.service"

if [ -f "$SERVICE_SRC" ]; then
    cp "$SERVICE_SRC" "$SERVICE_DST"
    chmod 0644 "$SERVICE_DST"
    chown root:root "$SERVICE_DST"

    systemctl daemon-reload
    systemctl enable theadmin372.service
    systemctl restart theadmin372.service
    echo -e "  ${GREEN}✔ Servizio 'theadmin372.service' abilitato e avviato.${NC}"
else
    echo -e "  ${YELLOW}⚠️ File servizio '$SERVICE_SRC' non trovato. Impossibile configurare systemd.${NC}"
fi

# ------------------------------------------------------------------------------
# 9. Healthcheck e Verifica Finale
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}[8/8] Esecuzione test di connessione e audit di sicurezza...${NC}"
sleep 1.5

if theadmin372 health >/dev/null 2>&1; then
    echo -e "  ${GREEN}✔ Demone raggiungibile e operativo tramite UNIX socket!${NC}"
else
    echo -e "  ${YELLOW}ℹ Demone in fase di avvio iniziale... (verifica con: systemctl status theadmin372.service)${NC}"
fi

# Esegui l'audit di sicurezza integrato
theadmin372 security check || true

echo -e "\n${BOLD}${GREEN}================================================================${NC}"
echo -e "${BOLD}${GREEN}        Installazione di TheAdmin372 completata con successo!   ${NC}"
echo -e "${BOLD}${GREEN}================================================================${NC}"
echo -e "\n${BOLD}Riepilogo Configurazione:${NC}"
echo -e " • Percorso Sorgenti:      ${CYAN}/opt/TheAdmin372${NC}"
echo -e " • Comando CLI Globale:    ${CYAN}theadmin372${NC} (disponibile per tutti gli utenti)"
echo -e " • Gruppo di Sistema:      ${CYAN}sysadmin${NC}"
echo -e " • Socket UNIX:            ${CYAN}/run/theadmin372/theadmin372.sock${NC} (permessi 0660 root:sysadmin)"
echo -e " • Servizio Systemd:       ${CYAN}theadmin372.service${NC}\n"
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    echo -e "${BOLD}Nota per l'utente '$SUDO_USER':${NC}"
    echo -e "  Sei stato aggiunto al gruppo 'sysadmin'. Per attivare il nuovo gruppo nella sessione terminale corrente:"
    echo -e "  👉 ${YELLOW}newgrp sysadmin${NC}  (oppure effettua logout e riconnettiti via SSH)\n"
else
    echo -e "${BOLD}Suggerimento:${NC} Per consentire ad un utente normale di gestire il demone senza sudo:"
    echo -e "  ${YELLOW}sudo usermod -aG sysadmin <nome_utente>${NC}\n"
fi