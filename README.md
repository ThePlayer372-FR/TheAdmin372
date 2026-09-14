# TheAdmin372 🛡️⚙️

> **Linux Root Daemon Engine & Modular CLI**
> Gestione sicura, dichiarativa e modulare di server Linux: Reverse Proxy Nginx, Firewall UFW, Container Docker, Backup cifrati con Envelope Encryption (Zero-Knowledge) e protezione integrata Anti-Privilege Escalation.

---

## 📑 Indice

- [Architettura di Sistema](#-architettura-di-sistema)
- [Caratteristiche Principali](#-caratteristiche-principali)
- [Moduli](#-moduli)
  - [1. Security Guard & Anti-Privilege Escalation](#1-security-guard--anti-privilege-escalation)
  - [2. Backup, Scheduler & Envelope Encryption](#2-backup-scheduler--envelope-encryption)
  - [3. Nginx Reverse Proxy & SSL](#3-nginx-reverse-proxy--ssl)
  - [4. Firewall UFW](#4-firewall-ufw)
  - [5. Docker & Compose Detection](#5-docker--compose-detection)
- [Guida alla CLI (`theadmin372`)](#-guida-alla-cli-theadmin372)
- [Installazione di Sistema](#-installazione-di-sistema)
- [Ambiente di Test Docker (DinD + Systemd)](#-ambiente-di-test-docker-dind--systemd)
- [Struttura del Repository](#-struttura-del-repository)

---

## 🏛️ Architettura di Sistema

```
┌────────────────────────────────────────────────────────┐
│               Utente / Amministratore                  │
│       (root oppure membro del gruppo 'sysadmin')       │
└───────────────────────────┬────────────────────────────┘
                            │  theadmin372 <comando>
                            ▼
┌────────────────────────────────────────────────────────┐
│           TheAdmin372 CLI (Rich + HTTPX)               │
└───────────────────────────┬────────────────────────────┘
                            │  UDS (Unix Domain Socket)
                            ▼  /run/theadmin372/theadmin372.sock (0660)
┌────────────────────────────────────────────────────────┐
│         TheAdmin372 Root Daemon (FastAPI Engine)       │
│  ├─ SO_PEERCRED: Tracciamento UID, GID e PID chiamante │
│  ├─ SecurityGuard: Verifica permessi anti-tampering    │
│  ├─ Zero-Knowledge Sanitizer: Audit log protetto       │
│  └─ Background Scheduler: Pianificazione cron job      │
└────────┬───────────┬────────────┬───────────┬──────────┘
         │           │            │           │
         ▼           ▼            ▼           ▼
      [ Nginx ]   [ UFW ]     [ Docker ]  [ Backup / Crypto ]
```

- **Comunicazione UDS Isolata**: Nessuna porta TCP esposta sulla rete locale; il demone comunica esclusivamente tramite Unix Domain Socket in `/run/theadmin372/theadmin372.sock`.
- **Autenticazione via Kernel (`SO_PEERCRED`)**: Il demone interroga direttamente il socket kernel Linux per identificare in modo non contraffabile l'UID, il GID e il PID di ogni processo client.
- **Accesso Delegato `sysadmin`**: I membri del gruppo di sistema `sysadmin` possono amministrare i servizi senza dover utilizzare `sudo` per invocare la CLI.
- **Esecuzione Protetta**: Il demone gira come servizio systemd dedicato (`theadmin372.service`) garantendo isolamento del processo, gestione dei crash e restart automatico.

---

## ✨ Caratteristiche Principali

- **🛡️ Anti-Privilege Escalation**: Il demone verifica che tutti i file del progetto appartengano a `root` e non siano modificabili da utenti standard prima di eseguire comandi privileged (`run_secure_command`).
- **🔐 Envelope Encryption Zero-Knowledge**: I backup vengono cifrati con una Data Encryption Key (DEK) casuale AES-256-GCM. La DEK viene sigillata con una chiave pubblica RSA 4096-bit conservata sul server. La chiave privata RSA **non risiede mai sul server**, rendendo impossibile decifrare i dati in caso di compromissione dell'host.
- **📋 Audit Trail Sanitizzato**: Ogni richiesta viene registrata in formato JSONL in `/var/log/theadmin372/audit.jsonl` con mascheramento automatico e ricorsivo di chiavi private (`[REDACTED_PRIVATE_KEY]`), password e token.
- **🚀 Prestazioni e Modernità**: Sviluppato in Python con toolchain ultrarapida `uv`, API asincrone con FastAPI, e formattazione terminale con `Rich`.

---

## 🧩 Moduli

### 1. Security Guard & Anti-Privilege Escalation
- **Obiettivo**: Prevenire vettori di privilege escalation locali. Se un utente malintenzionato riuscisse a modificare uno script Python o una configurazione del demone, potrebbe indurre il processo root a eseguire codice arbitrario.
- **Comportamento**:
  - Scansione preventiva ad ogni avvio e on-demand dei permessi di 1800+ file critici del demone.
  - Verifica che l'owner sia `root` (UID 0), che non vi siano permessi `go-w` (modifica gruppo/altri) e che tutte le directory genitrici siano sicure.
  - **Fail-Safe**: In presenza di anomalie, l'esecuzione di comandi di sistema viene bloccata e restituito un errore HTTP 403 Forbidden finché non viene applicato il comando di correzione `theadmin372 security fix`.

### 2. Backup, Scheduler & Envelope Encryption
- **Cifratura Ibrida**:
  - Compressione ad alte prestazioni `zstd` (o `gzip`).
  - Cifratura simmetrica AES-256-GCM con IV a 96-bit e tag di autenticazione a 128-bit.
  - Cifratura asimmetrica della DEK con RSA-OAEP (SHA-256).
- **Integrità SHA-256**: Generazione del digest crittografico SHA-256 dell'archivio, salvato nel manifest ed esplicitamente verificato prima di qualsiasi restore.
- **Snapshot Preventivo**: Prima di eseguire qualsiasi ripristino in-place sul filesystem di sistema, il demone crea automaticamente uno snapshot di sicurezza in `/var/backups/theadmin372/snapshots/`.
- **Schedulatore Background**: Daemon thread asincrono per l'esecuzione automatica programmata con intervalli configurabili (es. `30m`, `6h`, `24h`, `7d`) e politica di retention configurabile (rotazione degli archivi eccedenti).

### 3. Nginx Reverse Proxy & SSL
- Creazione e gestione dichiarativa di Virtual Hosts per Nginx.
- Supporto per protocolli WebSocket (`Upgrade`, `Connection`).
- Configurazione automatica dimensione massima payload (`client_max_body_size`).
- Ricarica configurazione senza downtime (`systemctl reload nginx` con fallback automatico).
- Automazione certificati SSL tramite Certbot e Let's Encrypt.

### 4. Firewall UFW
- Controllo dello stato del firewall di sistema (`active` / `inactive`).
- Ispezione delle regole numerate con supporto direzioni `IN`/`OUT`, porte, protocolli e IPv6.
- Aggiunta atomica di regole `allow` e `deny`.
- Eliminazione sicura delle regole per indice numerico.

### 5. Docker & Compose Detection
- Interazione nativa via socket UNIX `/var/run/docker.sock` tramite connessioni HTTP standard.
- Raggruppamento automatico dei container in base ai progetti **Docker Compose** tramite label standard (`com.docker.compose.project`, `com.docker.compose.service`).
- Visualizzazione tabellare con stato, uptime e porte mappate su host.

---

## 💻 Guida alla CLI (`theadmin372`)

La CLI è modulare, supporta l'auto-discovery dei comandi e visualizza tabelle e spinner interattivi con `Rich`.

### Comandi Generali & Stato
```bash
# Verifica connessione con il demone e stato di salute
theadmin372 health
```

### Modulo Security Guard
```bash
# Controllo integrità permessi dei file critici del demone
theadmin372 security check

# Ripristino automatico dei permessi corretti (Owner: root, rimozione bit di scrittura go-w)
theadmin372 security fix
```

### Modulo Backup & Restore
```bash
# 1. Genera la coppia di chiavi RSA 4096-bit (la privata viene salvata localmente, la pubblica inviata al demone)
theadmin372 backup keygen --out ~/.theadmin_backup_priv.pem

# 2. Crea un nuovo piano di backup dichiarativo
theadmin372 backup create WebApp /var/www/html /etc/nginx --compression zstd --retention 7

# 3. Gestisci i percorsi target inclusi nel piano
theadmin372 backup add WebApp /opt/data
theadmin372 backup remove WebApp /etc/nginx

# 4. Configura la schedulazione automatica
theadmin372 backup schedule WebApp --every 24h
theadmin372 backup schedule WebApp --disable

# 5. Visualizza i dettagli del piano e lo storico archivi con relativi hash SHA-256
theadmin372 backup show WebApp
theadmin372 backup list

# 6. Avvia un backup manuale immediato
theadmin372 backup run WebApp

# 7. Ripristina un archivio cifrato (Zero-Knowledge, richiede la chiave privata dell'admin)
# Ripristino in una directory di destinazione specifica:
theadmin372 backup restore WebApp --key ~/.theadmin_backup_priv.pem --target /tmp/ripristino/

# Ripristino in-place sui file originali di sistema (con snapshot preventivo automatico):
theadmin372 backup restore WebApp --key ~/.theadmin_backup_priv.pem -y

# 8. Elimina la configurazione di un piano di backup
theadmin372 backup delete WebApp
```

### Modulo Nginx Reverse Proxy
```bash
# Elenca tutti i virtual hosts configurati e il loro stato
theadmin372 nginx list

# Crea un virtual host reverse proxy con supporto WebSocket
theadmin372 nginx proxy app.mio-dominio.it http://127.0.0.1:8000 --ws --max-body 50M

# Abilita o disabilita un virtual host esistente
theadmin372 nginx disable app.mio-dominio.it
theadmin372 nginx enable app.mio-dominio.it

# Testa la sintassi e ricarica Nginx a caldo (zero-downtime)
theadmin372 nginx reload

# Configura certificato SSL con Let's Encrypt / Certbot
theadmin372 nginx ssl app.mio-dominio.it --email admin@mio-dominio.it

# Elimina definitivamente un virtual host
theadmin372 nginx delete app.mio-dominio.it --force
```

### Modulo Firewall UFW
```bash
# Mostra lo stato del firewall e l'elenco delle regole attive
theadmin372 ufw status

# Aggiungi regole per porte e protocolli specifici
theadmin372 ufw allow 8080 --proto tcp
theadmin372 ufw deny 9090 --proto tcp

# Rimuovi una regola tramite il suo indice numerico
theadmin372 ufw delete 1

# Abilita, disabilita o ricarica UFW
theadmin372 ufw enable
theadmin372 ufw disable
theadmin372 ufw reload
```

### Modulo Docker & Compose
```bash
# Elenca i container in esecuzione raggruppati per progetto Docker Compose
theadmin372 docker ps
```

### Autocompletamento Shell (Bash / Zsh)
TheAdmin372 supporta l'autocompletamento intelligente (tasto `TAB`) per tutti i comandi, sotto-comandi, flag e argomenti dinamici (domini Nginx e piani di backup esistenti):

```bash
# Installazione automatica nel sistema (/etc/bash_completion.d o ~/.bashrc)
theadmin372 completion install

# Oppure genera lo script per la tua shell
eval "$(theadmin372 completion bash)"    # per Bash
eval "$(theadmin372 completion zsh)"     # per Zsh
```

---

## 📦 Installazione di Sistema

Lo script di installazione automatizza l'intero setup su distribuzioni Debian/Ubuntu:

```bash
curl -fsSL https://gitea.theplayer372.dev/ThePlayer372/TheAdmin372/raw/branch/main/install.sh | sudo bash
```

### Cosa fa lo script:
1. Verifica i privilegi di root.
2. Crea il gruppo di sistema dedicato **`sysadmin`** e vi assegna l'utente corrente.
3. Installa le dipendenze di sistema (`python3`, `python3-venv`, `git`, `curl`).
4. Configura `uv` e installa Python nella directory condivisa di sistema `/opt/uv-python` (permessi `0755`).
5. Clona/aggiorna i sorgenti in `/opt/TheAdmin372` e sincronizza i virtualenv isolati per `daemon` e `cli`.
6. Installa l'eseguibile globale `/usr/local/bin/theadmin372` e configura l'autocompletamento in `/etc/bash_completion.d/theadmin372`.
7. Crea le cartelle di runtime e log (`/run/theadmin372`, `/var/log/theadmin372`, `/etc/theadmin372/keys`) con permessi restrittivi `root:sysadmin`.
8. Configura, abilita e avvia il servizio **systemd** `theadmin372.service`.

> [!TIP]
> Per consentire a un utente normale di gestire TheAdmin372 senza usare `sudo`:
> ```bash
> sudo usermod -aG sysadmin <nome_utente>
> ```

---

## 🐳 Ambiente di Test Docker (DinD + Systemd)

È inclusa una configurazione Docker completa per testare in totale isolamento tutti i moduli, compresi i comandi che richiedono privilegi root, systemd come PID 1, Docker-in-Docker e regole iptables/UFW.

### Avvio Sandbox di Test
```bash
# Avvia il container in background
docker compose up --build -d
```

### Esecuzione della Suite di Test Completa (9/9 Test)
All'interno del container è disponibile lo script di collaudo automatizzato `test-all`:

```bash
# Esegui tutti i test come utente non-root del gruppo sysadmin (testuser)
docker exec -it -u testuser theadmin-container test-all
```

#### Test eseguiti automaticamente:
- `[Test 1/9]` Connessione UDS e Healthcheck demone
- `[Test 2/9]` Controllo integrità permessi Anti-Privilege Escalation (1800+ file)
- `[Test 3/9]` Firewall UFW (regole allow, deny, delete)
- `[Test 4/9]` Nginx Reverse Proxy (creazione vhost con o senza estensione .conf, WebSocket, disable, enable, reload, clean)
- `[Test 5/9]` Docker-in-Docker (pull immagine Alpine, compose up, verifica porte, compose down)
- `[Test 6/9]` Backup con Envelope Encryption (RSA 4096 + AES-256-GCM), verifica hash SHA-256 e Restore
- `[Test 7/9]` Verifica Zero-Knowledge dell'Audit Log (nessuna chiave privata esposta in `/var/log/theadmin372/audit.jsonl`)
- `[Test 8/9]` Verifica accesso e permessi dell'utente non-root `testuser`
- `[Test 9/9]` Verifica generazione e funzionamento script di autocompletamento shell

---

## 📁 Struttura del Repository

```
TheAdmin372/
├── .gitignore                      # Esclusioni globali (cache, chiavi, venv, log)
├── Dockerfile.test                 # Sandbox container con Ubuntu 24.04, Systemd & DinD
├── docker-compose.yml              # Configurazione compose con cgroup e volumi isolati
├── install.sh                      # Installer di produzione bare-metal per Linux
├── test-all.sh                     # Test runner automatizzato per tutti gli 8 sottosistemi
├── Test/
│   └── docker-compose.yml          # Compose stack di test per il modulo Docker
├── cli/                            # Client CLI Modulare
│   ├── pyproject.toml              # Definizione pacchetto CLI e dipendenze (Rich, HTTPX)
│   ├── uv.lock                     # Lockfile deterministico CLI
│   └── cli/
│       ├── main.py                 # Entry point CLI e router dei comandi
│       ├── client.py               # Client HTTP over Unix Domain Socket
│       ├── base.py                 # Interfaccia base per i comandi CLI
│       └── commands/
│           ├── backup.py           # Comandi `theadmin372 backup ...`
│           ├── docker.py           # Comandi `theadmin372 docker ...`
│           ├── nginx.py            # Comandi `theadmin372 nginx ...`
│           ├── security.py         # Comandi `theadmin372 security ...`
│           └── ufw.py              # Comandi `theadmin372 ufw ...`
└── daemon/                         # Demone di Sistema Root
    ├── pyproject.toml              # Definizione pacchetto Demone e dipendenze (FastAPI, Cryptography)
    ├── uv.lock                     # Lockfile deterministico Demone
    ├── main.py                     # Entry point del processo demone
    ├── service/
    │   └── theadmin372.service     # Unit file systemd di produzione
    ├── core/
    │   ├── server.py               # Configurazione server FastAPI, UDS e middleware audit
    │   ├── logger.py               # Logger JSONL audit e sanitizzazione Zero-Knowledge
    │   └── security.py             # SecurityGuard e verifica anti-privilege escalation
    └── modules/
        ├── base.py                 # Base class per i moduli del demone
        ├── backup/                 # Engine backup, crittografia envelope, scheduler e storage
        ├── docker/                 # Client Docker Engine UDS e compose detector
        ├── nginx/                  # Gestore virtual hosts e reload Nginx
        ├── security/               # Endpoints REST per audit e fix permessi
        └── ufw/                    # Parser e controller firewall UFW
```

---

## 🔒 Sicurezza e Best Practices

- **Zero-Knowledge sul Server**: La chiave privata RSA per decifrare i backup non deve mai essere salvata sul server. Generala e conservala esclusivamente sulla workstation dell'amministratore.
- **Permessi Ristretti**:
  - `/run/theadmin372`: permessi `0770 root:sysadmin`.
  - `/run/theadmin372/theadmin372.sock`: permessi `0660 root:sysadmin`.
  - `/var/log/theadmin372/audit.jsonl`: permessi `0640 root:sysadmin`.
  - `/etc/theadmin372/keys/backup_pub.pem`: permessi `0644 root:root`.
- **Esecuzione Comandi**: Ogni comando invocato dal demone viene sottoposto a validazione dei permessi preventivi tramite `run_secure_command()` per prevenire qualsiasi escalation di privilegi.