from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from logging.config import dictConfig
from typing import Any, Dict
from pathlib import Path
import logging
import json
import os
import re

# Cartelle standard per demoni Linux
LOG_DIR = Path("/var/log/theadmin372")
APP_LOG_FILE = LOG_DIR / "daemon.log"
AUDIT_LOG_FILE = LOG_DIR / "audit.jsonl"

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"private[-_]?key", re.IGNORECASE),
    re.compile(r"priv[-_]?key", re.IGNORECASE),
    re.compile(r"privkey", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"passphrase", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"api[-_]?key", re.IGNORECASE),
]

PEM_PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----(?:\\n|[\s\S])*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
    re.IGNORECASE,
)


def mask_sensitive_data(data: Any) -> Any:
    """
    Maschera ricorsivamente dati e parametri sensibili prima della registrazione nell'audit log.
    - Chiavi crittografiche private (RSA, EC, PKCS#8) -> [REDACTED_PRIVATE_KEY]
    - Password, token, segreti, credenziali -> [REDACTED_SECRET]
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_str = str(k)
            # Controlla se il nome della chiave è sensibile
            if any(pat.search(k_str) for pat in SENSITIVE_KEY_PATTERNS):
                if any(p.search(k_str) for p in [re.compile(r"private|priv", re.IGNORECASE)]):
                    sanitized[k] = "[REDACTED_PRIVATE_KEY]"
                else:
                    sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = mask_sensitive_data(v)
        return sanitized
    elif isinstance(data, (list, tuple)):
        sanitized_list = [mask_sensitive_data(item) for item in data]
        return type(data)(sanitized_list)
    elif isinstance(data, str):
        # Riconosce e oscura blocchi PEM contenenti chiavi private
        if "PRIVATE KEY-----" in data:
            return PEM_PRIVATE_KEY_REGEX.sub("[REDACTED_PRIVATE_KEY]", data)
        return data
    return data


def scrub_audit_log_file(log_file: Path = AUDIT_LOG_FILE) -> int:
    """
    Rimuove e maschera retroattivamente chiavi private e dati sensibili
    già scritti nel file di audit trail (/var/log/theadmin372/audit.jsonl).
    Ritorna il numero di righe corrette.
    """
    if not log_file.is_file():
        return 0

    scrubbed_count = 0
    try:
        lines = log_file.read_text(encoding="utf-8").splitlines()
        new_lines = []
        for line in lines:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                sanitized_data = mask_sensitive_data(data)
                sanitized_line = json.dumps(sanitized_data)
                if sanitized_line != line:
                    scrubbed_count += 1
                new_lines.append(sanitized_line)
            except Exception:
                sanitized_line = PEM_PRIVATE_KEY_REGEX.sub("[REDACTED_PRIVATE_KEY]", line)
                if sanitized_line != line:
                    scrubbed_count += 1
                new_lines.append(sanitized_line)

        if scrubbed_count > 0:
            log_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            os.chmod(log_file, 0o600)
    except Exception as e:
        logger.warning(f"Impossibile eseguire lo scrub del log di audit {log_file}: {e}")

    return scrubbed_count


class JSONAuditFormatter(logging.Formatter):
    """Formatta ogni log di audit come riga JSON autonoma valida (JSONL) con mascheramento preventivo."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        # Inietta metadati custom passati tramite extra={'audit_data': {...}}
        if hasattr(record, "audit_data"):
            log_entry["audit"] = mask_sensitive_data(record.audit_data)  # pyright: ignore[reportAttributeAccessIssue]

        return json.dumps(log_entry)


def setup_logging(debug: bool = False) -> None:
    # Se eseguito in locale/sviluppo senza permessi root su /var/log
    target_dir = LOG_DIR if os.access("/var/log", os.W_OK) else Path("/tmp/theadmin372/logs")
    target_dir.mkdir(parents=True, exist_ok=True)

    app_log = target_dir / "daemon.log"
    audit_log = target_dir / "audit.jsonl"

    # Esegui lo scrub preventivo su eventuali log preesistenti per eliminare chiavi private passate
    scrub_audit_log_file(audit_log)

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "audit_json": {
                "()": JSONAuditFormatter,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "level": "DEBUG" if debug else "INFO",
                "stream": "ext://sys.stdout",
            },
            "app_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": str(app_log),
                "formatter": "standard",
                "maxBytes": 10 * 1024 * 1024,  # 10 MB
                "backupCount": 5,
                "encoding": "utf-8",
                "level": "INFO",
            },
            "audit_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": str(audit_log),
                "formatter": "audit_json",
                "maxBytes": 20 * 1024 * 1024,  # 20 MB
                "backupCount": 10,
                "encoding": "utf-8",
                "level": "INFO",
            },
        },
        "loggers": {
            "": {  # Root logger
                "handlers": ["console", "app_file"],
                "level": "INFO",
            },
            "uvicorn.error": {
                "level": "INFO",
                "handlers": ["console", "app_file"],
                "propagate": False,
            },
            "audit": {
                "handlers": ["audit_file"],
                "level": "INFO",
                "propagate": False,  # Non spammare l'audit su stdout
            },
        },
    }

    dictConfig(config)

    # Restringe i permessi dell'audit log a 0640 root:sysadmin (lettura per sysadmin, scrittura solo root)
    if audit_log.exists():
        try:
            import grp
            gid = grp.getgrnam("sysadmin").gr_gid
            os.chown(audit_log, 0, gid)
            os.chmod(audit_log, 0o640)
        except Exception:
            os.chmod(audit_log, 0o640)


# Logger applicativo per il codice normale
logger = logging.getLogger("theadmin")
# Logger separato per l'audit trail
audit_logger = logging.getLogger("audit")


def log_audit(actor: str, module: str, action: str, params: Dict[str, Any], status: str, detail: str = ""):
    """Helper tipizzato per registrare un'azione di sistema con sanitizzazione preventiva automatica."""
    sanitized_params = mask_sensitive_data(params)
    sanitized_detail = mask_sensitive_data(detail) if isinstance(detail, str) else detail

    payload = {
        "actor": actor,
        "module": module,
        "action": action,
        "params": sanitized_params,
        "status": status,  # "SUCCESS", "FAILED", "DENIED"
        "detail": sanitized_detail,
    }
    audit_logger.info("AUDIT_EVENT", extra={"audit_data": payload})