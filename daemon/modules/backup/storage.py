import os
import re
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from .models import BackupPlan, ArchiveItem

CONFIGS_DIR = Path(os.getenv("THEADMIN_CONFIG_DIR", "/etc/theadmin372")) / "backups" / "configs"
KEYS_DIR = Path(os.getenv("THEADMIN_CONFIG_DIR", "/etc/theadmin372")) / "keys"
ARCHIVES_BASE_DIR = Path(os.getenv("THEADMIN_BACKUP_DIR", "/var/backups/theadmin372")) / "archives"
SNAPSHOTS_BASE_DIR = Path(os.getenv("THEADMIN_BACKUP_DIR", "/var/backups/theadmin372")) / "snapshots"

SERVER_PUBLIC_KEY_PATH = KEYS_DIR / "backup_pub.pem"

FORBIDDEN_ROOTS = [
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/lost+found",
]


def ensure_directories():
    """Garantisce l'esistenza delle directory di base per configurazioni, chiavi e archivi."""
    for d in [CONFIGS_DIR, KEYS_DIR, ARCHIVES_BASE_DIR, SNAPSHOTS_BASE_DIR]:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass


def format_bytes(num_bytes: int) -> str:
    """Formatta i byte in unità umane leggibili (KB, MB, GB)."""
    val = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(val) < 1024.0:
            return f"{val:3.1f} {unit}" if unit != "B" else f"{int(val)} B"
        val /= 1024.0
    return f"{val:.1f} PB"


def validate_plan_name(name: str) -> str:
    """Valida il nome del piano per prevenire path traversal e caratteri non ammessi."""
    name = name.strip()
    if not name:
        raise ValueError("Il nome del piano non può essere vuoto")
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        raise ValueError("Il nome del piano può contenere solo caratteri alfanumerici, trattini e underscore")
    return name


def validate_backup_path(path_str: str) -> str:
    """
    Valida un percorso filesystem da includere nel backup:
    - Obbligo di percorso assoluto
    - Nessun path traversal
    - Divieto di cartelle di sistema speciali (/proc, /sys, /dev, /run)
    """
    if not path_str or not isinstance(path_str, str):
        raise ValueError("Il percorso specificato non è valido")

    path_str = path_str.strip()
    raw_p = Path(path_str)
    if not raw_p.is_absolute():
        raise ValueError(f"Il percorso deve essere assoluto: '{path_str}'")

    p = raw_p.resolve()
    resolved_str = str(p)

    if resolved_str == "/":
        raise ValueError("Non è consentito inserire l'intero filesystem radice '/' nel piano")

    for forbidden in FORBIDDEN_ROOTS:
        if resolved_str == forbidden or resolved_str.startswith(f"{forbidden}/"):
            raise ValueError(f"Percorso di sistema speciale non consentito: '{resolved_str}'")

    return resolved_str


def get_plan_config_path(name: str) -> Path:
    clean_name = validate_plan_name(name)
    return CONFIGS_DIR / f"{clean_name}.json"


def get_plan_archive_dir(name: str) -> Path:
    clean_name = validate_plan_name(name)
    return ARCHIVES_BASE_DIR / clean_name


def save_plan(plan: BackupPlan) -> None:
    """Salva la configurazione del piano su file JSON in modo atomico."""
    ensure_directories()
    config_path = get_plan_config_path(plan.name)
    tmp_path = config_path.parent / f".tmp_{config_path.name}"

    data = plan.model_dump()
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    tmp_path.replace(config_path)


def load_plan(name: str) -> Optional[BackupPlan]:
    """Carica un piano di backup da file JSON."""
    ensure_directories()
    config_path = get_plan_config_path(name)
    if not config_path.is_file():
        return None

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return BackupPlan(**data)
    except Exception as e:
        raise ValueError(f"Errore lettura configurazione piano '{name}': {e}")


def list_plans() -> List[BackupPlan]:
    """Restituisce l'elenco di tutti i piani registrati."""
    ensure_directories()
    plans: List[BackupPlan] = []
    if not CONFIGS_DIR.exists():
        return plans

    for f in sorted(CONFIGS_DIR.glob("*.json")):
        if f.name.startswith("."):
            continue
        plan_name = f.stem
        loaded = load_plan(plan_name)
        if loaded:
            plans.append(loaded)
    return plans


def delete_plan(name: str) -> bool:
    """Elimina il file di configurazione del piano."""
    config_path = get_plan_config_path(name)
    if config_path.is_file():
        config_path.unlink()
        return True
    return False


def calculate_sha256(file_path: Path) -> str:
    """Calcola l'hash SHA-256 di un file a blocchi da 64KB."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_or_create_archive_sha256(archive_path: Path) -> str:
    """Recupera l'hash SHA-256 dalla cache companion (.sha256) o lo calcola."""
    sha_file = archive_path.with_name(archive_path.name + ".sha256")
    if sha_file.is_file():
        try:
            cached = sha_file.read_text(encoding="utf-8").strip()
            if len(cached) == 64 and all(c in "0123456789abcdefABCDEF" for c in cached):
                return cached.lower()
        except Exception:
            pass

    sha = calculate_sha256(archive_path)
    try:
        sha_file.write_text(sha, encoding="utf-8")
    except Exception:
        pass
    return sha


def list_plan_archives(name: str) -> List[ArchiveItem]:
    """Elenca tutti gli archivi generati per un determinato piano, ordinati dal più recente."""
    archive_dir = get_plan_archive_dir(name)
    if not archive_dir.is_dir():
        return []

    items: List[ArchiveItem] = []
    for f in archive_dir.iterdir():
        if f.name.startswith(".") or f.name.endswith(".sha256"):
            continue
        if not f.is_file():
            continue

        st = f.stat()
        sha = get_or_create_archive_sha256(f)
        created_dt = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        is_enc = f.name.endswith(".enc")
        comp = "zstd" if ".zst" in f.name else ("gz" if ".gz" in f.name else "none")

        items.append(
            ArchiveItem(
                filename=f.name,
                size_bytes=st.st_size,
                size_human=format_bytes(st.st_size),
                created_at=created_dt,
                sha256=sha,
                is_encrypted=is_enc,
                compression=comp,
            )
        )

    items.sort(key=lambda x: x.created_at, reverse=True)
    return items


def prune_plan_archives(name: str, retention_count: int) -> List[str]:
    """
    Rimuove gli archivi più vecchi che eccedono il numero di ritenzione configurato.
    Restituisce la lista dei nomi di file eliminati.
    """
    if retention_count < 1:
        return []

    archives = list_plan_archives(name)
    if len(archives) <= retention_count:
        return []

    to_prune = archives[retention_count:]
    pruned_names = []
    archive_dir = get_plan_archive_dir(name)

    for item in to_prune:
        archive_path = archive_dir / item.filename
        sha_path = archive_dir / (item.filename + ".sha256")
        try:
            if archive_path.is_file():
                archive_path.unlink()
                pruned_names.append(item.filename)
            if sha_path.is_file():
                sha_path.unlink()
        except Exception:
            pass

    return pruned_names


def save_server_public_key(pub_key_pem: str) -> Path:
    """Salva la chiave pubblica RSA in /etc/theadmin372/keys/backup_pub.pem con permessi 0644."""
    ensure_directories()
    pub_key_pem = pub_key_pem.strip()
    if "-----BEGIN PUBLIC KEY-----" not in pub_key_pem:
        raise ValueError("Il contenuto fornito non è una chiave pubblica PEM valida")

    tmp_path = SERVER_PUBLIC_KEY_PATH.with_name(f".tmp_{SERVER_PUBLIC_KEY_PATH.name}")
    tmp_path.write_text(pub_key_pem + "\n", encoding="utf-8")
    os.chmod(tmp_path, 0o644)
    tmp_path.replace(SERVER_PUBLIC_KEY_PATH)
    return SERVER_PUBLIC_KEY_PATH


def has_server_public_key() -> bool:
    """Verifica se la chiave pubblica del server è presente su disco."""
    return SERVER_PUBLIC_KEY_PATH.is_file()
