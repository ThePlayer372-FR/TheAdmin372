import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional
from core.logger import logger, log_audit, scrub_audit_log_file


class InsecurePermissionsError(PermissionError):
    """Sollevata quando l'esecuzione di comandi viene bloccata a causa di permessi insicuri."""

    def __init__(self, message: str, violations: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.violations = violations or []


PROJECT_ROOT = Path(__file__).resolve().parent.parent  # /opt/TheAdmin372/daemon
CONFIG_DIR = Path(os.getenv("THEADMIN_CONFIG_DIR", "/etc/theadmin372"))
SERVICE_FILE = Path("/etc/systemd/system/theadmin372.service")

# Cache temporanea delle violazioni per evitare scansioni ripetute I/O intensive su ogni comando
_security_cache_time: float = 0.0
_security_cache_violations: List[Dict[str, Any]] = []
_CACHE_TTL_SECONDS: float = 5.0


def clear_security_cache() -> None:
    """Invalida la cache dei controlli di sicurezza."""
    global _security_cache_time, _security_cache_violations
    _security_cache_time = 0.0
    _security_cache_violations = []


def is_read_only_filesystem(path: Path) -> bool:
    """
    Verifica se il percorso si trova su un filesystem montato in sola lettura (Read-Only / ro).
    Se il filesystem è RO, nessun processo può modificare i file tramite filesystem locale.
    """
    try:
        resolved = path.resolve()
        check_target = resolved if resolved.exists() else resolved.parent
        while not check_target.exists() and check_target != check_target.parent:
            check_target = check_target.parent

        if check_target.exists() and hasattr(os, "ST_RDONLY"):
            st = os.statvfs(str(check_target))
            if bool(st.f_flag & os.ST_RDONLY):
                return True
    except Exception:
        pass
    return False


def is_path_modifiable_by_non_root(path: Path) -> Tuple[bool, str]:
    """
    Verifica rigorosamente se un file o cartella può essere modificato da utenti non-root (UID != 0).
    Ritorna (True, motivo) se il percorso è INSICURO (modificabile da non-root).
    Ritorna (False, "Sicuro") se il percorso è protetto.
    """
    if not path.exists():
        return False, "Percorso non esistente"

    try:
        # Risolvi eventuali symlink per verificare il target reale
        target = path.resolve()
        st = target.stat()
    except Exception as e:
        return True, f"Errore durante stat del percorso: {e}"

    mode = st.st_mode
    uid = st.st_uid
    gid = st.st_gid

    # Se il filesystem è montato in sola lettura (:ro):
    if is_read_only_filesystem(target):
        # Su filesystem RO, nessun utente può scrivere, ma verifichiamo comunque
        # che non sia world-writable per prevenire rischi in caso di rimontaggio RW.
        if (mode & 0o002) != 0:
            return True, f"Permessi world-writable (o+w, {oct(mode)}) su filesystem RO"
        return False, "Protetto da mount in sola lettura (Read-Only)"

    # Se il demone non gira come root (es. dev locale senza privilegi), non bloccare se non siamo root
    if os.geteuid() != 0 and os.getenv("THEADMIN_SECURITY_STRICT", "0") != "1":
        return False, "Demone non in esecuzione come root (ambiente non privilegiato)"

    # Su filesystem scrivibile:
    # 1. Proprietario DEVE essere root (UID == 0)
    if uid != 0:
        return True, f"Proprietario non-root (UID={uid}): modificabile dal proprietario"

    # 2. Non deve essere world-writable (o+w, bit 0o002)
    if (mode & 0o002) != 0:
        return True, f"Permessi world-writable (o+w, {oct(mode)}): modificabile da chiunque"

    # 3. Non deve essere group-writable a meno che il gruppo non sia root (GID == 0)
    if (mode & 0o020) != 0 and gid != 0:
        return True, f"Permessi group-writable (g+w, {oct(mode)}) con gruppo non-root (GID={gid})"

    # 4. Verifica di sicurezza sulle directory genitrici (fino alla radice /)
    # Se una directory genitrice è modificabile da non-root, il file può essere sostituito o ridenominato
    curr = target.parent
    while curr != curr.parent:
        if curr.exists():
            if is_read_only_filesystem(curr):
                break
            try:
                pst = curr.stat()
                # Se la cartella è world-writable senza sticky bit (bit 0o1000)
                if (pst.st_mode & 0o002) != 0 and not (pst.st_mode & 0o1000):
                    return True, f"Directory genitrice '{curr}' è world-writable senza sticky bit ({oct(pst.st_mode)})"
                # Se la cartella genitrice appartiene a un utente non-root
                if pst.st_uid != 0:
                    return True, f"Directory genitrice '{curr}' appartiene a utente non-root (UID={pst.st_uid})"
            except Exception:
                pass
        curr = curr.parent

    return False, "Sicuro (owner root, non modificabile da non-root)"


def get_critical_paths() -> List[Path]:
    """Elenco di tutti i file e directory critici del demone da verificare."""
    paths: List[Path] = [
        PROJECT_ROOT,
        PROJECT_ROOT / "main.py",
        PROJECT_ROOT / "core",
        PROJECT_ROOT / "modules",
        CONFIG_DIR,
        CONFIG_DIR / "keys",
        CONFIG_DIR / "backups",
        CONFIG_DIR / "backups" / "configs",
    ]

    if SERVICE_FILE.exists():
        paths.append(SERVICE_FILE)

    venv_dir = PROJECT_ROOT / ".venv"
    if venv_dir.exists():
        paths.append(venv_dir)
        venv_bin = venv_dir / "bin"
        if venv_bin.exists():
            paths.append(venv_bin)
            for bin_file in venv_bin.glob("*"):
                if bin_file.is_file():
                    paths.append(bin_file)

    # Includi tutti i file Python del demone
    for py_file in PROJECT_ROOT.glob("**/*.py"):
        # Ignora pycache e directory nascoste non critiche
        if "__pycache__" in str(py_file) or ".git" in str(py_file):
            continue
        paths.append(py_file)

    # Includi file di chiavi e configurazioni se esistono
    if CONFIG_DIR.exists():
        for conf_file in CONFIG_DIR.glob("**/*"):
            if conf_file.is_file():
                paths.append(conf_file)

    # Rimuovi duplicati mantenendo l'ordine
    unique_paths = []
    seen = set()
    for p in paths:
        norm = str(p)
        if norm not in seen:
            seen.add(norm)
            unique_paths.append(p)

    return unique_paths


def check_security_violations(force: bool = False) -> List[Dict[str, Any]]:
    """
    Esegue la scansione dei percorsi critici e restituisce la lista delle violazioni riscontrate.
    Usa una cache di 5 secondi per minimizzare il sovraccarico I/O durante comandi consecutivi.
    """
    global _security_cache_time, _security_cache_violations
    now = time.time()
    if not force and (now - _security_cache_time) < _CACHE_TTL_SECONDS:
        return _security_cache_violations

    violations: List[Dict[str, Any]] = []
    critical_paths = get_critical_paths()

    for p in critical_paths:
        if not p.exists():
            continue
        is_bad, reason = is_path_modifiable_by_non_root(p)
        if is_bad:
            try:
                st = p.stat()
                violations.append({
                    "path": str(p),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mode": oct(st.st_mode),
                    "reason": reason,
                })
            except Exception:
                violations.append({
                    "path": str(p),
                    "reason": reason,
                })

    _security_cache_time = now
    _security_cache_violations = violations
    return violations


def verify_can_execute_commands(binary_path: Optional[str] = None) -> None:
    """
    Valida l'integrità del demone prima di consentire l'esecuzione di comandi di sistema.
    Solleva InsecurePermissionsError se i file del demone o il binario sono modificabili da non-root.
    """
    # 1. Se specificato, verifica la sicurezza del binario eseguibile
    if binary_path:
        bin_p = Path(binary_path)
        is_bad_bin, bin_reason = is_path_modifiable_by_non_root(bin_p)
        if is_bad_bin:
            log_audit(
                actor="security_guard",
                module="security",
                action="COMMAND_EXECUTION_BLOCKED",
                params={"binary": binary_path, "reason": bin_reason},
                status="BLOCKED",
                detail=f"Binario '{binary_path}' non sicuro: {bin_reason}",
            )
            raise InsecurePermissionsError(
                f"Esecuzione bloccata: il binario '{binary_path}' può essere modificato da utenti non-root ({bin_reason})"
            )

    # 2. Verifica integrità generale dei file del demone
    violations = check_security_violations()
    if violations:
        log_audit(
            actor="security_guard",
            module="security",
            action="COMMAND_EXECUTION_BLOCKED",
            params={"violations_count": len(violations)},
            status="BLOCKED",
            detail=f"Esecuzione comandi bloccata: {len(violations)} percorsi del demone modificabili da non-root",
        )
        sample = "; ".join([f"{v['path']} ({v['reason']})" for v in violations[:3]])
        if len(violations) > 3:
            sample += f" ... e altri {len(violations) - 3} file"
        raise InsecurePermissionsError(
            f"Permessi non conformi: per eseguire comandi, tutti i file del demone devono appartenere a root e non essere modificabili da utenti non-root. Violazioni riscontrate: {sample}",
            violations=violations,
        )


def run_secure_command(
    cmd: List[str],
    *,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
    timeout: Optional[float] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
    **kwargs,
) -> subprocess.CompletedProcess:
    """
    Gateway unico e sicuro per l'esecuzione di comandi esterni da parte del demone TheAdmin372.
    Prima di eseguire il comando:
    1. Risolve il binario nel percorso assoluto tramite shutil.which().
    2. Verifica che il binario appartenga a root e non sia modificabile da non-root.
    3. Verifica che tutti i file del demone non siano modificabili da utenti non-root.
    4. Se le verifiche superano, esegue il comando e ne restituisce il risultato.
    """
    if not cmd or not isinstance(cmd, (list, tuple)):
        raise ValueError("Il comando deve essere una lista non vuota di argomenti")

    binary_name = cmd[0]
    binary_path = shutil.which(binary_name)
    if not binary_path:
        raise FileNotFoundError(f"Comando di sistema non trovato: '{binary_name}'")

    # Verifica vincoli di sicurezza anti-privilege escalation
    verify_can_execute_commands(binary_path=binary_path)

    logger.debug(f"[SecurityGuard] Comando autorizzato ed eseguito: {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        env=env,
        cwd=cwd,
        **kwargs,
    )


def fix_security_permissions() -> Dict[str, Any]:
    """
    Corregge automaticamente i permessi di tutti i file e cartelle del demone:
    - Imposta proprietario a root:root (UID=0, GID=0)
    - Rimuove i permessi di scrittura per gruppo e altri (chmod go-w)
    - Cartelle: 0755
    - File regolari: 0644 (o 0755 se eseguibili)
    - Chiavi private: 0600
    """
    fixed = []
    errors = []

    critical_paths = get_critical_paths()
    for p in critical_paths:
        if not p.exists():
            continue
        if is_read_only_filesystem(p):
            continue

        try:
            st = p.stat()
            # 1. Chown root:root se il processo è root
            if os.geteuid() == 0 and (st.st_uid != 0 or st.st_gid != 0):
                os.chown(str(p), 0, 0)
                fixed.append(f"{p}: chown root:root")

            # 2. Calcola chmod sicuro
            if p.is_dir():
                target_mode = 0o755
            elif "keys" in str(p) and p.name.endswith("_priv.pem"):
                target_mode = 0o600
            elif st.st_mode & 0o111 != 0:
                target_mode = 0o755
            else:
                target_mode = 0o644

            current_mode = st.st_mode & 0o777
            if current_mode != target_mode:
                os.chmod(str(p), target_mode)
                fixed.append(f"{p}: chmod {oct(target_mode)}")
        except Exception as e:
            errors.append(f"{p}: {e}")

    # 3. Scrubbing preventivo dell'audit log per eliminare retroattivamente chiavi private già registrate
    scrubbed = scrub_audit_log_file()
    if scrubbed > 0:
        fixed.append(f"Audit log scrubbed: mascherate {scrubbed} righe contenenti chiavi private o dati sensibili")

    clear_security_cache()

    remaining_violations = check_security_violations(force=True)

    log_audit(
        actor="security_guard",
        module="security",
        action="FIX_PERMISSIONS",
        params={"fixed_count": len(fixed), "errors_count": len(errors)},
        status="SUCCESS" if not errors else "PARTIAL",
        detail=f"Corretti {len(fixed)} percorsi. Violazioni rimanenti: {len(remaining_violations)}",
    )

    return {
        "fixed_count": len(fixed),
        "fixed_items": fixed,
        "errors_count": len(errors),
        "errors": errors,
        "is_secure": len(remaining_violations) == 0,
        "remaining_violations_count": len(remaining_violations),
        "remaining_violations": remaining_violations,
    }
