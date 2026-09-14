from core.logger import log_audit, logger, setup_logging, mask_sensitive_data
from core.security import InsecurePermissionsError, check_security_violations
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from importlib import import_module
from modules.base import BaseModule
from pathlib import Path
from typing import List, Optional
import uvicorn
import threading
import time
import json
import grp
import os
import socket
import struct
import pwd
import asyncio

setup_logging(debug=True)

WHITELIST: List[str] = []
BLACKLIST: List[str] = []
API_VERSION = "v1"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOCKET_PATH = Path(os.getenv("DAEMON_SOCKET", "/tmp/theadmin372.sock"))


def get_uds_peer_credentials(transport: asyncio.Transport) -> Optional[tuple[str, int]]:
    """Estrae le credenziali del chiamante (UID, PID, username) via SO_PEERCRED su Linux."""
    sock = transport.get_extra_info("socket")
    if sock is not None and getattr(sock, "family", None) == socket.AF_UNIX:
        try:
            SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
            creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _ = struct.unpack("3i", creds)
            try:
                username = pwd.getpwuid(uid).pw_name
            except Exception:
                username = str(uid)
            return (f"unix:{username}:{uid}", pid)
        except OSError:
            pass
    return None


def patch_uvicorn_uds_peercred():
    """Inietta l'estrazione di SO_PEERCRED in Uvicorn per i socket UNIX."""
    try:
        import uvicorn.protocols.utils as uvicorn_utils
        orig_get_remote_addr = uvicorn_utils.get_remote_addr

        def custom_get_remote_addr(transport: asyncio.Transport):
            peer = get_uds_peer_credentials(transport)
            if peer is not None:
                return peer
            return orig_get_remote_addr(transport)

        uvicorn_utils.get_remote_addr = custom_get_remote_addr

        for mod_name in ["uvicorn.protocols.http.h11_impl", "uvicorn.protocols.http.httptools_impl"]:
            try:
                mod = import_module(mod_name)
                setattr(mod, "get_remote_addr", custom_get_remote_addr)
            except (ImportError, AttributeError):
                pass
    except Exception as e:
        logger.warning(f"Impossibile abilitare il tracciamento SO_PEERCRED su Uvicorn: {e}")


def fix_socket_permissions(socket_path: Path):
    """Attende che il socket esista e ne corregge proprietario e permessi (socket e directory genitrice)."""
    parent_dir = socket_path.parent
    for _ in range(20):  # Prova fino a 2 secondi (20 * 0.1s)
        if socket_path.exists():
            try:
                gid = grp.getgrnam("sysadmin").gr_gid
                # Assicura che la directory genitrice (/run/theadmin372) appartenga a root:sysadmin (0770)
                if parent_dir.exists():
                    os.chown(parent_dir, 0, gid)
                    os.chmod(parent_dir, 0o770)
                # Assicura che il socket appartenga a root:sysadmin (0660)
                os.chown(socket_path, 0, gid)   # root:sysadmin
                os.chmod(socket_path, 0o660)    # rw-rw----
            except KeyError:
                if parent_dir.exists():
                    os.chmod(parent_dir, 0o775)
                os.chmod(socket_path, 0o666)
            except PermissionError:
                # Se non sei root durante lo sviluppo locale, ignora il cambio proprietario
                pass
            return
        time.sleep(0.1)


def clean_socket(path: Path = SOCKET_PATH):
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        gid = grp.getgrnam("sysadmin").gr_gid
        os.chown(path.parent, 0, gid)
        os.chmod(path.parent, 0o770)
    except Exception:
        pass


def init_modules(app_instance: FastAPI):
    modules_dir = PROJECT_ROOT / "modules"
    for file in modules_dir.glob("*/main.py"):
        dir_name = file.parent.name
        module_path = f"modules.{dir_name}.main"
        try:
            mod = import_module(module_path)
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseModule)
                    and attr is not BaseModule
                ):
                    instance = attr()
                    if hasattr(instance, "router"):
                        app_instance.include_router(instance.router, prefix=f"/{API_VERSION}")
                        logger.info(f"Modulo {dir_name} installato!")
        except Exception as err:
            logger.error(f"Errore durante il caricamento del modulo {dir_name}: {err}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_modules(app)
    # Controllo di sicurezza all'avvio: permessi anti-privilege escalation
    violations = check_security_violations(force=True)
    if violations:
        logger.warning(
            f"⚠️ ATTENZIONE SICUREZZA: Rilevate {len(violations)} violazioni di permessi! "
            "L'esecuzione di comandi da parte del demone è BLOCCATA finché i file non sono protetti da utenti non-root. "
            "Usa 'theadmin372 security fix' per ripristinare i permessi."
        )
    else:
        logger.info("🛡️ SecurityGuard: integrità permessi verificata. Esecuzione comandi autorizzata.")

    logger.info(f"TheAdmin372 Daemon inizializzato per {SOCKET_PATH}")
    yield
    clean_socket(SOCKET_PATH)
    logger.info("TheAdmin372 Daemon arrestato e socket rimosso.")


app = FastAPI(title="TheAdmin372 Daemon Engine", lifespan=lifespan)


@app.exception_handler(InsecurePermissionsError)
async def insecure_permissions_handler(request: Request, exc: InsecurePermissionsError):
    return JSONResponse(
        status_code=403,
        content={
            "detail": f"SICUREZZA: Esecuzione comandi bloccata. {str(exc)}",
            "violations": getattr(exc, "violations", []),
            "remediation": "I file del demone devono appartenere a root e non essere modificabili da utenti non-root. Esegui 'theadmin372 security fix' per ripristinare i permessi sicuri.",
        },
    )


@app.get("/health")
def ping():
    return {"status": True}


@app.middleware("http")
async def audit_requests_middleware(request: Request, call_next):
    start_time = time.perf_counter()

    body_bytes = b""
    parsed_params = {}

    if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
        body_bytes = await request.body()

        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request = Request(request.scope, receive=receive)

        if body_bytes:
            try:
                parsed_params = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                parsed_params = {"raw_body": body_bytes.decode("utf-8", errors="replace")}

    if request.query_params:
        parsed_params["_query"] = dict(request.query_params)

    response: Response = await call_next(request)

    duration = time.perf_counter() - start_time
    status_str = "SUCCESS" if response.status_code < 400 else "FAILED"

    logger.debug(f"{request.method} {request.url.path} -> {response.status_code} ({duration:.4f}s)")

    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        path_segments = [seg for seg in request.url.path.split("/") if seg and seg != API_VERSION]
        module_name = path_segments[0] if path_segments else "core"

        actor = "uds_client"
        if request.client and request.client.host:
            actor = f"{request.client.host} (pid={request.client.port})"

        sanitized_params = mask_sensitive_data(parsed_params)

        log_audit(
            actor=actor,
            module=module_name,
            action=f"{request.method} {request.url.path}",
            params=sanitized_params,
            status=status_str,
            detail=f"Status: {response.status_code}, Duration: {duration:.4f}s",
        )

    return response


def run_server():
    patch_uvicorn_uds_peercred()
    clean_socket(SOCKET_PATH)
    old_umask = os.umask(0o117)
    threading.Thread(target=fix_socket_permissions, args=(SOCKET_PATH,), daemon=True).start()
    try:
        uvicorn.run(app, uds=str(SOCKET_PATH), log_level="info")
    finally:
        os.umask(old_umask)

if __name__ == "__main__":
    run_server()