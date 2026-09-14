from .model import VHostProxyCreate, VHostStatusResponse, NginxActionResponse, HOSTNAME_REGEX
from fastapi import APIRouter, HTTPException
from modules.base import BaseModule
from typing import List, Optional, Tuple
from pathlib import Path
from core.security import run_secure_command
import logging
import os
import re

logger = logging.getLogger("theadmin")

NGINX_CONF_DIR = Path(os.getenv("NGINX_CONF_DIR", "/etc/nginx"))
SITES_AVAILABLE = NGINX_CONF_DIR / "sites-available"
SITES_ENABLED = NGINX_CONF_DIR / "sites-enabled"


def generate_reverse_proxy_config(
    domain: str,
    upstream: str,
    websocket: bool = False,
    client_max_body_size: str = "50M",
) -> str:
    """Genera il blocco di configurazione del server Nginx per il reverse proxy."""
    # Gestione specifica della sintassi proxy_pass per socket UNIX
    if upstream.startswith("unix:"):
        socket_path = upstream.split("unix:", 1)[1]
        proxy_pass_target = f"http://unix:{socket_path}:"
    else:
        proxy_pass_target = upstream

    ws_block = ""
    if websocket:
        ws_block = (
            "        # Supporto WebSockets\n"
            "        proxy_http_version 1.1;\n"
            "        proxy_set_header Upgrade $http_upgrade;\n"
            "        proxy_set_header Connection \"upgrade\";\n"
        )

    return (
        f"# Configurazione gestita automaticamente da TheAdmin372\n"
        f"server {{\n"
        f"    listen 80;\n"
        f"    listen [::]:80;\n"
        f"    server_name {domain};\n"
        f"\n"
        f"    client_max_body_size {client_max_body_size};\n"
        f"\n"
        f"    location / {{\n"
        f"        proxy_pass {proxy_pass_target};\n"
        f"        proxy_set_header Host $host;\n"
        f"        proxy_set_header X-Real-IP $remote_addr;\n"
        f"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        f"        proxy_set_header X-Forwarded-Proto $scheme;\n"
        f"{ws_block}"
        f"    }}\n"
        f"}}\n"
    )


def test_nginx() -> Tuple[bool, str]:
    """Esegue il dry-run 'nginx -t' per verificare la sintassi delle configurazioni."""
    # Permette il mock durante test isolati su macchine di sviluppo senza nginx
    if os.getenv("MOCK_NGINX_TEST") == "1":
        return True, "syntax is ok (mocked)"

    try:
        res = run_secure_command(["nginx", "-t"], capture_output=True, text=True)
        output = (res.stderr.strip() + "\n" + res.stdout.strip()).strip()
        return res.returncode == 0, output
    except FileNotFoundError:
        return False, "Comando 'nginx' non trovato nel sistema"


def is_nginx_running() -> bool:
    """Verifica se il processo Nginx è attualmente attivo nel sistema."""
    # 1. Verifica tramite systemctl
    try:
        res = run_secure_command(["systemctl", "is-active", "--quiet", "nginx"], capture_output=True)
        if res.returncode == 0:
            return True
    except Exception:
        pass

    # 2. Verifica tramite PID file
    for pid_path in [Path("/run/nginx.pid"), Path("/var/run/nginx.pid")]:
        if pid_path.exists():
            try:
                content = pid_path.read_text().strip()
                if content.isdigit():
                    os.kill(int(content), 0)
                    return True
            except (OSError, ValueError):
                pass

    # 3. Verifica tramite pgrep
    try:
        res = run_secure_command(["pgrep", "-x", "nginx"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            return True
    except Exception:
        pass

    return False


def reload_nginx() -> None:
    """
    Ricarica la configurazione di Nginx senza downtime.
    Se Nginx non è attivo o il reload fallisce perché il demone Nginx non è in esecuzione,
    lo avvia/riavvia automaticamente.
    """
    if os.getenv("MOCK_NGINX_TEST") == "1":
        return

    # 1. Tentativo primario con systemctl
    try:
        # Tenta il reload pulito senza downtime
        res = run_secure_command(["systemctl", "reload", "nginx"], capture_output=True, text=True)
        if res.returncode == 0:
            return

        # Se reload fallisce (ad es. unit inactive o non ancora avviata), esegui restart/start
        res_restart = run_secure_command(["systemctl", "restart", "nginx"], capture_output=True, text=True)
        if res_restart.returncode == 0:
            return
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning(f"systemctl non disponibile: {e}")

    # 2. Tentativo secondario con binario diretto nginx
    try:
        res = run_secure_command(["nginx", "-s", "reload"], capture_output=True, text=True)
        if res.returncode == 0:
            return

        err = (res.stderr.strip() + "\n" + res.stdout.strip()).strip()

        # Riconosce se l'errore indica che Nginx è spento (es. no such file or directory su /run/nginx.pid, invalid pid)
        is_not_running = any(
            hint in err.lower()
            for hint in [
                "no such file or directory",
                "invalid pid",
                "not running",
                "no such process",
                "nginx.pid",
            ]
        )

        if is_not_running:
            # Pulizia preventiva di eventuali PID file corrotti o vuoti
            for pid_file in ["/run/nginx.pid", "/var/run/nginx.pid"]:
                try:
                    p = Path(pid_file)
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass

            # Avvia Nginx direttamente
            res_start = run_secure_command(["nginx"], capture_output=True, text=True)
            if res_start.returncode == 0:
                return
            err_start = (res_start.stderr.strip() + "\n" + res_start.stdout.strip()).strip()
            raise HTTPException(status_code=500, detail=f"Errore durante l'avvio di Nginx: {err_start}")

        raise HTTPException(status_code=500, detail=f"Errore durante il reload di Nginx: {err}")

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Comando 'nginx' non presente nel sistema")


class NginxModule(BaseModule):
    def __init__(self):
        self._router = APIRouter(prefix="/nginx", tags=["Nginx"])
        self._ensure_directories()
        self._register_routes()

    @property
    def router(self) -> APIRouter:
        return self._router

    def _ensure_directories(self) -> None:
        """Assicura l'esistenza delle directory di configurazione."""
        try:
            SITES_AVAILABLE.mkdir(parents=True, exist_ok=True)
            SITES_ENABLED.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Impossibile creare directory Nginx ({e}). Verificare i permessi.")

    def _sanitize_domain(self, domain: str) -> str:
        """Sanitizza e valida il nome di dominio per prevenire path traversal."""
        domain_clean = domain.strip().lower()
        if not domain_clean or len(domain_clean) > 253:
            raise HTTPException(status_code=400, detail="Nome di dominio non valido (lunghezza non conforme)")
        if "/" in domain_clean or "\\" in domain_clean or ".." in domain_clean or domain_clean.startswith("."):
            raise HTTPException(status_code=400, detail="Nome di dominio non valido (rilevato tentativo di traversal)")
        if not HOSTNAME_REGEX.match(domain_clean):
            raise HTTPException(status_code=400, detail="Nome di dominio non conforme alle specifiche RFC 1123")
        return domain_clean

    def _get_vhost_status(self, domain: str) -> VHostStatusResponse:
        """Recupera lo stato corrente di un virtual host."""
        conf_file = SITES_AVAILABLE / f"{domain}.conf"
        if not conf_file.exists():
            raise HTTPException(status_code=404, detail=f"Virtual host '{domain}' non trovato")

        symlink_file = SITES_ENABLED / f"{domain}.conf"
        is_enabled = symlink_file.is_symlink() and symlink_file.exists()

        content = ""
        try:
            content = conf_file.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Errore lettura {conf_file}: {e}")

        has_ssl = bool(re.search(r"\bssl_certificate\b|\bssl\b|listen\s+443", content))

        upstream: Optional[str] = None
        match_up = re.search(r"proxy_pass\s+([^;]+);", content)
        if match_up:
            raw_up = match_up.group(1).strip()
            if raw_up.startswith("http://unix:"):
                upstream = "unix:" + raw_up.split("http://unix:", 1)[1].rstrip(":")
            else:
                upstream = raw_up

        return VHostStatusResponse(
            domain=domain,
            enabled=is_enabled,
            has_ssl=has_ssl,
            upstream=upstream,
            config_path=str(conf_file.resolve()),
        )

    def _register_routes(self):
        @self._router.get("/vhosts", response_model=List[VHostStatusResponse])
        def list_vhosts():
            """Elenca tutti i virtual host configurati in sites-available/."""
            vhosts: List[VHostStatusResponse] = []
            if not SITES_AVAILABLE.exists():
                return vhosts

            for conf_file in sorted(SITES_AVAILABLE.glob("*.conf")):
                domain = conf_file.stem
                try:
                    vhosts.append(self._get_vhost_status(domain))
                except Exception as e:
                    logger.error(f"Errore analisi vhost {conf_file.name}: {e}")
            return vhosts

        @self._router.post("/vhosts", response_model=VHostStatusResponse)
        def create_or_update_vhost(payload: VHostProxyCreate):
            """
            Crea o aggiorna atomicamente un virtual host reverse proxy.
            Esegue un dry-run (nginx -t): in caso di errore, esegue il rollback immediato e restituisce HTTP 422.
            """
            domain = self._sanitize_domain(payload.domain)
            conf_path = SITES_AVAILABLE / f"{domain}.conf"
            symlink_path = SITES_ENABLED / f"{domain}.conf"

            # 1. Salva lo stato precedente per il rollback
            old_conf_content: Optional[str] = None
            old_symlink_target: Optional[Path] = None
            had_old_symlink = symlink_path.is_symlink()

            if conf_path.exists():
                try:
                    old_conf_content = conf_path.read_text(encoding="utf-8")
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Impossibile leggere file esistente: {e}")

            if had_old_symlink:
                try:
                    old_symlink_target = symlink_path.resolve()
                except Exception:
                    old_symlink_target = conf_path.resolve()

            # 2. Genera e scrivi la nuova configurazione
            new_config = generate_reverse_proxy_config(
                domain=domain,
                upstream=payload.upstream,
                websocket=payload.websocket,
                client_max_body_size=payload.client_max_body_size,
            )

            try:
                conf_path.write_text(new_config, encoding="utf-8")

                if payload.enabled:
                    if symlink_path.is_symlink() or symlink_path.exists():
                        symlink_path.unlink()
                    symlink_path.symlink_to(conf_path.resolve())
                else:
                    if symlink_path.is_symlink() or symlink_path.exists():
                        symlink_path.unlink()
            except Exception as e:
                # Ripristino immediato in caso di errore I/O
                if old_conf_content is not None:
                    conf_path.write_text(old_conf_content, encoding="utf-8")
                elif conf_path.exists():
                    conf_path.unlink()
                raise HTTPException(status_code=500, detail=f"Errore scrittura configurazione: {e}")

            # 3. Dry-Run obbligatorio con 'nginx -t'
            is_valid, test_output = test_nginx()
            if not is_valid:
                # ROLLBACK: ripristina lo stato precedente
                try:
                    if old_conf_content is not None:
                        conf_path.write_text(old_conf_content, encoding="utf-8")
                    elif conf_path.exists():
                        conf_path.unlink()

                    if had_old_symlink and old_symlink_target is not None:
                        if symlink_path.is_symlink() or symlink_path.exists():
                            symlink_path.unlink()
                        symlink_path.symlink_to(old_symlink_target)
                    else:
                        if symlink_path.is_symlink() or symlink_path.exists():
                            symlink_path.unlink()
                except Exception as rollback_err:
                    logger.critical(f"Errore critico durante il rollback di {domain}: {rollback_err}")

                raise HTTPException(
                    status_code=422,
                    detail=f"Test di configurazione Nginx fallito (rollback automatico eseguito):\n{test_output}",
                )

            # 4. Ricarica Nginx se il test ha successo
            reload_nginx()
            return self._get_vhost_status(domain)

        @self._router.post("/vhosts/{domain}/toggle", response_model=VHostStatusResponse)
        def toggle_vhost(domain: str):
            """Inverte lo stato del virtual host (abilita se disabilitato, disabilita se abilitato)."""
            clean_domain = self._sanitize_domain(domain)
            conf_path = SITES_AVAILABLE / f"{clean_domain}.conf"
            symlink_path = SITES_ENABLED / f"{clean_domain}.conf"

            if not conf_path.exists():
                raise HTTPException(status_code=404, detail=f"Virtual host '{clean_domain}' non trovato")

            currently_enabled = symlink_path.is_symlink() and symlink_path.exists()
            target_enabled = not currently_enabled

            # Salva stato precedente per rollback
            had_symlink = symlink_path.is_symlink()

            try:
                if target_enabled:
                    if symlink_path.is_symlink() or symlink_path.exists():
                        symlink_path.unlink()
                    symlink_path.symlink_to(conf_path.resolve())
                else:
                    if symlink_path.is_symlink() or symlink_path.exists():
                        symlink_path.unlink()
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Errore modifica symlink: {e}")

            # Dry-run
            is_valid, test_output = test_nginx()
            if not is_valid:
                # Rollback symlink
                try:
                    if had_symlink:
                        if symlink_path.is_symlink() or symlink_path.exists():
                            symlink_path.unlink()
                        symlink_path.symlink_to(conf_path.resolve())
                    else:
                        if symlink_path.is_symlink() or symlink_path.exists():
                            symlink_path.unlink()
                except Exception as rollback_err:
                    logger.critical(f"Errore critico durante il rollback symlink di {clean_domain}: {rollback_err}")

                raise HTTPException(
                    status_code=422,
                    detail=f"Verifica Nginx fallita su toggle (rollback eseguito):\n{test_output}",
                )

            reload_nginx()
            return self._get_vhost_status(clean_domain)

        @self._router.post("/vhosts/{domain}/enable", response_model=VHostStatusResponse)
        def enable_vhost(domain: str):
            """Abilita esplicitamente un virtual host."""
            clean_domain = self._sanitize_domain(domain)
            conf_path = SITES_AVAILABLE / f"{clean_domain}.conf"
            symlink_path = SITES_ENABLED / f"{clean_domain}.conf"

            if not conf_path.exists():
                raise HTTPException(status_code=404, detail=f"Virtual host '{clean_domain}' non trovato")

            had_symlink = symlink_path.is_symlink()
            if had_symlink and symlink_path.exists():
                return self._get_vhost_status(clean_domain)

            try:
                if symlink_path.is_symlink() or symlink_path.exists():
                    symlink_path.unlink()
                symlink_path.symlink_to(conf_path.resolve())
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Errore creazione symlink: {e}")

            is_valid, test_output = test_nginx()
            if not is_valid:
                if not had_symlink and (symlink_path.is_symlink() or symlink_path.exists()):
                    symlink_path.unlink()
                raise HTTPException(
                    status_code=422,
                    detail=f"Verifica Nginx fallita su enable (rollback eseguito):\n{test_output}",
                )

            reload_nginx()
            return self._get_vhost_status(clean_domain)

        @self._router.post("/vhosts/{domain}/disable", response_model=VHostStatusResponse)
        def disable_vhost(domain: str):
            """Disabilita esplicitamente un virtual host."""
            clean_domain = self._sanitize_domain(domain)
            conf_path = SITES_AVAILABLE / f"{clean_domain}.conf"
            symlink_path = SITES_ENABLED / f"{clean_domain}.conf"

            if not conf_path.exists():
                raise HTTPException(status_code=404, detail=f"Virtual host '{clean_domain}' non trovato")

            had_symlink = symlink_path.is_symlink()
            if not had_symlink:
                return self._get_vhost_status(clean_domain)

            try:
                symlink_path.unlink()
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Errore rimozione symlink: {e}")

            is_valid, test_output = test_nginx()
            if not is_valid:
                symlink_path.symlink_to(conf_path.resolve())
                raise HTTPException(
                    status_code=422,
                    detail=f"Verifica Nginx fallita su disable (rollback eseguito):\n{test_output}",
                )

            reload_nginx()
            return self._get_vhost_status(clean_domain)

        @self._router.delete("/vhosts/{domain}", response_model=NginxActionResponse)
        def delete_vhost(domain: str):
            """Rimuove un virtual host (file di configurazione e relativo symlink)."""
            clean_domain = self._sanitize_domain(domain)
            conf_path = SITES_AVAILABLE / f"{clean_domain}.conf"
            symlink_path = SITES_ENABLED / f"{clean_domain}.conf"

            if not conf_path.exists():
                raise HTTPException(status_code=404, detail=f"Virtual host '{clean_domain}' non trovato")

            old_content = conf_path.read_text(encoding="utf-8")
            had_symlink = symlink_path.is_symlink()

            try:
                if had_symlink or symlink_path.exists():
                    symlink_path.unlink()
                conf_path.unlink()
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Errore durante l'eliminazione dei file: {e}")

            is_valid, test_output = test_nginx()
            if not is_valid:
                # ROLLBACK
                try:
                    conf_path.write_text(old_content, encoding="utf-8")
                    if had_symlink:
                        symlink_path.symlink_to(conf_path.resolve())
                except Exception as rollback_err:
                    logger.critical(f"Errore critico durante rollback eliminazione {clean_domain}: {rollback_err}")

                raise HTTPException(
                    status_code=422,
                    detail=f"Eliminazione non valida per la configurazione globale di Nginx (rollback eseguito):\n{test_output}",
                )

            reload_nginx()
            return NginxActionResponse(status="ok", message=f"Virtual host '{clean_domain}' rimosso con successo")

        @self._router.post("/reload", response_model=NginxActionResponse)
        def manual_reload():
            """Esegue test preventivo e reload manuale di Nginx."""
            is_valid, test_output = test_nginx()
            if not is_valid:
                raise HTTPException(
                    status_code=422,
                    detail=f"Test preventivo Nginx fallito. Ricaricamento annullato:\n{test_output}",
                )
            reload_nginx()
            return NginxActionResponse(status="ok", message="Configurazione Nginx verificata e ricaricata con successo")
