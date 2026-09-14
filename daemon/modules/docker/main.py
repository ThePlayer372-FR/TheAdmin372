from .model import ContainerItem, ComposeGroup, DockerGroupsResponse
from fastapi import APIRouter, HTTPException
from modules.base import BaseModule
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.security import run_secure_command
import http.client
import logging
import socket
import json
import os

logger = logging.getLogger("theadmin")

DOCKER_SOCKET_PATH = os.getenv("DOCKER_SOCKET", "/var/run/docker.sock")


class UDSHTTPConnection(http.client.HTTPConnection):
    """Client HTTP nativo standard library per comunicare via UNIX Domain Socket."""
    def __init__(self, uds_path: str, timeout: float = 5.0):
        super().__init__("localhost", timeout=timeout)
        self.uds_path = uds_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.uds_path)


def format_ports_api(ports_raw: List[Dict[str, Any]]) -> List[str]:
    """Formatta la lista porte restituita dalle API REST di Docker Engine."""
    formatted = []
    seen = set()
    for p in ports_raw:
        priv = p.get("PrivatePort")
        pub = p.get("PublicPort")
        proto = p.get("Type", "tcp")
        ip = p.get("IP")

        if pub:
            key = (priv, pub, proto)
            if key not in seen:
                seen.add(key)
                ip_prefix = f"{ip}:" if ip and ip not in ["::", "0.0.0.0"] else ""
                formatted.append(f"{ip_prefix}{pub}->{priv}/{proto}")
        elif priv:
            key = (priv, None, proto)
            if key not in seen:
                seen.add(key)
                formatted.append(f"{priv}/{proto}")
    return formatted


def format_ports_cli(ports_str: str) -> List[str]:
    """Formatta la stringa porte restituita da 'docker ps --format'."""
    if not ports_str:
        return []
    parts = [p.strip() for p in ports_str.split(",") if p.strip()]
    dedup = []
    seen = set()
    for item in parts:
        # Rimuovi prefissi IPv6 ridondanti tipo ':::80->80/tcp' se già presente '0.0.0.0:80->80/tcp'
        normalized = item.replace("::: ", "").replace("0.0.0.0:", "")
        if normalized not in seen:
            seen.add(normalized)
            dedup.append(item)
    return dedup


def fetch_containers_from_engine(all_containers: bool = False) -> List[Dict[str, Any]]:
    """Tenta il recupero dei container tramite socket Docker o CLI."""
    all_param = "1" if all_containers else "0"

    # 1. Prova prima via socket UNIX nativo di Docker
    if Path(DOCKER_SOCKET_PATH).exists():
        try:
            conn = UDSHTTPConnection(DOCKER_SOCKET_PATH, timeout=5.0)
            conn.request("GET", f"/containers/json?all={all_param}")
            res = conn.getresponse()
            if res.status == 200:
                raw_body = res.read().decode("utf-8")
                return json.loads(raw_body)
        except Exception as e:
            logger.debug(f"Connessione socket Docker {DOCKER_SOCKET_PATH} non riuscita: {e}")

    # 2. Fallback tramite CLI 'docker inspect' per avere tutti i dettagli
    try:
        ps_cmd = ["docker", "ps", "-a", "-q"] if all_containers else ["docker", "ps", "-q"]
        res_ids = run_secure_command(ps_cmd, capture_output=True, text=True, check=True)
        container_ids = res_ids.stdout.strip().split()
        if not container_ids:
            return []

        inspect_cmd = ["docker", "inspect"] + container_ids
        res_inspect = run_secure_command(inspect_cmd, capture_output=True, text=True, check=True)
        raw_inspect = json.loads(res_inspect.stdout)

        # Normalizza il formato inspect nel formato standard compatibile con /containers/json
        normalized_list = []
        for item in raw_inspect:
            config = item.get("Config", {})
            state = item.get("State", {})
            net_settings = item.get("NetworkSettings", {})
            ports_raw = []
            for port_proto, bindings in (net_settings.get("Ports") or {}).items():
                priv = int(port_proto.split("/")[0]) if "/" in port_proto else 0
                proto = port_proto.split("/")[1] if "/" in port_proto else "tcp"
                if bindings:
                    for b in bindings:
                        ports_raw.append({
                            "IP": b.get("HostIp", ""),
                            "PrivatePort": priv,
                            "PublicPort": int(b.get("HostPort", 0)),
                            "Type": proto,
                        })
                else:
                    ports_raw.append({"PrivatePort": priv, "Type": proto})

            normalized_list.append({
                "Id": item.get("Id", ""),
                "Names": [item.get("Name", "")],
                "Image": config.get("Image", ""),
                "State": state.get("Status", "unknown"),
                "Status": f"{state.get('Status', 'unknown')} ({state.get('ExitCode', 0)})" if state.get("Status") != "running" else "running",
                "Labels": config.get("Labels") or {},
                "Ports": ports_raw,
            })
        return normalized_list
    except Exception as e:
        logger.debug(f"Fallback su docker CLI fallito: {e}")

    raise HTTPException(
        status_code=503,
        detail="Servizio Docker non disponibile. Verifica che Docker Engine sia attivo e che /var/run/docker.sock sia accessibile.",
    )


def group_containers(containers_raw: List[Dict[str, Any]]) -> DockerGroupsResponse:
    """Raggruppa i container per percorso compose.yml o Standalone."""
    groups_dict: Dict[str, ComposeGroup] = {}

    for c in containers_raw:
        full_id = c.get("Id", "")
        short_id = full_id[:12] if len(full_id) >= 12 else full_id
        names = c.get("Names") or [""]
        clean_name = names[0].lstrip("/") if names else short_id
        image = c.get("Image", "")
        state = c.get("State", "")
        status = c.get("Status", state)

        # Gestione porte sia da formato API che da formato CLI
        ports_field = c.get("Ports")
        if isinstance(ports_field, list):
            ports = format_ports_api(ports_field)
        elif isinstance(ports_field, str):
            ports = format_ports_cli(ports_field)
        else:
            ports = []

        labels = c.get("Labels") or {}
        compose_file = labels.get("com.docker.compose.project.config_files")
        project_name = labels.get("com.docker.compose.project")
        service_name = labels.get("com.docker.compose.service") or clean_name
        working_dir = labels.get("com.docker.compose.project.working_dir")

        # Se config_files non è esplicito ma c'è working_dir, cerca il file compose
        if not compose_file and working_dir:
            wdir = Path(working_dir)
            for candidate in ["compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"]:
                c_path = wdir / candidate
                if c_path.exists():
                    compose_file = str(c_path.resolve())
                    break

        exists_on_disk = bool(compose_file and Path(compose_file).exists())

        # Chiave di raggruppamento
        if compose_file:
            group_key = compose_file
            group_project = project_name or Path(compose_file).parent.name
        elif project_name:
            group_key = f"project:{project_name}"
            group_project = project_name
        else:
            group_key = "__standalone__"
            group_project = "Standalone"

        if group_key not in groups_dict:
            groups_dict[group_key] = ComposeGroup(
                compose_file=compose_file,
                project_name=group_project,
                working_dir=working_dir,
                exists_on_disk=exists_on_disk,
                containers=[],
            )

        groups_dict[group_key].containers.append(
            ContainerItem(
                id=short_id,
                full_id=full_id,
                name=clean_name,
                service=service_name,
                image=image,
                state=state,
                status=status,
                ports=ports,
            )
        )

    # Ordina i gruppi: prima i progetti compose (con path), poi gli standalone
    sorted_groups = sorted(
        groups_dict.values(),
        key=lambda g: (0 if g.compose_file else 1, g.project_name.lower()),
    )

    total_cnt = sum(len(g.containers) for g in sorted_groups)

    return DockerGroupsResponse(
        total_containers=total_cnt,
        total_groups=len(sorted_groups),
        groups=sorted_groups,
    )


class DockerModule(BaseModule):
    def __init__(self):
        self._router = APIRouter(prefix="/docker", tags=["Docker"])
        self._register_routes()

    @property
    def router(self) -> APIRouter:
        return self._router

    def _register_routes(self):
        @self._router.get("/ps", response_model=DockerGroupsResponse)
        @self._router.get("/compose-groups", response_model=DockerGroupsResponse)
        def list_compose_groups(all: bool = False):
            """
            Recupera i container Docker raggruppandoli per percorso compose.yml.
            Se all=False (default), restituisce solo i container attivi/running.
            Se all=True, include tutti i container (anche spenti/exited).
            """
            raw_containers = fetch_containers_from_engine(all_containers=all)
            return group_containers(raw_containers)

        @self._router.get("/containers", response_model=List[ContainerItem])
        def list_flat_containers(all: bool = False):
            """Restituisce l'elenco piatto dei container Docker."""
            raw_containers = fetch_containers_from_engine(all_containers=all)
            grouped = group_containers(raw_containers)
            flat = []
            for g in grouped.groups:
                flat.extend(g.containers)
            return flat
