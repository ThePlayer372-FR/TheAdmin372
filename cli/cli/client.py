from typing import Any, Dict, Optional
from pathlib import Path
import httpx
import sys
import os

DEFAULT_SOCKET = os.getenv("DAEMON_SOCKET", "/run/theadmin372/theadmin372.sock")


class DaemonClient:
    def __init__(self, socket_path: str = DEFAULT_SOCKET, timeout: float = 10.0):
        self.socket_path = socket_path
        self._validate_socket()
        self.transport = httpx.HTTPTransport(uds=socket_path)
        self.client = httpx.Client(transport=self.transport, base_url="http://daemon", timeout=timeout)

    def _validate_socket(self) -> None:
        path = Path(self.socket_path)
        if not path.exists():
            self._abort(
                f"Socket non trovato in '{self.socket_path}'.\n"
                "Verifica che il demone sia attivo (es. 'sudo systemctl status theadmin372.service')."
            )
        if not os.access(self.socket_path, os.R_OK | os.W_OK):
            self._abort(
                f"Permessi insufficienti per accedere a '{self.socket_path}'.\n"
                "L'utente corrente non ha permessi di lettura/scrittura sul socket.\n"
                "Verifica che il tuo utente appartenga al gruppo 'sysadmin' ('groups $USER')."
            )

    @staticmethod
    def _abort(message: str) -> None:
        try:
            from rich.console import Console
            Console(stderr=True).print(f"[bold red][!] Errore Demone:[/bold red]\n{message}")
        except Exception:
            sys.stderr.write(f"[!] Errore Demone:\n{message}\n")
        sys.exit(1)

    def request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        try:
            return self.client.request(method, endpoint, **kwargs)
        except httpx.ConnectError as e:
            self._abort(
                f"Impossibile stabilire la connessione con il demone sul socket '{self.socket_path}'.\n"
                f"Dettaglio: {e}\n"
                "Possibile causa: il socket è orfano o il processo demone è terminato in modo anomalo."
            )
        except httpx.TimeoutException:
            self._abort(f"Timeout durante la comunicazione con il demone su '{self.socket_path}'.")
        except httpx.RequestError as e:
            self._abort(f"Errore di comunicazione con il demone: {e}")

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
        return self.request("GET", endpoint, params=params)

    def post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> httpx.Response:
        return self.request("POST", endpoint, json=json_data)

    def put(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> httpx.Response:
        return self.request("PUT", endpoint, json=json_data)

    def delete(self, endpoint: str, params: Optional[Dict[str, Any]] = None, json_data: Optional[Dict[str, Any]] = None) -> httpx.Response:
        return self.request("DELETE", endpoint, params=params, json=json_data)