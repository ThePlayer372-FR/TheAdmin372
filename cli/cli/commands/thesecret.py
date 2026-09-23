import argparse
import sys
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()


class TheSecretCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "thesecret"

    @property
    def help(self) -> str:
        return "Integrazione con TheSecret372 Cryptographic Oracle per Envelope Decryption (mTLS 372)"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        ts_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = ts_parser.add_subparsers(dest="thesecret_action", required=True)

        # 1. theadmin372 thesecret status
        status_p = sub_actions.add_parser("status", help="Verifica lo stato mTLS e le autorizzazioni verso TheSecret372")
        status_p.add_argument("--host", default=None, help="Host del server TheSecret372 (default: 127.0.0.1)")
        status_p.add_argument("--port", type=int, default=None, help="Porta TCP del server (default: 372)")

        # 2. theadmin372 thesecret enroll
        enroll_p = sub_actions.add_parser("enroll", help="Esegue il bootstrap e richiede il certificato mTLS firmato da TheSecret372")
        enroll_p.add_argument("--host", default=None, help="Host del server TheSecret372 (default: 127.0.0.1)")
        enroll_p.add_argument("--port", type=int, default=None, help="Porta TCP del server (default: 372)")
        enroll_p.add_argument("--name", default=None, help="Machine name / hostname per la richiesta CSR")

        # 3. theadmin372 thesecret test
        test_p = sub_actions.add_parser("test", help="Testa la connettività e l'interrogazione dell'oracolo")
        test_p.add_argument("--host", default=None, help="Host del server TheSecret372 (default: 127.0.0.1)")
        test_p.add_argument("--port", type=int, default=None, help="Porta TCP del server (default: 372)")

    def _get_error_detail(self, res) -> str:
        try:
            data = res.json()
            if isinstance(data, dict):
                if "detail" in data:
                    return data["detail"]
                if "message" in data:
                    return data["message"]
        except Exception:
            pass
        return res.text.strip() or f"Codice HTTP {res.status_code}"

    def handle(self, args: argparse.Namespace, client: DaemonClient) -> None:
        action = getattr(args, "thesecret_action", None)

        if action == "status":
            self._handle_status(args, client)
        elif action == "enroll":
            self._handle_enroll(args, client)
        elif action == "test":
            self._handle_test(args, client)

    def _handle_status(self, args: argparse.Namespace, client: DaemonClient) -> None:
        params = {}
        if args.host:
            params["host"] = args.host
        if args.port:
            params["port"] = str(args.port)

        res = client.get("/v1/backup/thesecret/status", params=params)
        if res.status_code != 200:
            console.print(f"[red]✖ Errore interrogazione stato ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        data = res.json()
        enrolled = data.get("enrolled", False)
        connected = data.get("connected", False)
        authorized = data.get("authorized", False)
        status_label = data.get("status", "UNKNOWN")
        uid = data.get("uid") or "-"
        host = data.get("host", "-")
        port = data.get("port", "-")
        scopes = data.get("scopes", [])

        table = Table(
            title="Stato Integrazione TheSecret372 (Cryptographic Oracle)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Parametro", style="dim", width=22)
        table.add_column("Valore", width=55)

        table.add_row("Server Endpoint", f"[bold]{host}:{port}[/bold]")
        table.add_row(
            "Enrollment mTLS",
            "[green]✔ Registrato (Certificati presenti)[/green]" if enrolled else "[yellow]✖ Non registrato[/yellow]",
        )
        table.add_row(
            "Connessione TLS",
            "[green]✔ Raggiungibile[/green]" if connected else f"[red]✖ Non raggiungibile ({status_label})[/red]",
        )
        table.add_row("UID Nodo", f"[yellow]{uid}[/yellow]")

        if authorized:
            auth_str = "[bold green]✔ AUTORIZZATO[/bold green]"
        elif status_label == "PENDING":
            auth_str = "[bold yellow]⏳ IN ATTESA DI APPROVAZIONE (PENDING)[/bold yellow]"
        else:
            auth_str = f"[bold red]✖ {status_label}[/bold red]"

        table.add_row("Stato Accesso ACL", auth_str)
        scopes_str = ", ".join(scopes) if scopes else "[dim]Nessuno[/dim]"
        table.add_row("Scopes Abilitati", scopes_str)

        can_decrypt = data.get("can_decrypt_backup", False)
        table.add_row(
            "Envelope Decryption",
            "[green]✔ Abilitata (backup:decrypt)[/green]" if can_decrypt else "[dim yellow]Disabilitata[/dim yellow]",
        )

        console.print()
        console.print(table)

        next_step = data.get("next_step")
        if next_step:
            console.print(
                Panel(
                    f"[bold yellow]Azione Richiesta:[/bold yellow]\n{next_step}",
                    title="[bold yellow]Autorizzazione Necessaria[/bold yellow]",
                    border_style="yellow",
                )
            )
        console.print()

    def _handle_enroll(self, args: argparse.Namespace, client: DaemonClient) -> None:
        payload = {}
        if args.host:
            payload["host"] = args.host
        if args.port:
            payload["port"] = args.port
        if args.name:
            payload["machine_name"] = args.name

        console.print("[cyan]Avvio procedura di bootstrap & enrollment con TheSecret372...[/cyan]")
        res = client.post("/v1/backup/thesecret/enroll", json_data=payload)

        if res.status_code != 200:
            console.print(f"[bold red]✖ Errore durante l'enrollment ({res.status_code}):[/bold red] {self._get_error_detail(res)}")
            return

        data = res.json()
        uid = data.get("uid", "sconosciuto")
        status = data.get("status", "")
        msg = data.get("message", "")
        next_step = data.get("next_step")

        if status == "ALREADY_ENROLLED":
            console.print(f"\n[green]✔ Certificati mTLS già presenti per il nodo:[/green] [bold yellow]{uid}[/bold yellow]")
        else:
            console.print(f"\n[bold green]✔ Certificati mTLS ottenuti con successo![/bold green]")
            console.print(f"UID del nodo: [bold yellow]{uid}[/bold yellow]")
            if next_step:
                console.print(
                    Panel(
                        f"[bold yellow]Richiesta registrata sul server TheSecret372.[/bold yellow]\n\n"
                        f"Il nodo è in attesa di approvazione dall'operatore.\n"
                        f"Per autorizzarlo, esegui sul server TheSecret372:\n\n"
                        f"[bold green]{next_step}[/bold green]",
                        title="[bold cyan]Prossimo Passo (Human-In-The-Loop)[/bold cyan]",
                        border_style="cyan",
                    )
                )
        console.print()

    def _handle_test(self, args: argparse.Namespace, client: DaemonClient) -> None:
        console.print("[cyan]Test di connettività verso l'oracolo TheSecret372...[/cyan]")
        self._handle_status(args, client)
