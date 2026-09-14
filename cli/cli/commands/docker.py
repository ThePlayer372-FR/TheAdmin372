import argparse
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()


class DockerCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "docker"

    @property
    def help(self) -> str:
        return "Monitoraggio e raggruppamento container Docker e progetti Compose"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        docker_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = docker_parser.add_subparsers(dest="docker_action", required=False)

        # theadmin372 docker ps / list
        ps_parser = sub_actions.add_parser("ps", help="Elenca e raggruppa i container per file compose.yml")
        ps_parser.add_argument("-a", "--all", action="store_true", help="Mostra tutti i container (inclusi quelli terminati)")
        ps_parser.add_argument("--json", action="store_true", help="Restituisce l'output raw in formato JSON")

        list_parser = sub_actions.add_parser("list", help="Alias di 'ps'")
        list_parser.add_argument("-a", "--all", action="store_true", help="Mostra tutti i container")
        list_parser.add_argument("--json", action="store_true", help="Restituisce l'output raw in formato JSON")

        compose_parser = sub_actions.add_parser("compose", help="Mostra i progetti Docker Compose e i relativi servizi")
        compose_parser.add_argument("--json", action="store_true", help="Restituisce l'output raw in formato JSON")

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
        return res.text.strip() or f"Codice di errore HTTP {res.status_code}"

    def handle(self, args: argparse.Namespace, client: DaemonClient) -> None:
        # Azione predefinita se nessuna sotto-azione è specificata
        action = getattr(args, "docker_action", None) or "ps"
        output_json = getattr(args, "json", False)
        show_all = getattr(args, "all", False)

        params = {"all": "true" if show_all else "false"}
        res = client.get("/v1/docker/compose-groups", params=params)
        if res.status_code != 200:
            console.print(f"[red]✖ Errore recupero informazioni Docker ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        data = res.json()

        if output_json:
            console.print_json(json.dumps(data, indent=2))
            return

        total_cnt = data.get("total_containers", 0)
        total_grp = data.get("total_groups", 0)
        groups = data.get("groups", [])

        if total_cnt == 0:
            console.print("[yellow]Nessun container Docker rilevato nel sistema.[/yellow]")
            return

        console.print(f"\n[bold]Container Docker rilevati:[/bold] [cyan]{total_cnt}[/cyan] in [cyan]{total_grp}[/cyan] gruppo/i\n")

        for grp in groups:
            compose_file = grp.get("compose_file")
            project_name = grp.get("project_name", "Standalone")
            working_dir = grp.get("working_dir")
            exists_on_disk = grp.get("exists_on_disk", False)
            containers = grp.get("containers", [])

            # Intestazione del gruppo compose
            if compose_file:
                disk_badge = "[green]✓ presente[/green]" if exists_on_disk else "[dim]non trovato su disco[/dim]"
                header_text = (
                    f"📦 [bold white]Compose Project:[/bold white] [bold cyan]{project_name}[/bold cyan]  "
                    f"| File: [bold yellow]{compose_file}[/bold yellow] ({disk_badge})"
                )
                if working_dir and working_dir != compose_file:
                    header_text += f"\n📁 [dim]Directory: {working_dir}[/dim]"
                box_style = box.ROUNDED
                border_color = "cyan"
            else:
                header_text = "📦 [bold white]Container Standalone (Nessun compose.yml associato)[/bold white]"
                box_style = box.SIMPLE
                border_color = "yellow"

            table = Table(
                show_header=True,
                header_style="bold dim",
                box=box_style,
                expand=True,
                title=header_text,
                title_justify="left",
                title_style="bold",
                border_style=border_color,
            )

            table.add_column("Servizio", style="bold cyan", min_width=16)
            table.add_column("Nome Container", style="green", min_width=18)
            table.add_column("Immagine", style="magenta", min_width=20)
            table.add_column("Stato", style="bold", min_width=16)
            table.add_column("Porte", style="yellow")

            for c in containers:
                state_raw = str(c.get("state", "")).lower()
                status_raw = str(c.get("status", ""))
                if "running" in state_raw or "up" in status_raw.lower():
                    state_colored = f"[green]✔ {status_raw}[/green]"
                elif "exited" in state_raw or "stopped" in state_raw:
                    state_colored = f"[red]✖ {status_raw}[/red]"
                else:
                    state_colored = f"[yellow]⚠ {status_raw}[/yellow]"

                ports_list = c.get("ports", [])
                ports_str = ", ".join(ports_list) if ports_list else "[dim]-[/dim]"

                table.add_row(
                    c.get("service", ""),
                    c.get("name", ""),
                    c.get("image", ""),
                    state_colored,
                    ports_str,
                )

            console.print(table)
            console.print()
