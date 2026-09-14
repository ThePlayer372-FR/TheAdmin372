import argparse
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()


class NginxCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "nginx"

    @property
    def help(self) -> str:
        return "Gestione e configurazione del reverse proxy Nginx"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        nginx_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = nginx_parser.add_subparsers(dest="nginx_action", required=True)

        # theadmin372 nginx list
        sub_actions.add_parser("list", help="Elenca tutti i virtual host configurati")

        # theadmin372 nginx proxy <domain> <upstream> [--disable] [--ws] [--max-body 100M]
        proxy_parser = sub_actions.add_parser("proxy", help="Crea o aggiorna un virtual host di reverse proxy")
        proxy_parser.add_argument("domain", help="Nome a dominio o FQDN (es. app.example.com)")
        proxy_parser.add_argument("upstream", help="URL upstream (es. http://127.0.0.1:8000 o unix:/run/app.sock)")
        proxy_parser.add_argument("--disable", action="store_true", help="Crea il virtual host senza abilitarlo in sites-enabled/")
        proxy_parser.add_argument("--ws", action="store_true", help="Abilita il supporto a WebSockets (Upgrade/Connection headers)")
        proxy_parser.add_argument("--max-body", default="50M", help="Dimensione massima del body richiesta (default: 50M)")

        # theadmin372 nginx enable <domain>
        enable_parser = sub_actions.add_parser("enable", help="Abilita un virtual host creando il symlink")
        enable_parser.add_argument("domain", help="Nome a dominio da abilitare")

        # theadmin372 nginx disable <domain>
        disable_parser = sub_actions.add_parser("disable", help="Disabilita un virtual host rimuovendo il symlink")
        disable_parser.add_argument("domain", help="Nome a dominio da disabilitare")

        # theadmin372 nginx delete <domain> [--force]
        delete_parser = sub_actions.add_parser("delete", help="Rimuove la configurazione e il symlink del virtual host")
        delete_parser.add_argument("domain", help="Nome a dominio da eliminare")
        delete_parser.add_argument("-f", "--force", action="store_true", help="Salta la conferma di eliminazione")

        # theadmin372 nginx reload
        sub_actions.add_parser("reload", help="Esegue il dry-run 'nginx -t' e ricarica Nginx")

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
        if args.nginx_action == "list":
            res = client.get("/v1/nginx/vhosts")
            if res.status_code != 200:
                console.print(f"[red]✖ Errore recupero virtual host ({res.status_code}):[/red] {self._get_error_detail(res)}")
                return

            vhosts = res.json()
            if not vhosts:
                console.print("[dim]Nessun virtual host configurato in sites-available/.[/dim]")
                return

            table = Table(title="Virtual Hosts Nginx", show_lines=False)
            table.add_column("Dominio", style="cyan bold")
            table.add_column("Upstream", style="yellow")
            table.add_column("Abilitato", style="bold")
            table.add_column("SSL", style="magenta")
            table.add_column("Configurazione", style="dim")

            for v in vhosts:
                enabled_str = "[green]✔ ATTIVO[/green]" if v.get("enabled") else "[red]✖ DISATTIVO[/red]"
                ssl_str = "[green]✔ Sì[/green]" if v.get("has_ssl") else "[dim]✖ No[/dim]"
                upstream_str = v.get("upstream") or "[dim]N/A[/dim]"
                config_path = v.get("config_path", "")

                table.add_row(
                    v.get("domain", ""),
                    upstream_str,
                    enabled_str,
                    ssl_str,
                    config_path,
                )
            console.print(table)

        elif args.nginx_action == "proxy":
            payload = {
                "domain": args.domain,
                "upstream": args.upstream,
                "enabled": not args.disable,
                "websocket": args.ws,
                "client_max_body_size": args.max_body,
            }
            res = client.post("/v1/nginx/vhosts", json_data=payload)
            if res.status_code == 200:
                data = res.json()
                status_text = "abilitato" if data.get("enabled") else "creato (disabilitato)"
                console.print(
                    f"[green]✔ Virtual host reverse proxy per '[bold]{args.domain}[/bold]' {status_text} con successo![/green]\n"
                    f"  Upstream: [cyan]{data.get('upstream')}[/cyan]\n"
                    f"  File config: [dim]{data.get('config_path')}[/dim]"
                )
            elif res.status_code == 422:
                err = self._get_error_detail(res)
                console.print(f"[bold red]✖ Configurazione non valida per Nginx (Rollback eseguito):[/bold red]\n{err}")
            else:
                console.print(f"[red]✖ Errore ({res.status_code}):[/red] {self._get_error_detail(res)}")

        elif args.nginx_action in ["enable", "disable"]:
            endpoint = f"/v1/nginx/vhosts/{args.domain}/{args.nginx_action}"
            res = client.post(endpoint)
            if res.status_code == 200:
                action_text = "abilitato" if args.nginx_action == "enable" else "disabilitato"
                console.print(f"[green]✔ Virtual host '{args.domain}' {action_text} con successo.[/green]")
            elif res.status_code == 422:
                console.print(f"[bold red]✖ Errore Nginx durante {args.nginx_action} (Rollback eseguito):[/bold red]\n{self._get_error_detail(res)}")
            else:
                console.print(f"[red]✖ Errore ({res.status_code}):[/red] {self._get_error_detail(res)}")

        elif args.nginx_action == "delete":
            if not args.force:
                confirmed = Confirm.ask(f"Sei sicuro di voler rimuovere la configurazione del virtual host '[bold]{args.domain}[/bold]'?")
                if not confirmed:
                    console.print("[yellow]Operazione annullata dall'utente.[/yellow]")
                    return

            res = client.delete(f"/v1/nginx/vhosts/{args.domain}")
            if res.status_code == 200:
                console.print(f"[green]✔ Virtual host '{args.domain}' rimosso con successo.[/green]")
            elif res.status_code == 422:
                console.print(f"[bold red]✖ Errore Nginx durante l'eliminazione (Rollback eseguito):[/bold red]\n{self._get_error_detail(res)}")
            else:
                console.print(f"[red]✖ Errore ({res.status_code}):[/red] {self._get_error_detail(res)}")

        elif args.nginx_action == "reload":
            res = client.post("/v1/nginx/reload")
            if res.status_code == 200:
                console.print("[green]✔ Configurazione Nginx testata con successo e servizio ricaricato.[/green]")
            elif res.status_code == 422:
                console.print(f"[bold red]✖ Test configurazione fallito, reload non effettuato:[/bold red]\n{self._get_error_detail(res)}")
            else:
                console.print(f"[red]✖ Errore reload ({res.status_code}):[/red] {self._get_error_detail(res)}")
