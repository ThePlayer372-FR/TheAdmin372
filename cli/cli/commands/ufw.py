import argparse
from rich.console import Console
from rich.table import Table
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()


class UFWCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "ufw"

    @property
    def help(self) -> str:
        return "Gestione e configurazione del firewall UFW"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        ufw_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = ufw_parser.add_subparsers(dest="ufw_action", required=True)

        # theadmin ufw status
        sub_actions.add_parser("status", help="Mostra lo stato e la tabella delle regole attive")

        # theadmin ufw allow <port> [--proto tcp|udp]
        allow_parser = sub_actions.add_parser("allow", help="Apri una porta")
        allow_parser.add_argument("port", type=int, help="Porta da aprire (1-65535)")
        allow_parser.add_argument("--proto", choices=["tcp", "udp"], default="tcp", help="Protocollo di trasporto (default: tcp)")

        # theadmin ufw deny <port> [--proto tcp|udp]
        deny_parser = sub_actions.add_parser("deny", help="Blocca una porta")
        deny_parser.add_argument("port", type=int, help="Porta da bloccare (1-65535)")
        deny_parser.add_argument("--proto", choices=["tcp", "udp"], default="tcp", help="Protocollo di trasporto (default: tcp)")

        # theadmin ufw delete <rule_id>
        delete_parser = sub_actions.add_parser("delete", help="Elimina una regola tramite il suo indice numerico (#)")
        delete_parser.add_argument("rule_id", type=int, help="Numero identificativo della regola da eliminare")

        # theadmin ufw enable
        sub_actions.add_parser("enable", help="Abilita e avvia il firewall UFW")

        # theadmin ufw disable
        sub_actions.add_parser("disable", help="Disabilita e arresta il firewall UFW")

        # theadmin ufw reload
        sub_actions.add_parser("reload", help="Ricarica le regole e la configurazione del firewall UFW")

    def _get_error_detail(self, res) -> str:
        try:
            data = res.json()
            if isinstance(data, dict) and "detail" in data:
                return data["detail"]
            if isinstance(data, dict) and "message" in data:
                return data["message"]
        except Exception:
            pass
        return res.text.strip() or f"Codice di stato HTTP {res.status_code}"

    def handle(self, args: argparse.Namespace, client: DaemonClient) -> None:
        if args.ufw_action in ["allow", "deny"]:
            payload = {"port": args.port, "proto": args.proto, "action": args.ufw_action}
            res = client.post("/v1/ufw/rule", json_data=payload)

            if res.status_code == 200:
                console.print(f"[green]✔ Regola applicata con successo:[/green] {args.ufw_action} {args.port}/{args.proto}")
            else:
                err = self._get_error_detail(res)
                console.print(f"[red]✖ Errore ({res.status_code}):[/red] {err}")

        elif args.ufw_action == "delete":
            res = client.delete(f"/v1/ufw/rules/{args.rule_id}")
            if res.status_code == 200:
                msg = res.json().get("message", f"Regola #{args.rule_id} eliminata")
                console.print(f"[green]✔ {msg}[/green]")
            else:
                err = self._get_error_detail(res)
                console.print(f"[red]✖ Errore eliminazione ({res.status_code}):[/red] {err}")

        elif args.ufw_action in ["enable", "disable", "reload"]:
            res = client.post(f"/v1/ufw/{args.ufw_action}")
            if res.status_code == 200:
                msg = res.json().get("message", f"Operazione {args.ufw_action} eseguita con successo")
                console.print(f"[green]✔ {msg}[/green]")
            else:
                err = self._get_error_detail(res)
                console.print(f"[red]✖ Errore operazione {args.ufw_action} ({res.status_code}):[/red] {err}")

        elif args.ufw_action == "status":
            res = client.get("/v1/ufw/status")
            if res.status_code != 200:
                err = self._get_error_detail(res)
                console.print(f"[red]✖ Impossibile recuperare lo stato:[/red] {err}")
                return

            data = res.json()
            is_active = data.get("active", False)
            status_color = "green" if is_active else "red"
            status_text = "ATTIVO" if is_active else "DISATTIVO"
            console.print(f"Stato Firewall: [{status_color} bold]{status_text}[/{status_color} bold]\n")

            rules = data.get("rules", [])
            if not rules:
                console.print("[dim]Nessuna regola configurata nel firewall.[/dim]")
                return

            table = Table(title="Regole Firewall UFW", show_lines=False)
            table.add_column("#", style="bold dim", width=4)
            table.add_column("Porta / Servizio", style="cyan")
            table.add_column("Protocollo", style="magenta")
            table.add_column("Azione", style="bold")
            table.add_column("Direzione", style="blue")
            table.add_column("Sorgente", style="yellow")
            table.add_column("IPv6", style="dim cyan")

            for rule in rules:
                action = str(rule.get("action", ""))
                action_style = "green" if "ALLOW" in action else ("red" if "DENY" in action or "REJECT" in action else "yellow")
                v6_flag = "✓ v6" if rule.get("v6") else "-"

                table.add_row(
                    str(rule.get("index", rule.get("id", ""))),
                    str(rule.get("port", "")),
                    str(rule.get("proto", "any")),
                    f"[{action_style}]{action}[/{action_style}]",
                    str(rule.get("direction", "IN")),
                    str(rule.get("from", rule.get("from_ip", "Anywhere"))),
                    v6_flag,
                )
            console.print(table)