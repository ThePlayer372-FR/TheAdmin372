import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()


class SecurityCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "security"

    @property
    def help(self) -> str:
        return "Controllo integrità permessi file e anti-privilege escalation del demone"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        sec_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = sec_parser.add_subparsers(dest="security_action", required=False)

        # theadmin372 security check (default)
        sub_actions.add_parser("check", help="Verifica che i file del demone non siano modificabili da utenti non-root")

        # theadmin372 security status (alias di check)
        sub_actions.add_parser("status", help="Mostra lo stato di autorizzazione all'esecuzione dei comandi")

        # theadmin372 security fix
        sub_actions.add_parser("fix", help="Corregge automaticamente i permessi impostando owner root:root e chmod go-w")

    def _get_error_detail(self, res) -> str:
        try:
            data = res.json()
            if isinstance(data, dict) and "detail" in data:
                return data["detail"]
        except Exception:
            pass
        return res.text.strip() or f"Codice di stato HTTP {res.status_code}"

    def handle(self, args: argparse.Namespace, client: DaemonClient) -> None:
        action = getattr(args, "security_action", None) or "check"

        if action in ["check", "status"]:
            self._handle_check(client)
        elif action == "fix":
            self._handle_fix(client)
        else:
            console.print(f"[red]✖ Azione non riconosciuta:[/red] {action}")

    def _handle_check(self, client: DaemonClient) -> None:
        res = client.get("/v1/security/status")
        if res.status_code != 200:
            console.print(f"[red]✖ Errore recupero stato sicurezza ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        data = res.json()
        is_secure = data.get("is_secure", False)
        can_exec = data.get("can_execute_commands", False)
        violations = data.get("violations", [])
        total_checked = data.get("total_critical_paths", 0)

        console.print("\n[bold cyan]🛡️ TheAdmin372 Security Guard - Anti-Privilege Escalation[/bold cyan]\n")

        if is_secure and can_exec:
            panel_msg = (
                f"[bold green]✔ SISTEMA SICURO: ESECUZIONE COMANDI AUTORIZZATA[/bold green]\n\n"
                f"• Tutti i [bold cyan]{total_checked}[/bold cyan] file e cartelle critici appartengono a [bold white]root[/bold white] "
                f"e [bold underline]non possono essere modificati da utenti non-root[/bold underline].\n"
                f"• Il demone può eseguire comandi di sistema in totale sicurezza."
            )
            console.print(Panel(panel_msg, border_style="green", title="[bold]Stato Permessi[/bold]"))
        else:
            table = Table(title=f"⚠️ Violazioni Rilevate ({len(violations)} percorsi a rischio)", header_style="bold red")
            table.add_column("Percorso Critico", style="yellow")
            table.add_column("Proprietario", justify="center")
            table.add_column("Permessi", justify="center")
            table.add_column("Rischio / Motivo della Violazione", style="red")

            for v in violations:
                uid_str = f"UID={v.get('uid', '?')}:GID={v.get('gid', '?')}"
                mode_str = str(v.get("mode", "?"))
                table.add_row(v.get("path", "?"), uid_str, mode_str, v.get("reason", "Modificabile da non-root"))

            console.print(table)

            panel_msg = (
                f"[bold red]✖ ESECUZIONE COMANDI BLOCCATA PER MOTIVI DI SICUREZZA[/bold red]\n\n"
                f"Il demone è in esecuzione come root ma alcuni suoi file possono essere modificati da utenti non-root.\n"
                f"Per prevenire attacchi di [bold underline]Privilege Escalation[/bold underline], l'esecuzione di comandi esterni è disabilitata.\n\n"
                f"[bold yellow]👉 Per correggere automaticamente i permessi esegui:[/bold yellow]\n"
                f"   [bold white]theadmin372 security fix[/bold white]"
            )
            console.print(Panel(panel_msg, border_style="red", title="[bold]Allarme Sicurezza[/bold]"))

        console.print()

    def _handle_fix(self, client: DaemonClient) -> None:
        console.print("[cyan]Avvio hardening e correzione automatica dei permessi...[/cyan]")
        res = client.post("/v1/security/fix")
        if res.status_code != 200:
            console.print(f"[red]✖ Errore applicazione fix sicurezza ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        data = res.json()
        fixed_count = data.get("fixed_count", 0)
        fixed_items = data.get("fixed_items", [])
        errors = data.get("errors", [])
        is_secure = data.get("is_secure", False)

        if fixed_items:
            console.print(f"\n[green]✔ Applicate correzioni su [bold]{fixed_count}[/bold] percorsi:[/green]")
            for item in fixed_items[:20]:
                console.print(f"  🔧 [dim]{item}[/dim]")
            if len(fixed_items) > 20:
                console.print(f"  [dim]... e altri {len(fixed_items) - 20} file[/dim]")

        if errors:
            console.print(f"\n[yellow]⚠️ Avvisi durante l'applicazione ({len(errors)}):[/yellow]")
            for err in errors[:10]:
                console.print(f"  ✖ {err}")

        if is_secure:
            panel_msg = (
                "[bold green]✔ Hardening completato con successo![/bold green]\n\n"
                "Tutti i file del demone sono ora protetti da modifiche non-root (owner root:root, chmod go-w).\n"
                "L'esecuzione dei comandi di sistema da parte del demone è [bold cyan]AUTORIZZATA[/bold cyan]."
            )
            console.print(Panel(panel_msg, border_style="green", title="[bold]Sicurezza Ripristinata[/bold]"))
        else:
            rem = data.get("remaining_violations_count", 0)
            panel_msg = (
                f"[bold red]✖ Alcune violazioni non sono state risolte automaticamente ({rem} rimanenti).[/bold red]\n\n"
                "Verifica se i percorsi risiedono su mount non scrivibili o se è necessario un intervento manuale."
            )
            console.print(Panel(panel_msg, border_style="yellow", title="[bold]Attenzione[/bold]"))

        console.print()
