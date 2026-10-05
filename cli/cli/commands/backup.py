import argparse
import os
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()


class BackupCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "backup"

    @property
    def help(self) -> str:
        return "Gestione piani di backup, schedulazione, cifratura envelope e restore"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        backup_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = backup_parser.add_subparsers(dest="backup_action", required=True)

        # 1. theadmin372 backup keygen
        keygen_p = sub_actions.add_parser("keygen", help="Genera la coppia di chiavi RSA a 4096 bit per Envelope Encryption")
        keygen_p.add_argument("--out-pub", default=None, help="Percorso copia chiave pubblica locale")
        keygen_p.add_argument("--out", "--out-priv", dest="out_priv", default=None, help="Percorso chiave privata locale (default: ~/.theadmin_backup_priv.pem)")

        # 2. theadmin372 backup create <nome> [paths...] [--retention 7] [--compression zstd|gz]
        create_p = sub_actions.add_parser("create", help="Crea un nuovo piano di backup")
        create_p.add_argument("name", help="Nome identificativo univoco del piano (es. sys-config)")
        create_p.add_argument("paths", nargs="*", default=[], help="Percorsi target opzionali da aggiungere subito al piano")
        create_p.add_argument("--retention", type=int, default=7, help="Numero di archivi storici da conservare (default: 7)")
        create_p.add_argument("--compression", choices=["zstd", "gz"], default="zstd", help="Algoritmo di compressione (default: zstd)")
        create_p.add_argument("--no-encrypt", action="store_true", help="Disabilita la cifratura Envelope (sconsigliato)")
        create_p.add_argument("--r2-endpoint", help="Cloudflare R2 Endpoint URL")
        create_p.add_argument("--r2-bucket", help="Cloudflare R2 Bucket Name")
        create_p.add_argument("--r2-access-key", help="Cloudflare R2 Access Key ID")
        create_p.add_argument("--r2-secret-key", help="Cloudflare R2 Secret Access Key")

        # 3. theadmin372 backup add <nome> <path1> [path2 ...]
        add_p = sub_actions.add_parser("add", help="Aggiunge uno o più percorsi target al piano")
        add_p.add_argument("name", help="Nome del piano")
        add_p.add_argument("paths", nargs="+", help="Percorsi relativi o assoluti da includere nel backup")

        # 3b. theadmin372 backup remove <nome> <path1> [path2 ...]
        remove_p = sub_actions.add_parser("remove", help="Rimuove uno o più percorsi target dal piano")
        remove_p.add_argument("name", help="Nome del piano")
        remove_p.add_argument("paths", nargs="+", help="Percorsi da rimuovere dal backup")

        # 4. theadmin372 backup schedule <nome> --every <intervallo> [--disable]
        sched_p = sub_actions.add_parser("schedule", help="Configura la frequenza automatica del piano")
        sched_p.add_argument("name", help="Nome del piano")
        sched_p.add_argument("--every", default=None, help="Intervallo di esecuzione (es. 30m, 6h, 12h, 24h, 7d)")
        sched_p.add_argument("--disable", action="store_true", help="Disabilita la pianificazione automatica")

        # 5. theadmin372 backup show <nome>
        show_p = sub_actions.add_parser("show", help="Mostra i dettagli completi del piano e lo storico archivi")
        show_p.add_argument("name", help="Nome del piano da visualizzare")

        # 6. theadmin372 backup list
        sub_actions.add_parser("list", help="Elenca tutti i piani di backup registrati")

        # 7. theadmin372 backup run <nome>
        run_p = sub_actions.add_parser("run", help="Avvia l'esecuzione manuale immediata del backup")
        run_p.add_argument("name", help="Nome del piano da eseguire")

        # 8. theadmin372 backup restore <nome> [--key <path>] [--thesecret] [--archive <filename>] [--target <dir>] [--yes]
        restore_p = sub_actions.add_parser("restore", help="Ripristina un archivio cifrato verificando integrità e manifest")
        restore_p.add_argument("name", help="Nome del piano da ripristinare")
        restore_p.add_argument("--key", required=False, default=None, help="Percorso locale della chiave privata RSA PEM (opzionale con --thesecret)")
        restore_p.add_argument("--thesecret", action="store_true", help="Usa TheSecret372 come oracolo crittografico per decifrare l'archivio senza chiave privata")
        restore_p.add_argument("--archive", default="latest", help="Nome dell'archivio specifico da ripristinare (default: latest)")
        restore_p.add_argument("--target", default=None, help="Cartella di destinazione (se omessa: ripristino in-place con snapshot preventivo)")
        restore_p.add_argument("-y", "--yes", action="store_true", help="Conferma automatica senza richiesta interattiva")

        # 9. theadmin372 backup delete <nome>
        del_p = sub_actions.add_parser("delete", help="Elimina la configurazione di un piano di backup")
        del_p.add_argument("name", help="Nome del piano da eliminare")

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
        action = getattr(args, "backup_action", None)

        if action == "keygen":
            self._handle_keygen(args, client)
        elif action == "create":
            self._handle_create(args, client)
        elif action == "add":
            self._handle_add(args, client)
        elif action == "remove":
            self._handle_remove(args, client)
        elif action == "schedule":
            self._handle_schedule(args, client)
        elif action == "show":
            self._handle_show(args, client)
        elif action == "list":
            self._handle_list(args, client)
        elif action == "run":
            self._handle_run(args, client)
        elif action == "restore":
            self._handle_restore(args, client)
        elif action == "delete":
            self._handle_delete(args, client)
        else:
            console.print(f"[yellow]Azione non riconosciuta: {action}[/yellow]")

    def _handle_delete(self, args: argparse.Namespace, client: DaemonClient) -> None:
        res = client.delete(f"/v1/backup/plans/{args.name}")
        if res.status_code == 200:
            console.print(f"[green]✔ Piano di backup '[bold]{args.name}[/bold]' eliminato con successo.[/green]")
        elif res.status_code == 404:
            console.print(f"[yellow]ℹ Piano '[bold]{args.name}[/bold]' non trovato.[/yellow]")
        else:
            console.print(f"[red]✖ Errore eliminazione piano ({res.status_code}):[/red] {self._get_error_detail(res)}")

    def _handle_keygen(self, args: argparse.Namespace, client: DaemonClient) -> None:
        out_priv = Path(args.out_priv or (Path.home() / ".theadmin_backup_priv.pem")).expanduser().resolve()
        out_pub = Path(args.out_pub).expanduser().resolve() if args.out_pub else None

        console.print("[cyan]Generazione coppia di chiavi RSA a 4096 bit per Envelope Encryption...[/cyan]")

        pub_pem_str = None
        priv_pem_str = None

        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization

            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            priv_pem_bytes = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_pem_bytes = priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            priv_pem_str = priv_pem_bytes.decode("utf-8")
            pub_pem_str = pub_pem_bytes.decode("utf-8")

            # Deposita la chiave pubblica sul server demone
            res = client.post("/v1/backup/keys/init", json_data={"public_key": pub_pem_str})
            if res.status_code != 200:
                console.print(f"[red]✖ Errore deposito chiave pubblica sul server:[/red] {self._get_error_detail(res)}")
                return
        except ImportError:
            # Fallback tramite endpoint demone
            res = client.post("/v1/backup/keys/init", json_data={})
            if res.status_code != 200:
                console.print(f"[red]✖ Errore generazione chiavi sul server:[/red] {self._get_error_detail(res)}")
                return
            data = res.json()
            pub_pem_str = data.get("public_key")
            priv_pem_str = data.get("private_key")

        # Salva la chiave privata in locale con permessi 0600
        out_priv.parent.mkdir(parents=True, exist_ok=True)
        out_priv.write_text(priv_pem_str, encoding="utf-8")
        os.chmod(out_priv, 0o600)

        if out_pub and pub_pem_str:
            out_pub.parent.mkdir(parents=True, exist_ok=True)
            out_pub.write_text(pub_pem_str, encoding="utf-8")

        panel_content = (
            f"[bold green]✔ Coppia di chiavi RSA 4096 bit generata con successo![/bold green]\n\n"
            f"• [bold cyan]Chiave Pubblica (Server):[/bold cyan] [yellow]/etc/theadmin372/keys/backup_pub.pem[/yellow]\n"
            f"• [bold cyan]Chiave Privata (Locale):[/bold cyan]  [green]{out_priv}[/green] [dim](permessi 0600)[/dim]\n\n"
            f"[bold red]ATTENZIONE: ZERO-KNOWLEDGE ENCRYPTION[/bold red]\n"
            f"Il server non possiede la chiave privata e non potrà decifrare gli archivi senza di essa.\n"
            f"Conserva il file [green]{out_priv.name}[/green] in una posizione offline sicura."
        )
        console.print(Panel(panel_content, title="[bold]Envelope Encryption Keypair[/bold]", border_style="green"))

    def _handle_create(self, args: argparse.Namespace, client: DaemonClient) -> None:
        abs_paths = [str(Path(p).expanduser().resolve()) for p in getattr(args, "paths", [])]
        
        r2_upload = None
        if args.r2_endpoint and args.r2_bucket and args.r2_access_key and args.r2_secret_key:
            r2_upload = {
                "enabled": True,
                "endpoint_url": args.r2_endpoint,
                "bucket_name": args.r2_bucket,
                "access_key_id": args.r2_access_key,
                "secret_access_key": args.r2_secret_key,
            }

        payload = {
            "name": args.name,
            "paths": abs_paths,
            "retention_count": args.retention,
            "compression": args.compression,
            "encryption": not args.no_encrypt,
            "schedule_enabled": True,
            "schedule_interval": "24h",
            "r2_upload": r2_upload,
        }
        res = client.post("/v1/backup/plans", json_data=payload)
        if res.status_code == 201:
            data = res.json()
            console.print(f"[green]✔ Piano di backup '[bold]{data['name']}[/bold]' creato con successo![/green]")
            console.print(f"  • Cifratura: [cyan]{'Envelope RSA+AES-GCM' if data['encryption'] else 'Disabilitata'}[/cyan]")
            console.print(f"  • Compressione: [cyan]{data['compression']}[/cyan] | Retention: [cyan]{data['retention_count']} archivi[/cyan]")
            if r2_upload:
                console.print(f"  • Cloudflare R2 Upload: [cyan]Abilitato (Bucket: {args.r2_bucket})[/cyan]")
            console.print(f"  • Schedulazione predefinita: [cyan]ogni 24h[/cyan] (usa 'theadmin372 backup schedule' per personalizzare)")
            if data.get("paths"):
                console.print(f"  • Target iniziali configurati:")
                for p in data["paths"]:
                    console.print(f"    📁 [cyan]{p}[/cyan]")
            else:
                console.print(f"\n[dim]Per aggiungere directory target: theadmin372 backup add {data['name']} /path/1 /path/2[/dim]")
        else:
            console.print(f"[red]✖ Errore creazione piano ({res.status_code}):[/red] {self._get_error_detail(res)}")

    def _handle_add(self, args: argparse.Namespace, client: DaemonClient) -> None:
        abs_paths = [str(Path(p).expanduser().resolve()) for p in args.paths]
        payload = {"paths": abs_paths}
        res = client.post(f"/v1/backup/plans/{args.name}/paths", json_data=payload)
        if res.status_code == 200:
            data = res.json()
            console.print(f"[green]✔ Percorsi aggiornati per il piano '[bold]{args.name}[/bold]':[/green]")
            for p in data.get("paths", []):
                console.print(f"  📁 [cyan]{p}[/cyan]")
        else:
            console.print(f"[red]✖ Errore aggiunta percorsi ({res.status_code}):[/red] {self._get_error_detail(res)}")

    def _handle_remove(self, args: argparse.Namespace, client: DaemonClient) -> None:
        abs_paths = [str(Path(p).expanduser().resolve()) for p in args.paths]
        payload = {"paths": abs_paths}
        res = client.delete(f"/v1/backup/plans/{args.name}/paths", json_data=payload)
        if res.status_code == 200:
            data = res.json()
            console.print(f"[green]✔ Percorsi aggiornati per il piano '[bold]{args.name}[/bold]':[/green]")
            for p in data.get("paths", []):
                console.print(f"  📁 [cyan]{p}[/cyan]")
        else:
            console.print(f"[red]✖ Errore rimozione percorsi ({res.status_code}):[/red] {self._get_error_detail(res)}")

    def _handle_schedule(self, args: argparse.Namespace, client: DaemonClient) -> None:
        payload = {}
        if args.disable:
            payload["disable"] = True
        elif args.every:
            payload["every"] = args.every
            payload["enabled"] = True
        else:
            console.print("[yellow]Specificare --every <intervallo> (es. 6h, 24h, 7d) oppure --disable[/yellow]")
            return

        res = client.put(f"/v1/backup/plans/{args.name}/schedule", json_data=payload)
        if res.status_code == 200:
            data = res.json()
            sched = data.get("schedule", {})
            if sched.get("enabled"):
                console.print(f"[green]✔ Schedulazione attiva per '{args.name}':[/green] ogni [bold cyan]{sched.get('interval')}[/bold cyan]")
                console.print(f"  • Prossimo run calcolato: [yellow]{sched.get('next_run') or 'immediato'}[/yellow]")
            else:
                console.print(f"[yellow]✔ Schedulazione automatica disabilitata per il piano '{args.name}'.[/yellow]")
        else:
            console.print(f"[red]✖ Errore configurazione schedulazione ({res.status_code}):[/red] {self._get_error_detail(res)}")

    def _handle_show(self, args: argparse.Namespace, client: DaemonClient) -> None:
        res = client.get(f"/v1/backup/plans/{args.name}")
        if res.status_code != 200:
            console.print(f"[red]✖ Errore recupero piano ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        plan = res.json()
        sched = plan.get("schedule", {})
        sched_status = f"[green]Attivo (ogni {sched.get('interval')})[/green]" if sched.get("enabled") else "[dim]Disabilitato[/dim]"

        console.print(f"\n[bold]Piano di Backup:[/bold] [bold cyan]{plan['name']}[/bold cyan]")
        console.print(f"• [bold]Creato il:[/bold]       {plan['created_at']}")
        console.print(f"• [bold]Cifratura:[/bold]       {'[green]✔ Envelope RSA-OAEP + AES-GCM[/green]' if plan['encryption'] else '[red]✖ Disabilitata[/red]'}")
        console.print(f"• [bold]Compressione:[/bold]    {plan['compression']} | [bold]Retention:[/bold] max {plan['retention_count']} archivi")
        console.print(f"• [bold]Schedulazione:[/bold]   {sched_status}")
        console.print(f"• [bold]Ultimo run:[/bold]      {sched.get('last_run') or '[dim]Mai eseguito[/dim]'}")
        console.print(f"• [bold]Prossimo run:[/bold]    {sched.get('next_run') or '[dim]-[/dim]'}")

        console.print("\n[bold]Percorsi Target Inclusi:[/bold]")
        paths = plan.get("paths", [])
        if paths:
            for p in paths:
                console.print(f"  📁 [cyan]{p}[/cyan]")
        else:
            console.print("  [dim]Nessun percorso registrato[/dim]")

        # Elenco archivi storici
        res_arch = client.get(f"/v1/backup/plans/{args.name}/archives")
        archives = res_arch.json() if res_arch.status_code == 200 else []

        console.print(f"\n[bold]Archivi Storici Disponibili:[/bold] [cyan]{len(archives)}[/cyan] (Totale: {plan.get('total_size_human', '0 B')})\n")

        if archives:
            table = Table(box=box.ROUNDED, show_header=True, header_style="bold dim")
            table.add_column("Nome File Archivio", style="bold cyan")
            table.add_column("Data Creazione", style="green")
            table.add_column("Dimensione", style="yellow")
            table.add_column("Cifrato", style="magenta")
            table.add_column("SHA-256 (Hash)", style="dim")

            for a in archives:
                sha_trunc = (a.get("sha256") or "")[:12] + "…" if a.get("sha256") else "-"
                is_enc = "[green]✔ Sì[/green]" if a.get("is_encrypted") else "[dim]No[/dim]"
                table.add_row(
                    a.get("filename", ""),
                    a.get("created_at", "").replace("T", " ")[:19],
                    a.get("size_human", ""),
                    is_enc,
                    sha_trunc,
                )
            console.print(table)
        else:
            console.print("  [dim]Nessun archivio generato finora.[/dim]")
        console.print()

    def _handle_list(self, args: argparse.Namespace, client: DaemonClient) -> None:
        res = client.get("/v1/backup/plans")
        if res.status_code != 200:
            console.print(f"[red]✖ Errore recupero elenco piani ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        plans = res.json()
        if not plans:
            console.print("[yellow]Nessun piano di backup configurato. Usa 'theadmin372 backup create <nome>' per iniziare.[/yellow]")
            return

        table = Table(title="Piani di Backup Registrati", box=box.ROUNDED, header_style="bold cyan", expand=True)
        table.add_column("Nome Piano", style="bold white", min_width=16)
        table.add_column("Target", style="cyan", min_width=10)
        table.add_column("Schedulazione", style="green")
        table.add_column("Ultimo Run", style="yellow")
        table.add_column("Prossimo Run", style="yellow")
        table.add_column("Archivi", style="magenta")
        table.add_column("Spazio", style="blue")

        for p in plans:
            sched = p.get("schedule", {})
            sched_str = f"ogni {sched.get('interval')}" if sched.get("enabled") else "[dim]off[/dim]"
            last_run = (sched.get("last_run") or "-").replace("T", " ")[:16]
            next_run = (sched.get("next_run") or "-").replace("T", " ")[:16]
            paths_cnt = f"{len(p.get('paths', []))} percorsi"

            table.add_row(
                p.get("name", ""),
                paths_cnt,
                sched_str,
                last_run,
                next_run,
                f"{p.get('total_archives', 0)} / {p.get('retention_count', 7)}",
                p.get("total_size_human", "0 B"),
            )

        console.print()
        console.print(table)
        console.print()

    def _handle_run(self, args: argparse.Namespace, client: DaemonClient) -> None:
        res = client.post(f"/v1/backup/plans/{args.name}/run")
        if res.status_code != 200:
            console.print(f"[red]✖ Errore avvio backup ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        job_info = res.json()
        job_id = job_info.get("job_id")
        console.print(f"[bold cyan]Avvio backup per il piano '[white]{args.name}[/white]'...[/bold cyan]")

        with console.status(f"[bold green]Job {job_id[:8]} in corso...[/bold green]", spinner="dots") as status:
            while True:
                time.sleep(1.0)
                res_job = client.get(f"/v1/backup/jobs/{job_id}")
                if res_job.status_code != 200:
                    console.print(f"[red]✖ Errore polling stato job ({res_job.status_code})[/red]")
                    break

                job = res_job.json()
                st = job.get("status")
                progress = job.get("progress", 0)
                msg = job.get("message", "")
                status.update(f"[bold cyan][{progress}%][/bold cyan] {msg}")

                if st == "completed":
                    arch = job.get("archive_filename", "")
                    console.print(f"\n[bold green]✔ Backup completato con successo![/bold green]")
                    console.print(f"📦 Archivio generato: [bold yellow]{arch}[/bold yellow]\n")
                    break
                elif st == "failed":
                    err = job.get("error", "Errore sconosciuto")
                    console.print(f"\n[bold red]✖ Backup fallito:[/bold red] {err}\n")
                    break

    def _handle_restore(self, args: argparse.Namespace, client: DaemonClient) -> None:
        use_thesecret = getattr(args, "thesecret", False)
        priv_key_content = None

        if not use_thesecret and not args.key:
            console.print("[bold red]✖ Errore:[/bold red] È necessario specificare [bold cyan]--key <path>[/bold cyan] oppure [bold cyan]--thesecret[/bold cyan] per delegare la decifratura all'oracolo.")
            return

        if not use_thesecret:
            key_path = Path(args.key).expanduser().resolve()
            if not key_path.is_file():
                console.print(f"[bold red]✖ File chiave privata non trovato in:[/bold red] {key_path}")
                return

            try:
                priv_key_content = key_path.read_text(encoding="utf-8")
            except Exception as e:
                console.print(f"[bold red]✖ Errore lettura file chiave privata:[/bold red] {e}")
                return

        # Avviso di sovrascrittura se non è specificata una cartella di test / target
        if not args.target:
            console.print(
                Panel(
                    "[bold red]ATTENZIONE: RIPRISTINO IN-PLACE SUL FILESYSTEM DI SISTEMA[/bold red]\n\n"
                    "Non hai specificato una cartella di destinazione (--target <dir>).\n"
                    "I file originali del sistema verranno [bold underline]sovrascritti[/bold underline] con le versioni estratte dall'archivio!\n"
                    "[dim](Verrà comunque generato uno snapshot di sicurezza preventivo in /var/backups/theadmin372/snapshots/)[/dim]",
                    title="[bold yellow]Avviso di Sicurezza[/bold yellow]",
                    border_style="red",
                )
            )
            if not args.yes:
                confirmed = Confirm.ask("[bold yellow]Vuoi davvero procedere con il ripristino in-place?[/bold yellow]", default=False)
                if not confirmed:
                    console.print("[dim]Operazione di ripristino annullata dall'utente.[/dim]")
                    return

        target_dir = str(Path(args.target).expanduser().resolve()) if args.target else None
        payload = {
            "private_key": priv_key_content,
            "use_thesecret": use_thesecret,
            "archive": args.archive,
            "target_dir": target_dir,
        }

        res = client.post(f"/v1/backup/plans/{args.name}/restore", json_data=payload)
        if res.status_code != 200:
            console.print(f"[red]✖ Errore richiesta di ripristino ({res.status_code}):[/red] {self._get_error_detail(res)}")
            return

        job_info = res.json()
        job_id = job_info.get("job_id")
        arch_name = job_info.get("archive", "latest")

        console.print(f"[bold cyan]Avvio ripristino dall'archivio '[white]{arch_name}[/white]'...[/bold cyan]")

        with console.status(f"[bold green]Job {job_id[:8]} in esecuzione...[/bold green]", spinner="dots") as status:
            while True:
                time.sleep(1.0)
                res_job = client.get(f"/v1/backup/jobs/{job_id}")
                if res_job.status_code != 200:
                    console.print(f"[red]✖ Errore polling stato ripristino ({res_job.status_code})[/red]")
                    break

                job = res_job.json()
                st = job.get("status")
                progress = job.get("progress", 0)
                msg = job.get("message", "")
                status.update(f"[bold cyan][{progress}%][/bold cyan] {msg}")

                if st == "completed":
                    cnt = job.get("restored_files_count", 0)
                    dest = target_dir or "filesystem originale (in-place)"
                    console.print(f"\n[bold green]✔ Ripristino completato con successo![/bold green]")
                    console.print(f"• File ripristinati e verificati: [bold cyan]{cnt}[/bold cyan]")
                    console.print(f"• Destinazione: [bold yellow]{dest}[/bold yellow]")
                    files_list = job.get("restored_files", [])
                    if files_list:
                        console.print("• Percorsi file ripristinati:")
                        for fp in files_list[:15]:
                            console.print(f"  📄 [cyan]{fp}[/cyan]")
                        if len(files_list) > 15:
                            console.print(f"  [dim]... e altri {len(files_list) - 15} file[/dim]")
                    console.print()
                    break
                elif st == "failed":
                    err = job.get("error", "Errore sconosciuto")
                    console.print(f"\n[bold red]✖ Ripristino fallito:[/bold red] {err}\n")
                    break
