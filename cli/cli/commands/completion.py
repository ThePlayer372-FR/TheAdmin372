import argparse
import os
import sys
from pathlib import Path
from rich.console import Console
from cli.base import BaseCLICommand
from cli.client import DaemonClient

console = Console()

BASH_COMPLETION_SCRIPT = """# bash completion for theadmin372
_theadmin372_filedir() {
    if declare -F _filedir >/dev/null 2>&1; then
        _filedir
    else
        COMPREPLY=( $(compgen -f -- "$cur") )
    fi
}

_theadmin372_completion() {
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local main_commands="health security backup nginx ufw docker completion"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${main_commands} --socket --help -h" -- "$cur") )
        return 0
    fi

    local cmd="${words[1]}"

    case "$cmd" in
        security)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "check fix" -- "$cur") )
                return 0
            fi
            ;;
        docker)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "ps list compose" -- "$cur") )
                return 0
            fi
            case "${words[2]}" in
                ps|list)
                    COMPREPLY=( $(compgen -W "-a --all --json" -- "$cur") )
                    return 0
                    ;;
                compose)
                    COMPREPLY=( $(compgen -W "--json" -- "$cur") )
                    return 0
                    ;;
            esac
            ;;
        ufw)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "status allow deny delete enable disable reload" -- "$cur") )
                return 0
            fi
            case "${words[2]}" in
                allow|deny)
                    if [[ "$prev" == "--proto" ]]; then
                        COMPREPLY=( $(compgen -W "tcp udp" -- "$cur") )
                        return 0
                    fi
                    COMPREPLY=( $(compgen -W "--proto" -- "$cur") )
                    return 0
                    ;;
            esac
            ;;
        nginx)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list proxy enable disable delete reload" -- "$cur") )
                return 0
            fi
            local nginx_action="${words[2]}"
            case "$nginx_action" in
                enable|disable|delete)
                    if [[ $cword -eq 3 ]]; then
                        local domains=""
                        if [[ -d /etc/nginx/sites-available ]]; then
                            local files=$(command ls -1 /etc/nginx/sites-available 2>/dev/null | sed 's/\\.conf$//' | grep -v '^\\.')
                            local sns=$(command grep -h -s -o -E "server_name[[:space:]]+[^;]+" /etc/nginx/sites-available/* 2>/dev/null | sed -e 's/server_name[[:space:]]*//' | tr -s ' ' '\\n' | grep -v '^[#_]' | grep -v '^$')
                            domains=$(printf "%s\\n%s\\n" "$files" "$sns" | sort -u)
                        fi
                        COMPREPLY=( $(compgen -W "${domains}" -- "$cur") )
                        return 0
                    fi
                    if [[ "$nginx_action" == "delete" ]]; then
                        COMPREPLY=( $(compgen -W "-f --force" -- "$cur") )
                        return 0
                    fi
                    ;;
                proxy)
                    if [[ $cword -eq 3 ]]; then
                        local domains=""
                        if [[ -d /etc/nginx/sites-available ]]; then
                            local files=$(command ls -1 /etc/nginx/sites-available 2>/dev/null | sed 's/\\.conf$//' | grep -v '^\\.')
                            local sns=$(command grep -h -s -o -E "server_name[[:space:]]+[^;]+" /etc/nginx/sites-available/* 2>/dev/null | sed -e 's/server_name[[:space:]]*//' | tr -s ' ' '\\n' | grep -v '^[#_]' | grep -v '^$')
                            domains=$(printf "%s\\n%s\\n" "$files" "$sns" | sort -u)
                        fi
                        COMPREPLY=( $(compgen -W "${domains}" -- "$cur") )
                        return 0
                    fi
                    COMPREPLY=( $(compgen -W "--disable --ws --max-body" -- "$cur") )
                    return 0
                    ;;
            esac
            ;;
        backup)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "keygen create add remove schedule show list run restore delete" -- "$cur") )
                return 0
            fi
            local backup_action="${words[2]}"
            local plans=""
            if [[ -d /etc/theadmin372/backups/configs ]]; then
                plans=$(command ls -1 /etc/theadmin372/backups/configs 2>/dev/null | sed -n 's/\\.json$//p')
            fi

            case "$backup_action" in
                keygen)
                    COMPREPLY=( $(compgen -W "--out-pub --out-priv --out" -- "$cur") )
                    return 0
                    ;;
                create)
                    if [[ "$prev" == "--compression" ]]; then
                        COMPREPLY=( $(compgen -W "zstd gz" -- "$cur") )
                        return 0
                    fi
                    COMPREPLY=( $(compgen -W "--retention --compression --no-encrypt" -- "$cur") )
                    return 0
                    ;;
                add|remove)
                    if [[ $cword -eq 3 ]]; then
                        COMPREPLY=( $(compgen -W "${plans}" -- "$cur") )
                        return 0
                    else
                        _theadmin372_filedir
                        return 0
                    fi
                    ;;
                schedule)
                    if [[ $cword -eq 3 ]]; then
                        COMPREPLY=( $(compgen -W "${plans}" -- "$cur") )
                        return 0
                    fi
                    COMPREPLY=( $(compgen -W "--every --disable" -- "$cur") )
                    return 0
                    ;;
                show|run|delete)
                    if [[ $cword -eq 3 ]]; then
                        COMPREPLY=( $(compgen -W "${plans}" -- "$cur") )
                        return 0
                    fi
                    ;;
                restore)
                    if [[ $cword -eq 3 ]]; then
                        COMPREPLY=( $(compgen -W "${plans}" -- "$cur") )
                        return 0
                    fi
                    if [[ "$prev" == "--key" || "$prev" == "--target" ]]; then
                        _theadmin372_filedir
                        return 0
                    fi
                    COMPREPLY=( $(compgen -W "--key --archive --target -y --yes" -- "$cur") )
                    return 0
                    ;;
            esac
            ;;
        completion)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "bash zsh install" -- "$cur") )
                return 0
            fi
            ;;
    esac
}

complete -F _theadmin372_completion theadmin372
"""

ZSH_COMPLETION_SCRIPT = f"""#compdef theadmin372
# Zsh autocompletion for theadmin372 using bashcompinit

autoload -U +X bashcompinit 2>/dev/null && bashcompinit 2>/dev/null
{BASH_COMPLETION_SCRIPT}
"""


class CompletionCommand(BaseCLICommand):
    @property
    def name(self) -> str:
        return "completion"

    @property
    def help(self) -> str:
        return "Genera o installa gli script di autocompletamento shell (Bash/Zsh)"

    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        comp_parser = subparser.add_parser(self.name, help=self.help)
        sub_actions = comp_parser.add_subparsers(dest="shell_action", required=True)

        # theadmin372 completion bash
        sub_actions.add_parser("bash", help="Genera lo script di autocompletamento per Bash")

        # theadmin372 completion zsh
        sub_actions.add_parser("zsh", help="Genera lo script di autocompletamento per Zsh")

        # theadmin372 completion install
        install_p = sub_actions.add_parser("install", help="Installa automaticamente l'autocompletamento nel sistema")
        install_p.add_argument("--system", action="store_true", help="Forza l'installazione di sistema in /etc/bash_completion.d")

    def handle(self, args: argparse.Namespace, client: DaemonClient) -> None:
        if args.shell_action == "bash":
            sys.stdout.write(BASH_COMPLETION_SCRIPT.lstrip())
            sys.stdout.flush()

        elif args.shell_action == "zsh":
            sys.stdout.write(ZSH_COMPLETION_SCRIPT.lstrip())
            sys.stdout.flush()

        elif args.shell_action == "install":
            system_target = Path("/etc/bash_completion.d/theadmin372")
            installed = False

            # Tentativo installazione di sistema (richiede privilegi root o accesso a /etc)
            if os.geteuid() == 0 or args.system:
                try:
                    system_target.parent.mkdir(parents=True, exist_ok=True)
                    system_target.write_text(BASH_COMPLETION_SCRIPT.lstrip(), encoding="utf-8")
                    system_target.chmod(0o644)
                    console.print(f"[green]✔ Autocompletamento di sistema installato con successo in [bold]{system_target}[/bold][/green]")
                    console.print("[dim]Attivo per tutti gli utenti al prossimo login o eseguendo:[/dim] [cyan]source /etc/bash_completion.d/theadmin372[/cyan]")
                    installed = True
                except Exception as e:
                    if args.system:
                        console.print(f"[bold red]✖ Errore installazione di sistema ({e}). Esegui con 'sudo'.[/bold red]")
                        return
                    console.print(f"[yellow]Nota: Impossibile scrivere in {system_target} ({e}). Installazione utente locale in corso...[/yellow]")

            # Se non root o fallback: installa in ~/.theadmin372_completion.bash e collega a ~/.bashrc
            if not installed:
                user_home = Path.home()
                user_comp_file = user_home / ".theadmin372_completion.bash"
                user_comp_file.write_text(BASH_COMPLETION_SCRIPT.lstrip(), encoding="utf-8")
                user_comp_file.chmod(0o644)

                bashrc = user_home / ".bashrc"
                source_line = f"[ -f {user_comp_file} ] && source {user_comp_file}"

                already_in_bashrc = False
                if bashrc.exists():
                    bashrc_content = bashrc.read_text(encoding="utf-8")
                    if str(user_comp_file) in bashrc_content:
                        already_in_bashrc = True

                if not already_in_bashrc:
                    with open(bashrc, "a", encoding="utf-8") as f:
                        f.write(f"\n# TheAdmin372 Autocompletion\n{source_line}\n")

                console.print(f"[green]✔ Autocompletamento utente installato in [bold]{user_comp_file}[/bold][/green]")
                console.print(f"[green]✔ Riferimento aggiunto a [bold]{bashrc}[/bold][/green]")
                console.print("[dim]Attiva subito eseguendo:[/dim] [cyan]source ~/.bashrc[/cyan]")
