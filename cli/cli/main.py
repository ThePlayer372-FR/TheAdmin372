import argparse
from importlib import import_module
from pathlib import Path
from cli.base import BaseCLICommand
from cli.client import DaemonClient

COMMANDS_DIR = Path(__file__).resolve().parent / "commands"

def discover_commands() -> dict[str, BaseCLICommand]:
    commands: dict[str, BaseCLICommand] = {}
    for file in COMMANDS_DIR.glob("*.py"):
        if file.name == "__init__.py":
            continue

        module_name = f"cli.commands.{file.stem}"
        mod = import_module(module_name)

        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseCLICommand)
                and attr is not BaseCLICommand
            ):
                cmd_instance = attr()
                commands[cmd_instance.name] = cmd_instance
    return commands

def main():
    parser = argparse.ArgumentParser(prog="theadmin372", description="CLI client per TheAdmin372 Daemon Engine")
    parser.add_argument("--socket", default=None, help="Percorso alternativo del socket UNIX")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Healthcheck nativo
    health_p = subparsers.add_parser("health", help="Verifica stato connessione con il demone")

    # Registra tutti i comandi scoperti dinamicamente
    commands = discover_commands()
    for cmd in commands.values():
        cmd.register_subparser(subparsers)

    args = parser.parse_args()

    client = DaemonClient(socket_path=args.socket) if args.socket else DaemonClient()

    if args.subcommand == "health":
        res = client.get("/health")
        print("Demone raggiungibile:", res.json())
        return

    # Inoltra al gestore del modulo corrispondente
    if args.subcommand in commands:
        commands[args.subcommand].handle(args, client)

if __name__ == "__main__":
    main()