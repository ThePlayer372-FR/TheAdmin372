from abc import ABC, abstractmethod
import argparse
from cli.client import DaemonClient

class BaseCLICommand(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Nome del sottocomando (es. 'ufw', 'nginx')."""
        pass

    @property
    @abstractmethod
    def help(self) -> str:
        """Descrizione per l'help di argparse."""
        pass

    @abstractmethod
    def register_subparser(self, subparser: argparse._SubParsersAction) -> None:
        """Configura i sotto-argomenti e flag del comando."""
        pass

    @abstractmethod
    def handle(self, args: argparse.Namespace, client: DaemonClient) -> None:
        """Esecuzione effettiva del comando."""
        pass