from abc import ABC, abstractmethod
from fastapi import APIRouter

class BaseModule(ABC):
    @property
    @abstractmethod
    def router(self) -> APIRouter:
        """Restituisce il router FastAPI associato al modulo."""
        pass