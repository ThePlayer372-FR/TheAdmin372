from fastapi import APIRouter
from modules.base import BaseModule
from core.security import (
    check_security_violations,
    fix_security_permissions,
    get_critical_paths,
)
from pydantic import BaseModel
from typing import List, Dict, Any, Optional


class SecurityStatusResponse(BaseModel):
    is_secure: bool
    can_execute_commands: bool
    violations_count: int
    violations: List[Dict[str, Any]]
    total_critical_paths: int
    critical_paths: List[str]


class SecurityFixResponse(BaseModel):
    fixed_count: int
    fixed_items: List[str]
    errors_count: int
    errors: List[str]
    is_secure: bool
    remaining_violations_count: int
    remaining_violations: List[Dict[str, Any]]


class SecurityModule(BaseModule):
    """Modulo di gestione e verifica della sicurezza dei permessi del demone TheAdmin372."""

    def __init__(self):
        self._router = APIRouter(prefix="/security", tags=["security"])
        self._register_routes()

    @property
    def router(self) -> APIRouter:
        return self._router

    def _register_routes(self):
        @self._router.get("/status", response_model=SecurityStatusResponse)
        def get_security_status():
            """Restituisce lo stato corrente di sicurezza dei permessi e l'autorizzazione a eseguire comandi."""
            violations = check_security_violations(force=True)
            critical = get_critical_paths()
            return SecurityStatusResponse(
                is_secure=len(violations) == 0,
                can_execute_commands=len(violations) == 0,
                violations_count=len(violations),
                violations=violations,
                total_critical_paths=len(critical),
                critical_paths=[str(p) for p in critical],
            )

        @self._router.post("/fix", response_model=SecurityFixResponse)
        def fix_permissions():
            """Corregge automaticamente i permessi impostando ownership root:root e rimuovendo i bit write per group e others."""
            res = fix_security_permissions()
            return SecurityFixResponse(
                fixed_count=res["fixed_count"],
                fixed_items=res["fixed_items"],
                errors_count=res["errors_count"],
                errors=res["errors"],
                is_secure=res["is_secure"],
                remaining_violations_count=res["remaining_violations_count"],
                remaining_violations=res["remaining_violations"],
            )
