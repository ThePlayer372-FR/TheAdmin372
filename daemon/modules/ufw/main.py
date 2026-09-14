from .model import UfwRuleInput, UfwRuleOutput, UfwStatusOutput, UfwActionResponse
from fastapi import APIRouter, HTTPException
from modules.base import BaseModule
from typing import List, Tuple
from core.security import run_secure_command
import subprocess
import re


def parse_ufw_status(raw_output: str) -> Tuple[bool, List[UfwRuleOutput]]:
    """
    Esegue il parsing consolidato dell'output di 'ufw status numbered'.
    Supporta regole numerate con azioni ALLOW, DENY, REJECT, LIMIT,
    direzioni IN/OUT, protocolli specificati e flag IPv6 (v6).
    """
    is_active = "Status: active" in raw_output
    rules: List[UfwRuleOutput] = []

    pattern = re.compile(
        r"^\[\s*(\d+)\]\s+(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT))?\s+(.+)$",
        re.IGNORECASE,
    )

    for line in raw_output.splitlines():
        line = line.strip()
        match = pattern.match(line)
        if match:
            idx_str, target, action, direction, source = match.groups()
            rule_idx = int(idx_str)
            direction_str = (direction or "IN").upper()
            action_str = action.upper()

            is_v6 = "(v6)" in target or "(v6)" in source
            clean_target = target.replace("(v6)", "").strip()

            proto = "any"
            port = clean_target
            if "/" in clean_target:
                port, proto = clean_target.split("/", 1)

            rules.append(
                UfwRuleOutput(
                    index=rule_idx,
                    id=rule_idx,
                    port=port,
                    proto=proto,
                    action=action_str,
                    direction=direction_str,
                    to=target.strip(),
                    from_ip=source.strip(),
                    v6=is_v6,
                )
            )

    return is_active, rules


class UFWModule(BaseModule):
    def __init__(self):
        self._router = APIRouter(prefix="/ufw", tags=["UFW"])
        self._register_routes()

    @property
    def router(self) -> APIRouter:
        return self._router

    def _execute_ufw(self, cmd: List[str]) -> subprocess.CompletedProcess:
        try:
            return run_secure_command(cmd, check=True)
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() if e.stderr else str(e)
            raise HTTPException(status_code=500, detail=f"Errore esecuzione UFW: {err_msg}")
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Comando 'ufw' non presente nel sistema")

    def _run_ufw_cmd(self, cmd: List[str], error_prefix: str) -> str:
        try:
            res = run_secure_command(cmd)
            if res.returncode != 0:
                err = res.stderr.strip() or res.stdout.strip() or error_prefix
                raise HTTPException(status_code=400, detail=err)
            return res.stdout.strip()
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail="Comando 'ufw' non presente nel sistema")

    def _get_status_data(self) -> Tuple[bool, List[UfwRuleOutput]]:
        res = self._execute_ufw(["ufw", "status", "numbered"])
        return parse_ufw_status(res.stdout)

    def _register_routes(self):
        @self._router.get("/rules", response_model=List[UfwRuleOutput])
        def list_rules():
            _, rules = self._get_status_data()
            return rules

        @self._router.get("/status")
        def get_status():
            active, rules = self._get_status_data()
            return {
                "active": active,
                "rules": [rule.model_dump(by_alias=True) for rule in rules],
            }

        @self._router.post("/rule", response_model=UfwActionResponse)
        def add_rule(payload: UfwRuleInput):
            cmd = ["ufw", payload.action, f"{payload.port}/{payload.proto}"]
            self._run_ufw_cmd(cmd, "Errore aggiunta regola")
            return UfwActionResponse(
                status="ok",
                message=f"Regola {payload.action} applicata per {payload.port}/{payload.proto}",
            )

        @self._router.delete("/rules/{rule_id}", response_model=UfwActionResponse)
        @self._router.delete("/rule/{rule_id}", response_model=UfwActionResponse)
        def delete_rule(rule_id: int):
            if rule_id < 1:
                raise HTTPException(status_code=400, detail="L'indice della regola deve essere >= 1")
            cmd = ["ufw", "--force", "delete", str(rule_id)]
            self._run_ufw_cmd(cmd, "Errore eliminazione regola")
            return UfwActionResponse(
                status="ok",
                message=f"Regola #{rule_id} eliminata con successo",
            )

        @self._router.post("/enable", response_model=UfwActionResponse)
        def enable_firewall():
            cmd = ["ufw", "--force", "enable"]
            self._run_ufw_cmd(cmd, "Errore abilitazione UFW")
            return UfwActionResponse(status="ok", message="Firewall UFW abilitato con successo")

        @self._router.post("/disable", response_model=UfwActionResponse)
        def disable_firewall():
            cmd = ["ufw", "disable"]
            self._run_ufw_cmd(cmd, "Errore disabilitazione UFW")
            return UfwActionResponse(status="ok", message="Firewall UFW disabilitato con successo")

        @self._router.post("/reload", response_model=UfwActionResponse)
        def reload_firewall():
            cmd = ["ufw", "reload"]
            self._run_ufw_cmd(cmd, "Errore ricarica UFW")
            return UfwActionResponse(status="ok", message="Configurazione UFW ricaricata con successo")