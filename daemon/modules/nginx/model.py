from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re

# Regex per RFC 1123 hostname / FQDN valido
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-_]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-_]{1,63}(?<!-))*$"
)


class VHostProxyCreate(BaseModel):
    domain: str = Field(..., description="FQDN o nome host del virtual host (es. app.example.com)")
    upstream: str = Field(..., description="Destinazione upstream (es. http://127.0.0.1:8000 o unix:/run/app.sock)")
    enabled: bool = Field(True, description="Abilita il virtual host creando il symlink in sites-enabled/")
    websocket: bool = Field(False, description="Inietta gli header Upgrade e Connection per WebSockets")
    client_max_body_size: str = Field("50M", pattern=r"^\d+[kKmMgG]?$", description="Dimensione massima body (es. 50M, 100M)")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or len(v) > 253:
            raise ValueError("Il dominio deve contenere tra 1 e 253 caratteri.")
        if "/" in v or "\\" in v or ".." in v or v.startswith("."):
            raise ValueError("Nome di dominio non valido (rilevato tentativo di path traversal).")
        if not HOSTNAME_REGEX.match(v):
            raise ValueError("Formato del nome a dominio non valido secondo gli standard RFC 1123.")
        return v

    @field_validator("upstream")
    @classmethod
    def validate_upstream(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://") or v.startswith("unix:")):
            raise ValueError("L'upstream deve iniziare con 'http://', 'https://' o 'unix:'.")
        return v


class VHostStatusResponse(BaseModel):
    domain: str
    server_names: list[str] = Field(default_factory=list)
    enabled: bool
    has_ssl: bool
    upstream: Optional[str]
    config_path: str


class NginxActionResponse(BaseModel):
    status: str
    message: str
