from pydantic import BaseModel, Field
from typing import List


class UfwRuleInput(BaseModel):
    port: int = Field(..., ge=1, le=65535, description="Porta di rete (1-65535)")
    proto: str = Field("tcp", pattern=r"^(tcp|udp)$", description="Protocollo di trasporto")
    action: str = Field("allow", pattern=r"^(allow|deny)$", description="Azione della regola")


class UfwRuleOutput(BaseModel):
    index: int
    id: int
    port: str
    proto: str = "any"
    action: str
    direction: str = "IN"
    to: str
    from_ip: str = Field(..., serialization_alias="from")
    v6: bool = False

    model_config = {
        "populate_by_name": True
    }


class UfwStatusOutput(BaseModel):
    active: bool
    rules: List[UfwRuleOutput]


class UfwActionResponse(BaseModel):
    status: str
    message: str