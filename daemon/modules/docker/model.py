from pydantic import BaseModel, Field
from typing import List, Optional


class ContainerItem(BaseModel):
    id: str = Field(..., description="ID breve del container (12 caratteri)")
    full_id: str = Field(..., description="ID univoco completo del container")
    name: str = Field(..., description="Nome assegnato al container")
    service: str = Field(..., description="Nome del servizio nel compose file o nome container")
    image: str = Field(..., description="Tag o hash dell'immagine Docker")
    state: str = Field(..., description="Stato del container (running, exited, paused, etc.)")
    status: str = Field(..., description="Descrizione human-readable dello stato (es. Up 2 hours)")
    ports: List[str] = Field(default_factory=list, description="Elenco delle porte mappate o esposte")


class ComposeGroup(BaseModel):
    compose_file: Optional[str] = Field(None, description="Percorso assoluto del file compose.yml se identificato")
    project_name: str = Field("Standalone", description="Nome del progetto docker-compose")
    working_dir: Optional[str] = Field(None, description="Directory di lavoro associata al progetto")
    exists_on_disk: bool = Field(False, description="Indica se il file compose.yml esiste effettivamente sul filesystem")
    containers: List[ContainerItem] = Field(default_factory=list, description="Container appartenenti al gruppo")


class DockerGroupsResponse(BaseModel):
    total_containers: int
    total_groups: int
    groups: List[ComposeGroup]
