from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class ScheduleConfig(BaseModel):
    enabled: bool = True
    interval: str = "24h"
    last_run: Optional[str] = None
    next_run: Optional[str] = None


class BackupPlan(BaseModel):
    name: str
    created_at: str
    paths: List[str] = Field(default_factory=list)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    retention_count: int = Field(default=7, ge=1, le=100)
    compression: Literal["zstd", "gz"] = "zstd"
    encryption: bool = True


class CreatePlanRequest(BaseModel):
    name: str
    paths: List[str] = Field(default_factory=list)
    schedule_enabled: bool = True
    schedule_interval: str = "24h"
    retention_count: int = Field(default=7, ge=1, le=100)
    compression: Literal["zstd", "gz"] = "zstd"
    encryption: bool = True


class AddPathsRequest(BaseModel):
    paths: List[str]


class DeletePathsRequest(BaseModel):
    paths: List[str]


class ScheduleUpdateRequest(BaseModel):
    every: Optional[str] = None
    enabled: Optional[bool] = None
    disable: bool = False


class KeyInitRequest(BaseModel):
    public_key: Optional[str] = None


class RestoreRequest(BaseModel):
    private_key: Optional[str] = None
    archive: Optional[str] = "latest"
    target_dir: Optional[str] = None


class ArchiveItem(BaseModel):
    filename: str
    size_bytes: int
    size_human: str
    created_at: str
    sha256: str
    is_encrypted: bool
    compression: str


class BackupPlanDetail(BaseModel):
    name: str
    created_at: str
    paths: List[str]
    schedule: ScheduleConfig
    retention_count: int
    compression: str
    encryption: bool
    total_archives: int
    total_size_bytes: int
    total_size_human: str
    latest_archive: Optional[ArchiveItem] = None


class JobStatusResponse(BaseModel):
    job_id: str
    plan_name: str
    action: str = "backup"  # "backup" | "restore"
    status: str = "pending"  # "pending" | "running" | "completed" | "failed"
    progress: int = 0  # 0..100
    message: str = "Inizializzazione in corso..."
    archive_filename: Optional[str] = None
    restored_files_count: Optional[int] = None
    restored_files: Optional[List[str]] = None
    error: Optional[str] = None
    created_at: str
    finished_at: Optional[str] = None
