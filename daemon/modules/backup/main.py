import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks

from modules.base import BaseModule
from core.logger import logger, log_audit
from .models import (
    BackupPlan,
    BackupPlanDetail,
    CreatePlanRequest,
    AddPathsRequest,
    DeletePathsRequest,
    ScheduleUpdateRequest,
    ScheduleConfig,
    ArchiveItem,
    JobStatusResponse,
    RestoreRequest,
    KeyInitRequest,
    TheSecretEnrollRequest,
)
from .storage import (
    save_plan,
    load_plan,
    list_plans,
    delete_plan,
    list_plan_archives,
    validate_plan_name,
    validate_backup_path,
    save_server_public_key,
    has_server_public_key,
    SERVER_PUBLIC_KEY_PATH,
    format_bytes,
)
from .crypto import generate_keypair
from .engine import (
    create_job,
    get_job,
    run_backup_task,
    run_restore_task,
)
from .scheduler import (
    start_scheduler,
    stop_scheduler,
    parse_interval_to_seconds,
    calculate_next_run_iso,
)


class BackupModule(BaseModule):
    def __init__(self):
        self._router = APIRouter(prefix="/backup", tags=["Backup"])
        self._register_routes()
        # Avvia scheduler
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                start_scheduler()
            else:
                loop.call_soon_threadsafe(start_scheduler)
        except Exception:
            pass

    @property
    def router(self) -> APIRouter:
        return self._router

    def _build_plan_detail(self, plan: BackupPlan) -> BackupPlanDetail:
        archives = list_plan_archives(plan.name)
        total_size = sum(a.size_bytes for a in archives)
        latest = archives[0] if archives else None

        return BackupPlanDetail(
            name=plan.name,
            created_at=plan.created_at,
            paths=plan.paths,
            schedule=plan.schedule,
            retention_count=plan.retention_count,
            compression=plan.compression,
            encryption=plan.encryption,
            total_archives=len(archives),
            total_size_bytes=total_size,
            total_size_human=format_bytes(total_size),
            latest_archive=latest,
        )

    def _register_routes(self):
        # Assicura avvio scheduler all'avvio del router
        @self._router.on_event("startup")
        def on_startup():
            start_scheduler()

        @self._router.on_event("shutdown")
        def on_shutdown():
            stop_scheduler()

        # 1. Piani CRUD
        @self._router.post("/plans", response_model=BackupPlanDetail, status_code=201)
        def create_plan(req: CreatePlanRequest):
            """Crea un nuovo piano di backup nominato con configurazione dichiarativa."""
            try:
                name = validate_plan_name(req.name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

            if load_plan(name):
                raise HTTPException(status_code=409, detail=f"Un piano con nome '{name}' esiste già")

            clean_paths = []
            for p in req.paths:
                try:
                    clean_paths.append(validate_backup_path(p))
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Target non valido '{p}': {e}")

            now = datetime.now(timezone.utc)
            schedule_interval = req.schedule_interval or "24h"
            try:
                parse_interval_to_seconds(schedule_interval)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

            next_run = None
            if req.schedule_enabled:
                next_run = calculate_next_run_iso(schedule_interval, now)

            plan = BackupPlan(
                name=name,
                created_at=now.isoformat(),
                paths=sorted(list(set(clean_paths))),
                schedule=ScheduleConfig(
                    enabled=req.schedule_enabled,
                    interval=schedule_interval,
                    last_run=None,
                    next_run=next_run,
                ),
                retention_count=req.retention_count,
                compression="zstd" if req.compression == "zstd" else "gz",
                encryption=req.encryption,
            )

            save_plan(plan)
            log_audit(
                actor="api_client",
                module="backup",
                action="CREATE_PLAN",
                params={"name": name, "retention": plan.retention_count},
                status="SUCCESS",
            )
            return self._build_plan_detail(plan)

        @self._router.get("/plans", response_model=List[BackupPlanDetail])
        def get_all_plans():
            """Elenca tutti i piani registrati con metadati e statistiche."""
            plans = list_plans()
            return [self._build_plan_detail(p) for p in plans]

        @self._router.get("/plans/{name}", response_model=BackupPlanDetail)
        def get_single_plan(name: str):
            """Restituisce i dettagli completi del piano specificato."""
            plan = load_plan(name)
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")
            return self._build_plan_detail(plan)

        @self._router.delete("/plans/{name}")
        def delete_single_plan(name: str):
            """Elimina la configurazione del piano specificato."""
            if not load_plan(name):
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            delete_plan(name)
            log_audit(
                actor="api_client",
                module="backup",
                action="DELETE_PLAN",
                params={"name": name},
                status="SUCCESS",
            )
            return {"status": "deleted", "name": name}

        # 2. Gestione Target Filesystem
        @self._router.post("/plans/{name}/paths", response_model=BackupPlanDetail)
        def add_plan_paths(name: str, req: AddPathsRequest):
            """Aggiunge uno o più percorsi validati ai target del piano."""
            plan = load_plan(name)
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            if not req.paths:
                raise HTTPException(status_code=400, detail="Specificare almeno un percorso da aggiungere")

            current_set = set(plan.paths)
            for p in req.paths:
                try:
                    val_p = validate_backup_path(p)
                    current_set.add(val_p)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))

            plan.paths = sorted(list(current_set))
            save_plan(plan)
            return self._build_plan_detail(plan)

        @self._router.delete("/plans/{name}/paths", response_model=BackupPlanDetail)
        def remove_plan_paths(name: str, req: DeletePathsRequest):
            """Rimuove uno o più percorsi dai target del piano."""
            plan = load_plan(name)
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            current_set = set(plan.paths)
            for p in req.paths:
                resolved = str(Path(p).resolve())
                current_set.discard(resolved)
                current_set.discard(p)

            plan.paths = sorted(list(current_set))
            save_plan(plan)
            return self._build_plan_detail(plan)

        # 3. Gestione Schedulazione
        @self._router.put("/plans/{name}/schedule", response_model=BackupPlanDetail)
        def update_plan_schedule(name: str, req: ScheduleUpdateRequest):
            """Configura l'intervallo di esecuzione o abilita/disabilita la schedulazione."""
            plan = load_plan(name)
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            now = datetime.now(timezone.utc)
            if req.disable:
                plan.schedule.enabled = False
                plan.schedule.next_run = None
            else:
                if req.enabled is not None:
                    plan.schedule.enabled = req.enabled
                if req.every:
                    try:
                        parse_interval_to_seconds(req.every)
                        plan.schedule.interval = req.every
                    except ValueError as e:
                        raise HTTPException(status_code=400, detail=str(e))

                if plan.schedule.enabled:
                    plan.schedule.next_run = calculate_next_run_iso(plan.schedule.interval, now)
                else:
                    plan.schedule.next_run = None

            save_plan(plan)
            return self._build_plan_detail(plan)

        # 4. Esecuzione Backup & Polling Job
        @self._router.post("/plans/{name}/run")
        def run_backup_now(name: str, background_tasks: BackgroundTasks):
            """Avvia l'esecuzione manuale immediata del backup in background."""
            plan = load_plan(name)
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            if not plan.paths:
                raise HTTPException(status_code=400, detail=f"Il piano '{name}' non ha target configurati")

            if plan.encryption and not has_server_public_key():
                raise HTTPException(
                    status_code=412,
                    detail=f"Chiave pubblica server assente ({SERVER_PUBLIC_KEY_PATH}). Esegui 'theadmin372 backup keygen' prima del backup.",
                )

            job_id = create_job(name, action="backup")
            background_tasks.add_task(run_backup_task, job_id, name)
            return {"job_id": job_id, "status": "pending", "plan_name": name}

        @self._router.get("/jobs/{job_id}", response_model=JobStatusResponse)
        def get_job_status(job_id: str):
            """Restituisce lo stato corrente di un job di backup o restore."""
            job = get_job(job_id)
            if not job:
                raise HTTPException(status_code=404, detail=f"Job '{job_id}' non trovato")
            return job

        # 5. Storico Archivi
        @self._router.get("/plans/{name}/archives", response_model=List[ArchiveItem])
        def get_archives(name: str):
            """Elenco cronologico degli archivi generati (con dimensione e hash SHA-256)."""
            if not load_plan(name):
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")
            return list_plan_archives(name)

        # 6. Ripristino / Restore
        @self._router.post("/plans/{name}/restore")
        def restore_backup(name: str, req: RestoreRequest, background_tasks: BackgroundTasks):
            """Avvia il ripristino di un archivio con decifratura envelope e verifica SHA-256."""
            plan = load_plan(name)
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            archives = list_plan_archives(name)
            if not archives:
                raise HTTPException(status_code=404, detail=f"Nessun archivio disponibile per '{name}'")

            if req.target_dir and not Path(req.target_dir).is_absolute():
                raise HTTPException(
                    status_code=400,
                    detail="Il parametro 'target_dir' deve essere un percorso assoluto",
                )

            target_archive_name = req.archive or "latest"
            if target_archive_name != "latest":
                match = [a for a in archives if a.filename == target_archive_name]
                if not match:
                    raise HTTPException(status_code=404, detail=f"Archivio '{target_archive_name}' non trovato")
                selected_item = match[0]
            else:
                selected_item = archives[0]
                target_archive_name = selected_item.filename

            if selected_item.is_encrypted:
                if not req.use_thesecret and (not req.private_key or not req.private_key.strip()):
                    raise HTTPException(
                        status_code=400,
                        detail="L'archivio è protetto da Envelope Encryption: fornire la chiave privata RSA (parametro 'private_key') oppure specificare 'use_thesecret=true'",
                    )

            job_id = create_job(name, action="restore")
            background_tasks.add_task(
                run_restore_task,
                job_id,
                name,
                req.private_key,
                target_archive_name,
                req.target_dir,
                use_thesecret=req.use_thesecret,
            )
            return {
                "job_id": job_id,
                "status": "pending",
                "plan_name": name,
                "archive": target_archive_name,
                "use_thesecret": req.use_thesecret,
            }

        # 7. Inizializzazione Chiavi Crittografiche
        @self._router.post("/keys/init")
        def init_server_key(req: KeyInitRequest):
            """Deposita o genera la chiave pubblica RSA in /etc/theadmin372/keys/backup_pub.pem."""
            if req.public_key and req.public_key.strip():
                try:
                    p = save_server_public_key(req.public_key)
                    return {"status": "saved", "path": str(p)}
                except Exception as e:
                    raise HTTPException(status_code=400, detail=str(e))
            else:
                # Genera nuova coppia a 4096 bit: salva la pubblica sul server e restituisce la privata all'admin
                pub_pem, priv_pem = generate_keypair(4096)
                p = save_server_public_key(pub_pem.decode("utf-8"))
                return {
                    "status": "generated",
                    "public_key_path": str(p),
                    "public_key": pub_pem.decode("utf-8"),
                    "private_key": priv_pem.decode("utf-8"),
                }

        # 8. Gestione Integrazione Oracolo TheSecret372
        @self._router.get("/thesecret/status")
        async def thesecret_status(host: Optional[str] = None, port: Optional[int] = None):
            """Verifica lo stato della connessione mTLS e autorizzazione verso TheSecret372."""
            from .thesecret_client import get_thesecret_status
            return await get_thesecret_status(host=host, port=port)

        @self._router.post("/thesecret/enroll")
        async def thesecret_enroll(req: Optional[TheSecretEnrollRequest] = None):
            """Esegue la procedura di bootstrap ed enrollment mTLS con TheSecret372."""
            from .thesecret_client import ensure_enrolled
            host = req.host if req else None
            port = req.port if req else None
            machine_name = req.machine_name if req else None
            try:
                result = await ensure_enrolled(host=host, port=port, machine_name=machine_name)
                return result
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
