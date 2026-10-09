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
    R2UploadConfig,
    R2Preset,
    CreateR2PresetRequest,
    R2PresetSummary,
    ApplyPresetRequest,
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
    save_preset,
    load_preset,
    list_presets,
    delete_preset,
    validate_preset_name,
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
            r2_preset=getattr(plan, "r2_preset", None),
            r2_upload=getattr(plan, "r2_upload", None),
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

            # Risoluzione configurazione Cloudflare R2 da preset o da parametri espliciti
            r2_config = req.r2_upload if req.r2_upload else R2UploadConfig()
            r2_preset_name = req.r2_preset.strip() if req.r2_preset else None
            if r2_preset_name:
                preset = load_preset(r2_preset_name)
                if not preset:
                    raise HTTPException(status_code=404, detail=f"Preset R2 '{r2_preset_name}' non trovato")
                endpoint = req.r2_upload.endpoint_url if (req.r2_upload and req.r2_upload.endpoint_url) else preset.endpoint_url
                bucket = req.r2_upload.bucket_name if (req.r2_upload and req.r2_upload.bucket_name) else preset.bucket_name
                ak = req.r2_upload.access_key_id if (req.r2_upload and req.r2_upload.access_key_id) else preset.access_key_id
                sk = req.r2_upload.secret_access_key if (req.r2_upload and req.r2_upload.secret_access_key) else preset.secret_access_key
                r2_config = R2UploadConfig(
                    enabled=True,
                    endpoint_url=endpoint,
                    bucket_name=bucket,
                    access_key_id=ak,
                    secret_access_key=sk,
                )

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
                r2_preset=r2_preset_name,
                r2_upload=r2_config,
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
            try:
                plan = load_plan(name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            if not plan:
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

        # 1b. Preset Cloudflare R2
        @self._router.post("/presets", response_model=R2PresetSummary, status_code=201)
        def create_or_update_preset(req: CreateR2PresetRequest):
            """Crea o aggiorna un preset di credenziali ed endpoint Cloudflare R2."""
            try:
                name = validate_preset_name(req.name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

            if not req.endpoint_url or not req.endpoint_url.strip():
                raise HTTPException(status_code=400, detail="Specificare un endpoint URL valido per R2")
            if not req.bucket_name or not req.bucket_name.strip():
                raise HTTPException(status_code=400, detail="Specificare un bucket name valido per R2")
            if not req.access_key_id or not req.access_key_id.strip():
                raise HTTPException(status_code=400, detail="Specificare un Access Key ID valido per R2")
            if not req.secret_access_key or not req.secret_access_key.strip():
                raise HTTPException(status_code=400, detail="Specificare una Secret Access Key valida per R2")

            now = datetime.now(timezone.utc)
            preset = R2Preset(
                name=name,
                endpoint_url=req.endpoint_url.strip(),
                bucket_name=req.bucket_name.strip(),
                access_key_id=req.access_key_id.strip(),
                secret_access_key=req.secret_access_key.strip(),
                created_at=now.isoformat(),
                description=req.description.strip() if req.description else None,
            )
            save_preset(preset)
            ak_masked = preset.access_key_id[:4] + "..." + preset.access_key_id[-4:] if len(preset.access_key_id) > 8 else "***"
            log_audit(
                actor="api_client",
                module="backup",
                action="CREATE_R2_PRESET",
                params={"name": name, "bucket": preset.bucket_name},
                status="SUCCESS",
            )
            return R2PresetSummary(
                name=preset.name,
                endpoint_url=preset.endpoint_url,
                bucket_name=preset.bucket_name,
                access_key_id_masked=ak_masked,
                created_at=preset.created_at,
                description=preset.description,
            )

        @self._router.get("/presets", response_model=List[R2PresetSummary])
        def get_all_presets():
            """Elenca tutti i preset Cloudflare R2 registrati con chiavi segrete mascherate."""
            presets = list_presets()
            summaries = []
            for p in presets:
                ak_masked = p.access_key_id[:4] + "..." + p.access_key_id[-4:] if len(p.access_key_id) > 8 else "***"
                summaries.append(
                    R2PresetSummary(
                        name=p.name,
                        endpoint_url=p.endpoint_url,
                        bucket_name=p.bucket_name,
                        access_key_id_masked=ak_masked,
                        created_at=p.created_at,
                        description=p.description,
                    )
                )
            return summaries

        @self._router.get("/presets/{name}", response_model=R2PresetSummary)
        def get_preset_detail(name: str):
            """Restituisce i dettagli di un preset Cloudflare R2."""
            try:
                preset = load_preset(name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            if not preset:
                raise HTTPException(status_code=404, detail=f"Preset R2 '{name}' non trovato")

            ak_masked = preset.access_key_id[:4] + "..." + preset.access_key_id[-4:] if len(preset.access_key_id) > 8 else "***"
            return R2PresetSummary(
                name=preset.name,
                endpoint_url=preset.endpoint_url,
                bucket_name=preset.bucket_name,
                access_key_id_masked=ak_masked,
                created_at=preset.created_at,
                description=preset.description,
            )

        @self._router.delete("/presets/{name}")
        def delete_preset_route(name: str):
            """Elimina un preset Cloudflare R2."""
            if not delete_preset(name):
                raise HTTPException(status_code=404, detail=f"Preset R2 '{name}' non trovato")
            log_audit(
                actor="api_client",
                module="backup",
                action="DELETE_R2_PRESET",
                params={"name": name},
                status="SUCCESS",
            )
            return {"status": "deleted", "name": name}

        @self._router.post("/plans/{name}/r2/preset", response_model=BackupPlanDetail)
        def apply_preset_to_plan(name: str, req: ApplyPresetRequest):
            """Applica un preset R2 a un piano di backup esistente."""
            try:
                plan = load_plan(name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            if not plan:
                raise HTTPException(status_code=404, detail=f"Piano '{name}' non trovato")

            try:
                preset = load_preset(req.preset_name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            if not preset:
                raise HTTPException(status_code=404, detail=f"Preset R2 '{req.preset_name}' non trovato")

            bucket = req.bucket_override.strip() if req.bucket_override and req.bucket_override.strip() else preset.bucket_name
            plan.r2_preset = req.preset_name
            plan.r2_upload = R2UploadConfig(
                enabled=True,
                endpoint_url=preset.endpoint_url,
                bucket_name=bucket,
                access_key_id=preset.access_key_id,
                secret_access_key=preset.secret_access_key,
            )
            save_plan(plan)
            log_audit(
                actor="api_client",
                module="backup",
                action="APPLY_R2_PRESET",
                params={"plan": name, "preset": req.preset_name, "bucket": bucket},
                status="SUCCESS",
            )
            return self._build_plan_detail(plan)

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
            try:
                plan = load_plan(name)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

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
