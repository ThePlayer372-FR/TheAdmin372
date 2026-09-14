import os
import io
import gzip
import shutil
import tarfile
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List

from core.logger import logger, log_audit
from .models import JobStatusResponse, BackupPlan
from .storage import (
    load_plan,
    save_plan,
    get_plan_archive_dir,
    calculate_sha256,
    prune_plan_archives,
    SERVER_PUBLIC_KEY_PATH,
    SNAPSHOTS_BASE_DIR,
    list_plan_archives,
)
from .crypto import encrypt_envelope, decrypt_envelope, load_public_key

# Registro in-memory dei job asincroni
_jobs: Dict[str, JobStatusResponse] = {}


def create_job(plan_name: str, action: str = "backup") -> str:
    """Crea e registra un nuovo job con ID univoco UUID4."""
    job_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    job = JobStatusResponse(
        job_id=job_id,
        plan_name=plan_name,
        action=action,
        status="pending",
        progress=0,
        message="Job registrato in coda...",
        created_at=now_iso,
    )
    _jobs[job_id] = job
    return job_id


def get_job(job_id: str) -> Optional[JobStatusResponse]:
    """Recupera lo stato del job dal registro in-memory."""
    return _jobs.get(job_id)


def update_job(
    job_id: str,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    message: Optional[str] = None,
    archive_filename: Optional[str] = None,
    restored_files_count: Optional[int] = None,
    restored_files: Optional[List[str]] = None,
    error: Optional[str] = None,
):
    """Aggiorna progressivamente i dettagli di un job."""
    job = _jobs.get(job_id)
    if not job:
        return
    if status is not None:
        job.status = status
    if progress is not None:
        job.progress = progress
    if message is not None:
        job.message = message
    if archive_filename is not None:
        job.archive_filename = archive_filename
    if restored_files_count is not None:
        job.restored_files_count = restored_files_count
    if restored_files is not None:
        job.restored_files = restored_files
    if error is not None:
        job.error = error
    if status in ["completed", "failed"]:
        job.finished_at = datetime.now(timezone.utc).isoformat()


def compress_tar_data(tar_bytes: bytes, comp_type: str = "zstd") -> Tuple[bytes, str]:
    """Comprime i byte tar usando zstandard (se disponibile) o gzip in fallback."""
    if comp_type == "zstd":
        try:
            import zstandard as zstd
            cctx = zstd.ZstdCompressor(level=3)
            return cctx.compress(tar_bytes), "zst"
        except ImportError:
            logger.debug("Modulo 'zstandard' non trovato, fallback su gzip")
            pass

    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
        gz.write(tar_bytes)
    return buf.getvalue(), "gz"


def decompress_archive_data(data: bytes) -> bytes:
    """Rileva magic bytes e decomprime da zstd o gzip."""
    # zstd magic: 0x28, 0xB5, 0x2F, 0xFD
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        try:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        except ImportError:
            raise ValueError("Archivio compresso con zstandard, ma il modulo Python 'zstandard' non è installato")

    # gzip magic: 0x1F, 0x8B
    if data.startswith(b"\x1f\x8b"):
        buf = io.BytesIO(data)
        with gzip.GzipFile(fileobj=buf, mode="rb") as gz:
            return gz.read()

    # Presumibilmente tar non compresso
    return data


def compute_next_run(interval_str: str, base_time: datetime) -> Optional[str]:
    """Calcola il prossimo run dato un intervallo (es. '1h', '6h', '24h', '7d')."""
    interval_str = interval_str.strip().lower()
    match = None
    import re
    m = re.match(r"^(\d+)([mhd])$", interval_str)
    if not m:
        return None
    val, unit = int(m.group(1)), m.group(2)
    delta = timedelta()
    if unit == "m":
        delta = timedelta(minutes=val)
    elif unit == "h":
        delta = timedelta(hours=val)
    elif unit == "d":
        delta = timedelta(days=val)

    next_dt = base_time + delta
    return next_dt.isoformat()


async def run_backup_task(job_id: str, plan_name: str):
    """Esecuzione completa asincrona del processo di backup."""
    update_job(job_id, status="running", progress=5, message="Avvio procedura di backup...")
    try:
        plan = load_plan(plan_name)
        if not plan:
            raise ValueError(f"Piano di backup '{plan_name}' non trovato")

        if not plan.paths:
            raise ValueError(f"Il piano '{plan_name}' non ha alcun percorso target configurato")

        update_job(job_id, progress=15, message="Scansione dei target filesystem...")
        files_to_pack: List[Dict[str, Any]] = []

        for target in plan.paths:
            p = Path(target)
            if not p.exists():
                logger.warning(f"Target '{target}' non esistente sul filesystem, ignorato")
                continue

            if p.is_file():
                st = p.stat()
                sha = calculate_sha256(p)
                files_to_pack.append({
                    "disk_path": p,
                    "tar_path": str(p).lstrip("/"),
                    "size": st.st_size,
                    "mode": oct(st.st_mode),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "mtime": st.st_mtime,
                    "sha256": sha,
                })
            elif p.is_dir():
                for root, _, files in os.walk(p):
                    for fname in files:
                        file_path = Path(root) / fname
                        if file_path.is_symlink() and not file_path.exists():
                            continue
                        try:
                            st = file_path.stat()
                            sha = calculate_sha256(file_path)
                            files_to_pack.append({
                                "disk_path": file_path,
                                "tar_path": str(file_path).lstrip("/"),
                                "size": st.st_size,
                                "mode": oct(st.st_mode),
                                "uid": st.st_uid,
                                "gid": st.st_gid,
                                "mtime": st.st_mtime,
                                "sha256": sha,
                            })
                        except (PermissionError, FileNotFoundError):
                            pass

        if not files_to_pack:
            raise ValueError("Nessun file valido o leggibile trovato nei percorsi specificati")

        update_job(job_id, progress=35, message=f"Generazione manifest per {len(files_to_pack)} file...")
        now_utc = datetime.now(timezone.utc)
        now_str = now_utc.strftime("%Y%m%d_%H%M%S")
        now_iso = now_utc.isoformat()

        manifest_data = {
            "version": "0.1.0",
            "timestamp": now_iso,
            "plan_name": plan_name,
            "total_files": len(files_to_pack),
            "files": [
                {
                    "path": "/" + item["tar_path"],
                    "size": item["size"],
                    "mode": item["mode"],
                    "uid": item["uid"],
                    "gid": item["gid"],
                    "sha256": item["sha256"],
                }
                for item in files_to_pack
            ],
        }

        import json
        manifest_bytes = json.dumps(manifest_data, indent=2).encode("utf-8")

        update_job(job_id, progress=50, message="Archiviazione in archivio TAR...")
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            # 1. Inserisci manifest.json alla radice
            ti_manifest = tarfile.TarInfo(name="manifest.json")
            ti_manifest.size = len(manifest_bytes)
            ti_manifest.mtime = int(now_utc.timestamp())
            ti_manifest.mode = 0o644
            tar.addfile(ti_manifest, io.BytesIO(manifest_bytes))

            # 2. Inserisci ciascun file con il proprio percorso relativo
            for item in files_to_pack:
                try:
                    tar.add(str(item["disk_path"]), arcname=item["tar_path"], recursive=False)
                except Exception as e:
                    logger.debug(f"Salto file non leggibile '{item['disk_path']}': {e}")

        raw_tar_bytes = tar_buf.getvalue()

        update_job(job_id, progress=70, message=f"Compressione ({plan.compression})...")
        compressed_bytes, actual_ext = compress_tar_data(raw_tar_bytes, plan.compression)

        is_encrypted = plan.encryption
        if is_encrypted:
            update_job(job_id, progress=80, message="Cifratura Envelope (AES-256-GCM + RSA-OAEP)...")
            if not SERVER_PUBLIC_KEY_PATH.is_file():
                raise FileNotFoundError(
                    f"Chiave pubblica del server assente in '{SERVER_PUBLIC_KEY_PATH}'. "
                    "Inizializzala con 'theadmin372 backup keygen' o 'POST /v1/backup/keys/init'."
                )
            pub_key = load_public_key(SERVER_PUBLIC_KEY_PATH)
            final_payload = encrypt_envelope(compressed_bytes, pub_key)
            final_ext = f"tar.{actual_ext}.enc"
        else:
            final_payload = compressed_bytes
            final_ext = f"tar.{actual_ext}"

        update_job(job_id, progress=90, message="Scrittura atomica su storage...")
        archive_dir = get_plan_archive_dir(plan_name)
        archive_dir.mkdir(parents=True, exist_ok=True)

        archive_filename = f"{plan_name}_{now_str}.{final_ext}"
        final_path = archive_dir / archive_filename
        tmp_path = archive_dir / f".tmp_{uuid.uuid4()}"

        with open(tmp_path, "wb") as f:
            f.write(final_payload)

        # Calcola hash SHA-256 dell'archivio finale
        sha = calculate_sha256(tmp_path)
        sha_file = archive_dir / f"{archive_filename}.sha256"
        sha_file.write_text(sha, encoding="utf-8")

        # Rinomina atomica
        tmp_path.replace(final_path)

        # Pruning archivi in eccesso
        pruned = prune_plan_archives(plan_name, plan.retention_count)
        if pruned:
            logger.info(f"Pruning completato per '{plan_name}': rimossi {len(pruned)} archivi obsoleti")

        # Aggiorna schedule del piano
        plan.schedule.last_run = now_iso
        if plan.schedule.enabled and plan.schedule.interval:
            plan.schedule.next_run = compute_next_run(plan.schedule.interval, now_utc)
        save_plan(plan)

        log_audit(
            actor="backup_engine",
            module="backup",
            action="RUN_BACKUP",
            params={"plan": plan_name, "archive": archive_filename, "sha256": sha},
            status="SUCCESS",
            detail=f"Archivio {archive_filename} generato ({len(final_payload)} byte)",
        )

        update_job(
            job_id,
            status="completed",
            progress=100,
            message=f"Backup completato con successo: {archive_filename}",
            archive_filename=archive_filename,
        )

    except Exception as e:
        logger.error(f"Errore durante l'esecuzione del backup '{plan_name}': {e}", exc_info=True)
        log_audit(
            actor="backup_engine",
            module="backup",
            action="RUN_BACKUP",
            params={"plan": plan_name},
            status="FAILED",
            detail=str(e),
        )
        update_job(job_id, status="failed", progress=100, error=str(e), message="Backup fallito")


async def run_restore_task(
    job_id: str,
    plan_name: str,
    private_key_pem: Optional[str],
    archive_name: Optional[str] = "latest",
    target_dir: Optional[str] = None,
):
    """Esecuzione completa asincrona del ripristino/restore."""
    update_job(job_id, status="running", progress=5, message="Preparazione al ripristino...")
    try:
        archive_dir = get_plan_archive_dir(plan_name)
        if not archive_dir.is_dir():
            raise FileNotFoundError(f"Nessuna cartella archivi trovata per il piano '{plan_name}'")

        # 1. Trova l'archivio da ripristinare
        if not archive_name or archive_name == "latest":
            archives = list_plan_archives(plan_name)
            if not archives:
                raise FileNotFoundError(f"Nessun archivio disponibile per il piano '{plan_name}'")
            target_archive_file = archive_dir / archives[0].filename
        else:
            target_archive_file = archive_dir / archive_name
            if not target_archive_file.is_file():
                raise FileNotFoundError(f"Archivio specificato '{archive_name}' non trovato")

        update_job(job_id, progress=20, message=f"Caricamento archivio {target_archive_file.name}...")
        archive_bytes = target_archive_file.read_bytes()

        # 2. Decifratura (se archivio cifrato)
        is_encrypted = target_archive_file.name.endswith(".enc")
        if is_encrypted:
            update_job(job_id, progress=35, message="Decifratura envelope con chiave privata RSA...")
            if not private_key_pem or not private_key_pem.strip():
                raise ValueError("Chiave privata RSA mancante: necessaria per decifrare l'archivio")
            compressed_bytes = decrypt_envelope(archive_bytes, private_key_pem.strip())
        else:
            compressed_bytes = archive_bytes

        # 3. Decompressione
        update_job(job_id, progress=50, message="Decompressione payload TAR...")
        raw_tar_bytes = decompress_archive_data(compressed_bytes)

        # 4. Lettura del TAR e del Manifest
        update_job(job_id, progress=65, message="Verifica integrità manifest...")
        tar_buf = io.BytesIO(raw_tar_bytes)
        manifest = None

        with tarfile.open(fileobj=tar_buf, mode="r") as tar:
            try:
                manifest_member = tar.getmember("manifest.json")
                manifest_f = tar.extractfile(manifest_member)
                if manifest_f:
                    import json
                    manifest = json.load(manifest_f)
            except KeyError:
                raise ValueError("Archivio non valido: manifest.json mancante alla radice")

        if not manifest or "files" not in manifest:
            raise ValueError("Manifest non valido o corrotto nell'archivio")

        # 5. Snapshot preventivo se ripristino in-place
        now_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not target_dir:
            update_job(job_id, progress=75, message="Creazione snapshot preventivo di sicurezza...")
            snapshot_dir = SNAPSHOTS_BASE_DIR / f"pre_restore_{plan_name}_{now_ts}"
            for item in manifest.get("files", []):
                orig_p = Path(item["path"])
                if orig_p.is_file():
                    backup_dst = snapshot_dir / item["path"].lstrip("/")
                    backup_dst.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        shutil.copy2(orig_p, backup_dst)
                    except Exception:
                        pass

        # 6. Estrazione e ripristino controllato
        dest_root = Path(target_dir).resolve() if target_dir else Path("/")
        if target_dir:
            dest_root.mkdir(parents=True, exist_ok=True)

        update_job(job_id, progress=85, message=f"Estrazione file in '{dest_root}'...")
        restored_count = 0
        restored_file_paths: List[str] = []
        tar_buf.seek(0)

        with tarfile.open(fileobj=tar_buf, mode="r") as tar:
            for member in tar.getmembers():
                if member.name == "manifest.json":
                    continue

                member_rel = member.name.lstrip("/")
                dest_file_path = (dest_root / member_rel).resolve()

                # Prevenzione Tar Slip / Path Traversal
                try:
                    dest_file_path.relative_to(dest_root)
                except ValueError:
                    logger.warning(f"Path traversal tentato ignorato per '{member.name}'")
                    continue

                dest_file_path.parent.mkdir(parents=True, exist_ok=True)

                if member.isreg():
                    extracted_f = tar.extractfile(member)
                    if extracted_f:
                        content = extracted_f.read()
                        dest_file_path.write_bytes(content)
                        try:
                            os.chmod(dest_file_path, member.mode)
                        except Exception:
                            pass
                        restored_count += 1
                        restored_file_paths.append(str(dest_file_path))
                elif member.isdir():
                    dest_file_path.mkdir(parents=True, exist_ok=True)
                    try:
                        os.chmod(dest_file_path, member.mode)
                    except Exception:
                        pass

        # 7. Verifica SHA-256 dei file ripristinati
        update_job(job_id, progress=95, message="Verifica checksum dei file ripristinati...")
        for item in manifest.get("files", []):
            rel_path = item["path"].lstrip("/")
            checked_file = (dest_root / rel_path).resolve()
            if checked_file.is_file():
                current_sha = calculate_sha256(checked_file)
                if current_sha.lower() != item["sha256"].lower():
                    logger.warning(f"Checksum mismatch per {checked_file}: {current_sha} != {item['sha256']}")

        log_audit(
            actor="backup_engine",
            module="backup",
            action="RESTORE_BACKUP",
            params={
                "plan": plan_name,
                "archive": target_archive_file.name,
                "target_dir": str(dest_root),
                "restored_files": restored_count,
            },
            status="SUCCESS",
            detail=f"Ripristinati {restored_count} file con successo da {target_archive_file.name}",
        )

        update_job(
            job_id,
            status="completed",
            progress=100,
            restored_files_count=restored_count,
            restored_files=restored_file_paths,
            message=f"Ripristino completato con successo: {restored_count} file estratti in {dest_root}",
        )

    except Exception as e:
        logger.error(f"Errore durante il ripristino di '{plan_name}': {e}", exc_info=True)
        log_audit(
            actor="backup_engine",
            module="backup",
            action="RESTORE_BACKUP",
            params={"plan": plan_name},
            status="FAILED",
            detail=str(e),
        )
        update_job(job_id, status="failed", progress=100, error=str(e), message="Ripristino fallito")
