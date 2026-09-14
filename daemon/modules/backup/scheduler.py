import asyncio
import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from core.logger import logger
from .storage import list_plans, save_plan, prune_plan_archives
from .engine import create_job, run_backup_task

_scheduler_task: Optional[asyncio.Task] = None
_running: bool = False


def parse_interval_to_seconds(interval_str: str) -> int:
    """Converte una stringa di intervallo (es. '30m', '6h', '24h', '7d') in secondi."""
    interval_str = interval_str.strip().lower()
    m = re.match(r"^(\d+)([mhd])$", interval_str)
    if not m:
        raise ValueError(f"Formato intervallo non valido: '{interval_str}'. Usa formati come '30m', '6h', '24h', '7d'.")

    val = int(m.group(1))
    unit = m.group(2)
    if val <= 0:
        raise ValueError("L'intervallo temporale deve essere maggiore di zero")

    if unit == "m":
        return val * 60
    elif unit == "h":
        return val * 3600
    elif unit == "d":
        return val * 86400
    return 86400


def calculate_next_run_iso(interval_str: str, base_time: datetime) -> str:
    """Calcola la stringa ISO 8601 del prossimo run."""
    sec = parse_interval_to_seconds(interval_str)
    next_dt = base_time + timedelta(seconds=sec)
    return next_dt.isoformat()


async def scheduler_loop():
    """Loop asincrono del pianificatore periodico di backup."""
    global _running
    logger.info("Backup Scheduler avviato (controllo ogni 60s)")
    _running = True

    while _running:
        try:
            now = datetime.now(timezone.utc)
            plans = list_plans()

            for plan in plans:
                if not plan.schedule.enabled:
                    continue

                if not plan.paths:
                    continue

                interval = plan.schedule.interval or "24h"
                next_run_str = plan.schedule.next_run
                should_run = False

                if not next_run_str:
                    # Primo avvio o next_run non impostato
                    should_run = True
                else:
                    try:
                        next_dt = datetime.fromisoformat(next_run_str)
                        if next_dt.tzinfo is None:
                            next_dt = next_dt.replace(tzinfo=timezone.utc)
                        if now >= next_dt:
                            should_run = True
                    except Exception:
                        should_run = True

                if should_run:
                    logger.info(f"[Scheduler] Scadenza intervallo rilevata per il piano '{plan.name}'. Avvio job...")
                    job_id = create_job(plan.name, action="backup")

                    # Esegui in background senza bloccare il loop dello scheduler
                    asyncio.create_task(run_backup_task(job_id, plan.name))

                    # Calcola il prossimo run e aggiorna
                    plan.schedule.next_run = calculate_next_run_iso(interval, now)
                    save_plan(plan)

                    # Pruning preventivo
                    prune_plan_archives(plan.name, plan.retention_count)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[Scheduler] Errore nel ciclo di pianificazione: {e}")

        # Controlla ogni 60 secondi
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            break

    logger.info("Backup Scheduler arrestato")


def start_scheduler():
    """Avvia il task dello scheduler in background se non già in esecuzione."""
    global _scheduler_task
    if _scheduler_task is None or _scheduler_task.done():
        _scheduler_task = asyncio.create_task(scheduler_loop())


def stop_scheduler():
    """Arresta lo scheduler."""
    global _scheduler_task, _running
    _running = False
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()
