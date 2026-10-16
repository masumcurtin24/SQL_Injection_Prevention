from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from backend.core.database import SessionLocal
from backend.scripts.build_evaluation_corpus import build_domain_corpus
from backend.scripts.update_spam_reputation_feed import main as update_reputation_feed_main
from backend.scripts.update_spam_threat_corpus import refresh_spam_threat_corpus
from backend.services.defender_ai_service import DefenderAIService
from backend.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


def _env_bool(key: str, default: bool) -> bool:
    raw = str(os.getenv(key, str(default))).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _env_int(key: str, default: int, *, minimum: int = 0) -> int:
    try:
        value = int(str(os.getenv(key, str(default))).strip())
    except Exception:
        value = int(default)
    return max(minimum, value)


class SpamAutopipelineService:
    _instance: Optional["SpamAutopipelineService"] = None
    _initialized_flag: bool = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(SpamAutopipelineService, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if self._initialized_flag:
            return

        self._backend_root = Path(__file__).resolve().parents[1]
        self._corpus_root = self._backend_root / "data" / "corpus"
        self._corpus_root.mkdir(parents=True, exist_ok=True)

        self._enabled = _env_bool("SPAM_AUTOPIPELINE_ENABLED", True)
        self._run_on_start = _env_bool("SPAM_AUTOPIPELINE_RUN_ON_START", False)
        self._interval_minutes = _env_int("SPAM_AUTOPIPELINE_INTERVAL_MINUTES", 360, minimum=5)
        self._min_feedback_samples = _env_int("SPAM_AUTOPIPELINE_MIN_FEEDBACK_SAMPLES", 5, minimum=0)
        self._promote_if_better = _env_bool("SPAM_AUTOPIPELINE_PROMOTE_IF_BETTER", True)
        self._allow_corpus_only = _env_bool("SPAM_AUTOPIPELINE_ALLOW_CORPUS_ONLY", True)
        self._strict_corpus = _env_bool("SPAM_AUTOPIPELINE_STRICT_CORPUS", False)
        self._max_phish_rows = _env_int("SPAM_WEAKLABEL_MAX_PHISH_ROWS", 800, minimum=50)
        self._max_ham_rows = _env_int("SPAM_WEAKLABEL_MAX_HAM_ROWS", 300, minimum=20)
        self._feedback_limit = _env_int("SPAM_WEAKLABEL_FEEDBACK_LIMIT", 500, minimum=0)
        self._seed = _env_int("SPAM_AUTOPIPELINE_SEED", 42, minimum=0)

        self._running = False
        self._run_in_progress = False
        self._runner_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._run_lock = asyncio.Lock()

        self._runs_total = 0
        self._runs_succeeded = 0
        self._runs_failed = 0
        self._last_run: Optional[Dict[str, Any]] = None

        self._initialized_flag = True
        logger.info(
            "SpamAutopipelineService initialized (enabled=%s run_on_start=%s interval=%sm)",
            self._enabled,
            self._run_on_start,
            self._interval_minutes,
        )

    @classmethod
    def get_instance(cls) -> "SpamAutopipelineService":
        if cls._instance is None:
            raise RuntimeError("SpamAutopipelineService has not been initialized.")
        return cls._instance

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        if not self._enabled:
            logger.info("Spam autopipeline disabled by configuration.")
            return

        self._runner_task = asyncio.create_task(self._scheduler_loop(), name="spam-autopipeline-loop")
        logger.info("Spam autopipeline scheduler started.")

        if self._run_on_start:
            asyncio.create_task(self.run_now(trigger="startup"), name="spam-autopipeline-startup-run")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._stop_event.set()

        task = self._runner_task
        self._runner_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                logger.warning("Spam autopipeline scheduler stop raised: %s", exc)

        logger.info("Spam autopipeline scheduler stopped.")

    async def _scheduler_loop(self) -> None:
        interval_seconds = max(60, int(self._interval_minutes * 60))
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval_seconds)
                break
            except asyncio.TimeoutError:
                try:
                    await self.run_now(trigger="scheduled")
                except Exception as exc:
                    logger.error("Scheduled spam autopipeline run failed: %s", exc, exc_info=True)

    async def run_now(self, *, trigger: str = "manual") -> Dict[str, Any]:
        if not self._enabled:
            return {
                "status": "disabled",
                "trigger": trigger,
                "message": "SPAM_AUTOPIPELINE_ENABLED is false",
            }

        if self._run_in_progress:
            return {
                "status": "busy",
                "trigger": trigger,
                "message": "spam autopipeline run already in progress",
            }

        async with self._run_lock:
            if self._run_in_progress:
                return {
                    "status": "busy",
                    "trigger": trigger,
                    "message": "spam autopipeline run already in progress",
                }

            self._run_in_progress = True
            started = datetime.now(timezone.utc)
            run_record: Dict[str, Any] = {
                "trigger": trigger,
                "started_at": started.isoformat(),
                "finished_at": None,
                "duration_seconds": None,
                "status": "running",
                "error": None,
                "details": {},
            }
            self._last_run = dict(run_record)
            self._runs_total += 1

            try:
                result = await asyncio.to_thread(self._run_once_sync, trigger, started)
                run_record.update(result)
                status_token = str(run_record.get("status") or "").lower()
                if status_token == "ok":
                    self._runs_succeeded += 1
                elif status_token not in {"busy", "disabled"}:
                    self._runs_failed += 1
                self._last_run = dict(run_record)
                return run_record
            except Exception as exc:
                finished = datetime.now(timezone.utc)
                run_record.update(
                    {
                        "finished_at": finished.isoformat(),
                        "duration_seconds": round(max(0.0, (finished - started).total_seconds()), 3),
                        "status": "error",
                        "error": str(exc),
                    }
                )
                self._runs_failed += 1
                self._last_run = dict(run_record)
                logger.error("Spam autopipeline run failed: %s", exc, exc_info=True)
                return run_record
            finally:
                self._run_in_progress = False

    def _run_once_sync(self, trigger: str, started: datetime) -> Dict[str, Any]:
        details: Dict[str, Any] = {}

        rep_exit = int(update_reputation_feed_main())
        details["reputation_update"] = {"exit_code": rep_exit, "status": "ok" if rep_exit == 0 else "error"}
        if rep_exit != 0:
            raise RuntimeError(f"reputation updater failed with exit code {rep_exit}")

        weaklabel_report = refresh_spam_threat_corpus(
            max_phish_rows=int(self._max_phish_rows),
            max_ham_rows=int(self._max_ham_rows),
            feedback_limit=int(self._feedback_limit),
            seed=int(self._seed),
        )
        details["weaklabel_corpus"] = weaklabel_report

        corpus_report = build_domain_corpus(
            domain="phishing",
            corpus_root=self._corpus_root,
            strict=bool(self._strict_corpus),
            seed=int(self._seed),
        )
        details["corpus_build"] = corpus_report

        defender_service = DefenderAIService.get_instance() if DefenderAIService._instance is not None else DefenderAIService()
        with SessionLocal() as db:
            retrain_results = defender_service.retrain_and_register_candidates(
                db=db,
                domain="spam",
                min_feedback_samples=int(self._min_feedback_samples),
                promote_if_better=bool(self._promote_if_better),
                notes=f"spam_autopipeline trigger={trigger}",
                allow_corpus_only=bool(self._allow_corpus_only),
            )
        details["defender_retrain"] = retrain_results

        retrain_error_count = 0
        for row in retrain_results:
            if str((row or {}).get("status") or "").lower() == "error":
                retrain_error_count += 1

        finished = datetime.now(timezone.utc)
        status = "ok" if retrain_error_count == 0 else "error"
        error = None if status == "ok" else f"defender retraining returned {retrain_error_count} error result(s)"
        return {
            "trigger": trigger,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "duration_seconds": round(max(0.0, (finished - started).total_seconds()), 3),
            "status": status,
            "error": error,
            "details": details,
        }

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self._enabled),
            "running": bool(self._running and self._enabled),
            "run_on_start": bool(self._run_on_start),
            "interval_minutes": int(self._interval_minutes),
            "in_progress": bool(self._run_in_progress),
            "min_feedback_samples": int(self._min_feedback_samples),
            "promote_if_better": bool(self._promote_if_better),
            "allow_corpus_only": bool(self._allow_corpus_only),
            "strict_corpus": bool(self._strict_corpus),
            "weaklabel_limits": {
                "max_phish_rows": int(self._max_phish_rows),
                "max_ham_rows": int(self._max_ham_rows),
                "feedback_limit": int(self._feedback_limit),
                "seed": int(self._seed),
            },
            "runs_total": int(self._runs_total),
            "runs_succeeded": int(self._runs_succeeded),
            "runs_failed": int(self._runs_failed),
            "last_run": self._last_run,
        }
