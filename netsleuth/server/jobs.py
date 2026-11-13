"""Background analysis jobs.

Captures are analysed in separate worker *processes*: parsing is CPU-bound
pure Python, so a process keeps the API responsive, and a worker that dies on
a pathological input cannot take the server down with it. Job state lives in
the catalogue database, so progress survives across requests and interrupted
jobs are re-queued on the next start.
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import threading
import time
from concurrent.futures import Executor, ProcessPoolExecutor, ThreadPoolExecutor
from concurrent.futures.process import BrokenProcessPool

from ..analysis.pipeline import AnalysisCancelled, analyze_capture
from ..config import Config
from ..ingest.reader import CaptureFormatError
from ..storage.catalog import DONE, FAILED, PROCESSING, Catalog

log = logging.getLogger("netsleuth.jobs")

# stage -> (start, end) share of the overall progress bar
_STAGES = {"hashing": (0.0, 0.05), "parsing": (0.05, 0.80), "indexing": (0.80, 0.92),
           "detecting": (0.92, 0.99), "done": (1.0, 1.0)}


def run_job(data_dir: str, cid: str, config: Config | None = None) -> None:
    """Analyse one capture. Runs inside a worker process (or thread)."""
    catalog = Catalog(data_dir)
    row = catalog.get(cid)
    if row is None:
        return
    db_path = catalog.db_file(cid)
    tmp_path = db_path + ".partial"
    last = [0.0]

    def progress(stage: str, frac: float) -> None:
        now = time.monotonic()
        if now - last[0] < 0.25 and frac < 1.0:
            return
        last[0] = now
        lo, hi = _STAGES.get(stage, (0.0, 1.0))
        catalog.update(cid, stage=stage, progress=round(lo + (hi - lo) * frac, 4))

    cancel_checked = [0.0, False]

    def cancelled() -> bool:
        now = time.monotonic()
        if now - cancel_checked[0] > 0.5:
            cancel_checked[0] = now
            cancel_checked[1] = catalog.is_cancelled(cid)
        return cancel_checked[1]

    catalog.update(cid, status=PROCESSING, stage="hashing", progress=0.0, error="")
    try:
        for p in (tmp_path, db_path):
            if os.path.exists(p):
                os.remove(p)
        summary = analyze_capture(catalog.capture_file(cid), tmp_path, config,
                                  progress=progress, cancelled=cancelled,
                                  filename=row["filename"])
        os.replace(tmp_path, db_path)
        catalog.update(cid, status=DONE, stage="done", progress=1.0,
                       finished_at=time.time(), summary=summary)
    except AnalysisCancelled:
        log.info("analysis of %s cancelled", cid)
        _cleanup(tmp_path)
    except CaptureFormatError as exc:
        _cleanup(tmp_path)
        catalog.update(cid, status=FAILED, error=str(exc), finished_at=time.time())
    except Exception as exc:  # noqa: BLE001 - a job must always reach a final state
        log.exception("analysis of %s failed", cid)
        _cleanup(tmp_path)
        catalog.update(cid, status=FAILED, finished_at=time.time(),
                       error=f"internal error during analysis: {type(exc).__name__}: {exc}"[:500])


def _cleanup(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


class JobManager:
    def __init__(self, data_dir: str, config: Config | None = None, workers: int = 2):
        self.data_dir = data_dir
        self.config = config
        self.workers = workers
        self.catalog = Catalog(data_dir)
        self._lock = threading.Lock()
        self._pool: Executor = self._make_pool()

    def _make_pool(self) -> Executor:
        if self.workers <= 0:
            # in-process fallback (tests, restricted environments)
            return ThreadPoolExecutor(max_workers=1, thread_name_prefix="netsleuth-job")
        return ProcessPoolExecutor(max_workers=self.workers,
                                   mp_context=multiprocessing.get_context("spawn"))

    def submit(self, cid: str) -> None:
        with self._lock:
            try:
                fut = self._pool.submit(run_job, self.data_dir, cid, self.config)
            except (BrokenProcessPool, RuntimeError):
                self._pool = self._make_pool()
                fut = self._pool.submit(run_job, self.data_dir, cid, self.config)
        fut.add_done_callback(lambda f, cid=cid: self._finished(cid, f))

    def _finished(self, cid: str, fut) -> None:
        exc = fut.exception()
        if exc is None:
            return
        # The worker process itself died (out of memory, killed, ...).
        log.error("worker for %s terminated abnormally: %r", cid, exc)
        row = self.catalog.get(cid)
        if row and row["status"] != DONE:
            self.catalog.update(
                cid, status=FAILED, finished_at=time.time(),
                error="the analysis worker terminated unexpectedly (possibly out of memory)")
        if isinstance(exc, BrokenProcessPool):
            with self._lock:
                self._pool = self._make_pool()

    def resume_pending(self) -> int:
        """Re-queue jobs that were queued or running when the server stopped."""
        ids = self.catalog.pending()
        for cid in ids:
            if os.path.exists(self.catalog.capture_file(cid)):
                self.submit(cid)
            else:
                self.catalog.update(cid, status=FAILED, error="capture file is missing")
        return len(ids)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
