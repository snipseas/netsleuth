"""The capture catalogue: one small SQLite database listing every uploaded
capture and the state of its analysis job.

It is shared between the API process and the analysis worker processes, so
every operation uses its own short-lived connection and the database runs in
WAL mode.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
import uuid
from contextlib import contextmanager

QUEUED, PROCESSING, DONE, FAILED = "queued", "processing", "done", "failed"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER NOT NULL,
    status TEXT NOT NULL, stage TEXT DEFAULT '', progress REAL DEFAULT 0,
    error TEXT DEFAULT '', created_at REAL NOT NULL, finished_at REAL,
    summary TEXT DEFAULT '', cancel INTEGER DEFAULT 0);
"""


class Catalog:
    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        self.captures_dir = os.path.join(self.data_dir, "captures")
        os.makedirs(self.captures_dir, exist_ok=True)
        self.path = os.path.join(self.data_dir, "catalog.db")
        with self._db() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(_SCHEMA)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            yield db
            db.commit()
        finally:
            db.close()

    # -- paths ---------------------------------------------------------------
    def capture_dir(self, cid: str) -> str:
        # ids are generated here (uuid4 hex); validating again keeps any
        # caller-supplied value from escaping the captures directory
        if not (len(cid) == 32 and all(c in "0123456789abcdef" for c in cid)):
            raise KeyError(cid)
        return os.path.join(self.captures_dir, cid)

    def capture_file(self, cid: str) -> str:
        return os.path.join(self.capture_dir(cid), "capture.bin")

    def db_file(self, cid: str) -> str:
        return os.path.join(self.capture_dir(cid), "analysis.db")

    # -- lifecycle -------------------------------------------------------------
    def new_id(self) -> str:
        cid = uuid.uuid4().hex
        os.makedirs(self.capture_dir(cid))
        return cid

    def register(self, cid: str, filename: str, size: int) -> dict:
        with self._db() as db:
            db.execute(
                "INSERT INTO captures (id, filename, size, status, created_at) VALUES (?,?,?,?,?)",
                (cid, filename, size, QUEUED, time.time()))
        return self.get(cid)

    def update(self, cid: str, **fields) -> None:
        if not fields:
            return
        if "summary" in fields and not isinstance(fields["summary"], str):
            fields["summary"] = json.dumps(fields["summary"])
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._db() as db:
            db.execute(f"UPDATE captures SET {cols} WHERE id = ?", (*fields.values(), cid))

    def get(self, cid: str) -> dict | None:
        with self._db() as db:
            cur = db.execute("SELECT * FROM captures WHERE id = ?", (cid,))
            row = cur.fetchone()
            return self._row(cur, row) if row else None

    def list(self) -> list[dict]:
        with self._db() as db:
            cur = db.execute("SELECT * FROM captures ORDER BY created_at DESC")
            return [self._row(cur, r) for r in cur.fetchall()]

    def pending(self) -> list[str]:
        with self._db() as db:
            return [r[0] for r in db.execute(
                "SELECT id FROM captures WHERE status IN (?, ?) ORDER BY created_at",
                (QUEUED, PROCESSING))]

    def is_cancelled(self, cid: str) -> bool:
        with self._db() as db:
            row = db.execute("SELECT cancel FROM captures WHERE id = ?", (cid,)).fetchone()
        return row is None or bool(row[0])

    def delete(self, cid: str) -> bool:
        """Remove a capture. A running job notices the missing row and stops."""
        with self._db() as db:
            n = db.execute("DELETE FROM captures WHERE id = ?", (cid,)).rowcount
        try:
            shutil.rmtree(self.capture_dir(cid), ignore_errors=True)
        except KeyError:
            return False
        return bool(n)

    @staticmethod
    def _row(cur, row) -> dict:
        d = dict(zip([c[0] for c in cur.description], row))
        d.pop("cancel", None)
        if d.get("summary"):
            try:
                d["summary"] = json.loads(d["summary"])
            except ValueError:
                d["summary"] = None
        else:
            d["summary"] = None
        return d
