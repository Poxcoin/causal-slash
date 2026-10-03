# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Causal-Slash Protocol Developers
"""
Crash-Proof Channel Store with Defect C1 Mitigation (Height Reset & Equivocation Guard).
Enforces Axiom 2 (Monotonic Schnorr 151B Micro-Cheques) and Axiom 6 (EOTS Safety).

Guarantees:
1. Fail-Forward 2-Phase Reservation (Leap-Ahead):
   Phase 1: reserve_height(peer_pk) -> next_h = max(reserved, committed) + 1
   Phase 2: commit_cheque(peer_pk, height, cumulative_amt)
   Upon crash/power cut: uncommitted reservations leap forward; rollbacks are strictly forbidden!
2. SQLite WAL with synchronous=EXTRA for durability.
3. OS-level process locking via fcntl.flock to prevent multi-instance concurrency hazards.
"""

from __future__ import annotations

import fcntl
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("causal_slash.channel_store")


class ChannelStoreLockedError(Exception):
    """Raised when channel store DB is locked by another OS process/container."""
    pass


class ChannelStoreError(Exception):
    """Base exception for channel store errors."""
    pass


@dataclass(slots=True, frozen=True)
class ChannelRecord:
    peer_pk: bytes
    reserved_height: int
    committed_height: int
    cumulative_amt: int
    cleared_amt: int
    updated_at: int


class SqliteChannelStore:
    """
    Crash-proof monotonic channel store.
    Guarantees strict height monotonicity even after sudden SIGKILL or power outage.
    Thread-safe and process-safe.
    """

    def __init__(self, db_dir: Path | str, db_name: str = "channels.db"):
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / db_name
        self.lock_path = self.db_dir / f"{db_name}.lock"

        self._lock_file = None
        self._conn: Optional[sqlite3.Connection] = None
        self._thread_lock = threading.RLock()

    def open(self) -> None:
        """Acquires fcntl.flock and initializes SQLite WAL store."""
        if self._conn is not None:
            return

        # 1. OS-level exclusive process lock
        f = open(self.lock_path, "a+b")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_file = f
        except (BlockingIOError, OSError) as e:
            f.close()
            raise ChannelStoreLockedError(
                f"Failed to acquire exclusive lock on {self.lock_path}. "
                f"Another agent process is already using this channel store!"
            ) from e

        # 2. SQLite WAL connection
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,  # Manual autocommit / explicit transaction control
            check_same_thread=False,
        )

        cursor = self._conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA synchronous = EXTRA;")
        cursor.execute("PRAGMA busy_timeout = 5000;")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS channels (
                peer_pk BLOB PRIMARY KEY,
                reserved_height INTEGER NOT NULL DEFAULT 0,
                committed_height INTEGER NOT NULL DEFAULT 0,
                cumulative_amt INTEGER NOT NULL DEFAULT 0,
                cleared_amt INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            );
            """
        )
        cursor.close()
        self._audit_and_recover()

    def _audit_and_recover(self) -> None:
        """Audits uncommitted reservations from a previous crash and logs leap-ahead state."""
        assert self._conn is not None
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT peer_pk, reserved_height, committed_height FROM channels WHERE reserved_height > committed_height"
        )
        uncommitted = cursor.fetchall()
        for pk, r_h, c_h in uncommitted:
            logger.warning(
                "[LEAP-AHEAD RECOVERY] Uncommitted reservation for peer %s: "
                "reserved=%d, committed=%d. Next emit will leap forward to next_h=%d. "
                "Rollbacks strictly prevented to uphold Axiom 2 & 6!",
                pk.hex()[:12] if isinstance(pk, (bytes, bytearray)) else pk,
                r_h,
                c_h,
                r_h + 1,
            )
        cursor.close()

    def get_channel(self, peer_pk: bytes) -> Optional[ChannelRecord]:
        """Returns the current channel record for peer_pk, or None."""
        assert self._conn is not None
        with self._thread_lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute(
                    "SELECT peer_pk, reserved_height, committed_height, cumulative_amt, cleared_amt, updated_at "
                    "FROM channels WHERE peer_pk = ?",
                    (peer_pk,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return ChannelRecord(*row)
            finally:
                cursor.close()

    def reserve_height(self, peer_pk: bytes) -> int:
        """
        PHASE 1: Reserves the next strictly monotonic height before cheque signing and network dispatch.
        Guarantees Fail-Forward Leap-Ahead: next_h = max(reserved, committed) + 1.
        """
        assert self._conn is not None
        now_ts = int(time.time() * 1000)
        with self._thread_lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE;")
                cursor.execute(
                    "SELECT reserved_height, committed_height FROM channels WHERE peer_pk = ?",
                    (peer_pk,),
                )
                row = cursor.fetchone()
                if row is None:
                    next_h = 1
                    cursor.execute(
                        """
                        INSERT INTO channels (peer_pk, reserved_height, committed_height, cumulative_amt, cleared_amt, updated_at)
                        VALUES (?, ?, 0, 0, 0, ?)
                        """,
                        (peer_pk, next_h, now_ts),
                    )
                else:
                    res_h, com_h = row
                    next_h = max(res_h, com_h) + 1
                    cursor.execute(
                        "UPDATE channels SET reserved_height = ?, updated_at = ? WHERE peer_pk = ?",
                        (next_h, now_ts, peer_pk),
                    )
                cursor.execute("COMMIT;")
                return next_h
            except Exception as e:
                cursor.execute("ROLLBACK;")
                raise ChannelStoreError(f"Error reserving channel height: {e}") from e
            finally:
                cursor.close()

    def commit_cheque(self, peer_pk: bytes, height: int, cumulative_amt: int) -> None:
        """
        PHASE 2: Commits the successfully dispatched cheque after network confirmation.
        """
        assert self._conn is not None
        now_ts = int(time.time() * 1000)
        with self._thread_lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE;")
                cursor.execute(
                    """
                    UPDATE channels 
                    SET committed_height = ?, cumulative_amt = ?, updated_at = ?
                    WHERE peer_pk = ? AND reserved_height >= ?
                    """,
                    (height, cumulative_amt, now_ts, peer_pk, height),
                )
                if cursor.rowcount == 0:
                    raise ChannelStoreError(
                        f"Inconsistent commit: peer {peer_pk.hex()[:12] if isinstance(peer_pk, bytes) else peer_pk} "
                        f"at height {height}"
                    )
                cursor.execute("COMMIT;")
            except Exception as e:
                cursor.execute("ROLLBACK;")
                raise ChannelStoreError(f"Error committing cheque: {e}") from e
            finally:
                cursor.close()

    def update_cleared_netting(self, peer_pk: bytes, cleared_amt: int) -> None:
        """
        Updates the cleared balance volume resulting from a valid MutualCloseAct (Axiom 3).
        Monotonic height is preserved.
        """
        assert self._conn is not None
        now_ts = int(time.time() * 1000)
        with self._thread_lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE;")
                cursor.execute(
                    "UPDATE channels SET cleared_amt = ?, updated_at = ? WHERE peer_pk = ?",
                    (cleared_amt, now_ts, peer_pk),
                )
                cursor.execute("COMMIT;")
            except Exception as e:
                cursor.execute("ROLLBACK;")
                raise ChannelStoreError(f"Error updating cleared netting: {e}") from e
            finally:
                cursor.close()

    def close(self) -> None:
        """Closes SQLite connection and releases OS flock."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._lock_file is not None:
            try:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                self._lock_file.close()
            except OSError:
                pass
            self._lock_file = None
