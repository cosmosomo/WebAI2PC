from __future__ import annotations

"""
SQLite WAL (`busy_timeout=5000`) cross-session shared memory blackboard and
edit activity ledger (`cosmos_mcp.core.memory`).

Stores per-workspace SQLite ledgers under `<state_root>/history/<workspace_hash>/`
so user Git repositories never accumulate `.localpc_memory/` untracked files.
Enforces read-only Tier `L1` hard block on `action="post"` (allowing only `read` and `search`).
Strictly depends only on Python >=3.9 stdlib and `cosmos_mcp.core`.
"""

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Union

from cosmos_mcp.core.guard import DEFAULT_GUARD, WorkspaceGuard, normalize_tier

DEFAULT_BUSY_TIMEOUT_MS = 5000
MAX_CONTENT_CHARS = 8000
MAX_TOPIC_CHARS = 200
MAX_AUTHOR_CHARS = 120
MAX_ROWS_RETAINED = 1000

_DB_INIT_LOCK = threading.RLock()
_INITIALIZED_DBS: set[str] = set()


def _compute_workspace_hash(workspace_root: Optional[Union[Path, str]]) -> str:
    if workspace_root is None or not str(workspace_root).strip():
        return "global"
    norm = os.path.normcase(str(Path(workspace_root).expanduser().resolve())).rstrip("\\/")
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]


def resolve_memory_db_path(
    workspace_root: Optional[Union[Path, str]] = None,
    *,
    guard: Optional[WorkspaceGuard] = None,
    state_root: Optional[Union[Path, str]] = None,
) -> Path:
    """Resolve `<state_root>/history/<workspace_hash>/shared_memory.sqlite3` outside user Git repositories."""
    ws_cand: Optional[Path] = None
    if workspace_root and str(workspace_root).strip():
        ws_cand = Path(workspace_root).expanduser().resolve()
    elif guard is not None and guard.workspace_roots:
        ws_cand = guard.workspace_roots[0]

    if state_root is not None and str(state_root).strip():
        base_state = Path(state_root).expanduser().resolve()
    elif guard is not None:
        base_state = guard.effective_state_root()
    else:
        base_state = DEFAULT_GUARD.effective_state_root()

    ws_hash = _compute_workspace_hash(ws_cand)
    hist_dir = base_state / "history" / ws_hash
    hist_dir.mkdir(parents=True, exist_ok=True)
    return hist_dir / "shared_memory.sqlite3"


def _open_wal_connection(db_path: Path, *, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    norm_k = os.path.normcase(str(db_path.resolve()))
    if norm_k not in _INITIALIZED_DBS or not db_path.exists():
        with _DB_INIT_LOCK:
            if norm_k not in _INITIALIZED_DBS or not db_path.exists():
                init_conn = sqlite3.connect(str(db_path), timeout=max(1.0, busy_timeout_ms / 1000.0), isolation_level=None)
                try:
                    init_conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)};")
                    init_conn.execute("PRAGMA journal_mode = WAL;")
                    init_conn.execute("PRAGMA synchronous = NORMAL;")
                    init_conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS memory_entries (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts REAL NOT NULL,
                            created_iso TEXT NOT NULL,
                            kind TEXT NOT NULL DEFAULT 'note',
                            topic TEXT NOT NULL DEFAULT '',
                            content TEXT NOT NULL DEFAULT '',
                            author TEXT NOT NULL DEFAULT '',
                            target_path TEXT NOT NULL DEFAULT ''
                        );
                        """
                    )
                    init_conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_ts ON memory_entries(ts DESC, id DESC);")
                    init_conn.execute("CREATE INDEX IF NOT EXISTS idx_mem_kind_ts ON memory_entries(kind, ts DESC);")
                    _INITIALIZED_DBS.add(norm_k)
                finally:
                    init_conn.close()
    conn = sqlite3.connect(str(db_path), timeout=max(1.0, busy_timeout_ms / 1000.0), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)};")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "id": int(row["id"]),
        "ts": float(row["ts"]),
        "created_iso": str(row["created_iso"]),
        "kind": str(row["kind"]),
        "topic": str(row["topic"]),
        "content": str(row["content"]),
        "author": str(row["author"]),
    }
    tp = str(row["target_path"] or "")
    if tp:
        out["target_path"] = tp
    return out


def _is_write_permitted(tier: str, allow_write: Optional[bool]) -> bool:
    norm_t = normalize_tier(tier) if tier else "L3"
    if norm_t == "L1":
        return False
    if allow_write is not None and not bool(allow_write):
        return False
    return True


def run_workspace_memory(
    action: str = "read",
    topic: str = "",
    content: str = "",
    author: str = "",
    limit: int = 10,
    query: str = "",
    workspace_root: Optional[Union[Path, str]] = None,
    allow_write: Optional[bool] = None,
    tier: str = "L3",
    kind: str = "",
    *,
    guard: Optional[WorkspaceGuard] = None,
    db_path: Optional[Union[Path, str]] = None,
) -> Dict[str, Any]:
    """
    Execute `workspace_memory(action='read'|'post'|'search')` against a SQLite WAL database.
    Accepts `action='write'` as a normalized alias for `'post'`.
    Hard-blocks `action='post'` when `tier == 'L1'` or `allow_write is False`.
    """
    act = (action or "read").strip().lower()
    if act == "write":
        act = "post"
    eff_tier = normalize_tier(tier if tier else (guard.tier if guard is not None else "L3"))

    if act not in ("read", "post", "search"):
        return {
            "ok": False,
            "error_code": "INVALID_PARAMETER",
            "action": action,
            "allowed_actions": ["read", "post", "search"],
            "error": f"Invalid workspace_memory action `{action}`; expected 'read', 'post', or 'search'.",
        }

    if act == "post" and not _is_write_permitted(eff_tier, allow_write):
        return {
            "ok": False,
            "blocked_by_permission_tier": True,
            "action": "post",
            "permission_tier": eff_tier,
            "allowed_actions": ["read", "search"],
            "error": (
                f"[GUARD TIER POLICY]: workspace_memory action='post' is disabled in read-only tier "
                f"'{eff_tier}' (only action='read' and action='search' are allowed)."
            ),
        }

    resolved_db = Path(db_path).expanduser().resolve() if db_path else resolve_memory_db_path(workspace_root, guard=guard)
    eff_limit = max(1, min(100, int(limit or 10)))
    kind_norm = (kind or "").strip().lower()

    if act == "post":
        clean_topic = (topic or "general").strip()[:MAX_TOPIC_CHARS] or "general"
        clean_content = (content or "").strip()[:MAX_CONTENT_CHARS]
        if not clean_content:
            return {
                "ok": False,
                "action": "post",
                "db_path": str(resolved_db),
                "error": "`content` is required when posting to workspace_memory.",
            }
        clean_author = (author or "agent").strip()[:MAX_AUTHOR_CHARS] or "agent"
        post_kind = kind_norm if kind_norm in ("note", "auto_activity") else "note"
        now = time.time()
        iso_now = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        conn = _open_wal_connection(resolved_db)
        try:
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                """
                INSERT INTO memory_entries (ts, created_iso, kind, topic, content, author, target_path)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (now, iso_now, post_kind, clean_topic, clean_content, clean_author, ""),
            )
            entry_id = int(cur.lastrowid or 0)
            conn.execute(
                """
                DELETE FROM memory_entries
                WHERE id NOT IN (
                    SELECT id FROM memory_entries ORDER BY ts DESC, id DESC LIMIT ?
                );
                """,
                (MAX_ROWS_RETAINED,),
            )
            conn.execute("COMMIT;")
        except BaseException:
            try:
                conn.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

        if guard is not None:
            clean_content = guard.redact_sensitive_output(clean_content)
        return {
            "ok": True,
            "action": "post",
            "db_path": str(resolved_db),
            "id": entry_id,
            "entry": {
                "id": entry_id,
                "ts": now,
                "created_iso": iso_now,
                "kind": post_kind,
                "topic": clean_topic,
                "content": clean_content,
                "author": clean_author,
            },
        }

    conn = _open_wal_connection(resolved_db)
    try:
        if act == "read":
            clauses: List[str] = []
            params: List[Any] = []
            if kind_norm and kind_norm != "all":
                clauses.append("kind = ?")
                params.append(kind_norm)
            if topic and topic.strip():
                clauses.append("LOWER(topic) LIKE ?")
                params.append(f"%{topic.strip().lower()}%")
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            params.append(eff_limit)
            rows = conn.execute(
                f"SELECT * FROM memory_entries {where_sql} ORDER BY ts DESC, id DESC LIMIT ?;",
                tuple(params),
            ).fetchall()
        else:
            q_str = (query or topic or content or "").strip()
            if not q_str:
                return {
                    "ok": False,
                    "action": "search",
                    "db_path": str(resolved_db),
                    "error": "`query` (or `topic`) is required when action='search'.",
                }
            like_pat = f"%{q_str.lower()}%"
            clauses_s = ["(LOWER(topic) LIKE ? OR LOWER(content) LIKE ? OR LOWER(author) LIKE ? OR LOWER(target_path) LIKE ?)"]
            params_s: List[Any] = [like_pat, like_pat, like_pat, like_pat]
            if kind_norm and kind_norm != "all":
                clauses_s.append("kind = ?")
                params_s.append(kind_norm)
            params_s.append(eff_limit)
            rows = conn.execute(
                f"SELECT * FROM memory_entries WHERE {' AND '.join(clauses_s)} ORDER BY ts DESC, id DESC LIMIT ?;",
                tuple(params_s),
            ).fetchall()
    finally:
        conn.close()

    entries = [_row_to_dict(r) for r in rows]
    if guard is not None:
        for item in entries:
            item["content"] = guard.redact_sensitive_output(str(item.get("content") or ""))
            item["topic"] = guard.redact_sensitive_output(str(item.get("topic") or ""))
    return {
        "ok": True,
        "action": act,
        "db_path": str(resolved_db),
        "count": len(entries),
        "entries": entries,
    }


def record_auto_activity(
    tool_name: str,
    target_path: str,
    summary: str,
    author: str = "",
    workspace_root: Optional[Union[Path, str]] = None,
    *,
    guard: Optional[WorkspaceGuard] = None,
    db_path: Optional[Union[Path, str]] = None,
) -> bool:
    """
    Append a lightweight `kind='auto_activity'` edit breadcrumb into the WAL memory board.
    Never raises on lock contention or read-only tier.
    """
    try:
        if guard is not None and normalize_tier(guard.tier) == "L1":
            return False
        resolved_db = Path(db_path).expanduser().resolve() if db_path else resolve_memory_db_path(workspace_root, guard=guard)
        now = time.time()
        iso_now = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        clean_author = (author or "agent").strip()[:MAX_AUTHOR_CHARS] or "agent"
        clean_summary = (summary or "").strip()[:800]
        if guard is not None:
            clean_summary = guard.redact_sensitive_output(clean_summary)
        conn = _open_wal_connection(resolved_db)
        try:
            conn.execute(
                """
                INSERT INTO memory_entries (ts, created_iso, kind, topic, content, author, target_path)
                VALUES (?, ?, 'auto_activity', ?, ?, ?, ?);
                """,
                (now, iso_now, str(tool_name)[:80], clean_summary, clean_author, str(target_path or "")[:500]),
            )
        finally:
            conn.close()
        return True
    except Exception:
        return False


def read_recent_activity(
    workspace_root: Optional[Union[Path, str]] = None,
    *,
    limit: int = 5,
    kind: str = "",
    guard: Optional[WorkspaceGuard] = None,
    db_path: Optional[Union[Path, str]] = None,
) -> List[Dict[str, Any]]:
    """Read recent entries without creating a new SQLite file if none exists yet."""
    try:
        if db_path:
            resolved_db = Path(db_path).expanduser().resolve()
        else:
            ws_cand: Optional[Path] = None
            if workspace_root and str(workspace_root).strip():
                ws_cand = Path(workspace_root).expanduser().resolve()
            elif guard is not None and guard.workspace_roots:
                ws_cand = guard.workspace_roots[0]
            base_state = guard.effective_state_root() if guard is not None else DEFAULT_GUARD.effective_state_root()
            resolved_db = base_state / "history" / _compute_workspace_hash(ws_cand) / "shared_memory.sqlite3"
        if not resolved_db.is_file():
            return []
        res = run_workspace_memory(
            action="read",
            limit=limit,
            kind=kind,
            workspace_root=workspace_root,
            guard=guard,
            db_path=resolved_db,
        )
        return list(res.get("entries") or []) if res.get("ok") else []
    except Exception:
        return []
