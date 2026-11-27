"""Lockfile (`skills-lock.json` v2), two-phase zero-TOCTOU installer, cross-host sync, and safe trash recovery.

Pure Python >= 3.9 standard-library implementation with zero third-party dependencies.
Byte-for-byte compatible with `vercel-labs/skills` v2 `computedHash` and ClawHub fingerprint rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union

from cosmos_mcp.capabilities.skills.models import (
    FetchedSkillPackage,
    SecurityAuditReport,
    SkillsConfig,
    VirtualFileEntry,
    atomic_write_bytes,
    atomic_write_json,
    default_host_skill_roots,
    is_link_or_junction,
    is_subpath,
    normalize_tier_level,
    unlink_link_or_junction,
)

LOCKFILE_VERSION = 2
LOCKFILE_NAME = "skills-lock.json"
BINDINGS_FILE_NAME = "skill_bindings.json"
TRASH_SOURCES_FILE_NAME = "trash_sources.json"
SYNC_MANIFEST_NAME = ".sync-manifest.json"
MANAGED_BY_ID = "cosmos-skills"

EXCLUDE_FILES: FrozenSet[str] = frozenset({"metadata.json", "_meta.json", SYNC_MANIFEST_NAME})
EXCLUDE_DIRS: FrozenSet[str] = frozenset({".git", "__pycache__", "__pypackages__"})

CLAWHUB_EXCLUDE_FILES: FrozenSet[str] = frozenset({"_meta.json", SYNC_MANIFEST_NAME})
CLAWHUB_EXCLUDE_DIRS: FrozenSet[str] = frozenset({".git", ".clawhub"})

STRIP_INSTALL_FILES: FrozenSet[str] = frozenset({"_meta.json", SYNC_MANIFEST_NAME})
STRIP_TOP_LEVEL_DOCS: FrozenSet[str] = frozenset({"readme.md", "changelog.md"})
STRIP_INSTALL_DIRS: FrozenSet[str] = frozenset({".git", "__pycache__", "__pypackages__"})

# NOTE: `cc_switch` (~/.cc-switch/skills) is strictly read-only SSOT for cc-switch coexistence
# and MUST NEVER appear in WRITABLE_HOST_IDS or be mutated/deleted by cosmos-skills!
WRITABLE_HOST_IDS: FrozenSet[str] = frozenset(
    {
        "universal_agents",
        "antigravity_global",
        "gemini_cli",
        "claude_code",
        "codex",
        "hermes",
        "hermes_appdata",
        "hermes_posix",
        "opencode",
        "grok",
        "kimi_code",
        "copilot",
        "cursor",
        "windsurf",
    }
)

_WIN_RESERVED_DEVICE_NAMES: FrozenSet[str] = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        "conin$",
        "conout$",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)

_SKILL_NAME_CLEAN_RE = re.compile(r"[^a-zA-Z0-9._-]+")
_TRASH_SEQ_LOCK = threading.Lock()
_TRASH_SEQ = 0

_HOST_ID_ALIASES: Dict[str, str] = {
    "claude": "claude_code",
    "claude-code": "claude_code",
    "cc-switch": "cc_switch",
    "cosmos-skills": "cosmos_skills_store",
    "cosmos-skills-store": "cosmos_skills_store",
    "agents": "universal_agents",
    "universal-agents": "universal_agents",
    "gemini": "gemini_cli",
    "gemini-cli": "gemini_cli",
    "kimi": "kimi_code",
    "kimi-code": "kimi_code",
}


def _normalize_host_id(raw_host: str) -> str:
    cleaned = (raw_host or "").strip()
    if not cleaned:
        return ""
    return _HOST_ID_ALIASES.get(cleaned.lower(), cleaned)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_abs_path(p: Union[str, Path]) -> str:
    ap = os.path.abspath(str(p))
    return os.path.normcase(ap) if os.name == "nt" else ap


def _norm_real_path(p: Union[str, Path]) -> str:
    rp = os.path.realpath(str(p))
    return os.path.normcase(rp) if os.name == "nt" else rp


def _has_skill_md_file(skill_dir: Path) -> bool:
    """Return True if `skill_dir` is a directory containing `SKILL.md` or `skill.md` (not plural `skills.md`)."""
    if not skill_dir.is_dir():
        return False
    try:
        with os.scandir(skill_dir) as it:
            for entry in it:
                if entry.name in ("SKILL.md", "skill.md") or entry.name.lower() == "skill.md":
                    if entry.is_file(follow_symlinks=True):
                        return True
    except OSError:
        return False
    return False


def _read_skill_md_text(skill_dir: Path) -> str:
    for cand_name in ("SKILL.md", "skill.md"):
        fp = skill_dir / cand_name
        if fp.is_file():
            try:
                raw = fp.read_bytes()
            except OSError:
                return ""
            if raw.startswith(b"\xff\xfe"):
                return raw[2:].decode("utf-16-le", errors="replace")
            if raw.startswith(b"\xfe\xff"):
                return raw[2:].decode("utf-16-be", errors="replace")
            return raw.decode("utf-8-sig", errors="replace")
    return ""


def is_managed_sync_dir(target_dir: Union[str, Path]) -> bool:
    """Return True ONLY when `target_dir` is a real directory containing `.sync-manifest.json` with `managed_by == 'cosmos-skills'`."""
    tp = Path(target_dir)
    if is_link_or_junction(tp) or not tp.is_dir():
        return False
    manifest_file = tp / SYNC_MANIFEST_NAME
    if is_link_or_junction(manifest_file) or not manifest_file.is_file():
        return False
    try:
        data = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    owner = str(data.get("managed_by") or data.get("managedBy") or "").strip()
    return owner == MANAGED_BY_ID


def sanitize_skill_dir_name(raw_name: str) -> str:
    """Sanitize a skill directory name, rejecting path traversal, trailing dots/spaces, and Windows reserved names."""
    cleaned = _SKILL_NAME_CLEAN_RE.sub("-", (raw_name or "").strip()).strip(".-/ ")
    cleaned = cleaned[:128].rstrip(".-/ ")
    if not cleaned or cleaned in (".", ".."):
        raise ValueError(f"Invalid skill name: {raw_name!r}")
    low = cleaned.lower()
    stem = low.split(".", 1)[0]
    if low in _WIN_RESERVED_DEVICE_NAMES or stem in _WIN_RESERVED_DEVICE_NAMES:
        raise ValueError(f"Reserved device name is not allowed as skill name: {raw_name!r}")
    return cleaned


def normalize_line_endings(content: bytes) -> bytes:
    """Text files (no NUL byte) have CRLF normalized to LF; binary files remain untouched."""
    if b"\x00" in content or b"\r\n" not in content:
        return content
    return content.replace(b"\r\n", b"\n")


def hash_skill_files(files: Sequence[Tuple[str, bytes]]) -> str:
    """Compute `skills.sh` v2 `computedHash` over `(relative_path, raw_bytes)` pairs."""
    entries: List[Tuple[bytes, bytes]] = []
    for rel_path, raw_bytes in files:
        path_bytes = rel_path.replace("\\", "/").encode("utf-8")
        norm_bytes = normalize_line_endings(raw_bytes)
        entries.append((path_bytes, norm_bytes))

    # Lexicographical sort on raw UTF-8 path bytes (matches Node Buffer.compare)
    entries.sort(key=lambda item: item[0])

    digest = hashlib.sha256()
    for path_bytes, content_bytes in entries:
        digest.update(path_bytes)
        digest.update(b"\x00")
        digest.update(str(len(content_bytes)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(content_bytes)
    return digest.hexdigest()


def _collect_skill_folder_files(
    skill_dir: Union[str, Path],
    *,
    exclude_files: FrozenSet[str] = EXCLUDE_FILES,
    exclude_dirs: FrozenSet[str] = EXCLUDE_DIRS,
) -> List[Tuple[str, bytes]]:
    root_str = os.path.realpath(str(skill_dir))
    collected: List[Tuple[str, bytes]] = []

    def _walk(curr_dir: str, prefix: str, ancestors: FrozenSet[str]) -> None:
        real_key = _norm_real_path(curr_dir)
        if real_key in ancestors:
            return
        branch = ancestors | frozenset({real_key})

        with os.scandir(curr_dir) as it:
            for entry in it:
                full_path = os.path.join(curr_dir, entry.name)
                is_link = is_link_or_junction(full_path)
                is_dir = False if is_link else entry.is_dir(follow_symlinks=False)
                if entry.name in exclude_files or (is_dir and entry.name in exclude_dirs):
                    continue
                rel_path = prefix + entry.name

                if is_link:
                    try:
                        target = os.path.realpath(full_path)
                    except OSError:
                        continue
                    if not os.path.exists(target):
                        continue
                    if not is_subpath(target, root_str):
                        continue
                    is_dir = os.path.isdir(target)
                    if is_dir and entry.name in exclude_dirs:
                        continue
                elif not is_dir and not entry.is_file(follow_symlinks=False):
                    continue

                if is_dir:
                    _walk(full_path, rel_path + "/", branch)
                else:
                    with open(full_path, "rb") as fh:
                        collected.append((rel_path, fh.read()))

    _walk(str(skill_dir), "", frozenset())
    return collected


def compute_skill_folder_hash(skill_dir: Union[str, Path]) -> str:
    """Compute portable `skills.sh` v2 `computedHash` for a local skill directory."""
    collected = _collect_skill_folder_files(skill_dir)
    return hash_skill_files(collected)


def _icu_locale_sort_key(rel_posix: str) -> Tuple[Any, ...]:
    """Approximate JS/ICU `localeCompare` ordering: punctuation < digits < case-insensitive letters."""
    char_keys: List[Tuple[int, str, int]] = []
    for ch in rel_posix:
        if ch.isalpha():
            case_rank = 0 if ch.islower() else 1
            char_keys.append((2, ch.lower(), case_rank))
        elif ch.isdigit():
            char_keys.append((1, ch, 0))
        else:
            char_keys.append((0, ch, 0))
    return tuple(char_keys)


def compute_clawhub_fingerprint(
    source: Union[str, Path, Sequence[Tuple[str, bytes]]],
) -> str:
    """Compute ClawHub `/api/v1/resolve` SHA-256 fingerprint excluding only `.git`, `.clawhub`, and `_meta.json` (retaining `metadata.json`)."""
    if isinstance(source, (str, Path)):
        raw_pairs = _collect_skill_folder_files(
            source,
            exclude_files=CLAWHUB_EXCLUDE_FILES,
            exclude_dirs=CLAWHUB_EXCLUDE_DIRS,
        )
    else:
        raw_pairs = list(source)

    filtered: List[Tuple[str, str]] = []
    for rel_path, raw_bytes in raw_pairs:
        posix = rel_path.replace("\\", "/").lstrip("/")
        if not posix:
            continue
        parts = posix.split("/")
        if parts[-1] in CLAWHUB_EXCLUDE_FILES:
            continue
        if any(pt in CLAWHUB_EXCLUDE_DIRS for pt in parts[:-1]):
            continue
        file_sha = hashlib.sha256(raw_bytes).hexdigest()
        filtered.append((posix, file_sha))

    filtered.sort(key=lambda item: _icu_locale_sort_key(item[0]))
    manifest_text = "".join(f"{p}:{sha}\n" for p, sha in filtered)
    return hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()


def _normalize_entry_rel_path(rel_path: str) -> str:
    norm = (rel_path or "").replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")
    if not norm:
        raise ValueError("Empty relative file path in skill package")
    pure = PurePosixPath(norm)
    for part in pure.parts:
        if part in ("", ".", ".."):
            raise ValueError(f"Unsafe relative path in skill package: {rel_path!r}")
    return pure.as_posix()


def clean_and_hash_package_entries(
    entries: Sequence[VirtualFileEntry],
) -> Tuple[List[Tuple[str, bytes]], List[str], str, str]:
    """Filter installable files (stripping `_meta.json`, `__pycache__`, and top-level `README.md`/`CHANGELOG.md`) and compute v2 + ClawHub hashes."""
    cleaned: List[Tuple[str, bytes]] = []
    clawhub_raw_pairs: List[Tuple[str, bytes]] = []
    stripped: List[str] = []
    seen_paths: Dict[str, int] = {}
    seen_clawhub: Dict[str, int] = {}

    for entry in entries:
        raw_rel = entry.rel_path or ""
        if entry.path_traversal or entry.symlink_escapes or entry.is_symlink:
            stripped.append(raw_rel)
            continue
        try:
            rel_posix = _normalize_entry_rel_path(raw_rel)
        except ValueError:
            stripped.append(raw_rel)
            continue

        parts = rel_posix.split("/")
        basename = parts[-1]
        if entry.raw_bytes is None:
            continue

        data = entry.raw_bytes
        if b"\x00" not in data:
            try:
                text = data.decode("utf-8")
                data = text.encode("utf-8")
            except UnicodeDecodeError:
                pass

        # Track unstripped valid archive entries for ClawHub upstream fingerprint (retaining metadata.json & docs)
        if basename not in CLAWHUB_EXCLUDE_FILES and not any(d in CLAWHUB_EXCLUDE_DIRS for d in parts[:-1]):
            if rel_posix in seen_clawhub:
                clawhub_raw_pairs[seen_clawhub[rel_posix]] = (rel_posix, data)
            else:
                seen_clawhub[rel_posix] = len(clawhub_raw_pairs)
                clawhub_raw_pairs.append((rel_posix, data))

        is_top_repo_doc = len(parts) == 1 and basename.lower() in STRIP_TOP_LEVEL_DOCS
        if basename in STRIP_INSTALL_FILES or is_top_repo_doc or any(d in STRIP_INSTALL_DIRS for d in parts[:-1]):
            stripped.append(rel_posix)
            continue

        if rel_posix in seen_paths:
            cleaned[seen_paths[rel_posix]] = (rel_posix, data)
        else:
            seen_paths[rel_posix] = len(cleaned)
            cleaned.append((rel_posix, data))

    hashable = [(p, b) for p, b in cleaned if p.split("/")[-1] not in EXCLUDE_FILES]
    computed_hash = hash_skill_files(hashable)
    clawhub_fp = compute_clawhub_fingerprint(clawhub_raw_pairs)
    return cleaned, stripped, computed_hash, clawhub_fp


def read_skills_lock(lock_path: Union[str, Path]) -> Dict[str, Any]:
    """Read a `skills-lock.json` file; returns normalized v2 dictionary even when missing."""
    lp = Path(lock_path)
    if not lp.is_file():
        return {"version": LOCKFILE_VERSION, "skills": {}}
    try:
        parsed = json.loads(lp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": LOCKFILE_VERSION, "skills": {}}
    if not isinstance(parsed, dict):
        return {"version": LOCKFILE_VERSION, "skills": {}}
    skills_raw = parsed.get("skills")
    skills_map: Dict[str, Dict[str, Any]] = {}
    if isinstance(skills_raw, dict):
        for k, v in skills_raw.items():
            if isinstance(k, str) and isinstance(v, dict):
                skills_map[k] = dict(v)
    return {
        "version": LOCKFILE_VERSION,
        "skills": skills_map,
    }


def write_skills_lock(lock_path: Union[str, Path], lock_data: Dict[str, Any]) -> None:
    """Atomically write `skills-lock.json` v2 with alphabetically sorted skill entries."""
    skills_in = lock_data.get("skills") if isinstance(lock_data, dict) else {}
    sorted_skills: Dict[str, Any] = {}
    if isinstance(skills_in, dict):
        for name in sorted(skills_in.keys()):
            val = skills_in[name]
            if isinstance(val, dict):
                sorted_skills[name] = val
    payload = {
        "version": LOCKFILE_VERSION,
        "skills": sorted_skills,
    }
    atomic_write_json(Path(lock_path), payload)


def build_lock_entry(
    pkg: FetchedSkillPackage,
    *,
    installed_name: str,
    computed_hash: str,
    clawhub_fingerprint: str = "",
    scope: str = "managed",
) -> Dict[str, Any]:
    """Construct a `skills.sh` v2 compatible lock entry (portable `local/<name>` when `scope='project'`)."""
    norm_scope = "project" if (scope or "managed").strip().lower() in ("project", "workspace") else "managed"
    is_local = (pkg.source_type or "") == "local"
    if is_local and norm_scope == "project":
        src_val = f"local/{installed_name}"
    else:
        src_val = pkg.source_id or pkg.source_url or f"local/{installed_name}"

    entry: Dict[str, Any] = {
        "source": src_val,
        "sourceType": pkg.source_type or "github",
        "commit": pkg.commit_sha or "",
        "computedHash": computed_hash,
    }
    if (
        not is_local
        and pkg.source_url
        and pkg.source_url != entry["source"]
        and not pkg.source_url.lower().startswith("file:")
    ):
        entry["sourceUrl"] = pkg.source_url
    if pkg.ref:
        entry["ref"] = pkg.ref
    if pkg.subpath and not (is_local and norm_scope == "project"):
        sub = pkg.subpath.replace("\\", "/").strip("/")
        skill_md_rel = sub if sub.lower().endswith("skill.md") else f"{sub}/SKILL.md"
        entry["skillPath"] = skill_md_rel
    if pkg.skill_name and pkg.skill_name != installed_name:
        entry["skillName"] = pkg.skill_name
    if pkg.version:
        entry["version"] = pkg.version
    if pkg.source_type == "clawhub" and clawhub_fingerprint:
        entry["clawhubFingerprint"] = clawhub_fingerprint
    return entry


_BINARY_PREVIEW_MAGIC: Tuple[bytes, ...] = (
    b"\x7fELF",
    b"\x89PNG\r\n\x1a\n",
    b"%PDF-",
    b"GIF87a",
    b"GIF89a",
    b"\xff\xd8\xff",
    b"\x00asm",
    b"SQLite format 3\x00",
    b"PK\x03\x04",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
)


def _decode_safe_preview_text(raw: Optional[bytes], rel_path: str, max_chars: int = 8000) -> Optional[str]:
    """Decode text/script bytes safely for read-only UI/CLI preview while skipping binary payloads."""
    if raw is None:
        return None
    if not raw:
        return ""
    if any(raw.startswith(m) for m in _BINARY_PREVIEW_MAGIC):
        return None
    if raw.startswith(b"MZ") and (len(raw) < 4 or b"\x00" in raw[2:64]):
        return None

    has_bom = raw.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf"))
    if not has_bom:
        sample = raw[:1024]
        if b"\x00" in sample:
            pairs = len(sample) // 2
            if pairs < 2:
                return None
            even_z = sum(1 for b in sample[0 : pairs * 2 : 2] if b == 0)
            odd_z = sum(1 for b in sample[1 : pairs * 2 : 2] if b == 0)
            is_utf16_like = (odd_z / pairs >= 0.30 and even_z / pairs <= 0.05) or (
                even_z / pairs >= 0.30 and odd_z / pairs <= 0.05
            )
            if not is_utf16_like:
                return None
        else:
            ctrl_cnt = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20))
            if sample and (ctrl_cnt / len(sample)) > 0.10:
                return None

    from cosmos_mcp.capabilities.skills.vetter import decode_text_with_bom_and_cookie

    ext = PurePosixPath(rel_path).suffix
    txt = decode_text_with_bom_and_cookie(raw, ext).replace("\x00", "")
    if len(txt) > max_chars:
        return txt[:max_chars] + "\n... [truncated]"
    return txt


def _extract_package_file_previews(
    cleaned_files: Sequence[Tuple[str, bytes]],
    raw_entries: Sequence[VirtualFileEntry] = (),
    audit_report: Optional[SecurityAuditReport] = None,
    max_chars_per_file: int = 8000,
    max_files: int = 20,
) -> Dict[str, str]:
    """Build bounded `{rel_path: text_preview}` map prioritizing `SKILL.md` and security-flagged files."""
    by_rel: Dict[str, bytes] = {rel: raw for rel, raw in cleaned_files}
    for ent in raw_entries:
        if ent.path_traversal or ent.symlink_escapes or ent.is_symlink or ent.raw_bytes is None:
            continue
        try:
            norm_rel = _normalize_entry_rel_path(ent.rel_path)
        except ValueError:
            continue
        if PurePosixPath(norm_rel).name.lower().startswith(".env"):
            continue
        by_rel.setdefault(norm_rel, ent.raw_bytes)

    ordered_rels: List[str] = []
    for rel in by_rel:
        if len(rel.split("/")) == 1 and rel.lower() in ("skill.md", "skills.md"):
            ordered_rels.append(rel)
    if audit_report is not None:
        for f in audit_report.findings:
            f_rel = (f.file_rel or "").replace("\\", "/").lstrip("/")
            if f_rel in by_rel and f_rel not in ordered_rels:
                ordered_rels.append(f_rel)
    for rel, _ in cleaned_files:
        if rel not in ordered_rels:
            ordered_rels.append(rel)

    previews: Dict[str, str] = {}
    for rel in ordered_rels:
        if len(previews) >= max_files:
            break
        if PurePosixPath(rel).name.lower().startswith(".env"):
            continue
        decoded = _decode_safe_preview_text(by_rel.get(rel), rel, max_chars=max_chars_per_file)
        if decoded is not None:
            previews[rel] = decoded
    return previews


def _extract_skill_md_preview(cleaned_files: Sequence[Tuple[str, bytes]], max_chars: int = 12000) -> str:
    for rel, raw in cleaned_files:
        if len(rel.split("/")) == 1 and rel.lower() == "skill.md":
            if raw.startswith(b"\xff\xfe"):
                txt = raw[2:].decode("utf-16-le", errors="replace")
            elif raw.startswith(b"\xfe\xff"):
                txt = raw[2:].decode("utf-16-be", errors="replace")
            else:
                txt = raw.decode("utf-8-sig", errors="replace")
            txt = txt.replace("\x00", "")
            return txt[:max_chars]
    return ""


@dataclass
class StagedInstallPreview:
    """Short-lived verified in-memory installation package preventing second network fetch / TOCTOU."""

    preview_token: str
    created_at: float
    source_ref: str
    scope: str
    target_workspace: Optional[Path]
    target_dir: Path
    lock_path: Path
    skill_name: str
    package: FetchedSkillPackage
    cleaned_files: List[Tuple[str, bytes]]
    stripped_files: List[str]
    computed_hash: str
    clawhub_fingerprint: str
    audit_report: SecurityAuditReport

    def to_preview_dict(
        self,
        *,
        conflict: Optional[Dict[str, Any]] = None,
        status: str = "preview",
        installed: bool = False,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        file_previews = _extract_package_file_previews(
            self.cleaned_files,
            self.package.entries,
            audit_report=self.audit_report,
        )
        return {
            "ok": True,
            "status": status,
            "installed": installed,
            "dry_run": dry_run,
            "preview_token": self.preview_token,
            "skill_name": self.skill_name,
            "scope": self.scope,
            "target_dir": str(self.target_dir),
            "lock_path": str(self.lock_path),
            "source": self.package.source_id,
            "source_type": self.package.source_type,
            "source_url": self.package.source_url,
            "commit": self.package.commit_sha,
            "version": self.package.version,
            "computed_hash": self.computed_hash,
            "clawhub_fingerprint": self.clawhub_fingerprint,
            "verdict": self.audit_report.verdict,
            "requires_confirmation": self.audit_report.verdict == "WARN",
            "file_count": len(self.cleaned_files),
            "files": [p for p, _ in self.cleaned_files],
            "stripped_files": list(self.stripped_files),
            "skill_md_preview": _extract_skill_md_preview(self.cleaned_files),
            "file_previews": file_previews,
            "audit": self.audit_report.to_dict(),
            "conflict": conflict or {"exists": False, "local_modified": False, "host_conflicts": [], "has_host_conflicts": False},
        }


class SkillPackageManager:
    """Two-phase zero-TOCTOU installer, lockfile manager, cross-host synchronizer, and safe trash handler."""

    def __init__(
        self,
        config: Optional[SkillsConfig] = None,
        *,
        market_client: Any = None,
        audit_entries_fn: Optional[Callable[..., SecurityAuditReport]] = None,
        preview_ttl_sec: float = 900.0,
        max_previews: int = 64,
    ) -> None:
        self.config = config or SkillsConfig()
        self._market_client = market_client
        self._audit_entries_fn = audit_entries_fn
        self._preview_ttl_sec = max(10.0, float(preview_ttl_sec))
        self._max_previews = max(4, int(max_previews))
        self._op_lock = threading.RLock()
        self._lock = self._op_lock
        self._preview_cache: Dict[str, StagedInstallPreview] = {}

    def _host_skill_roots(self) -> List[Tuple[str, Path]]:
        if hasattr(self.config, "host_skill_roots"):
            return self.config.host_skill_roots()
        explicit_arg = self.config.resolved_home() if self.config.home_dir is not None else None
        return default_host_skill_roots(explicit_arg)

    def _current_tier_level(self) -> int:
        if hasattr(self.config, "live_tier_level"):
            return int(self.config.live_tier_level())
        return normalize_tier_level(getattr(self.config, "tier_level", 3))

    def _check_workspace_containment(
        self,
        norm_scope: str,
        target_workspace: Optional[Union[str, Path]],
    ) -> Optional[Dict[str, Any]]:
        if not bool(getattr(self.config, "restrict_to_workspaces", False)):
            return None
        tier = self._current_tier_level()
        if target_workspace is not None and str(target_workspace).strip():
            ws_res = Path(str(target_workspace).strip()).expanduser().resolve()
            if not self.config.is_within_workspaces(ws_res):
                return {
                    "ok": False,
                    "installed": False,
                    "blocked_by_security_gate": True,
                    "tier_level": tier,
                    "error": (
                        f"Security gate: target_workspace '{ws_res}' is outside authorized "
                        f"workspace_roots {[str(w) for w in self.config.workspace_roots]}."
                    ),
                }
        elif norm_scope == "project":
            _, ws_res, _, _ = self._resolve_scope_paths("project", None)
            if ws_res is None or not self.config.is_within_workspaces(ws_res):
                return {
                    "ok": False,
                    "installed": False,
                    "blocked_by_security_gate": True,
                    "tier_level": tier,
                    "error": (
                        f"Security gate: project workspace '{ws_res}' is outside authorized "
                        f"workspace_roots {[str(w) for w in self.config.workspace_roots]}."
                    ),
                }
        return None

    def _check_write_gate(
        self,
        action_label: str,
        *,
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        host_mutation: bool = False,
    ) -> Optional[Dict[str, Any]]:
        tier = self._current_tier_level()
        if tier <= 1:
            return {
                "ok": False,
                "installed": False,
                "blocked_by_security_gate": True,
                "blocked_by_permission_tier": True,
                "tier_level": tier,
                "error": f"Security gate: Tier L{tier} (read-only) prohibits mutating operation '{action_label}'.",
            }
        norm_scope = "project" if (scope or "managed").strip().lower() in ("project", "workspace") else "managed"
        if tier == 2:
            if host_mutation:
                return {
                    "ok": False,
                    "installed": False,
                    "blocked_by_security_gate": True,
                    "blocked_by_permission_tier": True,
                    "tier_level": 2,
                    "error": f"Security gate: Tier L2 prohibits host/home directory mutation ('{action_label}').",
                }
            if norm_scope != "project":
                return {
                    "ok": False,
                    "installed": False,
                    "blocked_by_security_gate": True,
                    "blocked_by_permission_tier": True,
                    "tier_level": 2,
                    "scope": norm_scope,
                    "error": f"Security gate: Tier L2 only permits scope='project' inside authorized workspace_roots.",
                }
        return self._check_workspace_containment(norm_scope, target_workspace)

    def _resolve_scope_paths(
        self,
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
    ) -> Tuple[str, Optional[Path], Path, Path]:
        norm_scope = (scope or "managed").strip().lower()
        if norm_scope == "workspace":
            norm_scope = "project"
        if norm_scope not in ("managed", "project"):
            raise ValueError(f"Unsupported scope {scope!r}; expected 'managed' or 'project'")
        if norm_scope == "project":
            ws_raw = target_workspace
            if ws_raw is None and self.config.workspace_roots:
                ws_raw = self.config.workspace_roots[0]
            if ws_raw is None:
                ws_raw = Path.cwd()
            ws = Path(ws_raw).expanduser().resolve()
            skills_root = ws / ".agents" / "skills"
            lock_path = ws / LOCKFILE_NAME
            return "project", ws, skills_root, lock_path
        skills_root = self.config.managed_skills_store()
        lock_path = self.config.state_meta_dir() / LOCKFILE_NAME
        return "managed", None, skills_root, lock_path

    def _bindings_path(self) -> Path:
        return self.config.state_meta_dir() / BINDINGS_FILE_NAME

    def _read_bindings(self) -> Dict[str, Any]:
        with self._op_lock:
            bp = self._bindings_path()
            if not bp.is_file():
                return {"version": 1, "bindings": {}}
            try:
                data = json.loads(bp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return {"version": 1, "bindings": {}}
            if not isinstance(data, dict) or not isinstance(data.get("bindings"), dict):
                return {"version": 1, "bindings": {}}
            return {"version": 1, "bindings": dict(data["bindings"])}

    def _write_bindings(self, data: Dict[str, Any]) -> None:
        with self._op_lock:
            atomic_write_json(self._bindings_path(), data)

    def _get_market_client(self) -> Any:
        with self._op_lock:
            if self._market_client is not None:
                return self._market_client
            from cosmos_mcp.capabilities.skills.market import MarketClient

            self._market_client = MarketClient(self.config)
            return self._market_client

    def _fetch_package(self, source_ref: str) -> FetchedSkillPackage:
        ref_clean = (source_ref or "").strip()
        if ref_clean.lower().startswith("mcp:"):
            raise ValueError(
                f"'{ref_clean}' is an Official MCP Registry server reference (not a SKILL.md package). "
                "Configure it in mcpServers rather than installing as an Agent Skill."
            )
        client = self._get_market_client()
        return client.fetch_skill_package(ref_clean)

    def _audit_entries(self, entries: Sequence[VirtualFileEntry], skill_name: str) -> SecurityAuditReport:
        entry_list = list(entries)
        if self._audit_entries_fn is not None:
            fn = self._audit_entries_fn
            try:
                sig = inspect.signature(fn)
                params = list(sig.parameters.keys())
                if params and params[0] in ("skill_name", "name"):
                    return fn(skill_name, entry_list)
                if "skill_name" in sig.parameters:
                    return fn(entry_list, skill_name=skill_name)
                return fn(skill_name, entry_list)
            except (TypeError, ValueError):
                return fn(skill_name, entry_list)
        from cosmos_mcp.capabilities.skills.vetter import audit_package_entries

        return audit_package_entries(skill_name, entry_list)

    @staticmethod
    def _infer_candidate_skill_name(source_ref: str, force_name: str = "") -> str:
        if force_name and force_name.strip():
            try:
                return sanitize_skill_dir_name(force_name)
            except ValueError:
                return ""
        ref = (source_ref or "").strip()
        if not ref or ref.lower().startswith("mcp:"):
            return ""
        local_p = Path(ref)
        try:
            if local_p.exists() and local_p.is_dir() and _has_skill_md_file(local_p):
                return sanitize_skill_dir_name(local_p.name)
        except OSError:
            pass
        if "#" in ref:
            tail = ref.rsplit("#", 1)[-1].strip("/")
            if tail and "/" not in tail:
                try:
                    return sanitize_skill_dir_name(tail)
                except ValueError:
                    pass
        if "@" in ref and not ref.startswith("@"):
            tail = ref.rsplit("@", 1)[-1].strip("/")
            if tail and "/" not in tail and not re.match(r"^v?\d+\.\d+", tail):
                try:
                    return sanitize_skill_dir_name(tail)
                except ValueError:
                    pass
        if ref.startswith("clawhub:"):
            slug = ref.split(":", 1)[1].strip("/").split("/")[-1]
            if slug:
                try:
                    return sanitize_skill_dir_name(slug)
                except ValueError:
                    pass
        if ref.startswith("@") and "/" in ref:
            slug = ref.split("/", 1)[1].split("@", 1)[0].strip("/")
            if slug and "/" not in slug:
                try:
                    return sanitize_skill_dir_name(slug)
                except ValueError:
                    pass
        m = re.search(r"/skills/([a-zA-Z0-9._-]+)(?:/SKILL\.md)?/?$", ref, re.IGNORECASE)
        if m:
            try:
                return sanitize_skill_dir_name(m.group(1))
            except ValueError:
                pass
        return ""

    def _collect_host_conflicts(
        self,
        clean_name: str,
        norm_scope: str,
        ws_path: Optional[Path],
    ) -> List[Dict[str, Any]]:
        conflicts: List[Dict[str, Any]] = []
        if norm_scope == "managed":
            if not self.config.auto_discover_host_roots:
                return conflicts
            for hid, hroot in self._host_skill_roots():
                if hid == "antigravity_builtin" or str(hid).startswith("plugin:"):
                    continue
                if not hroot.is_dir():
                    continue
                cand = hroot / clean_name
                is_link = is_link_or_junction(cand)
                if not is_link and not cand.exists():
                    continue
                if not is_managed_sync_dir(cand):
                    conflicts.append(
                        {
                            "host_id": hid,
                            "target_dir": str(cand),
                            "is_link": is_link,
                            "readonly_host": hid not in WRITABLE_HOST_IDS,
                            "managed_by_cosmos": False,
                        }
                    )
        elif ws_path is not None:
            proj_claude = ws_path / ".claude" / "skills" / clean_name
            is_link = is_link_or_junction(proj_claude)
            if (is_link or proj_claude.exists()) and not is_managed_sync_dir(proj_claude):
                conflicts.append(
                    {
                        "host_id": "workspace_claude",
                        "target_dir": str(proj_claude),
                        "is_link": is_link,
                        "readonly_host": False,
                        "managed_by_cosmos": False,
                    }
                )
        return conflicts

    def inspect_target_conflict(
        self,
        skill_name: str,
        scope: str = "managed",
        target_workspace: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Inspect whether `<target_dir>` or host directories have unmanaged/modified conflicts."""
        norm_scope, ws_path, skills_root, lock_path = self._resolve_scope_paths(scope, target_workspace)
        clean_name = sanitize_skill_dir_name(skill_name)
        target_dir = skills_root / clean_name
        host_conflicts = self._collect_host_conflicts(clean_name, norm_scope, ws_path)
        is_link = is_link_or_junction(target_dir)
        exists = is_link or target_dir.exists()
        if not exists:
            return {
                "exists": False,
                "is_link": False,
                "tracked": False,
                "local_modified": False,
                "expected_hash": "",
                "actual_hash": "",
                "target_dir": str(target_dir),
                "scope": norm_scope,
                "host_conflicts": host_conflicts,
                "has_host_conflicts": bool(host_conflicts),
            }

        lock_data = read_skills_lock(lock_path)
        lock_entry = lock_data["skills"].get(clean_name)
        expected_hash = str(lock_entry.get("computedHash") or "") if isinstance(lock_entry, dict) else ""
        actual_hash = ""
        if not is_link and target_dir.is_dir():
            try:
                actual_hash = compute_skill_folder_hash(target_dir)
            except OSError:
                actual_hash = ""

        tracked = isinstance(lock_entry, dict) and bool(expected_hash)
        local_modified = (not tracked) or (actual_hash != expected_hash)
        return {
            "exists": True,
            "is_link": is_link,
            "tracked": tracked,
            "local_modified": local_modified,
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "target_dir": str(target_dir),
            "scope": norm_scope,
            "host_conflicts": host_conflicts,
            "has_host_conflicts": bool(host_conflicts),
        }

    def _prune_preview_cache_locked(self) -> None:
        now = time.monotonic()
        expired = [
            tok
            for tok, item in self._preview_cache.items()
            if (now - item.created_at) > self._preview_ttl_sec
        ]
        for tok in expired:
            self._preview_cache.pop(tok, None)
        while len(self._preview_cache) >= self._max_previews:
            oldest_tok = min(self._preview_cache.items(), key=lambda kv: kv[1].created_at)[0]
            self._preview_cache.pop(oldest_tok, None)

    def prepare_install(
        self,
        source_ref: str = "",
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        force_name: str = "",
        *,
        overwrite: bool = False,
        pre_fetched_package: Optional[FetchedSkillPackage] = None,
    ) -> Dict[str, Any]:
        """Single-pass fetch + 3-tier security audit + preview token caching without touching target disk."""
        norm_scope, ws_path, skills_root, lock_path = self._resolve_scope_paths(scope, target_workspace)
        ws_err = self._check_workspace_containment(norm_scope, target_workspace)
        if ws_err is not None:
            return ws_err

        src_clean = (source_ref or "").strip()
        if not src_clean and pre_fetched_package is not None:
            src_clean = pre_fetched_package.source_id or f"inline:{pre_fetched_package.skill_name}"
        if not src_clean:
            return {"ok": False, "status": "invalid_source", "error": "source_ref is required"}
        if pre_fetched_package is None and src_clean.lower().startswith("mcp:"):
            return {
                "ok": False,
                "status": "unsupported_mcp_server_ref",
                "installed": False,
                "error": (
                    f"'{src_clean}' is an Official MCP Registry server reference, not a SKILL.md skill package. "
                    "Configure it in mcpServers instead."
                ),
            }

        # Pre-fetch conflict check when target skill name can be determined upfront
        pre_name = self._infer_candidate_skill_name(src_clean, force_name=force_name)
        if pre_name and not overwrite:
            pre_conflict = self.inspect_target_conflict(pre_name, scope=norm_scope, target_workspace=ws_path)
            if pre_conflict["exists"] and pre_conflict["local_modified"]:
                return {
                    "ok": False,
                    "status": "conflict",
                    "installed": False,
                    "conflict": pre_conflict,
                    "local_modified": True,
                    "skill_name": pre_name,
                    "target_dir": pre_conflict["target_dir"],
                    "error": (
                        f"Target skill '{pre_name}' already exists with local modifications; "
                        "pass overwrite=True to replace it."
                    ),
                }

        try:
            pkg = pre_fetched_package if pre_fetched_package is not None else self._fetch_package(src_clean)
        except Exception as exc:
            err_msg = str(exc)
            if "outside authorized workspace" in err_msg or "escapes" in err_msg:
                return {
                    "ok": False,
                    "installed": False,
                    "blocked_by_security_gate": True,
                    "tier_level": self._current_tier_level(),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            raise

        eff_name = sanitize_skill_dir_name(force_name or pkg.skill_name or pre_name or "skill")
        target_dir = skills_root / eff_name

        conflict = self.inspect_target_conflict(eff_name, scope=norm_scope, target_workspace=ws_path)
        if conflict["exists"] and conflict["local_modified"] and not overwrite:
            return {
                "ok": False,
                "status": "conflict",
                "installed": False,
                "conflict": conflict,
                "local_modified": True,
                "skill_name": eff_name,
                "target_dir": str(target_dir),
                "error": (
                    f"Target skill '{eff_name}' already exists with local modifications; "
                    "pass overwrite=True to replace it."
                ),
            }

        audit_report = self._audit_entries(pkg.entries, skill_name=eff_name)
        cleaned_files, stripped_files, computed_hash, clawhub_fp = clean_and_hash_package_entries(pkg.entries)
        for sf in stripped_files:
            if sf not in audit_report.stripped_files:
                audit_report.stripped_files.append(sf)

        # Enforce strict root `SKILL.md` or `skill.md` requirement (rejecting packages that only contain plural `skills.md`)
        has_valid_root_skill_md = any(
            len(rel.split("/")) == 1 and rel.lower() == "skill.md"
            for rel, _ in cleaned_files
        )
        if not has_valid_root_skill_md:
            has_plural = any(len(rel.split("/")) == 1 and rel.lower() == "skills.md" for rel, _ in cleaned_files)
            detail_msg = (
                "Package only contains 'skills.md' (plural); canonical Agent Skills require 'SKILL.md' or 'skill.md'."
                if has_plural
                else "Skill package has no root SKILL.md or skill.md."
            )
            audit_report.add("BLOCK", "MISSING_SKILL_MD", "SKILL.md", detail_msg)

        if audit_report.verdict == "BLOCK":
            files_list = [p for p, _ in cleaned_files]
            file_previews = _extract_package_file_previews(
                cleaned_files,
                pkg.entries,
                audit_report=audit_report,
            )
            return {
                "ok": False,
                "status": "blocked",
                "installed": False,
                "blocked": True,
                "verdict": "BLOCK",
                "skill_name": eff_name,
                "scope": norm_scope,
                "target_dir": str(target_dir),
                "file_count": len(files_list),
                "files": files_list,
                "stripped_files": list(stripped_files),
                "skill_md_preview": _extract_skill_md_preview(cleaned_files) or file_previews.get("SKILL.md", ""),
                "file_previews": file_previews,
                "audit": audit_report.to_dict(),
                "error": f"Installation blocked by security audit for skill '{eff_name}'.",
            }

        token = f"prv_{secrets.token_urlsafe(18)}"
        staged = StagedInstallPreview(
            preview_token=token,
            created_at=time.monotonic(),
            source_ref=src_clean,
            scope=norm_scope,
            target_workspace=ws_path,
            target_dir=target_dir,
            lock_path=lock_path,
            skill_name=eff_name,
            package=pkg,
            cleaned_files=cleaned_files,
            stripped_files=stripped_files,
            computed_hash=computed_hash,
            clawhub_fingerprint=clawhub_fp,
            audit_report=audit_report,
        )
        with self._op_lock:
            self._prune_preview_cache_locked()
            self._preview_cache[token] = staged

        return staged.to_preview_dict(conflict=conflict, status="preview", installed=False, dry_run=True)

    def _get_staged_preview(self, preview_token: str) -> Optional[StagedInstallPreview]:
        tok = (preview_token or "").strip()
        if not tok:
            return None
        with self._op_lock:
            self._prune_preview_cache_locked()
            return self._preview_cache.get(tok)

    @staticmethod
    def _atomic_write_skill_directory(
        target_dir: Path,
        cleaned_files: Sequence[Tuple[str, bytes]],
        expected_hash: str,
    ) -> str:
        parent = target_dir.parent
        parent.mkdir(parents=True, exist_ok=True)
        stage_dir = parent / f".{target_dir.name}.stage_{secrets.token_hex(6)}"
        backup_dir = parent / f".{target_dir.name}.bak_{secrets.token_hex(6)}"

        try:
            stage_dir.mkdir(parents=True, exist_ok=False)
            for rel_posix, raw_bytes in cleaned_files:
                dest = (stage_dir / rel_posix).resolve()
                if not is_subpath(dest, stage_dir):
                    raise ValueError(f"Refusing to write path outside staging root: {rel_posix}")
                atomic_write_bytes(dest, raw_bytes)

            actual_hash = compute_skill_folder_hash(stage_dir)
            if expected_hash and actual_hash != expected_hash:
                raise RuntimeError(
                    f"Staging folder hash mismatch: expected {expected_hash}, got {actual_hash}"
                )

            had_backup = False
            if is_link_or_junction(target_dir):
                unlink_link_or_junction(target_dir)
            elif target_dir.exists():
                os.replace(str(target_dir), str(backup_dir))
                had_backup = True

            try:
                os.replace(str(stage_dir), str(target_dir))
            except BaseException:
                if had_backup and backup_dir.exists() and not target_dir.exists():
                    try:
                        os.replace(str(backup_dir), str(target_dir))
                    except OSError:
                        pass
                raise

            if had_backup and backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
            return actual_hash
        finally:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)

    @staticmethod
    def _atomic_sync_host_copy(
        src: Path,
        dest_dir: Path,
        manifest: Dict[str, Any],
    ) -> None:
        """Write synced host copy into same-parent temp dir + `.sync-manifest.json`, then swap atomically."""
        host_root = dest_dir.parent
        host_root.mkdir(parents=True, exist_ok=True)
        stage_dir = host_root / f".{dest_dir.name}.sync_{secrets.token_hex(6)}"
        backup_dir = host_root / f".{dest_dir.name}.bak_{secrets.token_hex(6)}"
        try:
            shutil.copytree(
                str(src),
                str(stage_dir),
                symlinks=False,
                ignore=shutil.ignore_patterns("__pycache__", "__pypackages__", ".git", "_meta.json", SYNC_MANIFEST_NAME),
            )
            atomic_write_json(stage_dir / SYNC_MANIFEST_NAME, manifest)

            had_backup = False
            if is_link_or_junction(dest_dir):
                unlink_link_or_junction(dest_dir)
            elif dest_dir.exists():
                os.replace(str(dest_dir), str(backup_dir))
                had_backup = True

            try:
                os.replace(str(stage_dir), str(dest_dir))
            except BaseException:
                if had_backup and backup_dir.exists() and not dest_dir.exists():
                    try:
                        os.replace(str(backup_dir), str(dest_dir))
                    except OSError:
                        pass
                raise

            if had_backup and backup_dir.exists():
                shutil.rmtree(backup_dir, ignore_errors=True)
        finally:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)

    def install(
        self,
        source_ref: str = "",
        preview_token: str = "",
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        confirm_warn: bool = False,
        overwrite: bool = False,
        sync_hosts: bool = True,
        *,
        dry_run: bool = False,
        force_name: str = "",
        pre_fetched_package: Optional[FetchedSkillPackage] = None,
        target_hosts: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Commit a previewed skill package or run two-phase prepare+commit with zero second fetch."""
        tier = self._current_tier_level()
        if tier <= 1:
            return {
                "ok": False,
                "installed": False,
                "blocked_by_security_gate": True,
                "blocked_by_permission_tier": True,
                "tier_level": tier,
                "error": f"Security gate: Tier L{tier} (read-only) prohibits skill installation.",
            }

        tok_clean = (preview_token or "").strip()
        if tok_clean:
            if target_workspace is not None:
                ws_arg_err = self._check_workspace_containment("project", target_workspace)
                if ws_arg_err is not None:
                    return ws_arg_err
            staged = self._get_staged_preview(tok_clean)
            if staged is None:
                return {
                    "ok": False,
                    "installed": False,
                    "status": "invalid_or_expired_preview_token",
                    "error": "preview_token is invalid or expired; run prepare_install again.",
                }
            gate_err = self._check_write_gate(
                "install",
                scope=staged.scope,
                target_workspace=staged.target_workspace,
            )
            if gate_err is not None:
                return gate_err
        else:
            gate_err = self._check_write_gate(
                "install",
                scope=scope,
                target_workspace=target_workspace,
            )
            if gate_err is not None:
                return gate_err
            prep = self.prepare_install(
                source_ref=source_ref,
                scope=scope,
                target_workspace=target_workspace,
                force_name=force_name,
                overwrite=overwrite,
                pre_fetched_package=pre_fetched_package,
            )
            if not prep.get("ok"):
                return prep
            staged = self._get_staged_preview(str(prep.get("preview_token") or ""))
            if staged is None:
                return {"ok": False, "installed": False, "status": "internal_error", "error": "Staging lost"}

        if tier == 2:
            sync_hosts = False
            if staged.audit_report.verdict == "WARN" or bool(staged.audit_report.scripts_detected):
                return {
                    "ok": False,
                    "installed": False,
                    "blocked_by_security_gate": True,
                    "blocked_by_permission_tier": True,
                    "tier_level": 2,
                    "verdict": staged.audit_report.verdict,
                    "scripts_detected": list(staged.audit_report.scripts_detected),
                    "audit": staged.audit_report.to_dict(),
                    "error": "Security gate: Tier L2 prohibits installing skills with executable scripts or WARN findings.",
                }

        conflict = self.inspect_target_conflict(
            staged.skill_name,
            scope=staged.scope,
            target_workspace=staged.target_workspace,
        )

        if dry_run:
            return staged.to_preview_dict(conflict=conflict, status="preview", installed=False, dry_run=True)

        if staged.audit_report.verdict == "WARN" and not confirm_warn:
            warn_out = staged.to_preview_dict(
                conflict=conflict,
                status="warn_confirmation_required",
                installed=False,
                dry_run=False,
            )
            if tok_clean:
                warn_out.update(
                    {
                        "ok": False,
                        "installed": False,
                        "status": "warn_confirmation_required",
                        "requires_confirmation": True,
                        "preview_token": staged.preview_token,
                        "error": "Skill triggered WARN security findings; review audit.findings and re-call with confirm_warn=True.",
                    }
                )
            return warn_out

        if conflict["exists"] and conflict["local_modified"] and not overwrite:
            return {
                "ok": False,
                "installed": False,
                "status": "conflict",
                "conflict": conflict,
                "local_modified": True,
                "preview_token": staged.preview_token,
                "skill_name": staged.skill_name,
                "target_dir": str(staged.target_dir),
                "error": (
                    f"Target skill '{staged.skill_name}' has local modifications; "
                    "pass overwrite=True to replace it."
                ),
            }

        with self._op_lock:
            actual_hash = self._atomic_write_skill_directory(
                staged.target_dir,
                staged.cleaned_files,
                staged.computed_hash,
            )
            self._preview_cache.pop(staged.preview_token, None)
            lock_data = read_skills_lock(staged.lock_path)
            lock_data["skills"][staged.skill_name] = build_lock_entry(
                staged.package,
                installed_name=staged.skill_name,
                computed_hash=actual_hash,
                clawhub_fingerprint=staged.clawhub_fingerprint,
                scope=staged.scope,
            )
            write_skills_lock(staged.lock_path, lock_data)

            synced_targets: List[Dict[str, Any]] = []
            skipped_unmanaged_hosts: List[Dict[str, Any]] = []
            if sync_hosts:
                if staged.scope == "managed":
                    if self.config.auto_discover_host_roots or target_hosts:
                        sync_res = self.sync_skill_to_hosts(
                            staged.skill_name,
                            source_dir=staged.target_dir,
                            overwrite=overwrite,
                            target_hosts=target_hosts,
                        )
                        synced_targets = list(sync_res.get("synced_targets") or [])
                        skipped_unmanaged_hosts = list(sync_res.get("skipped_unmanaged_hosts") or [])
                elif staged.scope == "project" and staged.target_workspace is not None:
                    proj_claude = staged.target_workspace / ".claude" / "skills"
                    if proj_claude.is_dir():
                        sync_res = self.sync_skill_to_hosts(
                            staged.skill_name,
                            source_dir=staged.target_dir,
                            host_roots=[("workspace_claude", proj_claude)],
                            overwrite=overwrite,
                        )
                        synced_targets = list(sync_res.get("synced_targets") or [])
                        skipped_unmanaged_hosts = list(sync_res.get("skipped_unmanaged_hosts") or [])

        return {
            "ok": True,
            "status": "installed",
            "installed": True,
            "dry_run": False,
            "skill_name": staged.skill_name,
            "scope": staged.scope,
            "target_dir": str(staged.target_dir),
            "lock_path": str(staged.lock_path),
            "computed_hash": actual_hash,
            "clawhub_fingerprint": staged.clawhub_fingerprint,
            "verdict": staged.audit_report.verdict,
            "stripped_files": list(staged.stripped_files),
            "synced_targets": synced_targets,
            "skipped_unmanaged_hosts": skipped_unmanaged_hosts,
            "audit": staged.audit_report.to_dict(),
        }

    def sync_skill_to_hosts(
        self,
        skill_name: str = "",
        source_dir: Optional[Path] = None,
        host_roots: Optional[Sequence[Tuple[str, Path]]] = None,
        *,
        overwrite: bool = False,
        target_hosts: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Sync managed skill(s) via atomic `copytree` + `.sync-manifest.json` ONLY into existing enabled host directories."""
        gate_err = self._check_write_gate("sync_skill_to_hosts", host_mutation=True)
        if gate_err is not None:
            return gate_err

        with self._op_lock:
            if not skill_name:
                store = self.config.managed_skills_store()
                if not store.is_dir():
                    return {
                        "ok": True,
                        "synced_skills": [],
                        "synced_targets": [],
                        "skipped_unmanaged_hosts": [],
                    }
                all_synced: List[str] = []
                all_targets: List[Dict[str, Any]] = []
                all_skipped: List[Dict[str, Any]] = []
                for child in sorted(store.iterdir(), key=lambda p: p.name.lower()):
                    if child.name.startswith(".") or not child.is_dir():
                        continue
                    if _has_skill_md_file(child):
                        res = self.sync_skill_to_hosts(
                            child.name,
                            source_dir=child,
                            host_roots=host_roots,
                            overwrite=overwrite,
                            target_hosts=target_hosts,
                        )
                        if res.get("ok"):
                            all_synced.append(child.name)
                            all_targets.extend(res.get("synced_targets") or [])
                            all_skipped.extend(res.get("skipped_unmanaged_hosts") or [])
                return {
                    "ok": True,
                    "synced_skills": all_synced,
                    "synced_targets": all_targets,
                    "skipped_unmanaged_hosts": all_skipped,
                }

            clean_name = sanitize_skill_dir_name(skill_name)
            src = Path(source_dir).resolve() if source_dir is not None else (self.config.managed_skills_store() / clean_name)
            if not _has_skill_md_file(src):
                return {
                    "ok": False,
                    "skill_name": clean_name,
                    "error": f"Canonical skill directory not found: {src}",
                }

            computed_hash = compute_skill_folder_hash(src)
            bindings_doc = self._read_bindings()
            prev_entry = bindings_doc["bindings"].get(clean_name)
            enabled_hosts_cfg: Optional[Set[str]] = None
            if isinstance(prev_entry, dict) and isinstance(prev_entry.get("enabled_hosts"), list):
                enabled_hosts_cfg = {
                    _normalize_host_id(str(h))
                    for h in prev_entry["enabled_hosts"]
                    if _normalize_host_id(str(h)) in WRITABLE_HOST_IDS
                }
            elif getattr(self.config, "enabled_hosts", None) is not None:
                enabled_hosts_cfg = {
                    _normalize_host_id(str(h))
                    for h in (self.config.enabled_hosts or ())
                    if _normalize_host_id(str(h)) in WRITABLE_HOST_IDS
                }

            explicit_filter = {_normalize_host_id(str(h)) for h in target_hosts} if target_hosts is not None else None

            candidates: List[Tuple[str, Path]]
            if host_roots is not None:
                candidates = [(hid, hp) for hid, hp in host_roots if hid != "cc_switch"]
            elif explicit_filter is None and not self.config.auto_discover_host_roots:
                candidates = []
            else:
                candidates = []
                for hid, hp in self._host_skill_roots():
                    if hid == "cc_switch" or hid not in WRITABLE_HOST_IDS:
                        continue
                    if explicit_filter is not None and hid not in explicit_filter:
                        continue
                    if explicit_filter is None and enabled_hosts_cfg is not None and hid not in enabled_hosts_cfg:
                        continue
                    candidates.append((hid, hp))

            synced_targets: List[Dict[str, Any]] = []
            skipped_unmanaged_hosts: List[Dict[str, Any]] = []
            src_real = _norm_real_path(src)
            src_parent_real = _norm_real_path(src.parent)

            for host_id, host_root in candidates:
                # Never touch read-only cc_switch or non-existent host directories
                if host_id == "cc_switch" or not host_root.is_dir():
                    continue
                dest_parent_real = _norm_real_path(host_root)
                if dest_parent_real == src_parent_real:
                    continue

                dest_dir = host_root / clean_name
                dest_is_link = is_link_or_junction(dest_dir)
                dest_exists = dest_is_link or dest_dir.exists()

                if dest_exists:
                    if not dest_is_link:
                        dest_real = _norm_real_path(dest_dir)
                        if dest_real == src_real:
                            continue
                    managed_copy = is_managed_sync_dir(dest_dir)
                    if not managed_copy:
                        if not overwrite:
                            skipped_unmanaged_hosts.append(
                                {
                                    "host_id": host_id,
                                    "target_dir": str(dest_dir),
                                    "is_link": dest_is_link,
                                    "reason": "unmanaged_link_or_junction" if dest_is_link else "unmanaged_directory",
                                }
                            )
                            continue
                        # When overwrite=True on a real unmanaged directory, move existing user dir to recoverable trash first!
                        if not dest_is_link and dest_dir.is_dir():
                            self._move_canonical_to_trash(
                                dest_dir,
                                reason=f"cosmos_skills.sync_overwrite_backup({clean_name}, host={host_id})",
                            )

                manifest = {
                    "managed_by": MANAGED_BY_ID,
                    "managedBy": MANAGED_BY_ID,
                    "skillName": clean_name,
                    "canonicalDir": str(src),
                    "hostId": host_id,
                    "computedHash": computed_hash,
                    "syncedAt": _utc_now_iso(),
                }
                self._atomic_sync_host_copy(src, dest_dir, manifest)
                synced_targets.append(
                    {
                        "host_id": host_id,
                        "target_dir": str(dest_dir),
                        "mode": "copytree",
                    }
                )

            if host_roots is None:
                merged_targets: Dict[str, Dict[str, Any]] = {}
                if isinstance(prev_entry, dict):
                    for item in prev_entry.get("targets") or []:
                        if isinstance(item, dict) and item.get("target_dir"):
                            tp = Path(str(item["target_dir"]))
                            if is_managed_sync_dir(tp):
                                merged_targets[str(item["target_dir"])] = dict(item)
                for item in synced_targets:
                    merged_targets[item["target_dir"]] = dict(item)

                updated_binding: Dict[str, Any] = {
                    "canonical_dir": str(src),
                    "computed_hash": computed_hash,
                    "updated_at": _utc_now_iso(),
                    "targets": list(merged_targets.values()),
                }
                if enabled_hosts_cfg is not None:
                    updated_binding["enabled_hosts"] = sorted(enabled_hosts_cfg)
                elif isinstance(prev_entry, dict) and "enabled_hosts" in prev_entry:
                    updated_binding["enabled_hosts"] = prev_entry["enabled_hosts"]
                bindings_doc["bindings"][clean_name] = updated_binding
                self._write_bindings(bindings_doc)

            return {
                "ok": True,
                "skill_name": clean_name,
                "canonical_dir": str(src),
                "computed_hash": computed_hash,
                "bindings_path": str(self._bindings_path()),
                "synced_targets": synced_targets,
                "skipped_unmanaged_hosts": skipped_unmanaged_hosts,
            }

    def get_skill_host_states(self, skill_name: str) -> List[Dict[str, Any]]:
        """Return per-host enablement and sync status for a managed skill."""
        if not self.config.auto_discover_host_roots:
            return []
        clean_name = sanitize_skill_dir_name(skill_name)
        bindings_doc = self._read_bindings()
        b_entry = bindings_doc["bindings"].get(clean_name)
        enabled_set: Optional[Set[str]] = None
        if isinstance(b_entry, dict) and isinstance(b_entry.get("enabled_hosts"), list):
            enabled_set = {_normalize_host_id(str(h)) for h in b_entry["enabled_hosts"]}

        out: List[Dict[str, Any]] = []
        for hid, hroot in self._host_skill_roots():
            if hid not in WRITABLE_HOST_IDS:
                continue
            dest = hroot / clean_name
            root_exists = hroot.is_dir()
            is_enabled = (hid in enabled_set) if enabled_set is not None else True
            managed_copy = is_managed_sync_dir(dest)
            unmanaged_present = (is_link_or_junction(dest) or dest.exists()) and not managed_copy
            out.append(
                {
                    "host_id": hid,
                    "host_root": str(hroot),
                    "target_dir": str(dest),
                    "host_root_exists": root_exists,
                    "enabled": is_enabled,
                    "synced": managed_copy,
                    "unmanaged_conflict": unmanaged_present,
                }
            )
        return out

    def set_skill_host_enabled(
        self,
        skill_name: str,
        host_id: str,
        enabled: bool,
    ) -> Dict[str, Any]:
        """Enable or disable a managed skill for a single host without affecting `skills_store` or unmanaged files."""
        gate_err = self._check_write_gate("set_skill_host_enabled", host_mutation=True)
        if gate_err is not None:
            return gate_err

        clean_name = sanitize_skill_dir_name(skill_name)
        hid = _normalize_host_id(host_id)
        if hid in ("cc_switch", "cosmos_skills_store"):
            return {
                "ok": False,
                "skill_name": clean_name,
                "host_id": hid,
                "error": f"Host '{hid}' is strictly read-only and cannot be modified.",
            }
        if hid not in WRITABLE_HOST_IDS:
            return {
                "ok": False,
                "skill_name": clean_name,
                "host_id": hid,
                "error": f"Unsupported writable host_id {hid!r}; expected one of {sorted(WRITABLE_HOST_IDS)}.",
            }

        canonical_dir = self.config.managed_skills_store() / clean_name
        if not _has_skill_md_file(canonical_dir):
            return {
                "ok": False,
                "skill_name": clean_name,
                "host_id": hid,
                "error": f"Managed skill '{clean_name}' is not installed in skills_store.",
            }

        host_map = dict(self._host_skill_roots())
        host_root = host_map.get(hid)

        with self._op_lock:
            bindings_doc = self._read_bindings()
            prev_entry = bindings_doc["bindings"].get(clean_name)
            if isinstance(prev_entry, dict) and isinstance(prev_entry.get("enabled_hosts"), list):
                enabled_set = {
                    _normalize_host_id(str(h))
                    for h in prev_entry["enabled_hosts"]
                    if _normalize_host_id(str(h)) in WRITABLE_HOST_IDS
                }
            else:
                enabled_set = set(WRITABLE_HOST_IDS)

            if enabled:
                enabled_set.add(hid)
            else:
                enabled_set.discard(hid)

            targets_list: List[Dict[str, Any]] = []
            if isinstance(prev_entry, dict):
                for item in prev_entry.get("targets") or []:
                    if isinstance(item, dict) and item.get("target_dir"):
                        if not enabled and item.get("host_id") == hid:
                            continue
                        targets_list.append(dict(item))

            bindings_doc["bindings"][clean_name] = {
                "canonical_dir": str(canonical_dir),
                "computed_hash": compute_skill_folder_hash(canonical_dir),
                "updated_at": _utc_now_iso(),
                "enabled_hosts": sorted(enabled_set),
                "targets": targets_list,
            }
            self._write_bindings(bindings_doc)

            removed_copy = False
            skipped_unmanaged = False
            synced_targets: List[Dict[str, Any]] = []
            skipped_hosts: List[Dict[str, Any]] = []

            if enabled:
                if host_root is not None and host_root.is_dir():
                    sync_res = self.sync_skill_to_hosts(
                        clean_name,
                        source_dir=canonical_dir,
                        target_hosts=[hid],
                        overwrite=False,
                    )
                    synced_targets = list(sync_res.get("synced_targets") or [])
                    skipped_hosts = list(sync_res.get("skipped_unmanaged_hosts") or [])
                    skipped_unmanaged = bool(skipped_hosts)
            else:
                if host_root is not None:
                    dest_dir = host_root / clean_name
                    if is_managed_sync_dir(dest_dir):
                        shutil.rmtree(dest_dir)
                        removed_copy = True
                    elif is_link_or_junction(dest_dir) or dest_dir.exists():
                        skipped_unmanaged = True

            return {
                "ok": True,
                "skill_name": clean_name,
                "host_id": hid,
                "enabled": bool(enabled),
                "enabled_hosts": sorted(enabled_set),
                "synced_targets": synced_targets,
                "removed_host_copy": removed_copy,
                "skipped_unmanaged": skipped_unmanaged,
                "host_states": self.get_skill_host_states(clean_name),
            }

    def scan_unmanaged_skills(self) -> Dict[str, Any]:
        """Scan host directories (including `.cc-switch/skills`) for unmanaged 'wild' skills not yet in `skills_store`."""
        if not self.config.auto_discover_host_roots:
            return {
                "ok": False,
                "blocked_by_security_gate": True,
                "tier_level": self._current_tier_level(),
                "count": 0,
                "unmanaged_skills": [],
                "error": "Security gate: host directory scanning is disabled when auto_discover_host_roots=False.",
            }

        store = self.config.managed_skills_store()
        managed_names: Set[str] = set()
        if store.is_dir():
            try:
                for child in store.iterdir():
                    if not child.name.startswith(".") and _has_skill_md_file(child):
                        managed_names.add(child.name.lower())
            except OSError:
                pass

        unmanaged: List[Dict[str, Any]] = []
        store_norm = _norm_real_path(store) if store.exists() else _norm_abs_path(store)
        for hid, hroot in self._host_skill_roots():
            if hid == "antigravity_builtin" or str(hid).startswith("plugin:"):
                continue
            if not hroot.is_dir():
                continue
            if _norm_real_path(hroot) == store_norm:
                continue
            try:
                children = sorted(hroot.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                continue
            for child in children:
                if child.name.startswith("."):
                    continue
                is_link = is_link_or_junction(child)
                if not is_link and is_managed_sync_dir(child):
                    continue
                check_dir = Path(os.path.realpath(str(child))) if is_link else child
                if not _has_skill_md_file(check_dir):
                    continue
                in_store = child.name.lower() in managed_names
                if in_store:
                    continue
                md_txt = _read_skill_md_text(check_dir)
                desc = ""
                for ln in md_txt.splitlines()[:30]:
                    if ln.strip().lower().startswith("description:"):
                        desc = ln.split(":", 1)[1].strip().strip("\"'")[:200]
                        break
                unmanaged.append(
                    {
                        "name": child.name,
                        "dir_name": child.name,
                        "host_id": hid,
                        "skill_dir": str(child),
                        "resolved_dir": str(check_dir),
                        "is_link": is_link,
                        "description": desc,
                    }
                )
        return {
            "ok": True,
            "count": len(unmanaged),
            "unmanaged_skills": unmanaged,
        }

    def adopt_unmanaged_skill(
        self,
        skill_name: str,
        source_host: str = "",
        *,
        source_path: Optional[Union[str, Path]] = None,
        confirm_warn: bool = False,
        sync_hosts: bool = True,
    ) -> Dict[str, Any]:
        """Adopt an unmanaged host skill into `skills_store` + `skills-lock.json` without deleting the original."""
        gate_err = self._check_write_gate("adopt_unmanaged_skill", host_mutation=True)
        if gate_err is not None:
            out_gate = dict(gate_err)
            out_gate["adopted"] = False
            return out_gate

        clean_name = sanitize_skill_dir_name(skill_name)
        norm_host = _normalize_host_id(source_host)
        src_dir: Optional[Path] = None
        orig_skill_dir: Optional[Path] = None
        if source_path is not None and str(source_path).strip():
            cand = Path(source_path).expanduser()
            orig_skill_dir = cand
            src_dir = Path(os.path.realpath(str(cand))) if is_link_or_junction(cand) else cand.resolve()
        else:
            scan_res = self.scan_unmanaged_skills()
            if not scan_res.get("ok"):
                out_scan_err = dict(scan_res)
                out_scan_err["installed"] = False
                out_scan_err["adopted"] = False
                return out_scan_err
            scanned = scan_res.get("unmanaged_skills") or []
            for item in scanned:
                if item.get("dir_name", "").lower() == clean_name.lower() or item.get("name", "").lower() == clean_name.lower():
                    if not norm_host or item.get("host_id") == norm_host:
                        orig_skill_dir = Path(str(item["skill_dir"]))
                        src_dir = Path(str(item["resolved_dir"]))
                        break

        if src_dir is None or not _has_skill_md_file(src_dir):
            return {
                "ok": False,
                "installed": False,
                "adopted": False,
                "skill_name": clean_name,
                "error": f"Unmanaged skill '{clean_name}' not found in host directories.",
            }

        eff_skill_dir = str(orig_skill_dir or src_dir)
        pre_pkg: Optional[FetchedSkillPackage] = None
        if orig_skill_dir is not None and self.config.auto_discover_host_roots and self._current_tier_level() >= 3:
            if any(is_subpath(orig_skill_dir.parent, hp) for _, hp in self._host_skill_roots()):
                from cosmos_mcp.capabilities.skills.vetter import _collect_local_dir_entries

                entries_ad = _collect_local_dir_entries(src_dir, config=self.config)
                pre_pkg = FetchedSkillPackage(
                    source_type="local",
                    source_id=str(src_dir),
                    source_url=src_dir.as_uri(),
                    skill_name=clean_name,
                    entries=entries_ad,
                    subpath="",
                )
        prep = self.prepare_install(
            source_ref=str(src_dir),
            scope="managed",
            force_name=clean_name,
            overwrite=False,
            pre_fetched_package=pre_pkg,
        )
        if not prep.get("ok"):
            out_prep = dict(prep)
            out_prep["adopted"] = False
            out_prep["adopted_from"] = str(src_dir)
            out_prep["skill_dir"] = eff_skill_dir
            return out_prep

        res = self.install(
            preview_token=str(prep.get("preview_token") or ""),
            scope="managed",
            force_name=clean_name,
            confirm_warn=bool(confirm_warn),
            overwrite=False,
            sync_hosts=sync_hosts,
            dry_run=False,
        )
        res["adopted"] = bool(res.get("installed"))
        res["adopted_from"] = str(src_dir)
        res["skill_dir"] = eff_skill_dir
        if not res.get("installed") and res.get("requires_confirmation"):
            res.setdefault("audit", prep.get("audit") or {})
        return res

    def check_skills(
        self,
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        skill_name: str = "",
        check_remote: bool = False,
    ) -> Dict[str, Any]:
        """Check installed skills against `skills-lock.json` v2 `computedHash` and host bindings."""
        norm_scope, ws_path, skills_root, lock_path = self._resolve_scope_paths(scope, target_workspace)
        ws_err = self._check_workspace_containment(norm_scope, target_workspace)
        if ws_err is not None:
            return ws_err
        with self._op_lock:
            lock_data = read_skills_lock(lock_path)
            bindings_doc = self._read_bindings()
        skills_map: Dict[str, Dict[str, Any]] = lock_data["skills"]

        filter_name = sanitize_skill_dir_name(skill_name) if skill_name.strip() else ""
        names = [filter_name] if filter_name else sorted(skills_map.keys())

        results: List[Dict[str, Any]] = []
        clean_count = 0
        modified_count = 0
        missing_count = 0

        for name in names:
            entry = skills_map.get(name)
            skill_dir = skills_root / name
            if entry is None:
                exists = is_link_or_junction(skill_dir) or skill_dir.exists()
                actual_h = compute_skill_folder_hash(skill_dir) if skill_dir.is_dir() and not is_link_or_junction(skill_dir) else ""
                results.append(
                    {
                        "skill_name": name,
                        "status": "untracked" if exists else "not_installed",
                        "tracked": False,
                        "local_modified": bool(exists),
                        "expected_hash": "",
                        "actual_hash": actual_h,
                        "skill_dir": str(skill_dir),
                    }
                )
                if exists:
                    modified_count += 1
                else:
                    missing_count += 1
                continue

            expected_hash = str(entry.get("computedHash") or "")
            is_link = is_link_or_junction(skill_dir)
            if not is_link and not skill_dir.is_dir():
                missing_count += 1
                results.append(
                    {
                        "skill_name": name,
                        "status": "missing",
                        "tracked": True,
                        "local_modified": False,
                        "expected_hash": expected_hash,
                        "actual_hash": "",
                        "source": entry.get("source", ""),
                        "source_type": entry.get("sourceType", ""),
                        "commit": entry.get("commit", ""),
                        "skill_dir": str(skill_dir),
                    }
                )
                continue

            actual_hash = compute_skill_folder_hash(skill_dir) if not is_link else ""
            modified = is_link or (bool(expected_hash) and actual_hash != expected_hash)
            if modified:
                modified_count += 1
                st = "modified"
            else:
                clean_count += 1
                st = "clean"

            host_checks: List[Dict[str, Any]] = []
            b_info = bindings_doc["bindings"].get(name)
            if isinstance(b_info, dict):
                for tgt in b_info.get("targets") or []:
                    if not isinstance(tgt, dict) or not tgt.get("target_dir"):
                        continue
                    tp = Path(str(tgt["target_dir"]))
                    t_link = is_link_or_junction(tp)
                    t_exists = t_link or tp.is_dir()
                    t_hash = compute_skill_folder_hash(tp) if (not t_link and tp.is_dir()) else ""
                    host_checks.append(
                        {
                            "host_id": tgt.get("host_id", ""),
                            "target_dir": str(tp),
                            "exists": t_exists,
                            "is_link": t_link,
                            "managed_by_cosmos": is_managed_sync_dir(tp),
                            "in_sync": bool(t_exists and not t_link and t_hash == actual_hash),
                        }
                    )

            item_res: Dict[str, Any] = {
                "skill_name": name,
                "status": st,
                "tracked": True,
                "local_modified": modified,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "source": entry.get("source", ""),
                "source_type": entry.get("sourceType", ""),
                "commit": entry.get("commit", ""),
                "skill_dir": str(skill_dir),
                "host_targets": host_checks,
            }

            if check_remote:
                src_ref = str(entry.get("sourceUrl") or entry.get("source") or "")
                if src_ref:
                    try:
                        remote_pkg = self._fetch_package(src_ref)
                        _, _, remote_hash, _ = clean_and_hash_package_entries(remote_pkg.entries)
                        item_res["remote_hash"] = remote_hash
                        item_res["remote_commit"] = remote_pkg.commit_sha
                        item_res["update_available"] = bool(remote_hash and remote_hash != expected_hash)
                    except Exception as exc:
                        item_res["remote_check_error"] = str(exc)

            results.append(item_res)

        return {
            "ok": True,
            "scope": norm_scope,
            "workspace": str(ws_path) if ws_path else "",
            "lock_path": str(lock_path),
            "total": len(results),
            "clean_count": clean_count,
            "modified_count": modified_count,
            "missing_count": missing_count,
            "skills": results,
        }

    @staticmethod
    def _source_ref_from_lock_entry(skill_name: str, entry: Dict[str, Any]) -> str:
        src_url = str(entry.get("sourceUrl") or "").strip()
        if src_url:
            return src_url
        src = str(entry.get("source") or "").strip()
        src_type = str(entry.get("sourceType") or "").strip()
        skill_path = str(entry.get("skillPath") or "").strip()
        if src_type == "clawhub" and not src.startswith("clawhub:") and not src.startswith("@"):
            return f"clawhub:{src}"
        if skill_path and "#" not in src and "@" not in src and not Path(src).exists():
            orig_name = str(entry.get("skillName") or skill_name)
            return f"{src}#{orig_name}"
        return src

    def relock_skill(
        self,
        skill_name: str = "",
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        *,
        sync_hosts: bool = False,
    ) -> Dict[str, Any]:
        """Recompute current `computedHash` of installed skill folder(s) and update `skills-lock.json`."""
        gate_err = self._check_write_gate("relock_skill", scope=scope, target_workspace=target_workspace)
        if gate_err is not None:
            out_gate = dict(gate_err)
            out_gate["relocked"] = False
            return out_gate

        tier = self._current_tier_level()
        if tier == 2:
            sync_hosts = False

        norm_scope, ws_path, skills_root, lock_path = self._resolve_scope_paths(scope, target_workspace)
        raw_name = (skill_name or "").strip()
        filter_name = "" if raw_name in ("", "*") else sanitize_skill_dir_name(raw_name)

        with self._op_lock:
            lock_data = read_skills_lock(lock_path)
            skills_map = lock_data["skills"]

            if filter_name:
                skill_dir_single = skills_root / filter_name
                if is_link_or_junction(skill_dir_single):
                    return {
                        "ok": False,
                        "relocked": False,
                        "status": "unsupported_link_or_junction",
                        "skill_name": filter_name,
                        "scope": norm_scope,
                        "error": f"Cannot relock symlink or junction skill directory: {skill_dir_single}",
                    }
                targets = [filter_name]
            else:
                target_set: Set[str] = set(skills_map.keys())
                if skills_root.is_dir():
                    try:
                        for ch in sorted(skills_root.iterdir(), key=lambda p: p.name.lower()):
                            if ch.name.startswith(".") or is_link_or_junction(ch) or not ch.is_dir():
                                continue
                            if _has_skill_md_file(ch):
                                target_set.add(ch.name)
                    except OSError:
                        pass
                targets = sorted(target_set)

            if tier == 2:
                from cosmos_mcp.capabilities.skills.vetter import audit_skill_directory

                for tname in targets:
                    cdir = skills_root / tname
                    if not is_link_or_junction(cdir) and cdir.is_dir():
                        rep = audit_skill_directory(cdir, skill_name=tname, config=self.config)
                        if rep.verdict != "INFO" or bool(rep.scripts_detected):
                            return {
                                "ok": False,
                                "installed": False,
                                "relocked": False,
                                "blocked_by_security_gate": True,
                                "blocked_by_permission_tier": True,
                                "tier_level": 2,
                                "verdict": rep.verdict,
                                "scripts_detected": list(rep.scripts_detected),
                                "audit": rep.to_dict(),
                                "error": "Security gate: Tier L2 prohibits relocking skills with executable scripts or WARN/BLOCK findings.",
                            }

            updated_items: List[Dict[str, Any]] = []
            unchanged_items: List[Dict[str, Any]] = []
            missing_names: List[str] = []
            all_rows: List[Dict[str, Any]] = []
            last_entry: Optional[Dict[str, Any]] = None

            for tname in targets:
                sdir = skills_root / tname
                if is_link_or_junction(sdir) or not sdir.is_dir() or not _has_skill_md_file(sdir):
                    missing_names.append(tname)
                    all_rows.append({"skill_name": tname, "status": "missing", "skill_dir": str(sdir)})
                    continue

                new_hash = compute_skill_folder_hash(sdir)
                prev_entry = skills_map.get(tname)
                previous_hash = str(prev_entry.get("computedHash") or "") if isinstance(prev_entry, dict) else ""

                if isinstance(prev_entry, dict):
                    updated_entry = dict(prev_entry)
                    updated_entry["computedHash"] = new_hash
                    if updated_entry.get("sourceType") == "clawhub" or "clawhubFingerprint" in updated_entry:
                        updated_entry["clawhubFingerprint"] = compute_clawhub_fingerprint(sdir)
                    if norm_scope == "project" and updated_entry.get("sourceType") == "local":
                        updated_entry["source"] = f"local/{tname}"
                        updated_entry.pop("sourceUrl", None)
                else:
                    updated_entry = {
                        "source": f"local/{tname}" if norm_scope == "project" else str(sdir),
                        "sourceType": "local",
                        "commit": "",
                        "computedHash": new_hash,
                    }

                skills_map[tname] = updated_entry
                last_entry = updated_entry
                changed = (previous_hash != new_hash) or (not isinstance(prev_entry, dict))
                row_info: Dict[str, Any] = {
                    "skill_name": tname,
                    "status": "relocked" if changed else "clean",
                    "changed": changed,
                    "previous_hash": previous_hash,
                    "computed_hash": new_hash,
                    "skill_dir": str(sdir),
                }
                all_rows.append(row_info)
                if changed:
                    updated_items.append(row_info)
                else:
                    unchanged_items.append(row_info)

            if missing_names and filter_name:
                return {
                    "ok": False,
                    "relocked": False,
                    "status": "not_found",
                    "skill_name": filter_name,
                    "scope": norm_scope,
                    "error": f"Skill '{filter_name}' is not installed with a valid SKILL.md at {skills_root / filter_name}",
                }

            write_skills_lock(lock_path, lock_data)

            if sync_hosts and updated_items:
                if norm_scope == "managed" and self.config.auto_discover_host_roots:
                    for row in updated_items:
                        self.sync_skill_to_hosts(
                            row["skill_name"],
                            source_dir=skills_root / row["skill_name"],
                            overwrite=False,
                        )
                elif norm_scope == "project" and ws_path is not None:
                    proj_claude = ws_path / ".claude" / "skills"
                    if proj_claude.is_dir():
                        for row in updated_items:
                            self.sync_skill_to_hosts(
                                row["skill_name"],
                                source_dir=skills_root / row["skill_name"],
                                host_roots=[("workspace_claude", proj_claude)],
                                overwrite=False,
                            )

        ok_flag = len(missing_names) == 0
        payload_out: Dict[str, Any] = {
            "ok": ok_flag,
            "relocked": ok_flag,
            "status": "relocked" if ok_flag else "missing_skill",
            "scope": norm_scope,
            "workspace": str(ws_path) if ws_path else "",
            "lock_path": str(lock_path),
            "total": len(all_rows),
            "relocked_count": len(updated_items),
            "unchanged_count": len(unchanged_items),
            "missing_count": len(missing_names),
            "skills": all_rows,
        }
        if filter_name and all_rows:
            first_row = all_rows[0]
            payload_out["skill_name"] = filter_name
            payload_out["skill_dir"] = first_row.get("skill_dir", "")
            payload_out["changed"] = bool(first_row.get("changed", False))
            payload_out["previous_hash"] = first_row.get("previous_hash", "")
            payload_out["computed_hash"] = first_row.get("computed_hash", "")
            if last_entry is not None:
                payload_out["entry"] = last_entry
        if not ok_flag and missing_names:
            payload_out["error"] = f"Missing skill directory on disk for: {', '.join(missing_names)}"
        return payload_out

    def update_skill(
        self,
        skill_name: str = "",
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        confirm_warn: bool = False,
        force: bool = False,
        sync_hosts: bool = True,
    ) -> Dict[str, Any]:
        """Update one or all locked skills when upstream changes, protecting local edits unless `force=True`."""
        gate_err = self._check_write_gate("update_skill", scope=scope, target_workspace=target_workspace)
        if gate_err is not None:
            return gate_err
        if self._current_tier_level() == 2:
            sync_hosts = False

        norm_scope, ws_path, _, lock_path = self._resolve_scope_paths(scope, target_workspace)
        lock_data = read_skills_lock(lock_path)
        skills_map = lock_data["skills"]

        if skill_name and skill_name.strip() and skill_name.strip() != "*":
            targets = [sanitize_skill_dir_name(skill_name)]
        else:
            targets = sorted(skills_map.keys())

        updated: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for name in targets:
            entry = skills_map.get(name)
            if not isinstance(entry, dict):
                errors.append({"skill_name": name, "status": "not_in_lockfile", "error": f"Skill '{name}' is not in {LOCKFILE_NAME}"})
                continue

            if entry.get("sourceType") == "local" and str(entry.get("source") or "").startswith("local/"):
                skipped.append(
                    {
                        "skill_name": name,
                        "status": "local_portable_skill",
                        "computed_hash": str(entry.get("computedHash") or ""),
                    }
                )
                continue

            conflict = self.inspect_target_conflict(name, scope=norm_scope, target_workspace=ws_path)
            if conflict["exists"] and conflict["local_modified"] and not force:
                skipped.append(
                    {
                        "skill_name": name,
                        "status": "protected_local_modifications",
                        "local_modified": True,
                        "error": f"Skill '{name}' has local modifications; pass force=True to overwrite.",
                    }
                )
                continue

            src_ref = self._source_ref_from_lock_entry(name, entry)
            if not src_ref:
                errors.append({"skill_name": name, "status": "missing_source", "error": f"No source recorded for '{name}'"})
                continue

            prep = self.prepare_install(
                source_ref=src_ref,
                scope=norm_scope,
                target_workspace=ws_path,
                force_name=name,
                overwrite=True,
            )
            if not prep.get("ok"):
                errors.append({"skill_name": name, **prep})
                continue

            old_hash = str(entry.get("computedHash") or "")
            new_hash = str(prep.get("computed_hash") or "")
            tok = str(prep.get("preview_token") or "")
            if old_hash and new_hash == old_hash and conflict["exists"] and not force:
                with self._op_lock:
                    self._preview_cache.pop(tok, None)
                skipped.append({"skill_name": name, "status": "up_to_date", "computed_hash": old_hash})
                continue

            inst = self.install(
                preview_token=tok,
                scope=norm_scope,
                target_workspace=ws_path,
                confirm_warn=confirm_warn,
                overwrite=True,
                sync_hosts=sync_hosts,
                dry_run=False,
            )
            if inst.get("installed"):
                updated.append(inst)
            elif inst.get("requires_confirmation"):
                skipped.append(inst)
            else:
                errors.append(inst)

        return {
            "ok": len(errors) == 0,
            "scope": norm_scope,
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
        }

    def _cleanup_host_copies_for_skill(
        self,
        skill_name: str,
        canonical_dir: Path,
        *,
        overwrite_unmanaged_links: bool = False,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Clean up ONLY cosmos-skills managed host copies (and links pointing to canonical_dir), protecting external files & junctions."""
        cleaned: List[Dict[str, Any]] = []
        skipped_unmanaged: List[Dict[str, Any]] = []
        seen_raw: Set[str] = set()

        with self._op_lock:
            bindings_doc = self._read_bindings()
            b_info = bindings_doc["bindings"].get(skill_name)
            bound_targets = list(b_info.get("targets") or []) if isinstance(b_info, dict) else []

            bound_abs_set: Set[str] = set()
            candidate_paths: List[Tuple[str, Path]] = []
            for item in bound_targets:
                if isinstance(item, dict) and item.get("target_dir"):
                    hid = str(item.get("host_id") or "bound")
                    if hid == "cc_switch":
                        continue
                    tp = Path(str(item["target_dir"]))
                    bound_abs_set.add(_norm_abs_path(tp))
                    candidate_paths.append((hid, tp))

            for hid, hroot in self._host_skill_roots():
                if hid == "cc_switch" or hid not in WRITABLE_HOST_IDS or not hroot.is_dir():
                    continue
                cand = hroot / skill_name
                if is_link_or_junction(cand) or cand.exists():
                    candidate_paths.append((hid, cand))

            canon_abs = _norm_abs_path(canonical_dir)
            canon_real = _norm_real_path(canonical_dir) if canonical_dir.exists() else canon_abs

            for host_id, tp in candidate_paths:
                if host_id == "cc_switch":
                    continue
                tp_abs = _norm_abs_path(tp)
                if tp_abs in seen_raw or tp_abs == canon_abs:
                    continue
                seen_raw.add(tp_abs)

                if is_link_or_junction(tp):
                    # Check if link points to our own canonical_dir or was previously bound
                    points_to_canon = False
                    try:
                        points_to_canon = _norm_real_path(tp) == canon_real
                    except OSError:
                        points_to_canon = False
                    if points_to_canon or (overwrite_unmanaged_links and tp_abs in bound_abs_set):
                        detached = unlink_link_or_junction(tp)
                        cleaned.append(
                            {
                                "host_id": host_id,
                                "target_dir": str(tp),
                                "action": "unlinked_junction_or_symlink",
                                "ok": detached,
                            }
                        )
                    else:
                        skipped_unmanaged.append(
                            {
                                "host_id": host_id,
                                "target_dir": str(tp),
                                "is_link": True,
                                "reason": "unmanaged_link_or_junction",
                            }
                        )
                elif tp.is_dir():
                    if is_managed_sync_dir(tp):
                        shutil.rmtree(tp)
                        cleaned.append({"host_id": host_id, "target_dir": str(tp), "action": "removed_copytree", "ok": True})
                    else:
                        skipped_unmanaged.append(
                            {
                                "host_id": host_id,
                                "target_dir": str(tp),
                                "is_link": False,
                                "reason": "unmanaged_directory",
                            }
                        )

            if skill_name in bindings_doc["bindings"]:
                bindings_doc["bindings"].pop(skill_name, None)
                self._write_bindings(bindings_doc)

        return cleaned, skipped_unmanaged

    def _trash_index_path(self) -> Path:
        return self.config.undo_dir() / "trash_index.json"

    def _trash_sources_registry_path(self) -> Path:
        return self.config.state_meta_dir() / TRASH_SOURCES_FILE_NAME

    def _register_external_trash_index(self, idx_path: Path) -> None:
        reg_file = self._trash_sources_registry_path()
        norm_new = _norm_abs_path(idx_path)
        existing: List[str] = []
        if reg_file.is_file():
            try:
                raw = json.loads(reg_file.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    existing = [str(x) for x in raw if isinstance(x, str)]
            except (OSError, ValueError):
                existing = []
        if not any(_norm_abs_path(x) == norm_new for x in existing):
            existing.append(str(idx_path))
            atomic_write_json(reg_file, existing[-64:])

    def _all_trash_index_paths(self) -> List[Path]:
        paths: List[Path] = [self._trash_index_path()]
        seen: Set[str] = {_norm_abs_path(paths[0])}
        for ws in self.config.workspace_roots:
            cand = Path(ws).expanduser().resolve() / ".undo_history" / "trash_index.json"
            k = _norm_abs_path(cand)
            if k not in seen:
                seen.add(k)
                paths.append(cand)
        reg_file = self._trash_sources_registry_path()
        if reg_file.is_file():
            try:
                raw = json.loads(reg_file.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    for s in raw:
                        if isinstance(s, str) and s.strip():
                            cp = Path(s)
                            k = _norm_abs_path(cp)
                            if k not in seen:
                                seen.add(k)
                                paths.append(cp)
            except (OSError, ValueError):
                pass
        return paths

    @staticmethod
    def _read_single_trash_index(idx_path: Path) -> List[Dict[str, Any]]:
        if not idx_path.is_file():
            return []
        try:
            loaded = json.loads(idx_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                return [dict(x) for x in loaded if isinstance(x, dict)]
        except (OSError, ValueError):
            pass
        return []

    @staticmethod
    def _write_single_trash_index(idx_path: Path, records: List[Dict[str, Any]]) -> None:
        atomic_write_json(idx_path, records[:500])

    def _read_trash_index(self) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()
        for idx_path in self._all_trash_index_paths():
            for rec in self._read_single_trash_index(idx_path):
                tid = str(rec.get("trash_id") or "")
                if not tid or tid in seen_ids:
                    continue
                seen_ids.add(tid)
                rec_copy = dict(rec)
                rec_copy.setdefault("_index_path", str(idx_path))
                merged.append(rec_copy)
        merged.sort(key=lambda r: (int(r.get("ts") or 0), str(r.get("trashed_at") or "")), reverse=True)
        return merged

    def _write_trash_index(self, records: List[Dict[str, Any]]) -> None:
        clean_recs = [{k: v for k, v in r.items() if k != "_index_path"} for r in records]
        self._write_single_trash_index(self._trash_index_path(), clean_recs)

    def _move_canonical_to_trash(self, canonical_dir: Path, reason: str) -> Dict[str, Any]:
        global _TRASH_SEQ
        undo_base = self.config.undo_dir()
        undo_base.mkdir(parents=True, exist_ok=True)

        if self.config.trash_fn is not None:
            fn = self.config.trash_fn
            try:
                sig = inspect.signature(fn)
                has_kw_undo = any(
                    name == "undo_dir" or p.kind == inspect.Parameter.VAR_KEYWORD
                    for name, p in sig.parameters.items()
                )
            except (TypeError, ValueError):
                has_kw_undo = True

            if has_kw_undo:
                res = fn(canonical_dir, reason, undo_dir=undo_base)  # type: ignore[call-arg]
            else:
                res = fn(canonical_dir, reason, undo_base)
            if isinstance(res, dict) and res.get("ok", True):
                trash_id = str(res.get("trash_id") or "")
                moved_to = str(res.get("moved_to") or res.get("trash_path") or "")
                if not trash_id and moved_to:
                    trash_id = Path(moved_to).name
                return {
                    "ok": True,
                    "trash_id": trash_id or f"trash_{int(time.time() * 1000)}_{canonical_dir.name}",
                    "original_path": str(res.get("original_path") or canonical_dir),
                    "trash_path": moved_to,
                    "ts": int(res.get("ts") or int(time.time() * 1000)),
                    "trashed_at": str(res.get("trashed_at") or _utc_now_iso()),
                    "via_injected_trash_fn": True,
                }
            return {
                "ok": False,
                "error": str(res.get("error") if isinstance(res, dict) else "trash_fn failed"),
            }

        trash_dir = undo_base / "trash"
        trash_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time() * 1000)
        with _TRASH_SEQ_LOCK:
            _TRASH_SEQ += 1
            seq = _TRASH_SEQ
        trashed_at = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).isoformat()
        trash_id = f"trash_{ts}_{seq:04d}_{canonical_dir.name}"
        dest = trash_dir / trash_id
        try:
            os.replace(str(canonical_dir), str(dest))
        except OSError:
            shutil.move(str(canonical_dir), str(dest))

        return {
            "ok": True,
            "trash_id": trash_id,
            "original_path": str(canonical_dir),
            "trash_path": str(dest),
            "ts": ts,
            "seq": seq,
            "trashed_at": trashed_at,
            "via_injected_trash_fn": False,
        }

    def remove_skill(
        self,
        skill_name: str,
        scope: str = "managed",
        target_workspace: Optional[Union[str, Path]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Safely clean up managed host copies and move canonical skill folder into `.undo_history/trash`."""
        gate_err = self._check_write_gate("remove_skill", scope=scope, target_workspace=target_workspace)
        if gate_err is not None:
            out_gate = dict(gate_err)
            out_gate["removed"] = False
            return out_gate

        norm_scope, ws_path, skills_root, lock_path = self._resolve_scope_paths(scope, target_workspace)
        clean_name = sanitize_skill_dir_name(skill_name)
        canonical_dir = skills_root / clean_name

        with self._op_lock:
            # If canonical path itself is a symlink or Windows junction, detach link without touching target!
            if is_link_or_junction(canonical_dir):
                cleaned_hosts: List[Dict[str, Any]] = []
                skipped_hosts: List[Dict[str, Any]] = []
                if norm_scope == "managed":
                    cleaned_hosts, skipped_hosts = self._cleanup_host_copies_for_skill(clean_name, canonical_dir)
                detached = unlink_link_or_junction(canonical_dir)
                lock_data = read_skills_lock(lock_path)
                lock_data["skills"].pop(clean_name, None)
                write_skills_lock(lock_path, lock_data)
                return {
                    "ok": detached,
                    "removed": detached,
                    "status": "unlinked_link_or_junction",
                    "skill_name": clean_name,
                    "scope": norm_scope,
                    "canonical_dir": str(canonical_dir),
                    "cleaned_host_targets": cleaned_hosts,
                    "skipped_unmanaged_hosts": skipped_hosts,
                }

            if not canonical_dir.exists():
                return {
                    "ok": False,
                    "removed": False,
                    "status": "not_found",
                    "skill_name": clean_name,
                    "scope": norm_scope,
                    "error": f"Skill '{clean_name}' is not installed at {canonical_dir}",
                }

            conflict = self.inspect_target_conflict(clean_name, scope=norm_scope, target_workspace=ws_path)
            if conflict["local_modified"] and not force:
                return {
                    "ok": False,
                    "removed": False,
                    "protected": True,
                    "local_modified": True,
                    "status": "protected_local_modifications",
                    "skill_name": clean_name,
                    "scope": norm_scope,
                    "canonical_dir": str(canonical_dir),
                    "expected_hash": conflict["expected_hash"],
                    "actual_hash": conflict["actual_hash"],
                    "error": (
                        f"Skill '{clean_name}' has local modifications relative to {LOCKFILE_NAME}; "
                        "pass force=True to move it to trash."
                    ),
                }

            # Step 1: Clean up ONLY cosmos-skills managed host copies before trashing canonical store
            cleaned_hosts = []
            skipped_hosts = []
            if norm_scope == "managed":
                cleaned_hosts, skipped_hosts = self._cleanup_host_copies_for_skill(clean_name, canonical_dir)
            elif ws_path is not None:
                proj_claude_copy = ws_path / ".claude" / "skills" / clean_name
                if is_link_or_junction(proj_claude_copy):
                    try:
                        same_canon = _norm_real_path(proj_claude_copy) == _norm_real_path(canonical_dir)
                    except OSError:
                        same_canon = False
                    if same_canon:
                        unlink_link_or_junction(proj_claude_copy)
                        cleaned_hosts.append({"host_id": "workspace_claude", "target_dir": str(proj_claude_copy), "action": "unlinked_junction_or_symlink", "ok": True})
                    else:
                        skipped_hosts.append({"host_id": "workspace_claude", "target_dir": str(proj_claude_copy), "is_link": True, "reason": "unmanaged_link_or_junction"})
                elif is_managed_sync_dir(proj_claude_copy):
                    shutil.rmtree(proj_claude_copy)
                    cleaned_hosts.append({"host_id": "workspace_claude", "target_dir": str(proj_claude_copy), "action": "removed_copytree", "ok": True})
                elif proj_claude_copy.exists():
                    skipped_hosts.append({"host_id": "workspace_claude", "target_dir": str(proj_claude_copy), "is_link": False, "reason": "unmanaged_directory"})

            # Step 2: Move canonical directory into trash
            reason = f"cosmos_skills.remove_skill({clean_name}, scope={norm_scope})"
            trash_res = self._move_canonical_to_trash(canonical_dir, reason=reason)
            if not trash_res.get("ok"):
                return {
                    "ok": False,
                    "removed": False,
                    "status": "trash_failed",
                    "skill_name": clean_name,
                    "error": str(trash_res.get("error") or "Failed to move skill directory to trash"),
                }

            trash_id = str(trash_res["trash_id"])
            trash_path = str(trash_res.get("trash_path") or "")

            # Step 3: Remove from skills-lock.json and update whichever trash_index.json owns `trash_id`
            lock_data = read_skills_lock(lock_path)
            removed_lock_entry = lock_data["skills"].pop(clean_name, None)
            write_skills_lock(lock_path, lock_data)

            meta_record: Dict[str, Any] = {
                "trash_id": trash_id,
                "skill_name": clean_name,
                "scope": norm_scope,
                "original_path": str(canonical_dir),
                "trash_path": trash_path,
                "ts": int(trash_res.get("ts") or int(time.time() * 1000)),
                "trashed_at": str(trash_res.get("trashed_at") or _utc_now_iso()),
                "reason": reason,
                "lock_path": str(lock_path),
                "lock_entry": removed_lock_entry if isinstance(removed_lock_entry, dict) else None,
                "had_host_sync": bool(cleaned_hosts),
            }

            target_idx_path = self._trash_index_path()
            if trash_res.get("via_injected_trash_fn") and trash_path:
                tp_obj = Path(trash_path)
                if tp_obj.parent.name == "trash":
                    cand_ext_idx = tp_obj.parent.parent / "trash_index.json"
                    if cand_ext_idx.is_file():
                        ext_records = self._read_single_trash_index(cand_ext_idx)
                        if any(r.get("trash_id") == trash_id for r in ext_records):
                            target_idx_path = cand_ext_idx
                            if _norm_abs_path(cand_ext_idx) != _norm_abs_path(self._trash_index_path()):
                                self._register_external_trash_index(cand_ext_idx)

            records = self._read_single_trash_index(target_idx_path)
            existing_idx = next((i for i, r in enumerate(records) if r.get("trash_id") == trash_id), None)
            if existing_idx is not None:
                merged = dict(records[existing_idx])
                merged.update({k: v for k, v in meta_record.items() if v is not None and v != ""})
                records[existing_idx] = merged
            else:
                records.insert(0, meta_record)
            self._write_single_trash_index(target_idx_path, records)

            return {
                "ok": True,
                "removed": True,
                "status": "trashed",
                "skill_name": clean_name,
                "scope": norm_scope,
                "trash_id": trash_id,
                "original_path": str(canonical_dir),
                "trash_path": trash_path,
                "cleaned_host_targets": cleaned_hosts,
                "skipped_unmanaged_hosts": skipped_hosts,
                "via_injected_trash_fn": bool(trash_res.get("via_injected_trash_fn")),
            }

    def list_trashed_skills(self, limit: int = 50) -> Dict[str, Any]:
        """List recoverable skill directories across state and workspace trash indices without duplicates."""
        cap = max(1, min(500, int(limit)))
        with self._op_lock:
            records = self._read_trash_index()
        items: List[Dict[str, Any]] = []
        for rec in records[:cap]:
            tp_str = str(rec.get("trash_path") or "")
            tp_exists = Path(tp_str).exists() if tp_str else False
            items.append(
                {
                    "trash_id": rec.get("trash_id", ""),
                    "skill_name": rec.get("skill_name") or Path(str(rec.get("original_path") or "")).name,
                    "scope": rec.get("scope", "managed"),
                    "original_path": rec.get("original_path", ""),
                    "trash_path": tp_str,
                    "trashed_at": rec.get("trashed_at", ""),
                    "restorable": tp_exists,
                }
            )
        return {
            "ok": True,
            "undo_dir": str(self.config.undo_dir()),
            "count": len(items),
            "items": items,
        }

    def restore_trashed_skill(
        self,
        trash_id: str = "latest",
        *,
        overwrite: bool = False,
        sync_hosts: bool = True,
    ) -> Dict[str, Any]:
        """Atomically restore a trashed skill back to its original path, lockfile, and host bindings."""
        tier = self._current_tier_level()
        if tier <= 1:
            return {
                "ok": False,
                "installed": False,
                "restored": False,
                "blocked_by_security_gate": True,
                "blocked_by_permission_tier": True,
                "tier_level": tier,
                "error": f"Security gate: Tier L{tier} (read-only) prohibits restoring trashed skills.",
            }

        tid = (trash_id or "latest").strip()
        with self._op_lock:
            records = self._read_trash_index()
            if not records:
                return {"ok": False, "restored": False, "error": "Trash is empty"}
            if tid == "latest":
                rec = dict(records[0])
            else:
                found = next((r for r in records if r.get("trash_id") == tid), None)
                if found is None:
                    return {"ok": False, "restored": False, "error": f"trash_id not found: {tid}"}
                rec = dict(found)

            resolved_tid = str(rec.get("trash_id") or tid)
            trash_path = Path(str(rec.get("trash_path") or ""))
            orig_path = Path(str(rec.get("original_path") or ""))
            rec_scope = str(rec.get("scope") or "managed")

            gate_err = self._check_write_gate(
                "restore_trashed_skill",
                scope=rec_scope,
                target_workspace=orig_path if rec_scope == "project" else None,
            )
            if gate_err is not None:
                out_gate = dict(gate_err)
                out_gate["restored"] = False
                return out_gate

            if not str(trash_path) or not trash_path.exists():
                return {
                    "ok": False,
                    "restored": False,
                    "trash_id": resolved_tid,
                    "error": f"Trashed payload no longer exists on disk: {trash_path}",
                }

            if tier == 2:
                sync_hosts = False
                if trash_path.is_dir():
                    from cosmos_mcp.capabilities.skills.vetter import audit_skill_directory

                    rep = audit_skill_directory(trash_path, skill_name=orig_path.name, config=self.config)
                    if rep.verdict != "INFO" or bool(rep.scripts_detected):
                        return {
                            "ok": False,
                            "installed": False,
                            "restored": False,
                            "blocked_by_security_gate": True,
                            "blocked_by_permission_tier": True,
                            "tier_level": 2,
                            "verdict": rep.verdict,
                            "scripts_detected": list(rep.scripts_detected),
                            "error": "Security gate: Tier L2 prohibits restoring skills with executable scripts or WARN/BLOCK findings.",
                        }

            if is_link_or_junction(orig_path) or orig_path.exists():
                if not overwrite:
                    return {
                        "ok": False,
                        "restored": False,
                        "conflict": True,
                        "trash_id": resolved_tid,
                        "original_path": str(orig_path),
                        "error": f"Destination already exists: {orig_path}; pass overwrite=True to replace.",
                    }
                if is_link_or_junction(orig_path):
                    unlink_link_or_junction(orig_path)
                elif orig_path.is_dir():
                    shutil.rmtree(orig_path)
                else:
                    orig_path.unlink()

            orig_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(str(trash_path), str(orig_path))
            except OSError:
                shutil.move(str(trash_path), str(orig_path))

            skill_name = str(rec.get("skill_name") or orig_path.name)
            lock_path_str = str(rec.get("lock_path") or "")
            lock_entry = rec.get("lock_entry")

            if lock_path_str and isinstance(lock_entry, dict):
                lp = Path(lock_path_str)
                lock_data = read_skills_lock(lp)
                lock_data["skills"][skill_name] = dict(lock_entry)
                write_skills_lock(lp, lock_data)

            # Remove restored `trash_id` from ALL candidate trash_index.json files (both state_root & cross-volume undo_dir)
            idx_candidates = list(self._all_trash_index_paths())
            if trash_path.parent.name == "trash":
                ext_cand = trash_path.parent.parent / "trash_index.json"
                if not any(_norm_abs_path(p) == _norm_abs_path(ext_cand) for p in idx_candidates):
                    idx_candidates.append(ext_cand)
            for idx_p in idx_candidates:
                if idx_p.is_file():
                    cur_list = self._read_single_trash_index(idx_p)
                    filtered = [r for r in cur_list if r.get("trash_id") != resolved_tid]
                    if len(filtered) != len(cur_list):
                        self._write_single_trash_index(idx_p, filtered)

            synced_targets: List[Dict[str, Any]] = []
            if sync_hosts and rec.get("scope", "managed") == "managed" and self.config.auto_discover_host_roots:
                sync_res = self.sync_skill_to_hosts(skill_name, source_dir=orig_path, overwrite=False)
                synced_targets = list(sync_res.get("synced_targets") or [])

        return {
            "ok": True,
            "restored": True,
            "trash_id": resolved_tid,
            "skill_name": skill_name,
            "scope": rec.get("scope", "managed"),
            "restored_path": str(orig_path),
            "synced_targets": synced_targets,
        }


__all__ = [
    "BINDINGS_FILE_NAME",
    "CLAWHUB_EXCLUDE_DIRS",
    "CLAWHUB_EXCLUDE_FILES",
    "EXCLUDE_DIRS",
    "EXCLUDE_FILES",
    "LOCKFILE_NAME",
    "LOCKFILE_VERSION",
    "MANAGED_BY_ID",
    "SYNC_MANIFEST_NAME",
    "SkillPackageManager",
    "StagedInstallPreview",
    "WRITABLE_HOST_IDS",
    "build_lock_entry",
    "clean_and_hash_package_entries",
    "compute_clawhub_fingerprint",
    "compute_skill_folder_hash",
    "hash_skill_files",
    "is_managed_sync_dir",
    "normalize_line_endings",
    "read_skills_lock",
    "sanitize_skill_dir_name",
    "write_skills_lock",
]
