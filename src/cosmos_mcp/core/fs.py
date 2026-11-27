from __future__ import annotations

"""
Core file reading, multimodal image adaptation (Pillow + pure-stdlib PNG fallback),
read-only Office/PDF/Notebook text extraction, MVCC/shrink-guarded writing, surgical
windowed patching (`±15` drift + `edits=[...]`), and `manage_files` / history / trash tools.

All low-level encoding, staging syntax validation, file locks, externalized snapshots, trash,
and 9-strategy fuzzy matching delegate directly to `cosmos_mcp.core.{fs_io,fs_tx,patch}`.
Strictly depends only on Python >=3.9 stdlib, `cosmos_mcp.core.*`, and optional lazy `Pillow` / `pypdf`.
"""

import base64
import contextlib
from datetime import date, datetime, timedelta
import hashlib
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import xml.etree.ElementTree as ET
import zipfile
import zlib

from cosmos_mcp.core import fs_io as _core_fs_io
from cosmos_mcp.core.code import (
    extract_symbols_from_text,
    insert_after_symbol as _code_insert_after_symbol,
    resolve_symbol_in_outline,
)
from cosmos_mcp.core.fs_io import (
    IMAGE_EXTENSIONS,
    MAX_DEFAULT_READ_BYTES,
    atomic_validate_and_replace,
    auto_check_syntax,
    check_office_or_os_file_lock,
    detect_and_decode_bytes,
    detect_image_magic,
    encode_with_detected_encoding,
    parse_image_dimensions_stdlib,
    read_local_image_payload as _io_read_local_image_payload,
    stream_read_text_window,
    verify_expected_sha256,
    write_file as _io_write_file,
)
from cosmos_mcp.core.fs_tx import (
    MultiFileLock,
    get_file_lock,
    list_undo_snapshots,
    pop_latest_undo_entry_quiet,
    record_file_creation_undo,
    record_move_undo,
    resolve_undo_dir,
    restore_trash_item as _tx_restore_trash_item,
    safe_trash_file as _tx_safe_trash_file,
    save_undo_snapshot as _tx_save_undo_snapshot,
    undo_last_edit as _tx_undo_last_edit,
)
from cosmos_mcp.core.guard import WorkspaceGuard, normalize_tier
from cosmos_mcp.core.patch import (
    WINDOW_DRIFT_LINES,
    OperationType,
    apply_line_range_edits_in_memory,
    apply_v4a_patch,
    compute_patched_bytes,
    make_compact_diff,
    parse_v4a_patch,
    patch_file as _patch_single_file,
)
from cosmos_mcp.core.path_heal import (
    check_object_literal_mapping_consistency,
    heal_and_resolve_path,
    is_link_or_junction,
)

MAX_IMAGE_FILE_BYTES = 50 * 1024 * 1024
MAX_PIL_IMAGE_BYTES = 340 * 1024
MAX_SMALL_LOSSLESS_PNG_BYTES = 160 * 1024
MAX_PIL_LONG_EDGE = 1440
MAX_DOC_EXTRACT_BYTES = 32 * 1024 * 1024

READONLY_DOC_EXTRACT_EXTS = frozenset({".docx", ".xlsx", ".pdf", ".pptx", ".ipynb"})
LEGACY_BINARY_OFFICE_EXTS = frozenset({".doc", ".xls", ".ppt"})
OLE2_MAGIC_PREFIX = b"\xd0\xcf\x11\xe0"

REDACTED_PLACEHOLDER_MARKERS: Tuple[str, ...] = (
    "[REDACTED_API_CREDENTIAL]",
    "[REDACTED_SECRET]",
    "[REDACTED_SECRET_BY_GUARD]",
    "[REDACTED_PRIVATE_KEY_BY_GUARD]",
    "[REDACTED_PRIVATE_KEY]",
    "[REDACTED_MCP_TOKEN]",
)

MANAGE_FILES_ACTIONS: Tuple[str, ...] = (
    "mkdir",
    "move",
    "rename",
    "copy",
    "trash",
    "restore",
    "undo",
    "list",
)


def _normalize_manage_files_action(action: str, default: str = "list") -> str:
    act = (action or default).strip().lower()
    if act in ("list_trash", "trash_list"):
        return "list"
    if act == "restore_trash":
        return "restore"
    return act


def _check_redacted_placeholder_writeback(
    fp: Path,
    orig_disk_text: str,
    candidate_text: str,
) -> Optional[Dict[str, Any]]:
    if not candidate_text:
        return None
    hit_markers = [
        m for m in REDACTED_PLACEHOLDER_MARKERS
        if m in candidate_text and m not in orig_disk_text
    ]
    if not hit_markers:
        return None
    joined = ", ".join(hit_markers)
    return {
        "ok": False,
        "error_code": "ERR_REDACTED_PLACEHOLDER_WRITEBACK",
        "blocked_by_guardrail": True,
        "redacted_placeholder_blocked": True,
        "redacted_markers": hit_markers,
        "path": str(fp),
        "error": (
            f"[REDACTED WRITEBACK BLOCKED]: Refusing to write redacted placeholder {joined} into `{fp.name}` "
            f"because the original file on disk does not contain that literal marker. "
            f"拒绝将脱敏占位符 {joined} 回写覆盖 `{fp.name}`，以免破坏磁盘原文件中的真实凭据。"
        ),
    }


def _build_legacy_office_error(fp: Path, ext: str) -> Dict[str, Any]:
    target_modern = {".doc": ".docx", ".xls": ".xlsx", ".ppt": ".pptx"}.get(ext, ".docx/.xlsx/.pptx")
    return {
        "ok": False,
        "path": str(fp),
        "is_binary": True,
        "is_legacy_office": True,
        "error_code": "ERR_LEGACY_BINARY_OFFICE",
        "detected_format": ext.lstrip(".") if ext in LEGACY_BINARY_OFFICE_EXTS else "ole2_cfbf",
        "error": (
            f"Legacy binary Office / OLE2 Compound Document `{fp.name}` cannot be decoded as plain text "
            f"(检测到旧版二进制 Office / OLE2 复合文档 `{fp.name}`，无法直接按普通文本解码). "
            f"Please convert or re-save it as `{target_modern}` or `.pdf` before calling `read_file` "
            f"(请先将其转换为现代 OpenXML 格式 `{target_modern}` 或 `.pdf` 后再读取)."
        ),
    }

_BUILTIN_EXCEL_DATE_NUMFMT_IDS = frozenset(
    {
        14,
        15,
        16,
        17,
        22,
        27,
        28,
        29,
        30,
        31,
        36,
        50,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
    }
)

_DATA_URI_IMAGE_B64_RE = re.compile(
    r"(data:image/[A-Za-z0-9.+-]+;base64,)[A-Za-z0-9+/=\s]{64,}"
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _default_guard(guard: Optional[WorkspaceGuard]) -> WorkspaceGuard:
    return guard if guard is not None else WorkspaceGuard(restrict_to_workspace=False, tier="L3")


def _ws_roots_list(guard: Optional[WorkspaceGuard]) -> List[Path]:
    return [Path(r) for r in getattr(guard, "workspace_roots", ()) or []]


def _primary_ws_root(guard: WorkspaceGuard) -> Optional[Path]:
    roots = _ws_roots_list(guard)
    return roots[0] if roots else None


def _matching_ws_root(target: Optional[Union[str, Path]], guard: WorkspaceGuard) -> Optional[Path]:
    roots = _ws_roots_list(guard)
    if target is not None and str(target).strip():
        with contextlib.suppress(Exception):
            tp = Path(str(target)).expanduser().resolve()
            tp_full = os.path.normcase(str(tp))
            tp_norm = tp_full.rstrip("\\/")
            sep = "\\" if os.name == "nt" else "/"
            matches: List[Tuple[str, Path]] = []
            for r in roots:
                r_res = r.expanduser().resolve()
                r_norm = os.path.normcase(str(r_res)).rstrip("\\/")
                if tp_norm == r_norm or tp_full.startswith(r_norm + sep):
                    matches.append((r_norm, r_res))
            if matches:
                return max(matches, key=lambda item: len(item[0]))[1]
    return roots[0] if roots else None


def _with_office_lock_code(lk: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if lk is None:
        return None
    out = dict(lk)
    out.setdefault("error_code", "ERR_OFFICE_FILE_LOCKED")
    return out


_SIG_PARAM_CACHE: Dict[Any, frozenset[str]] = {}


def _call_with_ws_roots(
    fn: Any,
    *args: Any,
    guard: Optional[WorkspaceGuard] = None,
    target_path: Optional[Union[str, Path]] = None,
    scope_to_workspace: bool = True,
    **kwargs: Any,
) -> Any:
    params = _SIG_PARAM_CACHE.get(fn)
    if params is None:
        try:
            params = frozenset(inspect.signature(fn).parameters.keys())
        except Exception:
            params = frozenset()
        _SIG_PARAM_CACHE[fn] = params

    g = _default_guard(guard)
    sr = g.effective_state_root()
    roots = _ws_roots_list(g) if scope_to_workspace else []
    matched_root = _matching_ws_root(target_path, g) if scope_to_workspace else None

    call_kw = dict(kwargs)
    if "state_root" in params and "state_root" not in call_kw:
        call_kw["state_root"] = sr
    if "guard" in params and "guard" not in call_kw:
        call_kw["guard"] = g
    if "workspace_roots" in params and roots:
        call_kw.setdefault("workspace_roots", roots)
    if "workspace_root" in params and "workspace_root" not in call_kw:
        if "workspace_roots" in call_kw and target_path is None and len(roots) > 1:
            call_kw["workspace_root"] = None
        else:
            call_kw["workspace_root"] = matched_root
    if "undo_dir" in params and "undo_dir" not in call_kw and "state_root" not in params:
        call_kw["undo_dir"] = resolve_undo_dir(
            target_path,
            workspace_root=matched_root,
            workspace_roots=roots,
            state_root=sr,
            guard=g,
        )
    return fn(*args, **call_kw)


def save_undo_snapshot(
    path: Union[Path, str],
    *,
    guard: Optional[WorkspaceGuard] = None,
    clear_redo: bool = True,
) -> Optional[Path]:
    """Save a pre-edit snapshot in `<state_root>/history/<workspace_hash>` honoring multi-root `workspace_roots`."""
    g = _default_guard(guard)
    return _call_with_ws_roots(
        _tx_save_undo_snapshot,
        path,
        guard=g,
        target_path=path,
        clear_redo=clear_redo,
    )


# ---------------------------------------------------------------------------
# 1. Pure-Stdlib PNG Encoder + Pillow Image Resize/Compression (`<=1440px`, `<=340KiB` JPEG)
# ---------------------------------------------------------------------------

def encode_rgb_png_stdlib(width: int, height: int, rgb_bytes: bytes) -> bytes:
    """Encode raw 24-bit RGB scanlines into a valid PNG image using only Python stdlib (`struct` + `zlib`)."""
    io_enc = getattr(_core_fs_io, "encode_rgb_png_stdlib", None)
    if callable(io_enc):
        return io_enc(width, height, rgb_bytes)
    w, h = int(width), int(height)
    stride = w * 3
    if len(rgb_bytes) != stride * h:
        raise ValueError(f"Expected {stride * h} RGB bytes for {w}x{h}, got {len(rgb_bytes)}")

    raw_rows = bytearray()
    for row_idx in range(h):
        raw_rows.append(0)
        off = row_idx * stride
        raw_rows.extend(rgb_bytes[off : off + stride])

    def _chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), level=6)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _try_bmp_to_png_stdlib(raw_bmp: bytes) -> Optional[Tuple[bytes, int, int]]:
    """Convert uncompressed 24-bit or 32-bit BMP bytes into compact stdlib PNG when Pillow is absent."""
    if len(raw_bmp) < 54 or raw_bmp[:2] != b"BM":
        return None
    pixel_offset = struct.unpack("<I", raw_bmp[10:14])[0]
    dib_size = struct.unpack("<I", raw_bmp[14:18])[0]
    if dib_size < 40:
        return None
    width, raw_height = struct.unpack("<ii", raw_bmp[18:26])
    bpp = struct.unpack("<H", raw_bmp[28:30])[0]
    compression = struct.unpack("<I", raw_bmp[30:34])[0]
    if width <= 0 or raw_height == 0 or compression != 0 or bpp not in (24, 32):
        return None

    top_down = raw_height < 0
    height = abs(raw_height)
    bytes_pp = bpp // 8
    row_stride = ((width * bytes_pp + 3) // 4) * 4
    if pixel_offset + row_stride * height > len(raw_bmp):
        return None

    rgb_out = bytearray(width * height * 3)
    for out_y in range(height):
        src_y = out_y if top_down else (height - 1 - out_y)
        src_row = pixel_offset + src_y * row_stride
        dst_row = out_y * width * 3
        for x in range(width):
            px_off = src_row + x * bytes_pp
            b_v, g_v, r_v = raw_bmp[px_off], raw_bmp[px_off + 1], raw_bmp[px_off + 2]
            dst_px = dst_row + x * 3
            rgb_out[dst_px] = r_v
            rgb_out[dst_px + 1] = g_v
            rgb_out[dst_px + 2] = b_v
    return encode_rgb_png_stdlib(width, height, bytes(rgb_out)), width, height


def read_image_as_mcp_blocks(
    file_path: Path,
    *,
    use_pillow: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """
    Read a local image and return standard MCP `[TextContent-dict, ImageContent-dict]`:
    - Small PNG (`<= 340 KiB` and `<= 1440px`): lossless raw PNG passthrough.
    - With Pillow: auto-transpose EXIF, resize long edge `<=1440px`, compress to `<=340KiB` JPEG.
    - Without Pillow: convert uncompressed BMP via stdlib PNG encoder or return verified raw bytes.
    """
    st_size = file_path.stat().st_size
    if st_size > MAX_IMAGE_FILE_BYTES:
        raise ValueError(f"Image file `{file_path.name}` exceeds 50 MiB limit ({st_size} bytes).")
    with file_path.open("rb") as fh:
        head = fh.read(32)
    magic_mime = detect_image_magic(head)
    if magic_mime is None:
        raise ValueError(
            f"Invalid image header for `{file_path.name}`: expected PNG/JPEG/GIF/WebP/BMP magic bytes."
        )

    pil_available = False
    if use_pillow is not False:
        try:
            from PIL import Image, ImageOps  # type: ignore

            pil_available = True
        except ImportError:
            pil_available = False

    # Lossless raw PNG passthrough when `<= 160 KiB` (up to 8192px flat UI/monitoring images)
    # or `<= 340 KiB` with dimensions `<= 1440px`
    if magic_mime == "image/png" and st_size <= MAX_PIL_IMAGE_BYTES:
        raw_png_bytes = file_path.read_bytes()
        png_w, png_h = parse_image_dimensions_stdlib(raw_png_bytes, "image/png")
        if (png_w <= 0 or png_h <= 0) and pil_available:
            from PIL import Image  # type: ignore

            with Image.open(io.BytesIO(raw_png_bytes)) as src_png:
                png_w, png_h = int(src_png.width), int(src_png.height)
        is_small_flat_png = (
            0 < png_w <= 8192
            and 0 < png_h <= 8192
            and len(raw_png_bytes) <= MAX_SMALL_LOSSLESS_PNG_BYTES
        )
        is_medium_bounded_png = (
            0 < png_w <= MAX_PIL_LONG_EDGE
            and 0 < png_h <= MAX_PIL_LONG_EDGE
            and len(raw_png_bytes) <= MAX_PIL_IMAGE_BYTES
        )
        if is_small_flat_png or is_medium_bounded_png:
            sha_png = hashlib.sha256(raw_png_bytes).hexdigest().lower()
            b64_png = base64.b64encode(raw_png_bytes).decode("ascii")
            meta_png: Dict[str, Any] = {
                "ok": True,
                "path": str(file_path),
                "is_image": True,
                "encoder": "png_lossless_passthrough",
                "compression_mode": "png_lossless_passthrough",
                "resized": False,
                "mime_type": "image/png",
                "source_mime_type": "image/png",
                "uri": "file:///localpc_capture_1.png",
                "width": int(png_w),
                "height": int(png_h),
                "byte_size": len(raw_png_bytes),
                "source_byte_size": len(raw_png_bytes),
                "sha256": sha_png,
                "sha256_prefix": sha_png[:12],
            }
            return [
                {"type": "text", "text": json.dumps(meta_png, ensure_ascii=False)},
                {"type": "image", "data": b64_png, "mimeType": "image/png"},
            ]

    if pil_available:
        from PIL import Image, ImageOps  # type: ignore

        raw_bytes = file_path.read_bytes()
        sha = hashlib.sha256(raw_bytes).hexdigest().lower()
        with Image.open(io.BytesIO(raw_bytes)) as src_im:
            if getattr(src_im, "is_animated", False):
                with contextlib.suppress(Exception):
                    src_im.seek(0)
            try:
                im = ImageOps.exif_transpose(src_im)
            except Exception:
                im = src_im.copy()
            if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
                rgba = im.convert("RGBA")
                canvas = Image.new("RGB", rgba.size, (255, 255, 255))
                canvas.paste(rgba, mask=rgba.split()[3])
                im = canvas
            elif im.mode != "RGB":
                im = im.convert("RGB")

            resample_lanczos = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
            if max(im.size) > MAX_PIL_LONG_EDGE:
                scale = float(MAX_PIL_LONG_EDGE) / float(max(im.size))
                nw = max(1, int(round(im.width * scale)))
                nh = max(1, int(round(im.height * scale)))
                im = im.resize((nw, nh), resample=resample_lanczos)

            png_cand_bytes: Optional[bytes] = None
            if magic_mime == "image/png":
                buf_png = io.BytesIO()
                im.save(buf_png, format="PNG", optimize=True)
                cand_v = buf_png.getvalue()
                if len(cand_v) <= MAX_PIL_IMAGE_BYTES:
                    png_cand_bytes = cand_v

            img_bytes = b""
            for quality in (86, 78, 70, 62, 54, 46, 38, 30):
                buf = io.BytesIO()
                im.save(buf, format="JPEG", quality=quality, optimize=True)
                img_bytes = buf.getvalue()
                if len(img_bytes) <= MAX_PIL_IMAGE_BYTES:
                    break
            while len(img_bytes) > MAX_PIL_IMAGE_BYTES and max(im.size) > 160:
                nw = max(1, int(round(im.width * 0.82)))
                nh = max(1, int(round(im.height * 0.82)))
                im = im.resize((nw, nh), resample=resample_lanczos)
                buf = io.BytesIO()
                im.save(buf, format="JPEG", quality=38, optimize=True)
                img_bytes = buf.getvalue()

            out_mime = "image/jpeg"
            encoder_name = "pillow_jpeg"
            if png_cand_bytes is not None and len(png_cand_bytes) <= len(img_bytes):
                img_bytes = png_cand_bytes
                out_mime = "image/png"
                encoder_name = "pillow_png"

            w, h = int(im.width), int(im.height)
            b64_data = base64.b64encode(img_bytes).decode("ascii")
            meta: Dict[str, Any] = {
                "ok": True,
                "path": str(file_path),
                "is_image": True,
                "encoder": encoder_name,
                "mime_type": out_mime,
                "source_mime_type": magic_mime,
                "width": w,
                "height": h,
                "byte_size": len(img_bytes),
                "source_byte_size": len(raw_bytes),
                "sha256": sha,
                "sha256_prefix": sha[:12],
            }
            return [
                {"type": "text", "text": json.dumps(meta, ensure_ascii=False)},
                {"type": "image", "data": b64_data, "mimeType": out_mime},
            ]

    # Pure-stdlib fallback (no Pillow)
    raw_bytes = file_path.read_bytes()
    sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    if magic_mime == "image/bmp":
        conv = _try_bmp_to_png_stdlib(raw_bytes)
        if conv is not None:
            png_bytes, w, h = conv
            if len(png_bytes) <= MAX_DEFAULT_READ_BYTES:
                meta_bmp: Dict[str, Any] = {
                    "ok": True,
                    "path": str(file_path),
                    "is_image": True,
                    "encoder": "stdlib_png",
                    "mime_type": "image/png",
                    "source_mime_type": "image/bmp",
                    "width": w,
                    "height": h,
                    "byte_size": len(png_bytes),
                    "source_byte_size": len(raw_bytes),
                    "sha256": sha,
                    "sha256_prefix": sha[:12],
                }
                return [
                    {"type": "text", "text": json.dumps(meta_bmp, ensure_ascii=False)},
                    {"type": "image", "data": base64.b64encode(png_bytes).decode("ascii"), "mimeType": "image/png"},
                ]

    fallback = _io_read_local_image_payload(file_path, max_raw_bytes=MAX_DEFAULT_READ_BYTES)
    meta_fb = dict(fallback["meta"])
    meta_fb["encoder"] = "stdlib_raw"
    return [
        {"type": "text", "text": json.dumps(meta_fb, ensure_ascii=False)},
        {"type": "image", "data": fallback["b64_data"], "mimeType": fallback["mime"]},
    ]


# ---------------------------------------------------------------------------
# 2. Read-Only Office (`.docx`, `.xlsx`, `.pptx`), `.ipynb` & `.pdf` Plain-Text Extraction
# ---------------------------------------------------------------------------

def _local_xml_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def extract_docx_text_stdlib(file_path: Path) -> List[str]:
    """Extract readable paragraphs and tables from `.docx` via Python stdlib `zipfile` + `ElementTree`."""
    lines: List[str] = []
    with zipfile.ZipFile(file_path, "r") as zf:
        names = set(zf.namelist())
        part_order = [n for n in sorted(names) if re.fullmatch(r"word/header\d*\.xml", n)]
        if "word/document.xml" in names:
            part_order.append("word/document.xml")
        part_order.extend(n for n in sorted(names) if re.fullmatch(r"word/footer\d*\.xml", n))

        for part in part_order:
            root = ET.fromstring(zf.read(part))
            body = next((el for el in root.iter() if _local_xml_tag(el.tag) == "body"), root)
            for child in list(body):
                ctag = _local_xml_tag(child.tag)
                if ctag == "p":
                    chunks: List[str] = []
                    for node in child.iter():
                        ntag = _local_xml_tag(node.tag)
                        if ntag == "t" and node.text:
                            chunks.append(node.text)
                        elif ntag == "tab":
                            chunks.append("\t")
                        elif ntag in ("br", "cr"):
                            chunks.append("\n")
                    para = "".join(chunks).strip("\r\n")
                    if para:
                        lines.extend(para.splitlines())
                elif ctag == "tbl":
                    for tr in child.iter():
                        if _local_xml_tag(tr.tag) != "tr":
                            continue
                        row_cells: List[str] = []
                        for tc in list(tr):
                            if _local_xml_tag(tc.tag) != "tc":
                                continue
                            cell_txt = "".join(
                                (n.text or "") for n in tc.iter() if _local_xml_tag(n.tag) == "t"
                            ).strip()
                            row_cells.append(cell_txt)
                        if any(row_cells):
                            lines.append(" | ".join(row_cells))
    return lines


def _col_letters_to_index(cell_ref: str) -> int:
    m = re.match(r"^([A-Za-z]+)", cell_ref or "")
    if not m:
        return -1
    idx = 0
    for ch in m.group(1).upper():
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def _is_excel_date_format_code(fmt_code: str) -> bool:
    if not fmt_code:
        return False
    primary = fmt_code.split(";", 1)[0]
    cleaned = re.sub(r'"[^"]*"|\\.|\[[^\]]*\]', "", primary).strip().lower()
    if not cleaned or "general" in cleaned:
        return False
    if any(ch in cleaned for ch in ("0", "#", "?", "@")):
        return False
    return bool(re.search(r"[yd]", cleaned))


def _parse_xlsx_date_styles(zf: zipfile.ZipFile, names: set[str]) -> List[bool]:
    if "xl/styles.xml" not in names:
        return []
    try:
        st_root = ET.fromstring(zf.read("xl/styles.xml"))
    except Exception:
        return []

    custom_date_ids: set[int] = set()
    for el in st_root.iter():
        if _local_xml_tag(el.tag) == "numFmts":
            for nf in list(el):
                if _local_xml_tag(nf.tag) != "numFmt":
                    continue
                raw_id = nf.attrib.get("numFmtId", "")
                fcode = nf.attrib.get("formatCode", "")
                if raw_id.isdigit() and _is_excel_date_format_code(fcode):
                    custom_date_ids.add(int(raw_id))

    xf_date_flags: List[bool] = []
    for el in st_root.iter():
        if _local_xml_tag(el.tag) == "cellXfs":
            for xf in list(el):
                if _local_xml_tag(xf.tag) != "xf":
                    continue
                raw_nf = xf.attrib.get("numFmtId", "0")
                nf_id = int(raw_nf) if raw_nf.isdigit() else -1
                xf_date_flags.append(nf_id in _BUILTIN_EXCEL_DATE_NUMFMT_IDS or nf_id in custom_date_ids)
            break
    return xf_date_flags


def _excel_serial_to_iso_date(raw_v: str, *, date1904: bool = False) -> Optional[str]:
    try:
        serial = float(raw_v)
    except (TypeError, ValueError):
        return None
    if not (1.0 <= serial <= 2958465.999999):
        return None
    days = int(serial)
    frac = serial - float(days)
    if abs(frac - 1.0) < 1e-6:
        days += 1
        frac = 0.0
    try:
        if date1904:
            dt = date(1904, 1, 1) + timedelta(days=days)
            d_str = dt.strftime("%Y-%m-%d")
        elif days == 60:
            d_str = "1900-02-29"
        elif days < 60:
            dt = date(1899, 12, 31) + timedelta(days=days)
            d_str = dt.strftime("%Y-%m-%d")
        else:
            dt = date(1899, 12, 30) + timedelta(days=days)
            d_str = dt.strftime("%Y-%m-%d")
    except OverflowError:
        return None

    if frac >= 1.0 / 86400.0:
        total_sec = int(round(frac * 86400.0)) % 86400
        hh, rem = divmod(total_sec, 3600)
        mm, ss = divmod(rem, 60)
        if hh or mm or ss:
            return f"{d_str} {hh:02d}:{mm:02d}:{ss:02d}"
    return d_str


def extract_xlsx_text_stdlib(file_path: Path) -> List[str]:
    """
    Extract sheet names, cell values, `YYYY-MM-DD` date serials, and uncached `=<formula>` expressions
    from `.xlsx` via Python stdlib `zipfile` + `ElementTree`.
    """
    lines: List[str] = []
    with zipfile.ZipFile(file_path, "r") as zf:
        names = set(zf.namelist())
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in names:
            ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in ss_root.iter():
                if _local_xml_tag(si.tag) == "si":
                    txt = "".join((t.text or "") for t in si.iter() if _local_xml_tag(t.tag) == "t")
                    shared_strings.append(txt)

        xf_is_date = _parse_xlsx_date_styles(zf, names)

        rels_map: Dict[str, str] = {}
        if "xl/_rels/workbook.xml.rels" in names:
            rel_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
            for rel in rel_root.iter():
                if _local_xml_tag(rel.tag) == "Relationship":
                    rid = rel.attrib.get("Id", "")
                    tgt = rel.attrib.get("Target", "").lstrip("/")
                    if rid and tgt:
                        rels_map[rid] = tgt if tgt.startswith("xl/") else f"xl/{tgt}"

        date1904 = False
        sheet_specs: List[Tuple[str, str]] = []
        if "xl/workbook.xml" in names:
            wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
            for el in wb_root.iter():
                ltag = _local_xml_tag(el.tag)
                if ltag == "workbookPr":
                    d1904 = str(el.attrib.get("date1904", "")).strip().lower()
                    if d1904 in ("1", "true"):
                        date1904 = True
                elif ltag == "sheet":
                    sname = el.attrib.get("name", "Sheet")
                    rid = ""
                    for ak, av in el.attrib.items():
                        if _local_xml_tag(ak) == "id":
                            rid = av
                            break
                    target_xml = rels_map.get(rid, "")
                    if target_xml in names:
                        sheet_specs.append((sname, target_xml))

        if not sheet_specs:
            for nm in sorted(names):
                if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", nm):
                    sheet_specs.append((Path(nm).stem, nm))

        for sname, sxml in sheet_specs:
            lines.append(f"[Sheet: {sname}]")
            sh_root = ET.fromstring(zf.read(sxml))
            shared_formulas: Dict[str, str] = {}
            for row_idx_fallback, row_el in enumerate(
                (el for el in sh_root.iter() if _local_xml_tag(el.tag) == "row"), start=1
            ):
                row_num_str = str(row_el.attrib.get("r") or row_idx_fallback).strip()
                vals: List[str] = []
                for c_pos, c_el in enumerate(list(row_el)):
                    if _local_xml_tag(c_el.tag) != "c":
                        continue
                    cell_ref = str(c_el.attrib.get("r") or "").strip().upper()
                    if not cell_ref:
                        cell_ref = f"{_index_to_col_letters(c_pos)}{row_num_str}"
                    ctype = c_el.attrib.get("t", "")
                    s_attr = c_el.attrib.get("s", "")
                    s_idx_style = int(s_attr) if s_attr.isdigit() else -1

                    f_el = next((ch for ch in list(c_el) if _local_xml_tag(ch.tag) == "f"), None)
                    v_el = next((ch for ch in list(c_el) if _local_xml_tag(ch.tag) == "v"), None)

                    formula_txt = ""
                    if f_el is not None:
                        formula_txt = (f_el.text or "").strip()
                        si_key = f_el.attrib.get("si", "")
                        if formula_txt and si_key:
                            shared_formulas[si_key] = formula_txt
                        elif not formula_txt and si_key and si_key in shared_formulas:
                            formula_txt = shared_formulas[si_key]

                    cell_val = ""
                    if ctype == "inlineStr":
                        cell_val = "".join((t.text or "") for t in c_el.iter() if _local_xml_tag(t.tag) == "t")
                    else:
                        raw_v = (v_el.text or "").strip() if v_el is not None else ""
                        if not raw_v and formula_txt:
                            cell_val = formula_txt if formula_txt.startswith("=") else f"={formula_txt}"
                        elif ctype == "s" and raw_v.isdigit():
                            ss_i = int(raw_v)
                            cell_val = shared_strings[ss_i] if 0 <= ss_i < len(shared_strings) else raw_v
                        elif ctype == "d" and raw_v:
                            cell_val = raw_v[:10] if raw_v.endswith("T00:00:00") else raw_v
                        elif ctype in ("", "n") and raw_v and 0 <= s_idx_style < len(xf_is_date) and xf_is_date[s_idx_style]:
                            iso_d = _excel_serial_to_iso_date(raw_v, date1904=date1904)
                            cell_val = iso_d if iso_d is not None else raw_v
                        else:
                            cell_val = raw_v
                    clean_val = cell_val.strip()
                    if clean_val:
                        vals.append(f"{cell_ref}: {clean_val}")
                if vals:
                    lines.append(" | ".join(vals))
    return lines


def _index_to_col_letters(col_idx0: int) -> str:
    n = int(col_idx0) + 1
    if n <= 0:
        return "A"
    chars: List[str] = []
    while n > 0:
        n, rem = divmod(n - 1, 26)
        chars.append(chr(ord("A") + rem))
    return "".join(reversed(chars))


def _format_openpyxl_cell_value(val: Any, *, number_format: str = "", date1904: bool = False) -> str:
    if val is None:
        return ""
    if isinstance(val, datetime):
        if val.hour == 0 and val.minute == 0 and val.second == 0 and val.microsecond == 0:
            return val.strftime("%Y-%m-%d")
        return val.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(val, date):
        return val.strftime("%Y-%m-%d")
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"
    if isinstance(val, (int, float)) and number_format and _is_excel_date_format_code(number_format):
        iso_d = _excel_serial_to_iso_date(str(val), date1904=date1904)
        if iso_d is not None:
            return iso_d
    return str(val)


def extract_xlsx_lines(file_path: Path) -> List[str]:
    """Extract per-sheet `Coord: Value` lines from `.xlsx` via lazy `openpyxl`, falling back to `extract_xlsx_text_stdlib`."""
    try:
        openpyxl = importlib.import_module("openpyxl")
        wb = openpyxl.load_workbook(filename=str(file_path), read_only=True, data_only=False)
        try:
            date1904 = bool(getattr(getattr(wb, "epoch", None), "year", 1899) == 1904)
            lines: List[str] = []
            for ws in wb.worksheets:
                lines.append(f"[Sheet: {ws.title}]")
                for row_idx, row in enumerate(ws.iter_rows(values_only=False), start=1):
                    row_entries: List[str] = []
                    for col_idx, cell in enumerate(row, start=1):
                        raw_v = getattr(cell, "value", None)
                        if raw_v is None:
                            continue
                        num_fmt = str(getattr(cell, "number_format", "") or "")
                        val_s = _format_openpyxl_cell_value(raw_v, number_format=num_fmt, date1904=date1904).strip()
                        if not val_s:
                            continue
                        coord = str(getattr(cell, "coordinate", "") or "").strip()
                        if not coord:
                            coord = f"{_index_to_col_letters(col_idx - 1)}{row_idx}"
                        row_entries.append(f"{coord}: {val_s}")
                    if row_entries:
                        lines.append(" | ".join(row_entries))
            return lines
        finally:
            with contextlib.suppress(Exception):
                wb.close()
    except Exception:
        return extract_xlsx_text_stdlib(file_path)


def _extract_pptx_element_lines(el: ET.Element, out: List[str]) -> None:
    ltag = _local_xml_tag(el.tag)
    if ltag == "tbl":
        for child_tr in list(el):
            if _local_xml_tag(child_tr.tag) != "tr":
                continue
            row_cells: List[str] = []
            for tc in list(child_tr):
                if _local_xml_tag(tc.tag) != "tc":
                    continue
                tc_txt = "".join(
                    (n.text or "") for n in tc.iter() if _local_xml_tag(n.tag) == "t"
                ).strip()
                row_cells.append(tc_txt)
            if any(row_cells):
                out.append(" | ".join(row_cells))
        return

    if ltag == "txBody":
        for p_el in list(el):
            if _local_xml_tag(p_el.tag) != "p":
                continue
            chunks: List[str] = []
            for node in p_el.iter():
                ntag = _local_xml_tag(node.tag)
                if ntag == "t" and node.text:
                    chunks.append(node.text)
                elif ntag == "tab":
                    chunks.append("\t")
                elif ntag == "br":
                    chunks.append("\n")
            para = "".join(chunks).strip("\r\n")
            if para:
                out.extend(ln.strip() for ln in para.splitlines() if ln.strip())
        return

    for ch in list(el):
        _extract_pptx_element_lines(ch, out)


def extract_pptx_text_stdlib(file_path: Path) -> List[str]:
    """Extract per-slide text and tables from `.pptx` via Python stdlib `zipfile` + `ElementTree`."""
    lines: List[str] = []
    with zipfile.ZipFile(file_path, "r") as zf:
        names = set(zf.namelist())
        rels_map: Dict[str, str] = {}
        if "ppt/_rels/presentation.xml.rels" in names:
            rel_root = ET.fromstring(zf.read("ppt/_rels/presentation.xml.rels"))
            for rel in rel_root.iter():
                if _local_xml_tag(rel.tag) == "Relationship":
                    rid = rel.attrib.get("Id", "")
                    tgt = rel.attrib.get("Target", "").lstrip("/")
                    if rid and tgt:
                        norm_tgt = tgt if tgt.startswith("ppt/") else f"ppt/{tgt}"
                        rels_map[rid] = os.path.normpath(norm_tgt).replace("\\", "/")

        ordered_slides: List[str] = []
        if "ppt/presentation.xml" in names and rels_map:
            pres_root = ET.fromstring(zf.read("ppt/presentation.xml"))
            for el in pres_root.iter():
                if _local_xml_tag(el.tag) == "sldId":
                    rid = ""
                    for ak, av in el.attrib.items():
                        if _local_xml_tag(ak) == "id":
                            rid = av
                            break
                    s_xml = rels_map.get(rid, "")
                    if s_xml in names and s_xml not in ordered_slides:
                        ordered_slides.append(s_xml)

        if not ordered_slides:
            numbered: List[Tuple[int, str]] = []
            for nm in names:
                m = re.fullmatch(r"ppt/slides/slide(\d+)\.xml", nm)
                if m:
                    numbered.append((int(m.group(1)), nm))
            numbered.sort(key=lambda item: item[0])
            ordered_slides = [nm for _, nm in numbered]

        for slide_idx, slide_xml in enumerate(ordered_slides, start=1):
            lines.append(f"[Slide {slide_idx}]")
            s_root = ET.fromstring(zf.read(slide_xml))
            slide_lines: List[str] = []
            _extract_pptx_element_lines(s_root, slide_lines)
            lines.extend(slide_lines)
    return lines


def _join_ipynb_lines(val: Any) -> str:
    if isinstance(val, list):
        return "".join(str(x) for x in val)
    if isinstance(val, str):
        return val
    return ""


def _strip_inline_b64_images(text: str) -> str:
    return _DATA_URI_IMAGE_B64_RE.sub(r"\1<base64_image_omitted>", text)


def extract_ipynb_text_stdlib(file_path: Path) -> List[str]:
    """
    Extract per-cell source code, markdown, and concise text/error outputs from `.ipynb`
    while stripping embedded Base64 image blobs and binary attachments.
    """
    raw_bytes = file_path.read_bytes()
    raw_txt, _ = detect_and_decode_bytes(raw_bytes, strict_for_edit=False)
    nb = json.loads(raw_txt.removeprefix("\ufeff"))
    if not isinstance(nb, dict):
        raise ValueError("Invalid Jupyter notebook JSON root (expected object).")

    cells = nb.get("cells")
    if not isinstance(cells, list):
        worksheets = nb.get("worksheets")
        if isinstance(worksheets, list) and worksheets and isinstance(worksheets[0], dict):
            cells = worksheets[0].get("cells")
    if not isinstance(cells, list):
        return []

    lines: List[str] = []
    image_mimes = ("image/png", "image/jpeg", "image/webp", "image/gif", "image/bmp", "image/svg+xml")

    for idx, cell in enumerate(cells, start=1):
        if not isinstance(cell, dict):
            continue
        ctype = str(cell.get("cell_type") or "code").strip().lower()
        if ctype == "code":
            exec_n = cell.get("execution_count")
            exec_label = str(exec_n) if exec_n is not None else " "
            lines.append(f"[Cell {idx} | code | In[{exec_label}]]")
        else:
            lines.append(f"[Cell {idx} | {ctype}]")

        src_raw = _strip_inline_b64_images(_join_ipynb_lines(cell.get("source")))
        for s_ln in src_raw.splitlines():
            lines.append(s_ln.rstrip("\r"))

        attachments = cell.get("attachments")
        if isinstance(attachments, dict) and attachments:
            lines.append(f"[Attachments: {len(attachments)} embedded attachment(s) omitted]")

        if ctype != "code":
            continue

        outputs = cell.get("outputs")
        if not isinstance(outputs, list) or not outputs:
            continue

        for out_item in outputs:
            if not isinstance(out_item, dict):
                continue
            otype = str(out_item.get("output_type") or "").strip()
            if otype == "stream":
                sname = str(out_item.get("name") or "stdout")
                stxt = _strip_inline_b64_images(_join_ipynb_lines(out_item.get("text"))).rstrip("\r\n")
                if stxt:
                    s_lines = stxt.splitlines()
                    lines.append(f"[Output:{sname}]")
                    for o_ln in s_lines[:120]:
                        lines.append(_ANSI_ESCAPE_RE.sub("", o_ln))
                    if len(s_lines) > 120:
                        lines.append(f"... ({len(s_lines) - 120} more stream lines omitted)")
            elif otype in ("execute_result", "display_data"):
                data_d = out_item.get("data")
                if not isinstance(data_d, dict):
                    continue
                omitted_imgs = [m for m in image_mimes if m in data_d]
                for im_m in omitted_imgs:
                    lines.append(f"[Output:image ({im_m} base64 omitted)]")
                if "text/plain" in data_d:
                    ptxt = _strip_inline_b64_images(_join_ipynb_lines(data_d["text/plain"])).rstrip("\r\n")
                    if ptxt:
                        p_lines = ptxt.splitlines()
                        lines.append("[Output:text]")
                        for p_ln in p_lines[:120]:
                            lines.append(p_ln)
                        if len(p_lines) > 120:
                            lines.append(f"... ({len(p_lines) - 120} more output lines omitted)")
                elif "text/markdown" in data_d:
                    mtxt = _strip_inline_b64_images(_join_ipynb_lines(data_d["text/markdown"])).rstrip("\r\n")
                    if mtxt:
                        lines.append("[Output:markdown]")
                        lines.extend(mtxt.splitlines()[:120])
            elif otype == "error":
                ename = str(out_item.get("ename") or "Error")
                evalue = str(out_item.get("evalue") or "")
                lines.append(f"[Output:error] {ename}: {evalue}".rstrip())
                tb_list = out_item.get("traceback")
                if isinstance(tb_list, list) and tb_list:
                    cleaned_tb: List[str] = []
                    for tb_entry in tb_list[-8:]:
                        for tb_ln in str(tb_entry).splitlines():
                            clean_ln = _ANSI_ESCAPE_RE.sub("", tb_ln).rstrip()
                            if clean_ln:
                                cleaned_tb.append(clean_ln)
                    lines.extend(cleaned_tb[-16:])
    return lines


def _decode_pdf_literal_string(raw: bytes) -> str:
    out = bytearray()
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if b == 0x5C and i + 1 < n:
            nxt = raw[i + 1]
            esc_map = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12, ord("("): 40, ord(")"): 41, ord("\\"): 92}
            if nxt in esc_map:
                out.append(esc_map[nxt])
                i += 2
                continue
            if 48 <= nxt <= 55:
                oct_digits = bytes([nxt])
                j = i + 2
                while j < n and len(oct_digits) < 3 and 48 <= raw[j] <= 55:
                    oct_digits += bytes([raw[j]])
                    j += 1
                out.append(int(oct_digits, 8) & 0xFF)
                i = j
                continue
            if nxt in (10, 13):
                i += 2
                if nxt == 13 and i < n and raw[i] == 10:
                    i += 1
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(b)
        i += 1
    data = bytes(out)
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _decode_pdf_hex_string(hex_bytes: bytes) -> str:
    clean = re.sub(rb"\s+", b"", hex_bytes)
    if len(clean) % 2 == 1:
        clean += b"0"
    try:
        raw = bytes.fromhex(clean.decode("ascii"))
    except Exception:
        return ""
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


_PDF_UNDECODED_MARKERS: Tuple[str, ...] = (
    "/CIDFont",
    "/Identity-H",
    "/Identity-V",
    "/ToUnicode",
    "/FlateDecode",
    "endstream",
    "endobj",
)
_PDF_CID_RAW_MARKERS: Tuple[bytes, ...] = (
    b"/CIDFont",
    b"/Identity-H",
    b"/Identity-V",
    b"/ToUnicode",
)


def _is_readable_pdf_fallback_text(lines: Sequence[str], raw_pdf: bytes = b"") -> bool:
    """Validate via structural/binary invariants that stdlib PDF extraction yielded decoded plain text rather than CID/stream bytes."""
    joined = "\n".join(str(ln) for ln in lines if str(ln).strip()).strip()
    if not joined:
        return False
    if not any(not ch.isspace() for ch in joined):
        return False

    if raw_pdf and any(marker in raw_pdf for marker in _PDF_CID_RAW_MARKERS):
        return False

    if any(tok in joined for tok in _PDF_UNDECODED_MARKERS):
        return False

    for ch in joined:
        if ch in ("\t", "\n", "\r"):
            continue
        cp = ord(ch)
        if (
            ch == "\ufffd"
            or cp < 0x20
            or (0x7F <= cp <= 0x9F)
            or (0xE000 <= cp <= 0xF8FF)
            or (0xF0000 <= cp <= 0x10FFFD)
        ):
            return False

    return True


def extract_pdf_text_readonly(file_path: Path) -> List[str]:
    """Extract readable plain text from `.pdf` using `pypdf`, with strict readability-checked stdlib fallback for simple ASCII/UTF-8 PDFs."""
    pypdf_available = False
    pypdf_error: Optional[Exception] = None
    try:
        import pypdf  # type: ignore

        pypdf_available = True
        reader = pypdf.PdfReader(str(file_path))
        out_lines: List[str] = []
        for page_idx, page in enumerate(reader.pages, start=1):
            txt = (page.extract_text() or "").strip()
            if txt:
                out_lines.append(f"[Page {page_idx}]")
                out_lines.extend(ln.rstrip() for ln in txt.splitlines() if ln.strip())
        if out_lines:
            return out_lines
    except ImportError:
        pypdf_available = False
    except Exception as exc:
        pypdf_error = exc

    raw_pdf = file_path.read_bytes()
    stream_re = re.compile(rb"stream\r?\n([\s\S]*?)\r?\nendstream")
    bt_et_re = re.compile(rb"BT\b([\s\S]*?)\bET\b")
    token_re = re.compile(rb"\((?:\\.|[^\\()])*\)\s*(?:Tj|'|\")\s*|<([0-9A-Fa-f\s]+)>\s*Tj|\[([\s\S]*?)\]\s*TJ")
    sub_str_re = re.compile(rb"\(((?:\\.|[^\\()])*)\)|<([0-9A-Fa-f\s]+)>")

    extracted_lines: List[str] = []
    buffers: List[bytes] = []
    for sm in stream_re.finditer(raw_pdf):
        chunk = sm.group(1)
        decompressed: Optional[bytes] = None
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                decompressed = zlib.decompress(chunk, wbits)
                break
            except Exception:
                continue
        if decompressed is not None:
            buffers.append(decompressed)
        elif b"/Filter" not in raw_pdf[:4096] and b"/FlateDecode" not in raw_pdf:
            buffers.append(chunk)
    if not buffers and b"stream" not in raw_pdf:
        buffers.append(raw_pdf)

    for buf in buffers:
        if b"BT" not in buf:
            continue
        for bm in bt_et_re.finditer(buf):
            block = bm.group(1)
            line_parts: List[str] = []
            for tm in token_re.finditer(block):
                full_tok = tm.group(0)
                if tm.group(1) is not None:
                    line_parts.append(_decode_pdf_hex_string(tm.group(1)))
                elif tm.group(2) is not None:
                    arr_parts: List[str] = []
                    for sm2 in sub_str_re.finditer(tm.group(2)):
                        if sm2.group(1) is not None:
                            arr_parts.append(_decode_pdf_literal_string(sm2.group(1)))
                        elif sm2.group(2) is not None:
                            arr_parts.append(_decode_pdf_hex_string(sm2.group(2)))
                    line_parts.append("".join(arr_parts))
                else:
                    m_lit = re.match(rb"\(((?:\\.|[^\\()])*)\)", full_tok)
                    if m_lit:
                        line_parts.append(_decode_pdf_literal_string(m_lit.group(1)))
            joined = re.sub(r"[ \t]+", " ", "".join(line_parts)).strip()
            if joined:
                extracted_lines.extend(ln.strip() for ln in joined.splitlines() if ln.strip())

    if _is_readable_pdf_fallback_text(extracted_lines, raw_pdf=raw_pdf):
        return extracted_lines

    if not pypdf_available:
        raise RuntimeError(
            "Missing `pypdf` PDF parser library required to decode CIDFont/ToUnicode or compressed PDF text; "
            "install `pypdf>=5.0.0` (缺少 PDF 解析库 `pypdf`，无法提取可读正文，请安装 `pypdf>=5.0.0`)."
        )
    if pypdf_error is not None:
        raise pypdf_error
    return []


def extract_document_lines(file_path: Path) -> List[str]:
    """Dispatch read-only plain-text extraction across `.docx`, `.xlsx`, `.pptx`, `.ipynb`, and `.pdf`."""
    ext = file_path.suffix.lower()
    if ext == ".docx":
        return extract_docx_text_stdlib(file_path)
    if ext == ".xlsx":
        return extract_xlsx_lines(file_path)
    if ext == ".pptx":
        return extract_pptx_text_stdlib(file_path)
    if ext == ".ipynb":
        return extract_ipynb_text_stdlib(file_path)
    if ext == ".pdf":
        return extract_pdf_text_readonly(file_path)
    raise ValueError(f"Unsupported structured document format: {ext}")


def _read_office_or_pdf_summary(
    fp: Path,
    *,
    start_line: int,
    end_line: int,
    max_lines: int,
    include_line_numbers: bool,
    guard: WorkspaceGuard,
    healed_note: str = "",
) -> Dict[str, Any]:
    ext = fp.suffix.lower()
    st_size = fp.stat().st_size
    if st_size > MAX_DOC_EXTRACT_BYTES:
        return {
            "ok": False,
            "path": str(fp),
            "error": f"Document `{fp.name}` ({st_size} bytes) exceeds 32 MiB read-only text extraction limit.",
        }
    try:
        raw_bytes = fp.read_bytes()
    except OSError as exc:
        lk = check_office_or_os_file_lock(fp, exc=exc, for_write=False)
        if lk is not None:
            return lk
        return {"ok": False, "path": str(fp), "error": f"{type(exc).__name__}: {exc}"}

    if ext in LEGACY_BINARY_OFFICE_EXTS or (len(raw_bytes) >= 4 and raw_bytes[:4] == OLE2_MAGIC_PREFIX):
        return _build_legacy_office_error(fp, ext)

    sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    try:
        doc_lines = extract_document_lines(fp)
    except Exception as exc:
        return {
            "ok": False,
            "path": str(fp),
            "is_document_extract": True,
            "document_format": ext.lstrip("."),
            "error": f"Failed to extract plain text from `{fp.name}` ({type(exc).__name__}: {exc}).",
        }

    total_lines = len(doc_lines)
    eff_max = max(1, min(4000, int(max_lines or 800)))
    if int(start_line) < 0:
        tail_n = min(eff_max, abs(int(start_line)))
        s_ln = max(1, total_lines - tail_n + 1)
        e_ln = total_lines
    else:
        s_ln = max(1, int(start_line or 1))
        req_e = int(end_line or 0)
        e_ln = min(total_lines, req_e if req_e > 0 else (s_ln + eff_max - 1))

    sliced = doc_lines[s_ln - 1 : e_ln] if total_lines > 0 and s_ln <= total_lines else []
    if include_line_numbers:
        rendered = "\n".join(f"{s_ln + idx}| {guard.redact_sensitive_output(ln)}" for idx, ln in enumerate(sliced))
    else:
        rendered = "\n".join(guard.redact_sensitive_output(ln) for ln in sliced)

    truncated = e_ln < total_lines
    out: Dict[str, Any] = {
        "ok": True,
        "path": str(fp),
        "is_document_extract": True,
        "read_only_extract": True,
        "document_format": ext.lstrip("."),
        "start_line": s_ln if total_lines > 0 else 1,
        "end_line": e_ln if total_lines > 0 else 0,
        "total_lines": total_lines,
        "truncated": truncated,
        "sha256": sha,
        "sha256_prefix": sha[:12],
        "content": rendered,
    }
    if ext == ".pdf" and not any(str(ln).strip() for ln in doc_lines):
        out["is_scanned_or_empty_text"] = True
        out["warning"] = (
            "Extracted PDF text is empty: this PDF appears to be a scanned image document without an OCR text layer "
            "or an encrypted PDF without extractable text (提取到的 PDF 文本为空：该文件可能是扫描件图片无文本层或受加密保护，请使用 OCR 或页面图像渲染读取)."
        )
    if truncated:
        out["next_start_line"] = e_ln + 1
    if healed_note:
        out["healed_note"] = healed_note
    return out


# ---------------------------------------------------------------------------
# 3. `read_file`
# ---------------------------------------------------------------------------

def read_file(
    path: Union[Path, str],
    start_line: int = 1,
    end_line: int = 0,
    max_lines: int = 800,
    include_line_numbers: bool = True,
    symbol: str = "",
    *,
    guard: Optional[WorkspaceGuard] = None,
    use_pillow: Optional[bool] = None,
) -> Any:
    """
    Read text slices (`>2MiB` streaming, negative tail `start_line`, `symbol=` AST slice),
    local images (`[TextContent, ImageContent]` with small-PNG lossless passthrough, Pillow JPEG resize, or stdlib fallback),
    or `.docx`/`.xlsx`/`.pptx`/`.ipynb`/`.pdf` read-only plain-text summaries.
    """
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path), g, mode="read", must_exist=True, tool_name="read_file")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    fp: Path = r_info["path"]
    if fp.is_dir():
        return {"ok": False, "path": str(fp), "error": f"Path is a directory, not a file: {fp} (use list_dir or find_files)."}
    if is_link_or_junction(fp):
        return {"ok": False, "path": str(fp), "error": f"Refusing symlink or junction file: {fp}"}

    ext = fp.suffix.lower()
    healed_note = str(r_info.get("healed_note") or "")

    # 1) Multimodal Image Reading
    if ext in IMAGE_EXTENSIONS:
        try:
            return read_image_as_mcp_blocks(fp, use_pillow=use_pillow)
        except Exception as exc:
            return {"ok": False, "path": str(fp), "is_image": True, "error": str(exc)}

    # 1b) Legacy Binary Office (`.doc`/`.xls`/`.ppt`) or OLE2 CFBF Magic (`\xd0\xcf\x11\xe0`)
    if ext in LEGACY_BINARY_OFFICE_EXTS:
        return _build_legacy_office_error(fp, ext)
    try:
        with fp.open("rb") as _hdr_fh:
            _hdr_b = _hdr_fh.read(8)
    except OSError as exc:
        lk = check_office_or_os_file_lock(fp, exc=exc, for_write=False)
        if lk is not None:
            return lk
        return {"ok": False, "path": str(fp), "error": f"{type(exc).__name__}: {exc}"}
    if len(_hdr_b) >= 4 and _hdr_b[:4] == OLE2_MAGIC_PREFIX:
        return _build_legacy_office_error(fp, ext)

    # 2) Read-Only Office / Notebook / PDF Plain-Text Summary Extraction
    if ext in READONLY_DOC_EXTRACT_EXTS:
        return _read_office_or_pdf_summary(
            fp,
            start_line=start_line,
            end_line=end_line,
            max_lines=max_lines,
            include_line_numbers=include_line_numbers,
            guard=g,
            healed_note=healed_note,
        )

    eff_max_lines = max(1, min(4000, int(max_lines or 800)))
    st_size = fp.stat().st_size

    # 3) Symbol-Scoped Slice (`symbol="MyClass.method"`)
    sym_q = (symbol or "").strip()
    resolved_sym_meta: Optional[Dict[str, Any]] = None
    if sym_q:
        if st_size > MAX_DEFAULT_READ_BYTES:
            return {"ok": False, "path": str(fp), "error": "File exceeds 2 MiB; use `start_line` and `end_line` streaming slice."}
        raw_b = fp.read_bytes()
        full_txt, _ = detect_and_decode_bytes(raw_b, strict_for_edit=False)
        syms = extract_symbols_from_text(full_txt, str(fp))
        target_sym, cands = resolve_symbol_in_outline(syms, sym_q)
        if target_sym is None:
            return {
                "ok": False,
                "path": str(fp),
                "symbol": sym_q,
                "symbol_candidates": cands,
                "error": f"Symbol `{sym_q}` not found in `{fp.name}`.",
            }
        start_line = int(target_sym["line"])
        end_line = int(target_sym["end_line"])
        resolved_sym_meta = {
            "name": target_sym.get("qualname") or target_sym.get("name"),
            "kind": target_sym.get("kind"),
            "line": start_line,
            "end_line": end_line,
        }

    # 4) Negative `start_line` Streaming Tail Read (supports `>2MiB` logs)
    if int(start_line) < 0:
        tail_n = min(eff_max_lines, abs(int(start_line)))
        try:
            tail_lines_list, enc_tag, total_lines, sha = stream_read_text_window(fp, tail_count=tail_n)
        except ValueError as exc:
            return {"ok": False, "path": str(fp), "error": str(exc)}
        actual_start = max(1, total_lines - len(tail_lines_list) + 1) if tail_lines_list else 1
        actual_end = total_lines
        clean_lines = [ln.rstrip("\r\n") for ln in tail_lines_list]
        if include_line_numbers:
            rendered = "\n".join(f"{actual_start + i}| {g.redact_sensitive_output(ln)}" for i, ln in enumerate(clean_lines))
        else:
            rendered = "\n".join(g.redact_sensitive_output(ln) for ln in clean_lines)
        out_tail: Dict[str, Any] = {
            "ok": True,
            "path": str(fp),
            "encoding": enc_tag,
            "start_line": actual_start,
            "end_line": actual_end,
            "total_lines": total_lines,
            "truncated": actual_start > 1,
            "sha256": sha,
            "sha256_prefix": sha[:12],
            "content": rendered,
        }
        if healed_note:
            out_tail["healed_note"] = healed_note
        return out_tail

    # 5) `>2MiB` Streaming Line Slice (keep the full-file encoding decision)
    req_start = max(1, int(start_line or 1))
    req_end = int(end_line or 0)
    if st_size > MAX_DEFAULT_READ_BYTES:
        eff_end = req_end if req_end > 0 else (req_start + eff_max_lines - 1)
        if eff_end < req_start:
            return {"ok": False, "path": str(fp), "error": f"Invalid line range {req_start}..{eff_end}: end_line < start_line."}
        try:
            decoded_lines, enc_tag, total_lines, sha = stream_read_text_window(
                fp, start_line=req_start, end_line=eff_end
            )
        except ValueError as exc:
            return {"ok": False, "path": str(fp), "error": str(exc)}
        slice_lines = [ln.rstrip("\r\n") for ln in decoded_lines]
        actual_end = min(total_lines, req_start + len(slice_lines) - 1) if slice_lines else min(total_lines, req_start)
        if include_line_numbers:
            rendered = "\n".join(f"{req_start + i}| {g.redact_sensitive_output(ln)}" for i, ln in enumerate(slice_lines))
        else:
            rendered = "\n".join(g.redact_sensitive_output(ln) for ln in slice_lines)
        truncated = actual_end < total_lines
        out_big: Dict[str, Any] = {
            "ok": True,
            "path": str(fp),
            "encoding": enc_tag,
            "streamed_large_file": True,
            "start_line": req_start,
            "end_line": actual_end,
            "total_lines": total_lines,
            "total_bytes": st_size,
            "truncated": truncated,
            "sha256": sha,
            "sha256_prefix": sha[:12],
            "content": rendered,
        }
        if truncated:
            out_big["next_start_line"] = actual_end + 1
        if healed_note:
            out_big["healed_note"] = healed_note
        return out_big

    # 6) Standard `<=2MiB` Multi-Encoding Read
    try:
        raw_bytes = fp.read_bytes()
    except OSError as exc:
        lk = check_office_or_os_file_lock(fp, exc=exc, for_write=False)
        if lk is not None:
            return lk
        return {"ok": False, "path": str(fp), "error": f"{type(exc).__name__}: {exc}"}

    sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    text, enc_tag = detect_and_decode_bytes(raw_bytes, strict_for_edit=False)
    if enc_tag == "binary-fallback" and b"\x00" in raw_bytes[:4096]:
        return {
            "ok": False,
            "path": str(fp),
            "is_binary": True,
            "total_bytes": len(raw_bytes),
            "sha256": sha,
            "error": f"Refusing to dump binary file `{fp.name}` ({len(raw_bytes)} bytes) as text.",
        }

    all_lines = text.splitlines()
    total_lines = len(all_lines)
    if req_end > 0 and req_end < req_start:
        return {"ok": False, "path": str(fp), "error": f"Invalid line range {req_start}..{req_end}: end_line < start_line."}
    eff_end = min(total_lines, req_end if req_end > 0 else (req_start + eff_max_lines - 1))
    sliced = all_lines[req_start - 1 : eff_end] if total_lines > 0 and req_start <= total_lines else []

    if include_line_numbers:
        rendered = "\n".join(f"{req_start + i}| {g.redact_sensitive_output(ln)}" for i, ln in enumerate(sliced))
    else:
        rendered = "\n".join(g.redact_sensitive_output(ln) for ln in sliced)

    truncated = eff_end < total_lines
    out: Dict[str, Any] = {
        "ok": True,
        "path": str(fp),
        "encoding": enc_tag,
        "start_line": req_start if total_lines > 0 else 1,
        "end_line": eff_end if total_lines > 0 else 0,
        "total_lines": total_lines,
        "total_bytes": len(raw_bytes),
        "truncated": truncated,
        "sha256": sha,
        "sha256_prefix": sha[:12],
        "content": rendered,
    }
    if truncated:
        out["next_start_line"] = eff_end + 1
    if resolved_sym_meta is not None:
        out["resolved_symbol"] = resolved_sym_meta
    if healed_note:
        out["healed_note"] = healed_note
    return out


# ---------------------------------------------------------------------------
# 4. `write_file`
# ---------------------------------------------------------------------------

def write_file(
    path: Union[Path, str],
    content: str,
    mode: str = "overwrite",
    allow_shrink: bool = False,
    overwrite_unread: bool = False,
    expected_sha256: str = "",
    check_syntax: bool = True,
    overwrite: bool = True,
    _legacy_disallow_overwrite: bool = False,
    *,
    encoding: str = "",
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Write or append file content (including `encoding='base64'` binary decode or explicit text codecs),
    delegating encoding preservation, shrink guard (`allow_shrink`), externalized history snapshot,
    and staged syntax validation to `cosmos_mcp.core.fs_io.write_file`.
    """
    _ = overwrite_unread  # Consumed by `SessionSidebandTracker.before_call` and exposed in MCP Schema
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=False, tool_name="write_file")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}

    fp: Path = r_info["path"]
    if is_link_or_junction(fp):
        return {"ok": False, "blocked_by_guardrail": True, "path": str(fp), "error": f"Refusing to write through symlink or junction: {fp}"}

    eff_mode = (mode or "overwrite").strip().lower()
    if eff_mode not in ("overwrite", "append"):
        return {"ok": False, "path": str(fp), "error": f"Invalid mode `{mode}`: expected 'overwrite' or 'append'."}

    disallow_ov = bool(_legacy_disallow_overwrite) or (overwrite is False)
    existed_before = fp.exists() and fp.is_file()
    if disallow_ov and eff_mode == "overwrite" and existed_before:
        return {
            "ok": False,
            "overwrite_blocked": True,
            "path": str(fp),
            "error": f"[OVERWRITE BLOCKED]: Target file `{fp.name}` already exists and overwrite=False.",
        }

    eff_enc = (encoding or "").strip()
    is_b64 = eff_enc.lower() == "base64"
    old_preview_txt = ""
    if not is_b64 and existed_before and isinstance(content, str):
        has_redacted_marker = any(m in content for m in REDACTED_PLACEHOLDER_MARKERS)
        need_js_preview = (
            eff_mode == "overwrite"
            and fp.suffix.lower() in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
        )
        if has_redacted_marker or need_js_preview:
            try:
                if has_redacted_marker or fp.stat().st_size <= 512 * 1024:
                    old_preview_txt, _ = detect_and_decode_bytes(fp.read_bytes(), strict_for_edit=False)
            except OSError as exc:
                lk = check_office_or_os_file_lock(fp, exc=exc, for_write=True)
                if lk is not None:
                    return lk
                if has_redacted_marker:
                    return {"ok": False, "path": str(fp), "error": f"{type(exc).__name__}: {exc}"}
            except Exception:
                pass
            if has_redacted_marker:
                red_err = _check_redacted_placeholder_writeback(fp, old_preview_txt, content)
                if red_err is not None:
                    return red_err

    ws_root = _matching_ws_root(fp, g)
    res = _call_with_ws_roots(
        _io_write_file,
        fp,
        content,
        guard=g,
        target_path=fp,
        mode=eff_mode,
        encoding=eff_enc,
        allow_shrink=bool(allow_shrink),
        expected_sha256=expected_sha256,
        check_syntax=bool(check_syntax),
        save_snapshot=True,
        workspace_root=ws_root,
    )
    if res.get("ok"):
        if not is_b64:
            mapping_notices = check_object_literal_mapping_consistency(old_preview_txt, content, str(fp))
            if mapping_notices:
                res = dict(res)
                res["mapping_contract_notice"] = mapping_notices
        if r_info.get("healed_note"):
            res = dict(res)
            res["healed_note"] = r_info["healed_note"]
    return res


# ---------------------------------------------------------------------------
# 5. `edit_file`, `patch_file`, `edit_docx_text_stdlib` & `edit_xlsx_cells`
# ---------------------------------------------------------------------------

_XML_SPACE_QNAME = "{http://www.w3.org/XML/1998/namespace}space"
_DOCX_STD_NAMESPACES: Tuple[Tuple[str, str], ...] = (
    ("w", "http://schemas.openxmlformats.org/wordprocessingml/2006/main"),
    ("r", "http://schemas.openxmlformats.org/officeDocument/2006/relationships"),
    ("wp", "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"),
    ("a", "http://schemas.openxmlformats.org/drawingml/2006/main"),
    ("pic", "http://schemas.openxmlformats.org/drawingml/2006/picture"),
    ("mc", "http://schemas.openxmlformats.org/markup-compatibility/2006"),
    ("m", "http://schemas.openxmlformats.org/officeDocument/2006/math"),
    ("v", "urn:schemas-microsoft-com:vml"),
    ("o", "urn:schemas-microsoft-com:office:office"),
    ("w14", "http://schemas.microsoft.com/office/word/2010/wordml"),
    ("w15", "http://schemas.microsoft.com/office/word/2012/wordml"),
    ("wps", "http://schemas.microsoft.com/office/word/2010/wordprocessingShape"),
    ("wpg", "http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"),
    ("wpc", "http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"),
)
_XLSX_COORD_RE = re.compile(
    r"^(?:(?:'((?:''|[^'])+)'|([^!:\r\n]+))!)?\$?([A-Za-z]{1,3})\$?([1-9]\d{0,6})$"
)


def _register_xml_namespaces(xml_bytes: bytes) -> None:
    for pfx, uri in _DOCX_STD_NAMESPACES:
        ET.register_namespace(pfx, uri)
    with contextlib.suppress(Exception):
        for _ev, ns_pair in ET.iterparse(io.BytesIO(xml_bytes), events=("start-ns",)):
            pfx_raw, uri_raw = ns_pair
            if pfx_raw and pfx_raw.lower() not in ("xml", "xmlns") and uri_raw:
                ET.register_namespace(pfx_raw, uri_raw)


def _collect_docx_paragraph_atoms(
    p_el: ET.Element,
) -> Tuple[str, List[Tuple[ET.Element, ET.Element, ET.Element, int, int]], List[Tuple[ET.Element, ET.Element, int, int]]]:
    """Return `(concatenated_text, t_slots, br_tab_atoms)` for a single `<w:p>` without descending into nested `<w:p>`/`<w:tbl>`."""
    chars: List[str] = []
    cur_pos = 0
    t_slots: List[Tuple[ET.Element, ET.Element, ET.Element, int, int]] = []
    sep_atoms: List[Tuple[ET.Element, ET.Element, int, int]] = []

    def _walk_inline(container: ET.Element) -> None:
        nonlocal cur_pos
        for ch in list(container):
            ltag = _local_xml_tag(ch.tag)
            if ltag in ("p", "tbl", "pPr", "del", "moveFrom"):
                continue
            if ltag == "r":
                for r_ch in list(ch):
                    rltag = _local_xml_tag(r_ch.tag)
                    if rltag == "t":
                        txt = r_ch.text or ""
                        s_i = cur_pos
                        e_i = cur_pos + len(txt)
                        t_slots.append((container, ch, r_ch, s_i, e_i))
                        if txt:
                            chars.append(txt)
                        cur_pos = e_i
                    elif rltag == "tab":
                        sep_atoms.append((ch, r_ch, cur_pos, cur_pos + 1))
                        chars.append("\t")
                        cur_pos += 1
                    elif rltag in ("br", "cr"):
                        sep_atoms.append((ch, r_ch, cur_pos, cur_pos + 1))
                        chars.append("\n")
                        cur_pos += 1
            else:
                _walk_inline(ch)

    _walk_inline(p_el)
    return "".join(chars), t_slots, sep_atoms


def _extract_docx_lines_from_bytes(raw_bytes: bytes) -> List[str]:
    lines: List[str] = []
    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        names = set(zf.namelist())
        part_order = [n for n in sorted(names) if re.fullmatch(r"word/header\d*\.xml", n)]
        if "word/document.xml" in names:
            part_order.append("word/document.xml")
        part_order.extend(n for n in sorted(names) if re.fullmatch(r"word/footer\d*\.xml", n))
        for part in part_order:
            root = ET.fromstring(zf.read(part))
            for p_el in (el for el in root.iter() if _local_xml_tag(el.tag) == "p"):
                txt, _, _ = _collect_docx_paragraph_atoms(p_el)
                if txt.strip():
                    lines.append(txt)
    return lines


def _compute_docx_patched_bytes(
    fp: Path,
    raw_bytes: bytes,
    chunks: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    if len(raw_bytes) >= 4 and raw_bytes[:4] == OLE2_MAGIC_PREFIX:
        return _build_legacy_office_error(fp, ".doc")

    try:
        zf_probe = zipfile.ZipFile(io.BytesIO(raw_bytes), "r")
    except Exception as exc:
        return {"ok": False, "path": str(fp), "error": f"Invalid `.docx` ZIP archive `{fp.name}`: {exc}"}

    with zf_probe:
        names = set(zf_probe.namelist())
        if "word/document.xml" not in names:
            return {"ok": False, "path": str(fp), "error": f"`{fp.name}` is missing `word/document.xml`."}
        part_order = [n for n in sorted(names) if re.fullmatch(r"word/header\d*\.xml", n)]
        part_order.append("word/document.xml")
        part_order.extend(n for n in sorted(names) if re.fullmatch(r"word/footer\d*\.xml", n))

        part_roots: Dict[str, ET.Element] = {}
        for part in part_order:
            p_bytes = zf_probe.read(part)
            _register_xml_namespaces(p_bytes)
            part_roots[part] = ET.fromstring(p_bytes)

    before_lines = _extract_docx_lines_from_bytes(raw_bytes)
    dirty_parts: set[str] = set()
    total_replaced = 0

    for ch_idx, chunk in enumerate(chunks):
        old_s = str(chunk.get("old_text") or "")
        new_s = str(chunk.get("new_text") or "")
        rep_all = bool(chunk.get("replace_all", False))
        if not old_s:
            return {
                "ok": False,
                "path": str(fp),
                "failed_index": ch_idx,
                "error": "Non-empty `old_text` is required when editing a `.docx` document.",
            }

        hit_paragraphs: List[Tuple[str, ET.Element, List[Tuple[int, int]]]] = []
        total_occ = 0
        for part in part_order:
            root = part_roots[part]
            for p_el in [el for el in root.iter() if _local_xml_tag(el.tag) == "p"]:
                p_txt, t_slots, _ = _collect_docx_paragraph_atoms(p_el)
                if not t_slots or old_s not in p_txt:
                    continue
                spans: List[Tuple[int, int]] = []
                pos = 0
                while True:
                    idx_found = p_txt.find(old_s, pos)
                    if idx_found < 0:
                        break
                    m_s, m_e = idx_found, idx_found + len(old_s)
                    if any(se > m_s and ss < m_e for _, _, _, ss, se in t_slots):
                        spans.append((m_s, m_e))
                    pos = m_e
                if spans:
                    hit_paragraphs.append((part, p_el, spans))
                    total_occ += len(spans)

        if total_occ == 0:
            return {
                "ok": False,
                "path": str(fp),
                "failed_index": ch_idx,
                "error": f"old_text {old_s!r} not found in `{fp.name}`.",
            }
        if total_occ > 1 and not rep_all:
            return {
                "ok": False,
                "path": str(fp),
                "failed_index": ch_idx,
                "multiple_matches": True,
                "match_count": total_occ,
                "error": (
                    f"Found {total_occ} occurrences of old_text in `{fp.name}`; "
                    "pass replace_all=True or include surrounding paragraph text."
                ),
            }

        for part, p_el, spans in hit_paragraphs:
            dirty_parts.add(part)
            for m_s, m_e in reversed(spans):
                _, t_slots_cur, sep_atoms_cur = _collect_docx_paragraph_atoms(p_el)
                overlapping = [sl for sl in t_slots_cur if sl[4] > m_s and sl[3] < m_e]
                if not overlapping:
                    continue
                for sep_r, sep_ch, sep_s, sep_e in sep_atoms_cur:
                    if sep_s >= m_s and sep_e <= m_e:
                        with contextlib.suppress(ValueError):
                            sep_r.remove(sep_ch)

                first_parent, first_r, first_t, first_s, _ = overlapping[0]
                _, _, last_t, last_s, _ = overlapping[-1]
                _ = first_parent
                prefix = (first_t.text or "")[: max(0, m_s - first_s)]
                suffix = (last_t.text or "")[max(0, m_e - last_s) :]
                combined = prefix + new_s + suffix
                first_t.text = combined
                if combined and (
                    combined[0].isspace()
                    or combined[-1].isspace()
                    or "  " in combined
                    or "\t" in combined
                    or "\n" in combined
                ):
                    first_t.set(_XML_SPACE_QNAME, "preserve")
                elif not combined and _XML_SPACE_QNAME in first_t.attrib:
                    first_t.attrib.pop(_XML_SPACE_QNAME, None)

                for o_parent, o_r, o_t, _, _ in overlapping[1:]:
                    o_t.text = ""
                    if o_r is not first_r:
                        with contextlib.suppress(ValueError):
                            o_r.remove(o_t)
                        has_remaining_payload = any(
                            _local_xml_tag(rc.tag) != "rPr" for rc in list(o_r)
                        )
                        if not has_remaining_payload:
                            with contextlib.suppress(ValueError):
                                o_parent.remove(o_r)
                    elif o_t is not first_t:
                        with contextlib.suppress(ValueError):
                            o_r.remove(o_t)
                total_replaced += 1

    out_buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf_src, zipfile.ZipFile(
        out_buf, "w", compression=zipfile.ZIP_DEFLATED
    ) as zf_dst:
        for info in zf_src.infolist():
            new_info = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
            new_info.compress_type = info.compress_type
            new_info.external_attr = info.external_attr
            new_info.comment = info.comment
            new_info.extra = info.extra
            new_info.create_system = info.create_system
            if info.filename in dirty_parts:
                xml_payload = ET.tostring(part_roots[info.filename], encoding="utf-8", xml_declaration=True)
                zf_dst.writestr(new_info, xml_payload)
            else:
                zf_dst.writestr(new_info, zf_src.read(info.filename))

    final_bytes = out_buf.getvalue()
    with zipfile.ZipFile(io.BytesIO(final_bytes), "r") as zf_chk:
        bad_entry = zf_chk.testzip()
        if bad_entry is not None:
            return {"ok": False, "path": str(fp), "error": f"Generated `.docx` failed testzip on `{bad_entry}`."}
        for dp in dirty_parts:
            ET.fromstring(zf_chk.read(dp))

    after_lines = _extract_docx_lines_from_bytes(final_bytes)
    diff_txt = make_compact_diff("\n".join(before_lines), "\n".join(after_lines), filename=fp.name, max_lines=24)
    return {
        "ok": True,
        "final_bytes": final_bytes,
        "strategy_used": "docx_stdlib_xml_runs",
        "replaced_count": total_replaced,
        "modified_xml_parts": sorted(dirty_parts),
        "start_line": 1,
        "end_line": max(1, len(after_lines)),
        "diff_preview": diff_txt,
    }


def edit_docx_text_stdlib(
    path: Union[Path, str],
    edits: Any = None,
    *,
    old_text: str = "",
    new_text: str = "",
    replace_all: bool = False,
    expected_sha256: str = "",
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """Safely replace run-split text inside `.docx` paragraphs and tables using Python stdlib only."""
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="edit_file")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    if is_link_or_junction(fp):
        return {"ok": False, "blocked_by_guardrail": True, "path": str(fp), "error": f"Refusing symlink or junction: {fp}"}

    with get_file_lock(fp):
        pre_lk = _with_office_lock_code(check_office_or_os_file_lock(fp, for_write=True))
        if pre_lk is not None:
            return pre_lk
        try:
            orig_bytes = fp.read_bytes()
        except OSError as exc:
            lk_e = _with_office_lock_code(check_office_or_os_file_lock(fp, exc=exc, for_write=True))
            if lk_e is not None:
                return lk_e
            return {"ok": False, "path": str(fp), "error": f"{type(exc).__name__}: {exc}"}

        if expected_sha256:
            sha_err = verify_expected_sha256(orig_bytes, expected_sha256)
            if sha_err:
                return {"ok": False, "optimistic_lock_conflict": True, "path": str(fp), "error": sha_err}

        parsed = _coerce_edits_list(edits) if edits is not None else None
        chunk_list = parsed if parsed is not None else [{"old_text": old_text, "new_text": new_text, "replace_all": replace_all}]
        calc = _compute_docx_patched_bytes(fp, orig_bytes, chunk_list)
        if not calc.get("ok"):
            return calc

        orig_doc_txt = "\n".join(_extract_docx_lines_from_bytes(orig_bytes))
        cand_doc_txt = "\n".join(_extract_docx_lines_from_bytes(calc["final_bytes"]))
        red_err = _check_redacted_placeholder_writeback(fp, orig_doc_txt, cand_doc_txt)
        if red_err is not None:
            return red_err

        cm = _call_with_ws_roots(
            atomic_validate_and_replace,
            fp,
            calc["final_bytes"],
            guard=g,
            target_path=fp,
            enforce_syntax=False,
            save_snapshot=True,
            workspace_root=_matching_ws_root(fp, g),
        )
        if not cm.get("ok"):
            if cm.get("file_locked_by_external_app"):
                return _with_office_lock_code(cm) or cm
            return {"ok": False, "path": str(fp), **cm}

        out: Dict[str, Any] = {
            "ok": True,
            "path": str(fp),
            "document_format": "docx",
            "strategy_used": calc["strategy_used"],
            "replaced_count": calc["replaced_count"],
            "applied_count": len(chunk_list),
            "modified_xml_parts": calc.get("modified_xml_parts", []),
            "sha256": cm["sha256"],
            "sha256_prefix": cm["sha256_prefix"],
            "undo_snapshot": cm.get("undo_snapshot"),
            "diff_preview": calc.get("diff_preview", ""),
        }
        if r_info.get("healed_note"):
            out["healed_note"] = r_info["healed_note"]
        return out


def _coerce_excel_cell_value(new_text: str) -> Any:
    if new_text == "":
        return None
    if new_text.startswith("="):
        return new_text
    s = new_text.strip()
    if s == "TRUE":
        return True
    if s == "FALSE":
        return False
    if re.fullmatch(r"[+-]?(?:0|[1-9]\d*)", s):
        with contextlib.suppress(ValueError):
            return int(s)
    if re.fullmatch(r"[+-]?(?:(?:0|[1-9]\d*)\.\d*|\.\d+)(?:[eE][+-]?\d+)?|[+-]?(?:0|[1-9]\d*)[eE][+-]?\d+", s):
        with contextlib.suppress(ValueError):
            return float(s)
    return new_text


def _iter_populated_ws_cells(ws: Any) -> List[Any]:
    cells_dict = getattr(ws, "_cells", None)
    if isinstance(cells_dict, dict):
        items = [c for c in cells_dict.values() if getattr(c, "value", None) is not None]
        items.sort(key=lambda c: (int(getattr(c, "row", 0) or 0), int(getattr(c, "column", 0) or 0)))
        return items
    out: List[Any] = []
    for row in ws.iter_rows(values_only=False):
        for cell in row:
            if getattr(cell, "value", None) is not None:
                out.append(cell)
    return out


def _summarize_wb_lines(wb: Any) -> List[str]:
    date1904 = bool(getattr(getattr(wb, "epoch", None), "year", 1899) == 1904)
    lines: List[str] = []
    for ws in wb.worksheets:
        lines.append(f"[Sheet: {ws.title}]")
        by_row: Dict[int, List[str]] = {}
        for cell in _iter_populated_ws_cells(ws):
            raw_v = getattr(cell, "value", None)
            if raw_v is None:
                continue
            num_fmt = str(getattr(cell, "number_format", "") or "")
            val_s = _format_openpyxl_cell_value(raw_v, number_format=num_fmt, date1904=date1904).strip()
            if not val_s:
                continue
            r_idx = int(getattr(cell, "row", 1) or 1)
            coord = str(getattr(cell, "coordinate", "") or "")
            by_row.setdefault(r_idx, []).append(f"{coord}: {val_s}")
        for r_idx in sorted(by_row):
            lines.append(" | ".join(by_row[r_idx]))
    return lines


def _compute_xlsx_patched_bytes(
    fp: Path,
    raw_bytes: bytes,
    chunks: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    if len(raw_bytes) >= 4 and raw_bytes[:4] == OLE2_MAGIC_PREFIX:
        return _build_legacy_office_error(fp, ".xls")

    try:
        openpyxl = importlib.import_module("openpyxl")
    except (ImportError, ModuleNotFoundError):
        return {
            "ok": False,
            "path": str(fp),
            "error_code": "ERR_MISSING_OPENPYXL",
            "error": "Editing `.xlsx` workbooks requires pure-Python `openpyxl>=3.1.2`.",
        }

    try:
        wb = openpyxl.load_workbook(filename=io.BytesIO(raw_bytes), data_only=False)
    except Exception as exc:
        return {"ok": False, "path": str(fp), "error": f"Failed to load `.xlsx` workbook `{fp.name}`: {exc}"}

    try:
        if not wb.worksheets:
            return {"ok": False, "path": str(fp), "error": f"Workbook `{fp.name}` has no worksheets."}

        before_lines = _summarize_wb_lines(wb)
        date1904 = bool(getattr(getattr(wb, "epoch", None), "year", 1899) == 1904)
        total_replaced = 0
        strategies: List[str] = []

        for ch_idx, chunk in enumerate(chunks):
            old_s = str(chunk.get("old_text") or "")
            new_s = str(chunk.get("new_text") or "")
            rep_all = bool(chunk.get("replace_all", False))
            if not old_s:
                return {
                    "ok": False,
                    "path": str(fp),
                    "failed_index": ch_idx,
                    "error": "Non-empty `old_text` (cell ref like 'Sheet1!B4' or cell text) is required for `.xlsx` edit.",
                }

            m_coord = _XLSX_COORD_RE.match(old_s.strip())
            used_coord = False
            if m_coord is not None:
                quoted_sh, bare_sh, col_let, row_str = m_coord.groups()
                col_idx0 = _col_letters_to_index(col_let)
                row_num = int(row_str)
                if 0 <= col_idx0 < 16384 and 1 <= row_num <= 1048576:
                    explicit_sheet = (quoted_sh.replace("''", "'") if quoted_sh is not None else (bare_sh or "")).strip()
                    coord_norm = f"{col_let.upper()}{row_num}"
                    if explicit_sheet:
                        target_ws = None
                        if explicit_sheet in wb.sheetnames:
                            target_ws = wb[explicit_sheet]
                        else:
                            for s_nm in wb.sheetnames:
                                if s_nm.lower() == explicit_sheet.lower():
                                    target_ws = wb[s_nm]
                                    break
                        if target_ws is None:
                            return {
                                "ok": False,
                                "path": str(fp),
                                "failed_index": ch_idx,
                                "available_sheets": list(wb.sheetnames),
                                "error": f"Worksheet `{explicit_sheet}` not found in `{fp.name}` (available: {list(wb.sheetnames)}).",
                            }
                        target_ws[coord_norm].value = _coerce_excel_cell_value(new_s)
                        total_replaced += 1
                        strategies.append(f"xlsx_cell({target_ws.title}!{coord_norm})")
                        used_coord = True
                    else:
                        ws0 = wb.worksheets[0]
                        cur_cell_val = ws0[coord_norm].value
                        prefer_text_match = False
                        if cur_cell_val is None and (col_idx0 + 1) > max(int(ws0.max_column or 1), 1):
                            for ws_chk in wb.worksheets:
                                if any(
                                    _format_openpyxl_cell_value(
                                        c.value,
                                        number_format=str(getattr(c, "number_format", "") or ""),
                                        date1904=date1904,
                                    )
                                    == old_s
                                    for c in _iter_populated_ws_cells(ws_chk)
                                ):
                                    prefer_text_match = True
                                    break
                        if not prefer_text_match:
                            ws0[coord_norm].value = _coerce_excel_cell_value(new_s)
                            total_replaced += 1
                            strategies.append(f"xlsx_cell({ws0.title}!{coord_norm})")
                            used_coord = True

            if used_coord:
                continue

            matched_cells: List[Tuple[Any, Any, str]] = []
            for ws in wb.worksheets:
                for cell in _iter_populated_ws_cells(ws):
                    num_fmt = str(getattr(cell, "number_format", "") or "")
                    c_str = _format_openpyxl_cell_value(cell.value, number_format=num_fmt, date1904=date1904)
                    if old_s in c_str:
                        matched_cells.append((ws, cell, c_str))

            if not matched_cells:
                return {
                    "ok": False,
                    "path": str(fp),
                    "failed_index": ch_idx,
                    "available_sheets": list(wb.sheetnames),
                    "error": f"old_text {old_s!r} not found in any worksheet of `{fp.name}`.",
                }
            if len(matched_cells) > 1 and not rep_all:
                locs = [f"{ws_m.title}!{c_m.coordinate}" for ws_m, c_m, _ in matched_cells[:20]]
                return {
                    "ok": False,
                    "path": str(fp),
                    "failed_index": ch_idx,
                    "multiple_matches": True,
                    "match_count": len(matched_cells),
                    "match_locations": locs,
                    "error": (
                        f"Found {len(matched_cells)} matching cells in `{fp.name}` ({', '.join(locs[:5])}); "
                        "pass replace_all=True or specify cell coordinate like 'Sheet1!B4'."
                    ),
                }

            for ws_m, cell_m, c_str in matched_cells:
                if c_str == old_s:
                    cell_m.value = _coerce_excel_cell_value(new_s)
                else:
                    updated_s = c_str.replace(old_s, new_s) if rep_all else c_str.replace(old_s, new_s, 1)
                    cell_m.value = _coerce_excel_cell_value(updated_s)
                total_replaced += 1
                strategies.append(f"xlsx_text({ws_m.title}!{cell_m.coordinate})")

        after_lines = _summarize_wb_lines(wb)
        out_buf = io.BytesIO()
        wb.save(out_buf)
        final_bytes = out_buf.getvalue()
    finally:
        with contextlib.suppress(Exception):
            wb.close()

    with zipfile.ZipFile(io.BytesIO(final_bytes), "r") as zf_chk:
        bad_entry = zf_chk.testzip()
        if bad_entry is not None:
            return {"ok": False, "path": str(fp), "error": f"Generated `.xlsx` failed testzip on `{bad_entry}`."}

    diff_txt = make_compact_diff("\n".join(before_lines), "\n".join(after_lines), filename=fp.name, max_lines=24)
    return {
        "ok": True,
        "final_bytes": final_bytes,
        "strategy_used": ", ".join(strategies[:4]) if strategies else "xlsx_openpyxl",
        "replaced_count": total_replaced,
        "start_line": 1,
        "end_line": max(1, len(after_lines)),
        "diff_preview": diff_txt,
        "_before_text": "\n".join(before_lines),
        "_after_text": "\n".join(after_lines),
    }


def edit_xlsx_cells(
    path: Union[Path, str],
    edits: Any = None,
    *,
    old_text: str = "",
    new_text: str = "",
    replace_all: bool = False,
    expected_sha256: str = "",
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """Safely update `.xlsx` cells by coordinate (`Sheet1!B4` / `B4`) or text match with `~$` lock guard and undo snapshot."""
    g = _default_guard(guard)
    r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="edit_file")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    if is_link_or_junction(fp):
        return {"ok": False, "blocked_by_guardrail": True, "path": str(fp), "error": f"Refusing symlink or junction: {fp}"}

    with get_file_lock(fp):
        pre_lk = _with_office_lock_code(check_office_or_os_file_lock(fp, for_write=True))
        if pre_lk is not None:
            return pre_lk
        try:
            orig_bytes = fp.read_bytes()
        except OSError as exc:
            lk_e = _with_office_lock_code(check_office_or_os_file_lock(fp, exc=exc, for_write=True))
            if lk_e is not None:
                return lk_e
            return {"ok": False, "path": str(fp), "error": f"{type(exc).__name__}: {exc}"}

        if expected_sha256:
            sha_err = verify_expected_sha256(orig_bytes, expected_sha256)
            if sha_err:
                return {"ok": False, "optimistic_lock_conflict": True, "path": str(fp), "error": sha_err}

        parsed = _coerce_edits_list(edits) if edits is not None else None
        chunk_list = parsed if parsed is not None else [{"old_text": old_text, "new_text": new_text, "replace_all": replace_all}]
        calc = _compute_xlsx_patched_bytes(fp, orig_bytes, chunk_list)
        if not calc.get("ok"):
            return calc

        red_err = _check_redacted_placeholder_writeback(
            fp,
            str(calc.get("_before_text") or ""),
            str(calc.get("_after_text") or ""),
        )
        if red_err is not None:
            return red_err

        cm = _call_with_ws_roots(
            atomic_validate_and_replace,
            fp,
            calc["final_bytes"],
            guard=g,
            target_path=fp,
            enforce_syntax=False,
            save_snapshot=True,
            workspace_root=_matching_ws_root(fp, g),
        )
        if not cm.get("ok"):
            if cm.get("file_locked_by_external_app"):
                return _with_office_lock_code(cm) or cm
            return {"ok": False, "path": str(fp), **cm}

        out: Dict[str, Any] = {
            "ok": True,
            "path": str(fp),
            "document_format": "xlsx",
            "strategy_used": calc["strategy_used"],
            "replaced_count": calc["replaced_count"],
            "applied_count": len(chunk_list),
            "sha256": cm["sha256"],
            "sha256_prefix": cm["sha256_prefix"],
            "undo_snapshot": cm.get("undo_snapshot"),
            "diff_preview": calc.get("diff_preview", ""),
        }
        if r_info.get("healed_note"):
            out["healed_note"] = r_info["healed_note"]
        return out


def _coerce_edits_list(edits: Any) -> Optional[List[Dict[str, Any]]]:
    if edits is None or edits == [] or edits == "":
        return None
    if isinstance(edits, str):
        s = edits.strip()
        if not s:
            return None
        parsed = json.loads(s)
        if not isinstance(parsed, list):
            raise ValueError("`edits` must be a JSON array of edit objects.")
        edits = parsed
    if isinstance(edits, (list, tuple)):
        out: List[Dict[str, Any]] = []
        for idx, item in enumerate(edits):
            if not isinstance(item, dict):
                raise ValueError(f"`edits[{idx}]` must be an object/dict.")
            out.append(dict(item))
        return out
    raise ValueError("`edits` must be a list of edit objects.")


def _apply_single_chunk_to_bytes(
    fp: Path,
    cur_bytes: bytes,
    chunk: Dict[str, Any],
) -> Dict[str, Any]:
    ext_low = fp.suffix.lower()
    if ext_low == ".docx":
        return _compute_docx_patched_bytes(fp, cur_bytes, [chunk])
    if ext_low == ".xlsx":
        return _compute_xlsx_patched_bytes(fp, cur_bytes, [chunk])

    old_text = str(chunk.get("old_text") or "")
    new_text = str(chunk.get("new_text") or "")
    s_ln = int(chunk.get("start_line") or 0)
    e_ln = int(chunk.get("end_line") or 0)
    sym_q = str(chunk.get("symbol") or "").strip()
    replace_all = bool(chunk.get("replace_all", False))

    raw_text, enc_tag = detect_and_decode_bytes(cur_bytes, strict_for_edit=True)
    lf_text = raw_text.replace("\r\n", "\n")

    if sym_q:
        syms = extract_symbols_from_text(lf_text, str(fp))
        target_sym, cands = resolve_symbol_in_outline(syms, sym_q)
        if target_sym is None:
            return {
                "ok": False,
                "path": str(fp),
                "symbol": sym_q,
                "symbol_candidates": cands,
                "error": f"Symbol `{sym_q}` not found in `{fp.name}`.",
            }
        sym_s, sym_e = int(target_sym["line"]), int(target_sym["end_line"])
        if not old_text:
            mem_res = apply_line_range_edits_in_memory(raw_text, [(sym_s, sym_e, new_text)])
            if not mem_res.get("ok"):
                return {"ok": False, "path": str(fp), "error": str(mem_res.get("error"))}
            final_b = encode_with_detected_encoding(mem_res["patched_text"], enc_tag)
            return {
                "ok": True,
                "final_bytes": final_b,
                "strategy_used": f"symbol_body({target_sym['qualname']})",
                "replaced_count": 1,
                "start_line": sym_s,
                "end_line": sym_e,
                "diff_preview": make_compact_diff(lf_text, mem_res["patched_text"].replace("\r\n", "\n"), filename=fp.name, max_lines=24),
            }
        s_ln = sym_s
        e_ln = sym_e

    if not old_text and s_ln > 0:
        eff_e = e_ln if e_ln >= s_ln else s_ln
        mem_res = apply_line_range_edits_in_memory(raw_text, [(s_ln, eff_e, new_text)])
        if not mem_res.get("ok"):
            return {"ok": False, "path": str(fp), "error": str(mem_res.get("error"))}
        final_b = encode_with_detected_encoding(mem_res["patched_text"], enc_tag)
        return {
            "ok": True,
            "final_bytes": final_b,
            "strategy_used": f"line_range({s_ln}..{eff_e})",
            "replaced_count": 1,
            "start_line": s_ln,
            "end_line": eff_e,
            "diff_preview": make_compact_diff(lf_text, mem_res["patched_text"].replace("\r\n", "\n"), filename=fp.name, max_lines=24),
        }

    return compute_patched_bytes(
        fp,
        cur_bytes,
        old_text,
        new_text,
        start_line=s_ln,
        end_line=e_ln,
        replace_all=replace_all,
    )


def edit_file(
    path: Union[Path, str] = "",
    old_text: str = "",
    new_text: str = "",
    start_line: int = 0,
    end_line: int = 0,
    symbol: str = "",
    replace_all: bool = False,
    edits: Any = None,
    expected_sha256: str = "",
    check_syntax: bool = True,
    patch_text: str = "",
    insert_after_symbol: Union[bool, str] = False,
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """
    Surgical single/multi-chunk file editor supporting `±15`-line window drift (`WINDOW_DRIFT_LINES`),
    `symbol` scope, `insert_after_symbol`, `patch_text` (V4A patch), and `edits=[...]` atomic transactions.
    """
    g = _default_guard(guard)

    clean_patch = str(patch_text or "").strip()
    if clean_patch:
        eff_patch = clean_patch
        if str(path or "").strip() and not re.search(
            r"^\*\*\*\s*(?:Update|Add|Delete|Move)\s+File:", eff_patch, flags=re.MULTILINE
        ):
            eff_patch = f"*** Begin Patch\n*** Update File: {path}\n{eff_patch}\n*** End Patch"
        ops, p_err = parse_v4a_patch(eff_patch)
        if p_err:
            return {"ok": False, "rolled_back_all": True, "error": p_err}
        base_ws = _matching_ws_root(path, g) or _primary_ws_root(g) or Path.cwd().resolve()
        first_target: Optional[Path] = None
        for op in ops:
            for idx_p, rel_cand in enumerate((op.file_path, op.new_path)):
                if not rel_cand:
                    continue
                cand_p = Path(rel_cand).expanduser()
                query_p = cand_p if cand_p.is_absolute() else (base_ws / cand_p)
                must_exist = idx_p == 0 and op.operation != OperationType.ADD
                r_chk = heal_and_resolve_path(
                    str(query_p),
                    g,
                    mode="write",
                    must_exist=must_exist,
                    tool_name="edit_file",
                )
                if not r_chk["ok"]:
                    return {
                        "ok": False,
                        "rolled_back_all": True,
                        **{k: (str(v) if isinstance(v, Path) else v) for k, v in r_chk.items() if v is not None},
                    }
                resolved_op_p: Path = r_chk["path"]
                if is_link_or_junction(resolved_op_p):
                    return {
                        "ok": False,
                        "blocked_by_guardrail": True,
                        "rolled_back_all": True,
                        "path": str(resolved_op_p),
                        "error": f"Refusing symlink or junction in patch_text: {resolved_op_p}",
                    }
                if first_target is None:
                    first_target = resolved_op_p
                if idx_p == 0 and resolved_op_p.exists() and resolved_op_p.is_file() and op.hunks:
                    added_blob = "\n".join(
                        hl.content for hk in op.hunks for hl in hk.lines if hl.prefix == "+"
                    )
                    if added_blob and any(m in added_blob for m in REDACTED_PLACEHOLDER_MARKERS):
                        orig_op_txt, _ = detect_and_decode_bytes(resolved_op_p.read_bytes(), strict_for_edit=False)
                        red_err = _check_redacted_placeholder_writeback(resolved_op_p, orig_op_txt, added_blob)
                        if red_err is not None:
                            return {**red_err, "rolled_back_all": True}
        return _call_with_ws_roots(
            apply_v4a_patch,
            eff_patch,
            guard=g,
            target_path=first_target or base_ws,
            base_dir=base_ws,
            check_syntax=bool(check_syntax),
            save_snapshot=True,
            workspace_root=_matching_ws_root(first_target or base_ws, g),
        )

    ins_active = False
    ins_target_sym = (symbol or "").strip()
    if isinstance(insert_after_symbol, bool):
        ins_active = insert_after_symbol
    elif isinstance(insert_after_symbol, str):
        s_ins = insert_after_symbol.strip()
        if s_ins.lower() in ("true", "1", "yes"):
            ins_active = True
        elif s_ins and s_ins.lower() not in ("false", "0", "no"):
            ins_active = True
            if not ins_target_sym:
                ins_target_sym = s_ins

    if ins_active:
        r_ins = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="edit_file")
        if not r_ins["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_ins.items() if v is not None}
        fp_ins: Path = r_ins["path"]
        if is_link_or_junction(fp_ins):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(fp_ins), "error": f"Refusing symlink or junction: {fp_ins}"}
        if any(m in str(new_text or "") for m in REDACTED_PLACEHOLDER_MARKERS) and fp_ins.exists() and fp_ins.is_file():
            orig_ins_txt, _ = detect_and_decode_bytes(fp_ins.read_bytes(), strict_for_edit=False)
            red_err = _check_redacted_placeholder_writeback(fp_ins, orig_ins_txt, str(new_text or ""))
            if red_err is not None:
                return red_err
        res_ins = _code_insert_after_symbol(
            fp_ins,
            ins_target_sym,
            new_text,
            expected_sha256=expected_sha256,
            check_syntax=bool(check_syntax),
            guard=g,
        )
        if r_ins.get("healed_note") and isinstance(res_ins, dict):
            res_ins = dict(res_ins)
            res_ins["healed_note"] = r_ins["healed_note"]
        return res_ins

    try:
        parsed_edits = _coerce_edits_list(edits)
    except ValueError as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if parsed_edits is None and not (symbol or "").strip() and old_text:
        r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="edit_file")
        if not r_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
        fp_single: Path = r_info["path"]
        if is_link_or_junction(fp_single):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(fp_single), "error": f"Refusing symlink or junction: {fp_single}"}
        single_ext = fp_single.suffix.lower()
        if single_ext == ".docx":
            return edit_docx_text_stdlib(
                fp_single,
                old_text=old_text,
                new_text=new_text,
                replace_all=bool(replace_all),
                expected_sha256=expected_sha256,
                guard=g,
            )
        if single_ext == ".xlsx":
            return edit_xlsx_cells(
                fp_single,
                old_text=old_text,
                new_text=new_text,
                replace_all=bool(replace_all),
                expected_sha256=expected_sha256,
                guard=g,
            )
        if single_ext in LEGACY_BINARY_OFFICE_EXTS:
            return _build_legacy_office_error(fp_single, single_ext)
        if any(m in str(new_text or "") for m in REDACTED_PLACEHOLDER_MARKERS) and fp_single.exists() and fp_single.is_file():
            orig_single_txt, _ = detect_and_decode_bytes(fp_single.read_bytes(), strict_for_edit=False)
            red_err = _check_redacted_placeholder_writeback(fp_single, orig_single_txt, str(new_text or ""))
            if red_err is not None:
                return red_err
        res_p = _call_with_ws_roots(
            _patch_single_file,
            fp_single,
            guard=g,
            target_path=fp_single,
            old_text=old_text,
            new_text=new_text,
            start_line=int(start_line or 0),
            end_line=int(end_line or 0),
            replace_all=bool(replace_all),
            auto_rollback_on_invalid=bool(check_syntax),
            save_snapshot=True,
            expected_sha256=expected_sha256,
            workspace_root=_matching_ws_root(fp_single, g),
        )
        if res_p.get("file_locked_by_external_app"):
            res_p = _with_office_lock_code(res_p) or res_p
        if r_info.get("healed_note") and isinstance(res_p, dict):
            res_p = dict(res_p)
            res_p["healed_note"] = r_info["healed_note"]
        return res_p

    chunk_list: List[Dict[str, Any]] = (
        parsed_edits
        if parsed_edits is not None
        else [
            {
                "path": str(path),
                "old_text": old_text,
                "new_text": new_text,
                "start_line": start_line,
                "end_line": end_line,
                "symbol": symbol,
                "replace_all": replace_all,
                "expected_sha256": expected_sha256,
            }
        ]
    )
    if not chunk_list:
        return {"ok": False, "error": "Provide `old_text`/`new_text`, `symbol`, `start_line`/`end_line`, or non-empty `edits`."}

    resolved_chunks: List[Tuple[Path, Dict[str, Any]]] = []
    unique_paths: List[Path] = []
    for idx, ch in enumerate(chunk_list):
        raw_p = str(ch.get("path") or path or "").strip()
        if not raw_p:
            return {"ok": False, "failed_index": idx, "rolled_back_all": True, "error": f"`path` is required for edit chunk {idx}."}
        r_info = heal_and_resolve_path(raw_p, g, mode="write", must_exist=True, tool_name="edit_file")
        if not r_info["ok"]:
            err_d = {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
            err_d["failed_index"] = idx
            err_d["rolled_back_all"] = True
            return err_d
        fp_c: Path = r_info["path"]
        resolved_chunks.append((fp_c, ch))
        if fp_c not in unique_paths:
            unique_paths.append(fp_c)

    if (
        len(unique_paths) == 1
        and all(
            not str(c.get("old_text") or "")
            and not str(c.get("symbol") or "").strip()
            and int(c.get("start_line") or 0) > 0
            for _, c in resolved_chunks
        )
    ):
        fp_only = unique_paths[0]
        with get_file_lock(fp_only):
            pre_lk = check_office_or_os_file_lock(fp_only, for_write=True)
            if pre_lk is not None:
                return pre_lk
            orig_b = fp_only.read_bytes()
            sha_err = verify_expected_sha256(orig_b, expected_sha256)
            if sha_err:
                return {"ok": False, "optimistic_lock_conflict": True, "path": str(fp_only), "error": sha_err}
            raw_t, enc_tag = detect_and_decode_bytes(orig_b, strict_for_edit=True)
            line_specs = [
                (int(c["start_line"]), int(c.get("end_line") or c["start_line"]), str(c.get("new_text") or ""))
                for _, c in resolved_chunks
            ]
            mem_r = apply_line_range_edits_in_memory(raw_t, line_specs)
            if not mem_r.get("ok"):
                return {"ok": False, "path": str(fp_only), "rolled_back_all": True, "error": str(mem_r.get("error"))}
            red_err_lr = _check_redacted_placeholder_writeback(fp_only, raw_t, mem_r["patched_text"])
            if red_err_lr is not None:
                return {**red_err_lr, "rolled_back_all": True}
            final_b = encode_with_detected_encoding(mem_r["patched_text"], enc_tag)
            cm = _call_with_ws_roots(
                atomic_validate_and_replace,
                fp_only,
                final_b,
                guard=g,
                target_path=fp_only,
                enforce_syntax=bool(check_syntax),
                save_snapshot=True,
                workspace_root=_matching_ws_root(fp_only, g),
            )
            if not cm.get("ok"):
                return {
                    "ok": False,
                    "auto_rolled_back": True,
                    "rolled_back_all": True,
                    "path": str(fp_only),
                    "syntax_check": cm.get("syntax_check"),
                    "error": f"Line edits introduced a syntax error in `{fp_only.name}`; rejected during staging.",
                }
            return {
                "ok": True,
                "path": str(fp_only),
                "applied_count": len(line_specs),
                "sha256": cm["sha256"],
                "sha256_prefix": cm["sha256_prefix"],
                "undo_snapshot": cm.get("undo_snapshot"),
                "diff_preview": make_compact_diff(raw_t.replace("\r\n", "\n"), mem_r["patched_text"].replace("\r\n", "\n"), filename=fp_only.name),
            }

    with MultiFileLock(unique_paths):
        orig_buffers: Dict[Path, bytes] = {}
        staged_buffers: Dict[Path, bytes] = {}
        chunk_receipts: List[Dict[str, Any]] = []

        for idx, (fp_c, ch) in enumerate(resolved_chunks):
            pre_lk = _with_office_lock_code(check_office_or_os_file_lock(fp_c, for_write=True))
            if pre_lk is not None:
                return {**pre_lk, "failed_index": idx, "failed_path": str(fp_c), "rolled_back_all": True}
            if fp_c not in orig_buffers:
                disk_b = fp_c.read_bytes()
                top_sha = str(ch.get("expected_sha256") or expected_sha256 or "").strip()
                if top_sha:
                    sha_err = verify_expected_sha256(disk_b, top_sha)
                    if sha_err:
                        return {
                            "ok": False,
                            "optimistic_lock_conflict": True,
                            "failed_index": idx,
                            "failed_path": str(fp_c),
                            "rolled_back_all": True,
                            "error": sha_err,
                        }
                orig_buffers[fp_c] = disk_b
                staged_buffers[fp_c] = disk_b

            calc = _apply_single_chunk_to_bytes(fp_c, staged_buffers[fp_c], ch)
            if not calc.get("ok"):
                err_out = dict(calc)
                err_out.update({"ok": False, "failed_index": idx, "failed_path": str(fp_c), "rolled_back_all": True})
                return err_out

            staged_buffers[fp_c] = calc["final_bytes"]
            chunk_receipts.append(
                {
                    "path": str(fp_c),
                    "strategy_used": calc.get("strategy_used", ""),
                    "replaced_count": calc.get("replaced_count", 1),
                    "start_line": calc.get("start_line", 1),
                    "end_line": calc.get("end_line", 1),
                    "diff_preview": calc.get("diff_preview", ""),
                }
            )

        for fp_u, final_b in staged_buffers.items():
            u_ext = fp_u.suffix.lower()
            if u_ext == ".docx":
                cand_doc_s = "\n".join(_extract_docx_lines_from_bytes(final_b))
                if any(m in cand_doc_s for m in REDACTED_PLACEHOLDER_MARKERS):
                    orig_doc_s = "\n".join(_extract_docx_lines_from_bytes(orig_buffers[fp_u]))
                    red_err_d = _check_redacted_placeholder_writeback(fp_u, orig_doc_s, cand_doc_s)
                    if red_err_d is not None:
                        return {**red_err_d, "failed_path": str(fp_u), "rolled_back_all": True}
                continue
            if u_ext == ".xlsx":
                continue
            if any(m.encode("utf-8") in final_b for m in REDACTED_PLACEHOLDER_MARKERS):
                orig_u_txt, _ = detect_and_decode_bytes(orig_buffers[fp_u], strict_for_edit=False)
                cand_u_txt, _ = detect_and_decode_bytes(final_b, strict_for_edit=False)
                red_err_m = _check_redacted_placeholder_writeback(fp_u, orig_u_txt, cand_u_txt)
                if red_err_m is not None:
                    return {**red_err_m, "failed_path": str(fp_u), "rolled_back_all": True}

        if check_syntax:
            for fp_u, final_b in staged_buffers.items():
                if fp_u.suffix.lower() in (".docx", ".xlsx"):
                    continue
                chk_txt, _ = detect_and_decode_bytes(final_b, strict_for_edit=False)
                sc = auto_check_syntax(fp_u, content=chk_txt, raw_bytes=final_b)
                if not sc.get("valid", True):
                    return {
                        "ok": False,
                        "failed_path": str(fp_u),
                        "auto_rolled_back": True,
                        "rolled_back_all": True,
                        "syntax_check": sc,
                        "error": f"Syntax check failed on `{fp_u.name}` ({sc.get('error')}); aborted before modifying any file.",
                    }

        committed_paths: List[Path] = []
        committed_meta: Dict[Path, Dict[str, Any]] = {}
        for fp_u, final_b in staged_buffers.items():
            eff_enforce_syntax = bool(check_syntax) and fp_u.suffix.lower() not in (".docx", ".xlsx")
            try:
                cm = _call_with_ws_roots(
                    atomic_validate_and_replace,
                    fp_u,
                    final_b,
                    guard=g,
                    target_path=fp_u,
                    enforce_syntax=eff_enforce_syntax,
                    save_snapshot=True,
                    workspace_root=_matching_ws_root(fp_u, g),
                )
            except BaseException as exc:
                for rp in reversed(committed_paths):
                    with contextlib.suppress(Exception):
                        _call_with_ws_roots(
                            atomic_validate_and_replace,
                            rp,
                            orig_buffers[rp],
                            guard=g,
                            target_path=rp,
                            enforce_syntax=False,
                            save_snapshot=False,
                            workspace_root=_matching_ws_root(rp, g),
                        )
                        _call_with_ws_roots(
                            pop_latest_undo_entry_quiet,
                            rp,
                            guard=g,
                            target_path=rp,
                            workspace_root=_matching_ws_root(rp, g),
                        )
                return {
                    "ok": False,
                    "failed_path": str(fp_u),
                    "auto_rolled_back": True,
                    "rolled_back_all": True,
                    "error": f"Write failed on `{fp_u.name}` ({type(exc).__name__}: {exc}); rolled back all files.",
                }
            if not cm.get("ok"):
                for rp in reversed(committed_paths):
                    with contextlib.suppress(Exception):
                        _call_with_ws_roots(
                            atomic_validate_and_replace,
                            rp,
                            orig_buffers[rp],
                            guard=g,
                            target_path=rp,
                            enforce_syntax=False,
                            save_snapshot=False,
                            workspace_root=_matching_ws_root(rp, g),
                        )
                        _call_with_ws_roots(
                            pop_latest_undo_entry_quiet,
                            rp,
                            guard=g,
                            target_path=rp,
                            workspace_root=_matching_ws_root(rp, g),
                        )
                return {
                    "ok": False,
                    "failed_path": str(fp_u),
                    "auto_rolled_back": True,
                    "rolled_back_all": True,
                    "syntax_check": cm.get("syntax_check"),
                    "error": str(cm.get("error") or f"Validation failed on `{fp_u.name}`; rolled back all files."),
                }
            committed_paths.append(fp_u)
            committed_meta[fp_u] = cm

        for rec in chunk_receipts:
            cm_i = committed_meta[Path(rec["path"])]
            rec["sha256"] = cm_i["sha256"]

        if len(unique_paths) == 1:
            fp0 = unique_paths[0]
            cm0 = committed_meta[fp0]
            return {
                "ok": True,
                "path": str(fp0),
                "window_drift_tolerance": WINDOW_DRIFT_LINES,
                "applied_count": len(chunk_receipts),
                "sha256": cm0["sha256"],
                "sha256_prefix": cm0["sha256_prefix"],
                "undo_snapshot": cm0.get("undo_snapshot"),
                "results": chunk_receipts,
                "diff_preview": chunk_receipts[-1].get("diff_preview", ""),
            }
        return {
            "ok": True,
            "applied_count": len(chunk_receipts),
            "files_modified": len(unique_paths),
            "results": chunk_receipts,
        }


patch_file = edit_file


# ---------------------------------------------------------------------------
# 6. `manage_files`, `undo_or_trash` & Aliases (`undo_edit`, `trash_file`, `restore_trash`)
# ---------------------------------------------------------------------------

def _readonly_tier_denied(tool_name: str, act: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "error_code": "ERR_READONLY_ACTION_BLOCKED",
        "tier_error_code": "ERR_TIER_DENIED",
        "blocked_by_guardrail": True,
        "blocked_by_permission_tier": True,
        "blocked_by_readonly_action": True,
        "action": act,
        "error": (
            f"[PERMISSION TIER BLOCKED] (ERR_TIER_DENIED / ERR_READONLY_ACTION_BLOCKED): "
            f"`{tool_name}` action='{act}' is forbidden in L1 read-only tier (only action='list' is allowed)."
        ),
    }


def undo_edit(
    path: Union[Path, str] = "",
    action: str = "undo",
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    act = (action or "undo").strip().lower()
    if normalize_tier(g.tier) == "L1":
        return _readonly_tier_denied("undo_edit", act)

    raw_p = str(path or "").strip()
    if not raw_p:
        ws_roots = _ws_roots_list(g)
        probe_target = str(ws_roots[0] if ws_roots else Path.cwd())
        g_err = g.check_path_access(probe_target, mode="write", tool_name="undo_edit")
        if g_err:
            return {"ok": False, "blocked_by_guardrail": True, "error": g_err}
        return _call_with_ws_roots(
            _tx_undo_last_edit,
            "",
            guard=g,
            scope_to_workspace=bool(g.restrict_to_workspace),
            action=act,
        )

    r_info = heal_and_resolve_path(raw_p, g, mode="write", must_exist=False, tool_name="undo_edit")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    return _call_with_ws_roots(
        _tx_undo_last_edit,
        fp,
        guard=g,
        target_path=fp,
        scope_to_workspace=bool(g.restrict_to_workspace),
        action=act,
        workspace_root=_matching_ws_root(fp, g) if g.restrict_to_workspace else None,
    )


def trash_file(
    path: Union[Path, str],
    reason: str = "",
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    if normalize_tier(g.tier) == "L1":
        return _readonly_tier_denied("trash_file", "trash")
    r_info = heal_and_resolve_path(str(path), g, mode="write", must_exist=True, tool_name="trash_file")
    if not r_info["ok"]:
        return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
    fp: Path = r_info["path"]
    if is_link_or_junction(fp):
        return {"ok": False, "blocked_by_guardrail": True, "path": str(fp), "error": f"Refusing to trash symlink or junction: {fp}"}
    res = _call_with_ws_roots(
        _tx_safe_trash_file,
        fp,
        guard=g,
        target_path=fp,
        reason=reason,
        workspace_root=_matching_ws_root(fp, g),
    )
    if isinstance(res, dict) and res.get("ok"):
        res = {"action": "trash", "path": str(fp), **res}
    return res


def restore_trash(
    action: str = "list",
    trash_id: str = "",
    limit: int = 20,
    *,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    g = _default_guard(guard)
    act = _normalize_manage_files_action(action, default="list")
    if act != "list":
        if normalize_tier(g.tier) == "L1":
            return _readonly_tier_denied("restore_trash", act)
        ws_roots = _ws_roots_list(g)
        probe_target = str(ws_roots[0] if ws_roots else Path.cwd())
        g_err = g.check_path_access(probe_target, mode="write", tool_name="restore_trash")
        if g_err:
            return {"ok": False, "blocked_by_guardrail": True, "error": g_err}
    return _call_with_ws_roots(
        _tx_restore_trash_item,
        guard=g,
        scope_to_workspace=bool(g.restrict_to_workspace),
        action=act,
        trash_id=trash_id,
        limit=limit,
    )


def manage_files(
    guard: Optional[WorkspaceGuard] = None,
    *,
    action: str = "list",
    path: Union[Path, str] = "",
    destination: Union[Path, str] = "",
    overwrite: bool = False,
    trash_id: str = "",
    reason: str = "",
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Unified file & recovery manager supporting `"mkdir"`, `"move"`, `"rename"`, `"copy"`,
    `"trash"`, `"restore"`, `"undo"` (and `"redo"`), and `"list"`:
    - Uses literal `os.replace` / `shutil` paths so bracketed names (`IMG_9842[1].png`) never suffer glob misinterpretation.
    - Records `"move"`, `"rename"`, `"trash"`, `"copy"`, and `"mkdir"` into externalized `<state_root>/history/<workspace_hash>`.
    - Supports `action="undo"` with `path=""` to roll back the most recent workspace modification or move.
    """
    if isinstance(guard, str) and action == "list":
        action = guard
        guard = None

    g = _default_guard(guard)
    act = _normalize_manage_files_action(action, default="list")

    if act != "list" and normalize_tier(g.tier) == "L1":
        return _readonly_tier_denied("manage_files", act)

    if act == "list":
        tr_res = restore_trash(action="list", limit=limit, guard=g)
        trash_items = list(tr_res.get("items") or [])
        undo_snaps = _call_with_ws_roots(
            list_undo_snapshots,
            guard=g,
            scope_to_workspace=bool(g.restrict_to_workspace),
            limit=limit,
            redo=False,
        )
        return {
            "ok": True,
            "action": "list",
            "undo_count": len(undo_snaps),
            "undo_snapshots": undo_snaps,
            "trash_count": len(trash_items),
            "trash_items": trash_items,
            "count": len(undo_snaps) + len(trash_items),
            "items": trash_items,
        }

    if act in ("undo", "redo"):
        return undo_edit(path=path, action=act, guard=g)

    if act == "trash":
        if not str(path or "").strip():
            return {"ok": False, "action": "trash", "error": "`path` is required when action='trash'."}
        return trash_file(path, reason=reason, guard=g)

    if act == "restore":
        eff_tid = (trash_id or str(destination or "") or "").strip() or "latest"
        return restore_trash(action="restore", trash_id=eff_tid, limit=limit, guard=g)

    if act == "mkdir":
        raw_p = str(path or "").strip()
        if not raw_p:
            return {"ok": False, "action": "mkdir", "error": "`path` is required when action='mkdir'."}
        r_info = heal_and_resolve_path(raw_p, g, mode="write", must_exist=False, tool_name="manage_files")
        if not r_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in r_info.items() if v is not None}
        fp: Path = r_info["path"]
        if is_link_or_junction(fp):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(fp), "error": f"Refusing symlink or junction path: {fp}"}
        existed_before = fp.exists()
        first_missing: Optional[Path] = None
        if not existed_before:
            cur = fp
            while not cur.exists() and cur.parent != cur:
                first_missing = cur
                cur = cur.parent
        fp.mkdir(parents=True, exist_ok=True)
        if not existed_before:
            target_created = first_missing or fp
            _call_with_ws_roots(
                record_file_creation_undo,
                target_created,
                guard=g,
                target_path=target_created,
                op_kind="mkdir",
                workspace_root=_matching_ws_root(target_created, g),
            )
        return {"ok": True, "action": "mkdir", "path": str(fp), "created": not existed_before}

    if act in ("move", "rename", "copy"):
        raw_src = str(path or "").strip()
        raw_dst = str(destination or "").strip()
        if not raw_src or not raw_dst:
            return {"ok": False, "action": act, "error": f"`path` and `destination` are required when action='{act}'."}

        src_mode = "read" if act == "copy" else "write"
        src_info = heal_and_resolve_path(raw_src, g, mode=src_mode, must_exist=True, tool_name="manage_files")
        if not src_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in src_info.items() if v is not None}
        src_p: Path = src_info["path"]
        if is_link_or_junction(src_p):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(src_p), "error": f"Refusing symlink or junction source: {src_p}"}

        if src_p.is_file():
            src_lk = check_office_or_os_file_lock(src_p, for_write=(act != "copy"))
            if src_lk is not None:
                return src_lk

        dst_query = raw_dst
        if act == "rename" and ("/" not in raw_dst and "\\" not in raw_dst) and not Path(raw_dst).is_absolute():
            dst_query = str(src_p.parent / raw_dst)

        dst_info = heal_and_resolve_path(dst_query, g, mode="write", must_exist=False, tool_name="manage_files")
        if not dst_info["ok"]:
            return {k: (str(v) if isinstance(v, Path) else v) for k, v in dst_info.items() if v is not None}
        dst_p: Path = dst_info["path"]

        if act in ("move", "copy") and dst_p.exists() and dst_p.is_dir() and not src_p.is_dir():
            dst_p = (dst_p / src_p.name).resolve()
            g_err_sub = g.check_path_access(str(dst_p), mode="write", tool_name="manage_files")
            if g_err_sub:
                return {"ok": False, "blocked_by_guardrail": True, "path": str(dst_p), "error": g_err_sub}

        if is_link_or_junction(dst_p):
            return {"ok": False, "blocked_by_guardrail": True, "path": str(dst_p), "error": f"Refusing symlink or junction destination: {dst_p}"}

        if os.path.normcase(str(src_p)) == os.path.normcase(str(dst_p)):
            return {"ok": True, "action": act, "path": str(src_p), "destination": str(dst_p), "noop": True}

        with MultiFileLock([src_p, dst_p]):
            dst_existed_before = dst_p.exists()
            overwritten_tid = ""
            overwritten_snap = ""
            if dst_existed_before:
                if not overwrite:
                    return {
                        "ok": False,
                        "action": act,
                        "already_exists": True,
                        "conflict": True,
                        "path": str(src_p),
                        "destination": str(dst_p),
                        "error": f"Destination `{dst_p.name}` already exists (pass overwrite=True to replace safely).",
                    }
                if dst_p.is_file():
                    dst_lk = check_office_or_os_file_lock(dst_p, for_write=True)
                    if dst_lk is not None:
                        return dst_lk
                    if act == "copy":
                        overwritten_snap = str(
                            _call_with_ws_roots(
                                _tx_save_undo_snapshot,
                                dst_p,
                                guard=g,
                                target_path=dst_p,
                                workspace_root=_matching_ws_root(dst_p, g),
                            )
                            or ""
                        )
                tr_ov = _call_with_ws_roots(
                    _tx_safe_trash_file,
                    dst_p,
                    guard=g,
                    target_path=dst_p,
                    reason=reason or f"manage_files:{act}:overwrite",
                    workspace_root=_matching_ws_root(dst_p, g),
                    record_undo=False,
                )
                if not tr_ov.get("ok"):
                    return tr_ov
                overwritten_tid = str(tr_ov.get("trash_id") or "")

            try:
                dst_p.parent.mkdir(parents=True, exist_ok=True)
                if act == "copy":
                    if src_p.is_dir():
                        shutil.copytree(str(src_p), str(dst_p))
                    else:
                        shutil.copy2(str(src_p), str(dst_p))
                    if not dst_existed_before or not overwritten_snap:
                        _call_with_ws_roots(
                            record_file_creation_undo,
                            dst_p,
                            guard=g,
                            target_path=dst_p,
                            op_kind="copy",
                            workspace_root=_matching_ws_root(dst_p, g),
                        )
                else:
                    try:
                        os.replace(str(src_p), str(dst_p))
                    except OSError:
                        shutil.move(str(src_p), str(dst_p))
                    _call_with_ws_roots(
                        record_move_undo,
                        src_p,
                        dst_p,
                        guard=g,
                        target_path=dst_p,
                        action_kind=act,
                        dst_existed_before=dst_existed_before,
                        overwritten_snap_path=overwritten_snap,
                        overwritten_trash_id=overwritten_tid,
                        workspace_root=_matching_ws_root(dst_p, g),
                    )
            except OSError as exc:
                lk_err = check_office_or_os_file_lock(src_p, exc=exc, for_write=(act != "copy"))
                if lk_err is not None:
                    return lk_err
                return {"ok": False, "action": act, "path": str(src_p), "destination": str(dst_p), "error": f"{type(exc).__name__}: {exc}"}

        out_mv: Dict[str, Any] = {
            "ok": True,
            "action": act,
            "path": str(src_p),
            "destination": str(dst_p),
        }
        if dst_existed_before:
            out_mv["overwritten"] = True
            if overwritten_tid:
                out_mv["overwritten_trash_id"] = overwritten_tid
        return out_mv

    return {
        "ok": False,
        "error_code": "INVALID_PARAMETER",
        "action": action,
        "allowed_actions": list(MANAGE_FILES_ACTIONS),
        "error": f"Invalid manage_files action `{action}`; expected one of {list(MANAGE_FILES_ACTIONS)}.",
    }


def undo_or_trash(
    action: str = "undo",
    path: Union[Path, str] = "",
    trash_id: str = "",
    reason: str = "",
    limit: int = 20,
    *,
    destination: Union[Path, str] = "",
    overwrite: bool = False,
    guard: Optional[WorkspaceGuard] = None,
) -> Dict[str, Any]:
    """Compatibility wrapper forwarding to `manage_files`."""
    act = _normalize_manage_files_action(action, default="undo")
    if act == "restore" and not (trash_id or "").strip() and not str(destination or "").strip():
        return {"ok": False, "action": "restore", "error": "Please provide trash_id (or 'latest') when action='restore'"}
    return manage_files(
        guard=guard,
        action=act,
        path=path,
        destination=destination,
        overwrite=overwrite,
        trash_id=trash_id,
        reason=reason,
        limit=limit,
    )
