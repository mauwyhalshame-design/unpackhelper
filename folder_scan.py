import hashlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from errors import AnalysisError
from fingerprint import fingerprint
from pe_parser import parse_pe
from report import build_result


@dataclass
class FolderItem:
    path: str
    status: str
    reason: str = ""
    result: Optional[dict] = None
    sha256: Optional[str] = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_files(root: Path, recursive: bool):
    iterator = root.rglob("*") if recursive else root.iterdir()
    for path in iterator:
        if path.is_symlink():
            yield path, "Skipped", "symbolic link"
        elif path.is_file():
            yield path, None, ""


def _review_reasons(result: dict) -> list[str]:
    return list(result["assessment"]["reasons"])


def scan_folder(root: Path, max_size: int, recursive: bool = True) -> dict:
    if not root.exists():
        raise AnalysisError(f"المجلد غير موجود: {root}")
    if not root.is_dir():
        raise AnalysisError(f"المسار ليس مجلدًا: {root}")

    items: list[FolderItem] = []
    hashes: dict[str, list[str]] = defaultdict(list)
    for path, preset_status, preset_reason in _iter_files(root, recursive):
        display_path = str(path)
        if preset_status:
            items.append(FolderItem(display_path, preset_status, preset_reason))
            continue
        try:
            size = path.stat().st_size
            if size > max_size:
                items.append(FolderItem(display_path, "Skipped", f"size exceeds limit ({size} bytes)"))
                continue
            file_hash = _sha256(path)
            hashes[file_hash].append(display_path)
            try:
                info = parse_pe(path, max_size=max_size)
            except AnalysisError as exc:
                if "ليس ملف PE صالحًا" in str(exc):
                    items.append(FolderItem(display_path, "Non-PE", sha256=file_hash))
                else:
                    items.append(FolderItem(display_path, "Error", str(exc), sha256=file_hash))
                continue
            result = build_result(info, fingerprint(info))
            result["review_reasons"] = _review_reasons(result)
            items.append(FolderItem(display_path, "PE", result=result, sha256=file_hash))
        except (OSError, PermissionError) as exc:
            items.append(FolderItem(display_path, "Error", str(exc)))

    counts = {status: sum(item.status == status for item in items) for status in ("PE", "Non-PE", "Error", "Skipped")}
    duplicate_groups = [paths for paths in hashes.values() if len(paths) > 1]
    pe_items = [item for item in items if item.status == "PE"]
    review_items = [item for item in pe_items if item.result and item.result["review_reasons"]]
    return {
        "folder": str(root),
        "recursive": recursive,
        "total_files": len(items),
        "counts": counts,
        "pe_files": [item.__dict__ for item in pe_items],
        "review_files": [{"path": item.path, "reasons": item.result["review_reasons"]} for item in review_items],
        "errors": [{"path": item.path, "reason": item.reason} for item in items if item.status == "Error"],
        "skipped": [{"path": item.path, "reason": item.reason} for item in items if item.status == "Skipped"],
        "duplicate_groups": duplicate_groups,
    }
