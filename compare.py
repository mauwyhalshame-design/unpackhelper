import hashlib
from pathlib import Path

from errors import AnalysisError


def file_sha256(path: Path) -> str:
    if not path.exists():
        raise AnalysisError(f"الملف غير موجود: {path}")
    if not path.is_file():
        raise AnalysisError(f"المسار ليس ملفًا: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except PermissionError as exc:
        raise AnalysisError(f"لا توجد صلاحية لقراءة الملف: {path}") from exc
    except OSError as exc:
        raise AnalysisError(f"تعذر قراءة الملف: {exc}") from exc
    return digest.hexdigest()


def compare_files(first: Path, second: Path) -> dict:
    first_hash = file_sha256(first)
    second_hash = file_sha256(second)
    return {
        "file1": str(first),
        "sha256_1": first_hash,
        "file2": str(second),
        "sha256_2": second_hash,
        "match": first_hash == second_hash,
        "note": "Hash equality means identical bytes; it is not a safety verdict.",
    }
