import json
from pathlib import Path
from typing import Optional
from errors import AnalysisError

DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024

def load_config(path: Optional[str]) -> dict:
    if not path:
        return {"max_file_size": DEFAULT_MAX_FILE_SIZE}
    config_path = Path(path)
    if not config_path.is_file():
        raise AnalysisError(f"ملف الإعدادات غير موجود: {config_path}")
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"ملف الإعدادات غير صالح: {exc}") from exc
    if not isinstance(value, dict):
        raise AnalysisError("يجب أن يكون ملف الإعدادات كائن JSON")
    max_size = value.get("max_file_size", DEFAULT_MAX_FILE_SIZE)
    if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size <= 0:
        raise AnalysisError("الإعداد max_file_size يجب أن يكون عددًا صحيحًا موجبًا")
    return {"max_file_size": max_size}
