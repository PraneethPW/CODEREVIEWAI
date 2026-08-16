from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

SUPPORTED = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".html", ".css", ".json", ".yml", ".yaml"}
IGNORED = {"node_modules", "dist", "build", ".next", "coverage", ".venv", "venv", "__pycache__", ".git", "target", "vendor"}
MAX_FILE_BYTES = 500_000
MAX_PROJECT_BYTES = 10_000_000
MAX_FILES = 250

@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str

def allowed_path(raw_path: str) -> bool:
    original = raw_path.replace("\\", "/")
    if original.startswith("/") or (len(original) > 1 and original[1] == ":"):
        return False
    normalized = original
    path = PurePosixPath(normalized)
    return (
        bool(normalized)
        and ".." not in path.parts
        and not any(part in IGNORED for part in path.parts)
        and path.suffix.lower() in SUPPORTED
    )

def decode_source(path: str, data: bytes) -> SourceFile | None:
    if not allowed_path(path) or len(data) > MAX_FILE_BYTES or b"\x00" in data:
        return None
    try:
        return SourceFile(path.replace("\\", "/").lstrip("/"), data.decode("utf-8"))
    except UnicodeDecodeError:
        return None

def extract_zip(data: bytes) -> list[SourceFile]:
    if len(data) > MAX_PROJECT_BYTES:
        raise ValueError("ZIP exceeds the 10 MB project limit")
    files: list[SourceFile] = []
    expanded = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive") from exc
    with archive:
        for entry in archive.infolist():
            archive_path=entry.filename.replace("\\","/")
            if archive_path.startswith("/") or (len(archive_path)>1 and archive_path[1]==":") or ".." in PurePosixPath(archive_path).parts:
                raise ValueError("ZIP contains an unsafe file path")
            if entry.is_dir() or not allowed_path(entry.filename):
                continue
            expanded += entry.file_size
            if expanded > MAX_PROJECT_BYTES:
                raise ValueError("Expanded ZIP exceeds the 10 MB project limit")
            if len(files) >= MAX_FILES:
                raise ValueError("ZIP contains more than 250 supported source files")
            source = decode_source(entry.filename, archive.read(entry))
            if source:
                files.append(source)
    if not files:
        raise ValueError("ZIP contains no supported UTF-8 source files")
    return files
