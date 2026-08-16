from __future__ import annotations
import re

EXTENSIONS = {"py": "python", "js": "javascript", "jsx": "javascript", "ts": "typescript", "tsx": "typescript", "java": "java", "html": "html", "css": "css", "json": "json", "yml": "yaml", "yaml": "yaml"}

def detect_language(filename: str, source: str, selected: str | None = None) -> str:
    if selected and selected != "auto": return selected.lower()
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in EXTENSIONS: return EXTENSIONS[ext]
    if re.search(r"\b(def|import|print|except)\b", source): return "python"
    if re.search(r"\b(function|const|let|interface)\b", source): return "typescript"
    if "public class" in source: return "java"
    return "text"
