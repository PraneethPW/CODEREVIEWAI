from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

import yaml

from .language_detection import detect_language


@dataclass
class Signal:
    rule_id: str
    title: str
    category: str
    severity: str
    line: int
    excerpt: str
    message: str


def _line(source: str, n: int) -> str:
    lines = source.splitlines()
    return lines[n - 1].strip() if 0 < n <= len(lines) else ""


def _signal(rule_id, title, category, severity, source, line, message):
    return Signal(rule_id, title, category, severity, line, _line(source, line), message)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _dict_flag_disabled(node: ast.AST, key_name: str) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and key.value == key_name:
            return isinstance(value, ast.Constant) and value.value is False
    return False


def _has_sensitive_log(line: str) -> bool:
    log_call = r"(?:print|console\.(?:log|warn|error)|(?:log|logger|logging)\.\w+|System\.(?:out|err)\.print\w*)"
    sensitive = r"(?:password|secret|token|authorization|api[_-]?key)"
    return bool(re.search(rf"\b{log_call}\s*\([^)]*\b{sensitive}\b", line, re.I))


def _looks_like_external_path(expression: str) -> bool:
    return bool(
        re.search(
            r"(?:request\.|req\.|request\[|params|query|user[_-]?input|filename|file[_-]?path|path[_-]?param)",
            expression,
            re.I,
        )
    )


def _python(source: str) -> list[Signal]:
    out: list[Signal] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [
            _signal(
                "PY-SYNTAX",
                "Python syntax error",
                "syntax",
                "high",
                source,
                exc.lineno or 1,
                exc.msg,
            )
        ]

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"eval", "exec"}:
                out.append(
                    _signal(
                        "PY-UNSAFE-EVAL",
                        f"Unsafe {name} execution",
                        "security",
                        "high",
                        source,
                        node.lineno,
                        f"{name} executes code derived at runtime.",
                    )
                )
            if name.startswith("subprocess.") and any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                out.append(
                    _signal(
                        "PY-SHELL-TRUE",
                        "Shell execution enabled",
                        "security",
                        "high",
                        source,
                        node.lineno,
                        "shell=True lets command strings be interpreted by a shell.",
                    )
                )
            if name in {"hashlib.md5", "hashlib.sha1"}:
                out.append(
                    _signal(
                        "GEN-WEAK-HASH",
                        "Weak cryptographic hash",
                        "security",
                        "medium",
                        source,
                        node.lineno,
                        f"{name} is not collision resistant for security-sensitive hashing.",
                    )
                )
            if name in {
                "pickle.load",
                "pickle.loads",
                "dill.load",
                "dill.loads",
                "marshal.load",
                "marshal.loads",
            } or (name == "yaml.load" and not any(keyword.arg == "Loader" for keyword in node.keywords)):
                out.append(
                    _signal(
                        "GEN-UNSAFE-DESERIALIZATION",
                        "Unsafe deserialization sink",
                        "security",
                        "high",
                        source,
                        node.lineno,
                        f"{name} can construct executable or trusted objects from data without an integrity boundary.",
                    )
                )
            if name in {"jwt.decode", "jose.jwt.decode"}:
                disabled = any(
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                ) or any(
                    keyword.arg == "options" and _dict_flag_disabled(keyword.value, "verify_signature")
                    for keyword in node.keywords
                )
                if disabled:
                    out.append(
                        _signal(
                            "GEN-JWT-NO-VERIFY",
                            "JWT signature verification disabled",
                            "security",
                            "high",
                            source,
                            node.lineno,
                            "The token is decoded while signature verification is explicitly disabled.",
                        )
                    )
            if name in {"open", "os.open", "pathlib.Path", "Path", "send_file"} and node.args:
                try:
                    path_expression = ast.unparse(node.args[0])
                except Exception:
                    path_expression = ""
                if _looks_like_external_path(path_expression):
                    out.append(
                        _signal(
                            "GEN-PATH-TRAVERSAL",
                            "Potential path traversal sink",
                            "security",
                            "high",
                            source,
                            node.lineno,
                            "A path-like external value reaches file access without visible canonicalisation or containment.",
                        )
                    )
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append(
                    _signal(
                        "PY-BARE-EXCEPT",
                        "Broad exception handler",
                        "quality",
                        "medium",
                        source,
                        node.lineno,
                        "A bare except masks interrupts and unexpected errors.",
                    )
                )
            elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                out.append(
                    _signal(
                        "GEN-SWALLOWED-EXCEPTION",
                        "Exception silently discarded",
                        "reliability",
                        "medium",
                        source,
                        node.lineno,
                        "The handler suppresses an exceptional condition without recovery, reporting, or propagation.",
                    )
                )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            branches = sum(
                isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.BoolOp, ast.Match))
                for child in ast.walk(node)
            )
            if branches + 1 > 10:
                out.append(
                    _signal(
                        "PY-COMPLEXITY",
                        "High cyclomatic complexity",
                        "complexity",
                        "medium",
                        source,
                        node.lineno,
                        f"Estimated cyclomatic complexity is {branches + 1}; consider extracting smaller functions.",
                    )
                )
            for default in node.args.defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    out.append(
                        _signal(
                            "PY-MUTABLE-DEFAULT",
                            "Mutable default argument",
                            "reliability",
                            "medium",
                            source,
                            node.lineno,
                            "Mutable defaults are shared between calls.",
                        )
                    )

    for line_number, line in enumerate(source.splitlines(), 1):
        if re.search(r"(?:password|secret|token|api[_-]?key)\s*=\s*['\"][^'\"]{8,}", line, re.I):
            out.append(_signal("GEN-HARDCODED-SECRET", "Possible hardcoded secret", "security", "high", source, line_number, "A credential-like value is embedded in submitted source."))
        if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|%\s*\(|\.format\()", line, re.I):
            out.append(_signal("PY-SQL-CONCAT", "SQL built through string construction", "security", "high", source, line_number, "String-built SQL can combine data with query syntax."))
        if re.search(r"\bdebug\s*=\s*True\b", line):
            out.append(_signal("PY-DEBUG-ENABLED", "Debug mode enabled", "security", "medium", source, line_number, "Debug mode can expose diagnostics or interactive tooling when enabled outside development."))
        if re.search(r"\bverify\s*=\s*False\b", line):
            out.append(_signal("GEN-TLS-VERIFY-DISABLED", "TLS certificate verification disabled", "security", "high", source, line_number, "The network request explicitly disables peer certificate verification."))
        if _has_sensitive_log(line):
            out.append(_signal("GEN-SENSITIVE-LOGGING", "Sensitive value written to logs", "security", "medium", source, line_number, "A credential or token-like value is passed to a logging or console sink."))
    return out


def _structured(filename: str, source: str, language: str) -> list[Signal]:
    try:
        document = json.loads(source) if language == "json" else yaml.safe_load(source)
    except Exception as exc:
        line_number = getattr(exc, "lineno", None) or getattr(getattr(exc, "problem_mark", None), "line", 0) + 1
        return [_signal(f"{language.upper()}-SYNTAX", f"Invalid {language.upper()} syntax", "syntax", "high", source, line_number, str(exc).splitlines()[0])]

    out: list[Signal] = []
    basename = PurePosixPath(filename.replace("\\", "/")).name.lower()
    if language == "json" and basename == "package.json" and isinstance(document, dict):
        dependencies: dict = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            value = document.get(key)
            if isinstance(value, dict):
                dependencies.update(value)
        for dependency, version in dependencies.items():
            if not isinstance(version, str):
                continue
            floating = version.strip().lower() in {"*", "latest", "next"}
            remote_unpinned = version.startswith(("http://", "git://", "git+http://", "git+https://")) and "#" not in version
            if floating or remote_unpinned:
                line_number = next((index for index, line in enumerate(source.splitlines(), 1) if re.search(rf"['\"]{re.escape(str(dependency))}['\"]\s*:", line)), 1)
                out.append(_signal("JSON-UNPINNED-DEPENDENCY", "Unpinned dependency source", "security", "medium", source, line_number, f"Dependency {dependency} uses the floating or unpinned source {version!r}."))
    if language == "yaml":
        for line_number, line in enumerate(source.splitlines(), 1):
            if re.search(r"\buses\s*:\s*[^\s@]+@(?:main|master|latest|head)\b", line, re.I):
                out.append(_signal("YAML-FLOATING-ACTION", "Workflow action uses a floating reference", "security", "medium", source, line_number, "The workflow action follows a mutable branch or floating tag instead of an immutable revision."))
    return out


def _delimiter_syntax(source: str, language: str) -> list[Signal]:
    """Conservative delimiter validator for languages without an embedded compiler."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    quote = None
    escaped = False
    for line_number, line in enumerate(source.splitlines(), 1):
        for char in line:
            if escaped:
                escaped = False
                continue
            if quote:
                if char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in {'"', "'", "`"}:
                quote = char
                continue
            if char in "([{":
                stack.append((char, line_number))
            elif char in pairs:
                if not stack or stack[-1][0] != pairs[char]:
                    return [_signal(f"{language.upper()}-SYNTAX", f"Unbalanced {language} delimiter", "syntax", "high", source, line_number, f"Unexpected closing delimiter {char}.")]
                stack.pop()
    if stack:
        delimiter, line_number = stack[-1]
        return [_signal(f"{language.upper()}-SYNTAX", f"Unbalanced {language} delimiter", "syntax", "high", source, line_number, f"Opening delimiter {delimiter} is not closed.")]
    return []


def _web(source: str, language: str) -> list[Signal]:
    out = _delimiter_syntax(source, language)
    for line_number, line in enumerate(source.splitlines(), 1):
        if re.search(r"\beval\s*\(", line):
            out.append(_signal("JS-UNSAFE-EVAL", "Unsafe eval execution", "security", "high", source, line_number, "eval executes dynamically assembled JavaScript."))
        if "dangerouslySetInnerHTML" in line or re.search(r"\.innerHTML\s*=", line):
            out.append(_signal("JS-DOM-SINK", "Unsafe HTML sink", "security", "high", source, line_number, "Raw HTML reaches a DOM sink; sanitisation must be demonstrated."))
        if re.search(r"(?:password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}", line, re.I):
            out.append(_signal("GEN-HARDCODED-SECRET", "Possible hardcoded secret", "security", "high", source, line_number, "A credential-like value is embedded in submitted source."))
        if re.search(r"while\s*\(true\)|for\s*\(;;\)", line):
            out.append(_signal("JS-BLOCKING-LOOP", "Potential blocking loop", "performance", "medium", source, line_number, "An unbounded loop can block the event loop."))
        if language == "typescript" and re.search(r":\s*(?:number|boolean)\s*=\s*['\"]", line):
            out.append(_signal("TS-TYPE-LITERAL", "Literal conflicts with declared type", "reliability", "high", source, line_number, "A string literal is assigned to a number or boolean declaration."))
        if re.search(r"(?:readFile|readFileSync|sendFile|createReadStream)\s*\([^)]*(?:req\.|request\.|params|query)", line, re.I):
            out.append(_signal("GEN-PATH-TRAVERSAL", "Potential path traversal sink", "security", "high", source, line_number, "A request-derived path reaches file access without visible canonicalisation or containment."))
        if re.search(r"rejectUnauthorized\s*:\s*false", line, re.I):
            out.append(_signal("GEN-TLS-VERIFY-DISABLED", "TLS certificate verification disabled", "security", "high", source, line_number, "The client explicitly accepts a peer without normal certificate verification."))
        if re.search(r"cors\s*\(\s*\{(?=[^}]*origin\s*:\s*['\"]\*['\"])(?=[^}]*credentials\s*:\s*true)", line, re.I):
            out.append(_signal("JS-CORS-WILDCARD-CREDENTIALS", "Credentialed wildcard CORS policy", "security", "high", source, line_number, "A wildcard origin is combined with credentialed cross-origin requests."))
        if re.search(r"\b(?:crypto\.)?createHash\s*\(\s*['\"](?:md5|sha1)['\"]", line, re.I):
            out.append(_signal("GEN-WEAK-HASH", "Weak cryptographic hash", "security", "medium", source, line_number, "MD5 or SHA-1 is not collision resistant for security-sensitive hashing."))
        if re.search(r"\bjwt\.decode\s*\(", line):
            out.append(_signal("GEN-JWT-NO-VERIFY", "JWT decoded without signature verification", "security", "high", source, line_number, "jwt.decode reads token claims without proving the token signature; use a verification API for authentication decisions."))
        if re.search(r"\b(?:nodeSerialize|serialize)\.unserialize\s*\(", line):
            out.append(_signal("GEN-UNSAFE-DESERIALIZATION", "Unsafe deserialization sink", "security", "high", source, line_number, "A general object deserializer can construct executable or trusted objects from untrusted data."))
        if _has_sensitive_log(line):
            out.append(_signal("GEN-SENSITIVE-LOGGING", "Sensitive value written to logs", "security", "medium", source, line_number, "A credential or token-like value is passed to a logging or console sink."))
        if re.search(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}", line):
            out.append(_signal("GEN-SWALLOWED-EXCEPTION", "Exception silently discarded", "reliability", "medium", source, line_number, "The catch block suppresses an exceptional condition without recovery, reporting, or propagation."))
    return out


def _java(source: str) -> list[Signal]:
    out = _delimiter_syntax(source, "java")
    for line_number, line in enumerate(source.splitlines(), 1):
        if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE).*\+", line, re.I):
            out.append(_signal("JAVA-SQL-CONCAT", "SQL built through string concatenation", "security", "high", source, line_number, "User-controlled data may be combined with SQL syntax; use a prepared statement."))
        if re.search(r"(?:password|secret|token|api[_-]?key)\s*=\s*\"[^\"]{8,}", line, re.I):
            out.append(_signal("GEN-HARDCODED-SECRET", "Possible hardcoded secret", "security", "high", source, line_number, "A credential-like value is embedded in submitted source."))
        if re.search(r"new\s+File\s*\([^)]*request\.getParameter", line, re.I):
            out.append(_signal("GEN-PATH-TRAVERSAL", "Potential path traversal sink", "security", "high", source, line_number, "A request parameter reaches a file path without visible canonicalisation or containment."))
        if re.search(r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"", line, re.I):
            out.append(_signal("GEN-WEAK-HASH", "Weak cryptographic hash", "security", "medium", source, line_number, "MD5 or SHA-1 is not collision resistant for security-sensitive hashing."))
        if "new ObjectInputStream" in line:
            out.append(_signal("GEN-UNSAFE-DESERIALIZATION", "Native object deserialization sink", "security", "high", source, line_number, "Native object deserialization requires a strict trust boundary and allow-list."))
        if _has_sensitive_log(line):
            out.append(_signal("GEN-SENSITIVE-LOGGING", "Sensitive value written to logs", "security", "medium", source, line_number, "A credential or token-like value is passed to a logging or console sink."))
        if re.search(r"\bcatch\s*\([^)]*\)\s*\{\s*\}", line):
            out.append(_signal("GEN-SWALLOWED-EXCEPTION", "Exception silently discarded", "reliability", "medium", source, line_number, "The catch block suppresses an exceptional condition without recovery, reporting, or propagation."))
    return out


def analyze_source(filename: str, source: str, selected_language: str | None = None, enabled: dict | None = None) -> tuple[str, list[Signal]]:
    language = detect_language(filename, source, selected_language)
    if language == "python":
        signals = _python(source)
    elif language in {"javascript", "typescript", "html"}:
        signals = _web(source, language)
    elif language == "java":
        signals = _java(source)
    elif language in {"json", "yaml"}:
        signals = _structured(filename, source, language)
    elif language == "css":
        signals = _delimiter_syntax(source, language)
    else:
        signals = []
    if enabled:
        signals = [signal for signal in signals if enabled.get(signal.category, True)]
    seen: set[tuple[str, int]] = set()
    unique: list[Signal] = []
    for signal in signals:
        key = (signal.rule_id, signal.line)
        if key not in seen:
            seen.add(key)
            unique.append(signal)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return language, sorted(unique, key=lambda signal: (rank[signal.severity], signal.line))
