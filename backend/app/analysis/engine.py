from __future__ import annotations
import ast, json, re
import yaml
from dataclasses import dataclass
from .language_detection import detect_language

@dataclass
class Signal:
    rule_id: str; title: str; category: str; severity: str; line: int; excerpt: str; message: str

def _line(source: str, n: int) -> str:
    lines = source.splitlines()
    return lines[n - 1].strip() if 0 < n <= len(lines) else ""

def _signal(rule_id, title, category, severity, source, line, message):
    return Signal(rule_id, title, category, severity, line, _line(source, line), message)

def _python(source: str) -> list[Signal]:
    out=[]
    try: tree=ast.parse(source)
    except SyntaxError as exc: return [_signal("PY-SYNTAX", "Python syntax error", "syntax", "high", source, exc.lineno or 1, exc.msg)]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
            if name in {"eval", "exec"}: out.append(_signal("PY-UNSAFE-EVAL", f"Unsafe {name} execution", "security", "high", source, node.lineno, f"{name} executes code derived at runtime."))
            if name.startswith("subprocess.") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords): out.append(_signal("PY-SHELL-TRUE", "Shell execution enabled", "security", "high", source, node.lineno, "shell=True lets command strings be interpreted by a shell."))
        if isinstance(node, ast.ExceptHandler) and node.type is None: out.append(_signal("PY-BARE-EXCEPT", "Broad exception handler", "quality", "medium", source, node.lineno, "A bare except masks interrupts and unexpected errors."))
        if isinstance(node, ast.FunctionDef):
            branches=sum(isinstance(child,(ast.If,ast.For,ast.While,ast.Try,ast.BoolOp,ast.Match)) for child in ast.walk(node))
            if branches+1>10: out.append(_signal("PY-COMPLEXITY", "High cyclomatic complexity", "complexity", "medium", source, node.lineno, f"Estimated cyclomatic complexity is {branches+1}; consider extracting smaller functions."))
            for default in node.args.defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)): out.append(_signal("PY-MUTABLE-DEFAULT", "Mutable default argument", "reliability", "medium", source, node.lineno, "Mutable defaults are shared between calls."))
    for i, line in enumerate(source.splitlines(),1):
        if re.search(r"(?:password|secret|token|api[_-]?key)\s*=\s*['\"][^'\"]{8,}", line, re.I): out.append(_signal("GEN-HARDCODED-SECRET", "Possible hardcoded secret", "security", "high", source, i, "A credential-like value is embedded in submitted source."))
        if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:\+|%\s*\(|\.format\()", line, re.I): out.append(_signal("PY-SQL-CONCAT", "SQL built through string construction", "security", "high", source, i, "String-built SQL can combine data with query syntax."))
    return out

def _structured(source: str, language: str) -> list[Signal]:
    try:
        json.loads(source) if language=="json" else yaml.safe_load(source)
        return []
    except Exception as exc:
        line=getattr(exc,"lineno",None) or getattr(getattr(exc,"problem_mark",None),"line",0)+1
        return [_signal(f"{language.upper()}-SYNTAX",f"Invalid {language.upper()} syntax","syntax","high",source,line,str(exc).splitlines()[0])]

def _delimiter_syntax(source: str, language: str) -> list[Signal]:
    """Conservative delimiter validator for languages without an embedded compiler."""
    pairs={')':'(',']':'[','}':'{'}; stack=[]; quote=None; escaped=False
    for line_number,line in enumerate(source.splitlines(),1):
        for char in line:
            if escaped: escaped=False;continue
            if quote:
                if char=='\\': escaped=True
                elif char==quote: quote=None
                continue
            if char in {'"',"'",'`'}: quote=char;continue
            if char in '([{': stack.append((char,line_number))
            elif char in pairs:
                if not stack or stack[-1][0]!=pairs[char]: return [_signal(f"{language.upper()}-SYNTAX",f"Unbalanced {language} delimiter","syntax","high",source,line_number,f"Unexpected closing delimiter {char}.")]
                stack.pop()
    if stack:
        delimiter,line_number=stack[-1]
        return [_signal(f"{language.upper()}-SYNTAX",f"Unbalanced {language} delimiter","syntax","high",source,line_number,f"Opening delimiter {delimiter} is not closed.")]
    return []

def _web(source: str, language: str) -> list[Signal]:
    out=_delimiter_syntax(source,language)
    for i,line in enumerate(source.splitlines(),1):
        if re.search(r"\beval\s*\(",line): out.append(_signal("JS-UNSAFE-EVAL","Unsafe eval execution","security","high",source,i,"eval executes dynamically assembled JavaScript."))
        if "dangerouslySetInnerHTML" in line: out.append(_signal("JS-DOM-SINK","Unsafe HTML sink","security","high",source,i,"Raw HTML reaches a DOM sink; sanitisation must be demonstrated."))
        if re.search(r"(?:password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}",line,re.I): out.append(_signal("GEN-HARDCODED-SECRET","Possible hardcoded secret","security","high",source,i,"A credential-like value is embedded in submitted source."))
        if re.search(r"while\s*\(true\)|for\s*\(;;\)", line): out.append(_signal("JS-BLOCKING-LOOP","Potential blocking loop","performance","medium",source,i,"An unbounded loop can block the event loop."))
        if language=="typescript" and re.search(r":\s*(?:number|boolean)\s*=\s*['\"]",line): out.append(_signal("TS-TYPE-LITERAL","Literal conflicts with declared type","reliability","high",source,i,"A string literal is assigned to a number or boolean declaration."))
    return out

def _java(source: str) -> list[Signal]:
    out=_delimiter_syntax(source,"java")
    for i,line in enumerate(source.splitlines(),1):
        if re.search(r"(?:SELECT|INSERT|UPDATE|DELETE).*\+",line,re.I): out.append(_signal("JAVA-SQL-CONCAT","SQL built through string concatenation","security","high",source,i,"User-controlled data may be combined with SQL syntax; use a prepared statement."))
        if re.search(r"(?:password|secret|token|api[_-]?key)\s*=\s*\"[^\"]{8,}",line,re.I): out.append(_signal("GEN-HARDCODED-SECRET","Possible hardcoded secret","security","high",source,i,"A credential-like value is embedded in submitted source."))
    return out

def analyze_source(filename: str, source: str, selected_language: str | None = None, enabled: dict | None = None) -> tuple[str, list[Signal]]:
    language=detect_language(filename,source,selected_language)
    signals=_python(source) if language=="python" else _web(source,language) if language in {"javascript","typescript"} else _java(source) if language=="java" else _structured(source,language) if language in {"json","yaml"} else _delimiter_syntax(source,language) if language=="css" else []
    seen=set(); unique=[]
    for s in signals:
        key=(s.rule_id,s.line)
        if key not in seen: seen.add(key); unique.append(s)
    rank={"critical":0,"high":1,"medium":2,"low":3,"info":4}
    return language, sorted(unique,key=lambda s:(rank[s.severity],s.line))
