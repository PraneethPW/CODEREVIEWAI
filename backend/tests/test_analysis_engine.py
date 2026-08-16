from app.analysis import analyze_source

def rules(filename, source):
    return {signal.rule_id for signal in analyze_source(filename, source, "auto")[1]}

def test_representative_language_signals():
    assert "PY-SYNTAX" in rules("broken.py", "def broken(:\n  pass")
    assert "JS-UNSAFE-EVAL" in rules("unsafe.js", "export const run = value => eval(value);")
    assert "JS-DOM-SINK" in rules("preview.tsx", "return <div dangerouslySetInnerHTML={{__html: html}} />;")
    assert "TS-TYPE-LITERAL" in rules("types.ts", 'const count: number = "five";')
    assert "JAVA-SQL-CONCAT" in rules("User.java", 'String sql = "SELECT * FROM users WHERE id=" + id;')

def test_structured_and_delimiter_syntax():
    assert "JSON-SYNTAX" in rules("invalid.json", '{"value": }')
    assert "CSS-SYNTAX" in rules("broken.css", ".card { color: red;")
