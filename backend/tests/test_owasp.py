import pytest

from app.analysis import OWASP_TOP_10, analyze_source, owasp_for_rule, owasp_summary


EXPECTED_CATEGORIES = [
    "Broken Access Control",
    "Security Misconfiguration",
    "Software Supply Chain Failures",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Authentication Failures",
    "Software or Data Integrity Failures",
    "Security Logging and Alerting Failures",
    "Mishandling of Exceptional Conditions",
]


def signal_for(filename, source, rule_id):
    _, signals = analyze_source(filename, source, "auto")
    return next(signal for signal in signals if signal.rule_id == rule_id)


def test_catalog_contains_the_exact_2025_top_ten():
    assert [item["category_id"] for item in OWASP_TOP_10] == [f"A{i:02}:2025" for i in range(1, 11)]
    assert [item["category_name"] for item in OWASP_TOP_10] == EXPECTED_CATEGORIES


@pytest.mark.parametrize(
    ("filename", "source", "rule_id", "category_id"),
    [
        ("files.py", "def read_file(filename):\n    return open(filename).read()\n", "GEN-PATH-TRAVERSAL", "A01:2025"),
        ("client.py", "response = requests.get(url, verify=False)\n", "GEN-TLS-VERIFY-DISABLED", "A02:2025"),
        ("package.json", '{"dependencies": {"demo-lib": "latest"}}', "JSON-UNPINNED-DEPENDENCY", "A03:2025"),
        ("hash.py", "digest = hashlib.md5(payload).hexdigest()\n", "GEN-WEAK-HASH", "A04:2025"),
        ("execute.py", "result = eval(user_input)\n", "PY-UNSAFE-EVAL", "A05:2025"),
        ("auth.py", 'claims = jwt.decode(token, options={"verify_signature": False})\n', "GEN-JWT-NO-VERIFY", "A07:2025"),
        ("codec.py", "value = pickle.loads(payload)\n", "GEN-UNSAFE-DESERIALIZATION", "A08:2025"),
        ("audit.py", 'logger.info("token=%s", token)\n', "GEN-SENSITIVE-LOGGING", "A09:2025"),
        ("errors.py", "try:\n    work()\nexcept ValueError:\n    pass\n", "GEN-SWALLOWED-EXCEPTION", "A10:2025"),
    ],
)
def test_supported_static_evidence_maps_to_owasp(filename, source, rule_id, category_id):
    signal = signal_for(filename, source, rule_id)
    mapping = owasp_for_rule(signal.rule_id)
    assert mapping["edition"] == "2025"
    assert mapping["category_id"] == category_id
    assert mapping["cwe_ids"]


def test_quality_signal_is_not_misrepresented_as_owasp():
    signal = signal_for("defaults.py", "def add(items=[]):\n    items.append(1)\n", "PY-MUTABLE-DEFAULT")
    assert owasp_for_rule(signal.rule_id) is None


def test_summary_distinguishes_no_evidence_from_not_assessed():
    summary = owasp_summary(["PY-UNSAFE-EVAL", "PY-MUTABLE-DEFAULT"])
    injection = next(item for item in summary["categories"] if item["category_id"] == "A05:2025")
    insecure_design = next(item for item in summary["categories"] if item["category_id"] == "A06:2025")
    assert summary["mapped_findings"] == 1
    assert injection["finding_count"] == 1
    assert injection["coverage"] == "limited_static"
    assert insecure_design["finding_count"] == 0
    assert insecure_design["coverage"] == "not_assessed"
    assert "does not prove" in summary["disclaimer"]


def test_scan_api_serializes_mapping_and_real_owasp_telemetry(client, auth):
    project = client.post(
        "/api/v1/projects",
        headers=auth,
        json={"name": "OWASP Review", "language": "Auto detected"},
    ).json()
    started = client.post(
        "/api/v1/scans/start",
        headers=auth,
        json={
            "project_id": project["id"],
            "input_type": "paste",
            "source": "result = eval(user_input)\n",
            "filename": "unsafe.py",
            "language": "auto",
            "review_mode": "Balanced",
        },
    )
    assert started.status_code == 202
    scan_id = started.json()["id"]
    scan = client.get(f"/api/v1/scans/{scan_id}", headers=auth).json()
    assert scan["findings"][0]["owasp"]["category_id"] == "A05:2025"
    assert scan["owasp"]["mapped_findings"] == 1

    telemetry = client.get(f"/api/v1/scans/{scan_id}/owasp", headers=auth)
    assert telemetry.status_code == 200
    injection = next(item for item in telemetry.json()["categories"] if item["category_id"] == "A05:2025")
    assert injection["finding_count"] == 1

