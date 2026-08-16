import io
import zipfile

def create_project(client, auth):
    response = client.post("/api/v1/projects", headers=auth, json={"name":"Student Project","language":"Auto detected"})
    assert response.status_code == 200
    return response.json()["id"]

def test_upload_scan_fix_verify_download(client, auth):
    project_id = create_project(client, auth)
    source = 'API_TOKEN = "a-secret-value-123"\nresult = eval(user_input)\n'
    response = client.post("/api/v1/scans/start", headers=auth, json={
        "project_id": project_id,
        "input_type": "paste",
        "source": source,
        "filename": "unsafe.py",
        "language": "auto",
        "review_mode": "Balanced",
    })
    assert response.status_code == 202
    scan_id = response.json()["id"]

    status = client.get(f"/api/v1/scans/{scan_id}/status", headers=auth)
    assert status.status_code == 200
    assert status.json()["status"] == "COMPLETED"
    events = client.get(f"/api/v1/scans/{scan_id}/events", headers=auth).json()
    assert [event["stage"] for event in events][-1] == "COMPLETE"
    assert all("AST created" not in event["message"] for event in events)

    scan = client.get(f"/api/v1/scans/{scan_id}", headers=auth).json()
    assert len(scan["findings"]) == 2
    secret_finding = next(item for item in scan["findings"] if item["rule_id"] == "GEN-HARDCODED-SECRET")
    assert "a-secret-value-123" not in secret_finding["excerpt"]
    eval_finding = next(item for item in scan["findings"] if item["rule_id"] == "PY-UNSAFE-EVAL")

    proposal_response = client.post(f"/api/v1/findings/{eval_finding['id']}/generate-fix", headers=auth, json={"use_ai": True})
    assert proposal_response.status_code == 200
    proposal = proposal_response.json()
    assert proposal["can_apply"] is True
    assert "ast.literal_eval" in proposal["replacement_code"]
    applied = client.post(f"/api/v1/fixes/{proposal['id']}/apply", headers=auth)
    assert applied.status_code == 200
    verification = client.post(f"/api/v1/scans/{scan_id}/verify", headers=auth).json()
    assert verification["tests"]["executed"] is False
    assert all(item["rule_id"] != "PY-UNSAFE-EVAL" for item in verification["remaining"])

    artifact = client.get(f"/api/v1/scans/{scan_id}/reviewed-file", headers=auth)
    assert artifact.status_code == 200
    assert "ast.literal_eval" in artifact.text
    assert "import ast" in artifact.text

def test_zip_traversal_is_rejected(client, auth):
    project_id = create_project(client, auth)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../escape.py", "print('unsafe path')")
    response = client.post(
        "/api/v1/import/project/start",
        headers=auth,
        data={"project_id": project_id},
        files={"uploads": ("project.zip", archive.getvalue(), "application/zip")},
    )
    assert response.status_code == 422
    assert "unsafe" in response.json()["detail"].lower()

def test_valid_zip_is_scanned_and_downloaded_as_zip(client, auth):
    project_id = create_project(client, auth)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("src/unsafe.js", "export const run = value => eval(value);")
        zipped.writestr("config/settings.json", '{"review": true}')
        zipped.writestr("node_modules/ignored.js", "eval('ignored')")
    response = client.post(
        "/api/v1/import/project/start",
        headers=auth,
        data={"project_id": project_id},
        files={"uploads": ("project.zip", archive.getvalue(), "application/zip")},
    )
    assert response.status_code == 202
    scan_id = response.json()["id"]
    scan = client.get(f"/api/v1/scans/{scan_id}", headers=auth).json()
    assert [item["path"] for item in scan["files"]] == ["src/unsafe.js", "config/settings.json"]
    assert scan["findings"][0]["rule_id"] == "JS-UNSAFE-EVAL"
    artifact = client.get(f"/api/v1/scans/{scan_id}/reviewed-file", headers=auth)
    assert artifact.status_code == 200
    assert artifact.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(artifact.content)) as downloaded:
        assert set(downloaded.namelist()) == {"src/unsafe.js", "config/settings.json"}

def test_invalid_python_returns_real_line(client, auth):
    project_id = create_project(client, auth)
    response = client.post("/api/v1/scans/start", headers=auth, json={
        "project_id":project_id,"input_type":"upload","source":"def broken():\n  print('x'\n","filename":"broken.py","language":"auto","review_mode":"Balanced"
    })
    scan = client.get(f"/api/v1/scans/{response.json()['id']}", headers=auth).json()
    finding = scan["findings"][0]
    assert finding["rule_id"] == "PY-SYNTAX"
    assert finding["line"] == 2
