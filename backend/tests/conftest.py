import os
import tempfile
from pathlib import Path

database_file = Path(tempfile.gettempdir()) / "codereview_ai_test.db"
if database_file.exists():
    database_file.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{database_file.as_posix()}"
os.environ.pop("OPENROUTER_API_KEY", None)

import pytest
from fastapi.testclient import TestClient
from app.main import app, engine

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()
    if database_file.exists():
        database_file.unlink()

@pytest.fixture()
def auth(client):
    response = client.post("/api/v1/auth/register", json={"name":"Test Student","email":f"student-{os.urandom(4).hex()}@example.com","password":"correct-horse-123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
