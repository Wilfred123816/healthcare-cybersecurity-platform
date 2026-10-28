
from fastapi.testclient import TestClient

from Backend.app.main import app


client = TestClient(app)


def test_root_endpoint_returns_api_message():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
    "message": "Healthcare Cybersecurity Platform API",
    "status": "running",
}


def test_health_endpoint_returns_healthy_status():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_openapi_documentation_is_available():
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()
    assert schema["info"]["title"] == "Healthcare Cybersecurity Platform"
