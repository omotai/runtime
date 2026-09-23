import pytest
from fastapi.testclient import TestClient

from omotai.dashboard.db import init_db
from omotai.dashboard.server import app, mask_api_key


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_mask_api_key_unit():
    # Standard omotai key
    full_key = "sk-omotai-0123456789abcdef0123456789abcdef"
    masked = mask_api_key(full_key)
    assert masked.startswith("sk-omotai-")
    assert masked.endswith("cdef")
    assert "*" * 28 in masked
    assert full_key != masked

    # Custom short key with prefix
    short_key = "sk-omotai-1234"
    assert mask_api_key(short_key) == "sk-omotai-****"

    # Key without prefix
    other_key = "1234567890"
    assert mask_api_key(other_key) == "******7890"


def test_create_and_list_agents_api():
    client = TestClient(app)

    # 1. Create agent
    agent_name = "test-agent-51"
    create_res = client.post("/api/agents", json={"name": agent_name})
    assert create_res.status_code == 200
    created_data = create_res.json()
    assert created_data["name"] == agent_name
    full_key = created_data["api_key"]
    assert full_key.startswith("sk-omotai-")
    agent_id = created_data["id"]

    # 2. List agents - key must be masked
    list_res = client.get("/api/agents")
    assert list_res.status_code == 200
    agents = list_res.json()

    target_agent = next((a for a in agents if a["id"] == agent_id), None)
    assert target_agent is not None
    assert target_agent["name"] == agent_name

    masked_key = target_agent["api_key"]
    assert masked_key != full_key
    assert "*" in masked_key
    assert masked_key.startswith("sk-omotai-")
    assert masked_key.endswith(full_key[-4:])

    # 3. Clean up
    del_res = client.delete(f"/api/agents/{agent_id}")
    assert del_res.status_code == 200
