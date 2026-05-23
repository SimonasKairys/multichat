import pytest
from fastapi.testclient import TestClient
import sqlite3
import json
import shutil
from pathlib import Path
import asyncio

import src.multichat.database as db
import src.multichat.api as api
from src.multichat.api import app
from src.multichat.core import WORKSPACE_ROOT
import src.multichat.providers as providers

@pytest.fixture(autouse=True)
def setup_temp_db(tmp_path, monkeypatch):
    # Set a temporary database path to avoid polluting the actual db
    temp_db = tmp_path / "test_chat.db"
    monkeypatch.setattr(db, "DB_PATH", temp_db)
    db.init_db()
    yield temp_db

def test_sqlite_wal_mode(setup_temp_db):
    # Verify that WAL journal mode was enabled successfully
    with sqlite3.connect(setup_temp_db) as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.upper() == "WAL"

def test_worm_cryptographic_chaining(setup_temp_db):
    # Add a sequence of messages
    db.add_message("user", "Hello World", "user")
    db.add_message("@agy", "Hello User, this is Agy.", "llm", {"model": "agy"})
    db.add_message("user", "Perform validation.", "user")
    
    # Verify integrity of log chain
    verification = db.verify_log_chain()
    assert verification["valid"] is True
    assert verification["total_messages"] == 3
    assert verification["corrupted_count"] == 0

    # Tamper with the database to simulate an adversarial breach
    with sqlite3.connect(setup_temp_db) as conn:
        # Update text of the second message
        conn.execute("UPDATE messages SET text = 'Tampered Response' WHERE sender = '@agy'")
        conn.commit()

    # Re-verify and ensure breach is successfully detected
    tampered_verification = db.verify_log_chain()
    assert tampered_verification["valid"] is False
    assert tampered_verification["corrupted_count"] > 0
    assert "SHA-256 mismatch" in tampered_verification["corrupted_details"][0]["error"]

def test_diagnostics_endpoint():
    client = TestClient(app)
    resp = client.get("/api/health/diagnostics")
    assert resp.status_code == 200
    data = resp.json()
    assert "claude" in data
    assert "agy" in data
    assert "ollama" in data
    assert "openrouter" in data
    for provider in ("claude", "agy", "ollama", "openrouter"):
        assert "status" in data[provider]
        assert "installed" in data[provider]

def test_agy_model_configuration(setup_temp_db, monkeypatch, tmp_path):
    from pathlib import Path
    
    # Mock home directory state path in AgyCLIProvider
    dummy_home = tmp_path / "mock_home"
    dummy_home.mkdir()
    state_dir = dummy_home / ".gemini" / "antigravity"
    state_dir.mkdir(parents=True, exist_ok=True)
    state_file = state_dir / "antigravity_state.pbtxt"
    state_file.write_text("last_selected_agent_model: MODEL_PLACEHOLDER_M27\n")
    
    # Patch Path.home() inside AgyCLIProvider
    monkeypatch.setattr(Path, "home", lambda: dummy_home)
    
    client = TestClient(app, client=("127.0.0.1", 50000))
    
    # 1. Verify get diagnostics returns raw active placeholder and model name
    resp = client.get("/api/health/diagnostics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agy"]["active_model"] == "Gemini 3.5 Flash (High)"
    assert data["agy"]["active_placeholder"] == "MODEL_PLACEHOLDER_M27"
    
    # 2. Verify saving new model placeholder updates state file
    config_payload = {
        "max_exchanges": 1,
        "max_token_budget": 100000,
        "context_limit": 20,
        "claude": {"enabled": True, "model": "claude-sonnet-4-6"},
        "agy": {"enabled": True, "model": "MODEL_PLACEHOLDER_M26"},
        "ollama": {"enabled": False, "host": "http://localhost:11434", "model": "llama3.2"},
        "openrouter": {"enabled": False, "api_key": "", "model": ""}
    }
    
    resp_save = client.post("/config", json=config_payload)
    assert resp_save.status_code == 200
    
    # Verify the state file got updated successfully
    updated_state = state_file.read_text()
    assert "last_selected_agent_model: MODEL_PLACEHOLDER_M26" in updated_state
    
    # Verify diagnostics now returns updated model
    resp2 = client.get("/api/health/diagnostics")
    assert resp2.json()["agy"]["active_model"] == "Gemini 3.5 Flash (Medium)"

def test_openrouter_api_key_persistence(setup_temp_db, monkeypatch, tmp_path):
    import src.multichat.config as cfg_module
    
    # Mock CONFIG_PATH to a temporary file
    temp_config = tmp_path / "config.json"
    monkeypatch.setattr(cfg_module, "CONFIG_PATH", temp_config)
    
    client = TestClient(app, client=("127.0.0.1", 50000))
    
    # 1. Post configuration with an OpenRouter API key
    payload = {
        "max_exchanges": 1,
        "max_token_budget": 100000,
        "context_limit": 20,
        "claude": {"enabled": True, "model": "claude-sonnet-4-6"},
        "agy": {"enabled": True, "model": "MODEL_PLACEHOLDER_M27"},
        "ollama": {"enabled": False, "host": "http://localhost:11434", "model": "llama3.2"},
        "openrouter": {"enabled": True, "api_key": "sk-or-test-key-12345", "model": "x-ai/grok-4.3"}
    }
    
    resp_save = client.post("/config", json=payload)
    assert resp_save.status_code == 200
    
    # 2. Load config via GET /config and verify the key is masked
    resp_get = client.get("/config")
    assert resp_get.status_code == 200
    get_data = resp_get.json()
    assert get_data["openrouter"]["api_key"] == "********"
    assert get_data["openrouter"]["model"] == "x-ai/grok-4.3"
    
    # 3. Post config again with the masked key and verify the key is preserved in the file
    payload2 = {
        "max_exchanges": 1,
        "max_token_budget": 100000,
        "context_limit": 20,
        "claude": {"enabled": True, "model": "claude-sonnet-4-6"},
        "agy": {"enabled": True, "model": "MODEL_PLACEHOLDER_M27"},
        "ollama": {"enabled": False, "host": "http://localhost:11434", "model": "llama3.2"},
        "openrouter": {"enabled": True, "api_key": "********", "model": "x-ai/grok-4.3"}
    }
    resp_save2 = client.post("/config", json=payload2)
    assert resp_save2.status_code == 200
    
    # Check that the actual config file still contains the original key
    actual_cfg = json.loads(temp_config.read_text())
    assert actual_cfg["openrouter"]["api_key"] == "sk-or-test-key-12345"

def test_context_limit_configuration(setup_temp_db):
    # Add 5 dummy messages to temporary test DB
    for i in range(1, 6):
        db.add_message("user", f"Message {i}", "user")
        
    # By default, checking context with limit=20 should return all 5 messages
    assert len(db.get_context(20)) == 5
    
    # Restricting context limit to 2 should return only the last 2 messages (WORM chain sliding window)
    assert len(db.get_context(2)) == 2
    context = db.get_context(2)
    assert context[0]["text"] == "Message 4"
    assert context[1]["text"] == "Message 5"

def test_workspace_apply_and_traversal_boundaries(tmp_path, monkeypatch):
    # Setup temporary project root sandbox
    sandbox_root = tmp_path / "sandbox_project"
    sandbox_root.mkdir()
    monkeypatch.setattr(api, "PROJECT_ROOT", sandbox_root)

    # Setup a dummy workspace in WORKSPACE_ROOT
    ws_id = "test_workspace_123"
    ws_dir = WORKSPACE_ROOT / ws_id
    ws_dir.mkdir(parents=True, exist_ok=True)
    
    # Create valid file in workspace
    valid_file = ws_dir / "app_config.py"
    valid_file.write_text("DEBUG = True", encoding="utf-8")
    
    client = TestClient(app)

    # 1. Traversal Boundary Attempt (Adversarial LLM trying to write to /etc/passwd or outside project root)
    payload_bad = {
        "workspace": ws_id,
        "path": "../../outside_boundary.py"
    }
    resp_bad = client.post("/workspace/apply", json=payload_bad)
    assert resp_bad.status_code == 400
    assert any(x in resp_bad.json()["detail"] for x in ("invalid path", "Invalid"))

    # 2. Valid File Apply to Project Root
    payload_good = {
        "workspace": ws_id,
        "path": "app_config.py"
    }
    resp_good = client.post("/workspace/apply", json=payload_good)
    assert resp_good.status_code == 200
    assert resp_good.json() == {"ok": True}

    # Verify sandbox root contains the written file
    target_dest = sandbox_root / "app_config.py"
    assert target_dest.is_file()
    assert target_dest.read_text(encoding="utf-8") == "DEBUG = True"

    # Cleanup workspace
    shutil.rmtree(ws_dir, ignore_errors=True)

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.anyio
async def test_simulated_stream_generators():
    # Verify that CLI generators yield chunks and finalize with metadata
    prov = providers.ClaudeCLIProvider("claude-haiku-4-5-20251001")
    
    # Mock CLI response
    async def dummy_respond(context, cwd=None, current_depth=0, max_exchanges=1, self_name=""):
        return {
            "text": "Simulated message response from Claude.",
            "model": "claude-haiku-4-5-20251001",
            "in_tokens": 15,
            "out_tokens": 20
        }
    
    prov.respond = dummy_respond
    
    chunks = []
    async for chunk in prov.respond_stream([]):
        chunks.append(chunk)
        
    assert len(chunks) > 0
    # Ensure text chunks are yielded first, followed by metadata block
    assert chunks[0]["type"] == "content"
    assert any(c["type"] == "meta" for c in chunks)
    meta = next(c for c in chunks if c["type"] == "meta")
    assert meta["model"] == "claude-haiku-4-5-20251001"
    assert meta["in_tokens"] == 15
    assert meta["out_tokens"] == 20

@pytest.mark.anyio
async def test_stop_action_cancellation(setup_temp_db, monkeypatch):
    from src.multichat.ws import manager
    import src.multichat.core as core

    # Mock get_provider to return a slow provider that sleeps
    class SlowProvider:
        async def respond_stream(self, context, cwd=None, current_depth=0, max_exchanges=1, self_name=""):
            yield {"type": "content", "text": "Start"}
            await asyncio.sleep(5)  # simulate long generation
            yield {"type": "content", "text": "End"}

    monkeypatch.setattr(core, "get_provider", lambda mention: SlowProvider())

    # Start trigger_mentions in a task
    task = manager.start_llm_task("test_user", core.trigger_mentions(["slow"], seen=set()))

    # Wait briefly for the task to start and yield "Start"
    await asyncio.sleep(0.1)

    # Verify task is running and not done
    if task.done() and task.exception():
        raise task.exception()
    assert not task.done()

    # Trigger global stop
    manager.stop_all_tasks()

    # Wait for the task to finish canceling and cleaning up
    await asyncio.sleep(0.2)

    assert task.done()

    # Check that the message was saved in the database as stopped
    messages = db.get_context(10)
    assert len(messages) > 0
    
    # The last message should be from @slow and contain [Stopped] or Stopped by user
    last_msg = messages[-1]
    assert last_msg["sender"] == "@slow"
    assert "[Stopped]" in last_msg["text"] or "stopped" in last_msg["text"].lower()


@pytest.mark.anyio
async def test_exchange_limit_halts_all_branches(setup_temp_db, monkeypatch):
    import src.multichat.core as core
    import src.multichat.config as cfg_module

    # Configure max_exchanges to 1
    monkeypatch.setattr(cfg_module, "load", lambda: {
        "max_exchanges": 1,
        "max_token_budget": 100000,
        "context_limit": 20
    })

    called_providers = []

    class MockProvider:
        def __init__(self, name):
            self.name = name

        async def respond_stream(self, context, cwd=None, current_depth=0, max_exchanges=1, self_name=""):
            called_providers.append(self.name)
            if self.name == "first":
                yield {"type": "content", "text": "Let's ask @second to help."}
            elif self.name == "second":
                yield {"type": "content", "text": "Let's ask @third to help."}
            else:
                yield {"type": "content", "text": "Done."}

    monkeypatch.setattr(core, "get_provider", lambda mention: MockProvider(mention))

    # Trigger with sibling and first mention
    await core.trigger_mentions(["first", "sibling"], seen=set())

    # "first" triggers recursive call to "second".
    # At "second", current_depth is 1. Since max_exchanges is 1, current_depth < max_exchanges is False.
    # It hits the Exchange Limit Reached block, sets state["halted"] = True, and breaks.
    # The parent loop at depth 0 checks state["halted"] and breaks without invoking "sibling".
    assert "first" in called_providers
    assert "second" in called_providers
    assert "sibling" not in called_providers


@pytest.mark.anyio
async def test_token_budget_halts_all_branches(setup_temp_db, monkeypatch):
    import src.multichat.core as core
    import src.multichat.config as cfg_module

    # Configure small token budget (50 output tokens)
    monkeypatch.setattr(cfg_module, "load", lambda: {
        "max_exchanges": 5,
        "max_token_budget": 50,
        "context_limit": 20
    })

    called_providers = []

    class MockBudgetProvider:
        def __init__(self, name):
            self.name = name

        async def respond_stream(self, context, cwd=None, current_depth=0, max_exchanges=1, self_name=""):
            called_providers.append(self.name)
            # Yield content chunk
            yield {"type": "content", "text": f"Response from {self.name}. Mentions @second" if self.name == "first" else f"Response from {self.name}"}
            
            # Yield metadata chunk — budget tracks only out_tokens
            if self.name == "first":
                # 30 output tokens (still within 50 budget)
                yield {"type": "meta", "model": self.name, "in_tokens": 100, "out_tokens": 30}
            elif self.name == "second":
                # 25 output tokens (cumulative out: 55, exceeds 50)
                yield {"type": "meta", "model": self.name, "in_tokens": 100, "out_tokens": 25}
            else:
                yield {"type": "meta", "model": self.name, "in_tokens": 1, "out_tokens": 1}

    monkeypatch.setattr(core, "get_provider", lambda mention: MockBudgetProvider(mention))

    # Trigger with sibling and first mention
    await core.trigger_mentions(["first", "sibling"], seen=set())

    # "first" (30 out_tokens) -> triggers "second" (25 out_tokens, cumulative 55) -> hits budget cap -> halts!
    # Sibling "sibling" is never called. Input tokens are NOT counted toward budget.
    assert "first" in called_providers
    assert "second" in called_providers
    assert "sibling" not in called_providers

