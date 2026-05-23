import json
import shutil
import sqlite3
import time
from collections import deque
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import FileResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx

from . import config as cfg_module
from . import database as db
from .providers import parse_mentions, get_provider
from . import providers
from .ws import manager
from .core import WORKSPACE_ROOT, MAX_FILE_BYTES, trigger_mentions, _setup_workspace, _scan_workspace

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="MultiChat")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Per-user WebSocket message rate limit: max messages per window.
_WS_RATE_WINDOW = 60   # seconds
_WS_RATE_MAX    = 20   # messages per window
_ws_buckets: dict[str, deque] = {}
db.init_db()

PROJECT_ROOT = Path(__file__).parent.parent.parent
STATIC_INDEX = PROJECT_ROOT / "static" / "index.html"

@app.get("/")
async def index():
    return FileResponse(STATIC_INDEX)

@app.get("/history")
async def history():
    return db.get_messages(100)

@app.get("/config")
async def get_config():
    cfg = cfg_module.load()
    if "openrouter" in cfg and "api_key" in cfg["openrouter"]:
        if cfg["openrouter"]["api_key"]:
            cfg["openrouter"]["api_key"] = "********"
    return cfg

@app.post("/config")
async def save_config(body: dict, request: Request):
    client_host = request.client.host if request.client else None
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Forbidden: Settings can only be modified from localhost.")

    old_cfg = cfg_module.load()
    if "openrouter" in body and "openrouter" in old_cfg:
        if body["openrouter"].get("api_key") == "********":
            body["openrouter"]["api_key"] = old_cfg["openrouter"].get("api_key", "")

    if "agy" in body and "model" in body["agy"]:
        providers.AgyCLIProvider._write_model(body["agy"]["model"])

    cfg_module.save(body)
    return {"ok": True}

@app.post("/session/clear")
async def clear_session(request: Request):
    client_host = request.client.host if request.client else None
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Forbidden: Session can only be cleared from localhost.")
    manager.stop_all_tasks()
    db.clear_messages()
    if WORKSPACE_ROOT.exists():
        for child in WORKSPACE_ROOT.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
    await manager.broadcast({"type": "session_cleared"})
    return {"ok": True}

@app.get("/file/{workspace}")
async def get_file(workspace: str, path: str):
    """Return contents of a file created by an LLM, scoped to its workspace."""
    ws_dir = (WORKSPACE_ROOT / workspace).resolve()
    if not ws_dir.is_dir() or WORKSPACE_ROOT.resolve() not in ws_dir.parents:
        raise HTTPException(404, "workspace not found")
    target = (ws_dir / path).resolve()
    if ws_dir not in target.parents and target != ws_dir:
        raise HTTPException(400, "invalid path")
    if not target.is_file():
        raise HTTPException(404, "file not found")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise HTTPException(413, f"file too large ({size} bytes)")
    data = target.read_bytes()
    try:
        text = data.decode("utf-8")
        return PlainTextResponse(text)
    except UnicodeDecodeError:
        return FileResponse(target, filename=target.name)

@app.post("/workspace/apply")
async def apply_workspace_file(body: dict):
    workspace = body.get("workspace")
    path = body.get("path")
    if not workspace or not path:
        raise HTTPException(400, "Missing workspace or path")

    ws_dir = (WORKSPACE_ROOT / workspace).resolve()
    if not ws_dir.is_dir() or WORKSPACE_ROOT.resolve() not in ws_dir.parents:
        raise HTTPException(404, "workspace not found")

    src_file = (ws_dir / path).resolve()
    if ws_dir not in src_file.parents:
        raise HTTPException(400, "invalid path")

    if not src_file.is_file():
        raise HTTPException(404, "file not found")

    dest_file = (PROJECT_ROOT / path).resolve()
    if PROJECT_ROOT.resolve() not in dest_file.parents and dest_file != PROJECT_ROOT.resolve():
        raise HTTPException(400, "Invalid destination path")

    dest_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_file, dest_file)

    sys_msg = db.add_message("system", f"Applied workspace changes: {path}", "system")
    await manager.broadcast(sys_msg)
    await manager.broadcast({"type": "file_applied", "path": path})
    return {"ok": True}

@app.get("/api/health/diagnostics")
async def get_diagnostics():
    claude_installed = shutil.which("claude") is not None
    agy_installed = shutil.which("agy") is not None

    ollama_online = False
    ollama_models = []
    cfg = cfg_module.load()
    ollama_host = cfg.get("ollama", {}).get("host", "http://localhost:11434").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            resp = await client.get(f"{ollama_host}/api/tags")
            if resp.status_code == 200:
                ollama_online = True
                ollama_models = [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        pass

    openrouter_configured = False
    openrouter_key = cfg.get("openrouter", {}).get("api_key", "")
    if openrouter_key and openrouter_key != "":
        openrouter_configured = True

    return {
        "claude": {
            "installed": claude_installed,
            "status": "Available" if claude_installed else "Not Installed",
            "info": "Uses your local Claude CLI subscription."
        },
        "agy": {
            "installed": agy_installed,
            "status": "Available" if agy_installed else "Not Installed",
            "active_model": providers.AgyCLIProvider._detect_model() if agy_installed else "N/A",
            "active_placeholder": providers.AgyCLIProvider._detect_model_raw() if agy_installed else "N/A",
            "info": "Uses your local Agy CLI subscription."
        },
        "ollama": {
            "installed": ollama_online,
            "status": "Online" if ollama_online else "Offline",
            "models": ollama_models,
            "info": f"Local host: {ollama_host}"
        },
        "openrouter": {
            "installed": openrouter_configured,
            "status": "Configured" if openrouter_configured else "Key Missing",
            "info": "Using OpenRouter API."
        }
    }

@app.get("/ollama/models")
async def ollama_models():
    cfg = cfg_module.load()
    host = cfg.get("ollama", {}).get("host", "http://localhost:11434").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            resp = await client.get(f"{host}/api/tags")
            models = [m["name"] for m in resp.json().get("models", [])]
            return {"online": True, "models": models}
    except Exception:
        return {"online": False, "models": []}

@app.get("/api/audit/verify")
def get_audit_verify():
    return db.verify_log_chain()

@app.post("/api/audit/cross_validate")
@limiter.limit("5/minute")
async def post_audit_cross_validate(request: Request, data: dict):
    msg_id = data.get("message_id")
    auditor_mention = data.get("auditor_mention")
    if not msg_id or not auditor_mention:
        raise HTTPException(status_code=400, detail="Missing message_id or auditor_mention")

    auditor_mention = auditor_mention.lower().strip().lstrip("@")

    with sqlite3.connect(db.DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        msg_row = conn.execute(
            "SELECT *, rowid as _rowid FROM messages WHERE id = ?", (msg_id,)
        ).fetchone()
        if not msg_row:
            raise HTTPException(status_code=404, detail="Message not found")
        msg_data = dict(msg_row)
        cfg = cfg_module.load()
        context_limit = cfg.get("context_limit", 20)
        rows = conn.execute(
            "SELECT sender, text, type FROM messages "
            "WHERE type IN ('user', 'llm') AND rowid <= ? ORDER BY rowid DESC LIMIT ?",
            (msg_data["_rowid"], context_limit)
        ).fetchall()
    context = [dict(r) for r in reversed(rows)]

    provider = get_provider(auditor_mention)
    if not provider:
        raise HTTPException(status_code=400, detail=f"Auditor '{auditor_mention}' is not enabled or not found")

    audit_prompt = (
        f"Perform an independent validation of the last response from {msg_data['sender']}:\n"
        f"\"\"\"\n{msg_data['text']}\n\"\"\"\n"
        f"Check for correctness, security vulnerabilities, or logic flaws. Write a structured Audit & Verification Report."
    )
    context.append({"sender": "Verifier", "text": audit_prompt, "type": "user"})

    await manager.broadcast({"type": "typing", "sender": f"@{auditor_mention} (Auditor)"})

    ws_id, ws_dir, copied_files = _setup_workspace()
    result = await provider.respond(context, cwd=str(ws_dir), current_depth=0, max_exchanges=1)

    meta = {k: result[k] for k in ("model", "in_tokens", "out_tokens")}
    meta["audit_target"] = msg_id
    files = _scan_workspace(ws_dir, copied_files)
    if files:
        meta["workspace"] = ws_id
        meta["files"] = files

    audit_msg = db.add_message(
        f"@{auditor_mention} (Auditor)",
        f"🔬 **[Cross-Model Validation Report]**\n\n{result['text']}",
        "llm",
        meta=meta
    )
    await manager.broadcast(audit_msg)
    return audit_msg

@app.websocket("/ws/{username}")
async def ws_endpoint(ws: WebSocket, username: str):
    query_token = ws.query_params.get("token")

    if username in manager.active_connections:
        existing_token = manager.active_tokens.get(username)
        if existing_token and query_token == existing_token:
            old_ws = manager.active_connections[username]
            try:
                await old_ws.close()
            except Exception:
                pass
        else:
            n = 2
            while f"{username}_{n}" in manager.active_connections:
                n += 1
            username = f"{username}_{n}"

    manager.active_tokens[username] = query_token
    await manager.connect(username, ws)
    sys_msg = db.add_message("system", f"{username} joined", "system")
    await manager.broadcast(sys_msg)
    await manager.broadcast_users()

    try:
        while True:
            raw = await ws.receive_text()
            data = json.loads(raw)

            action = data.get("action")

            if action == "stop":
                manager.stop_all_tasks()
                await manager.broadcast({"type": "llm_stopped"})
                continue

            text = data.get("text", "").strip()
            if not text:
                continue

            # Per-user rate limit: drop LLM triggers if user exceeds _WS_RATE_MAX msgs/_WS_RATE_WINDOW s.
            now = time.monotonic()
            bucket = _ws_buckets.setdefault(username, deque())
            while bucket and now - bucket[0] > _WS_RATE_WINDOW:
                bucket.popleft()
            if len(bucket) >= _WS_RATE_MAX:
                await ws.send_json({"type": "system", "text": f"⚠️ Rate limit: max {_WS_RATE_MAX} messages per {_WS_RATE_WINDOW}s. Slow down."})
                continue
            bucket.append(now)

            msg = db.add_message(username, text, "user")
            await manager.broadcast(msg)

            mentions = parse_mentions(text)
            if mentions:
                manager.start_llm_task(username, trigger_mentions(mentions, seen=set()))

    except WebSocketDisconnect:
        manager.disconnect(username)
        sys_msg = db.add_message("system", f"{username} left", "system")
        await manager.broadcast(sys_msg)
        await manager.broadcast_users()
