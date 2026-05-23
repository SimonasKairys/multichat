import uuid
import os
import shutil
import asyncio
from pathlib import Path
from . import config as cfg_module
from . import database as db
from .providers import parse_mentions, get_provider
from .ws import manager

WORKSPACE_ROOT = Path("/tmp/multichat_workspaces")
WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB cap for the viewer

def _scan_workspace(ws_dir: Path, copied_files: set[str] | None = None) -> list[dict]:
    """Return [{path, size}] for files created inside ws_dir; remove dir if empty."""
    if not ws_dir.exists():
        return []
    if copied_files is None:
        copied_files = set()
    files = []
    for p in sorted(ws_dir.rglob("*")):
        if p.is_file():
            rel = p.relative_to(ws_dir).as_posix()
            if rel in copied_files:
                continue
            files.append({"path": rel, "size": p.stat().st_size})
    if not files:
        try:
            # Clean up all copied files and folders so rmdir can succeed
            for p in sorted(ws_dir.rglob("*"), reverse=True):
                if p.is_file() or p.is_symlink():
                    p.unlink()
                elif p.is_dir():
                    p.rmdir()
            ws_dir.rmdir()
        except OSError:
            pass
    return files

_SKIP_NAMES = frozenset({
    ".git", "data", "__pycache__", ".venv", "venv", ".pytest_cache", "config.json", ".env",
})

def _setup_workspace() -> tuple[str, Path, set[str]]:
    """Create an isolated temp workspace with a copy of the project files."""
    ws_id = uuid.uuid4().hex
    ws_dir = WORKSPACE_ROOT / ws_id
    ws_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(ws_dir, 0o700)
    except Exception:
        pass

    copied_files: set[str] = set()
    project_root = Path(__file__).parent.parent.parent
    for item in project_root.iterdir():
        if item.name in _SKIP_NAMES:
            continue
        try:
            if item.is_file():
                shutil.copy2(item, ws_dir / item.name)
                copied_files.add(item.name)
            elif item.is_dir():
                shutil.copytree(item, ws_dir / item.name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                for p in (ws_dir / item.name).rglob("*"):
                    if p.is_file():
                        copied_files.add(p.relative_to(ws_dir).as_posix())
        except Exception:
            pass

    return ws_id, ws_dir, copied_files


async def trigger_mentions(mentions: list[str], seen: set[str], current_depth: int = 0, state: dict | None = None):
    cfg = cfg_module.load()
    max_exchanges = cfg.get("max_exchanges", 1)
    max_token_budget = cfg.get("max_token_budget", 100000)
    context_limit = cfg.get("context_limit", 20)

    if state is None:
        state = {
            "halted": False,
            "cumulative_tokens": 0
        }

    for mention in mentions:
        if state["halted"]:
            break
        if mention in seen:
            continue
        provider = get_provider(mention)
        if provider is None:
            continue
        seen.add(mention)
        await manager.broadcast({"type": "typing", "sender": f"@{mention}"})
        context = db.get_context(context_limit)

        ws_id, ws_dir, copied_files = _setup_workspace()

        msg_id = str(uuid.uuid4())
        await manager.broadcast({"type": "stream_start", "id": msg_id, "sender": f"@{mention}"})

        full_text = ""
        result_meta = {"model": mention, "in_tokens": 0, "out_tokens": 0}

        try:
            async for chunk in provider.respond_stream(context, cwd=str(ws_dir), current_depth=current_depth, max_exchanges=max_exchanges, self_name=mention):
                if chunk["type"] == "content":
                    text_delta = chunk["text"]
                    full_text += text_delta
                    await manager.broadcast({"type": "stream_chunk", "id": msg_id, "text": text_delta})
                elif chunk["type"] == "meta":
                    result_meta["model"] = chunk["model"]
                    result_meta["in_tokens"] = chunk["in_tokens"]
                    result_meta["out_tokens"] = chunk["out_tokens"]
                elif chunk["type"] == "error":
                    full_text = chunk["text"]
                    await manager.broadcast({"type": "stream_chunk", "id": msg_id, "text": full_text})
        except asyncio.CancelledError:
            state["halted"] = True
            if not full_text:
                full_text = "*Response stopped by user.*"
            else:
                full_text += " *[Stopped]*"
            
            # Spawn a task to save the partial response to the database and broadcast stream_end
            async def finalize_stopped():
                files = _scan_workspace(ws_dir, copied_files)
                if files:
                    result_meta["workspace"] = ws_id
                    result_meta["files"] = files
                llm_msg = db.add_message(f"@{mention}", full_text, "llm", meta=result_meta, msg_id=msg_id)
                await manager.broadcast({"type": "stream_end", "id": msg_id, "message": llm_msg})

            asyncio.create_task(finalize_stopped())
            break
        except Exception as e:
            full_text = f"Error: {str(e)}"
            await manager.broadcast({"type": "stream_chunk", "id": msg_id, "text": full_text})

        files = _scan_workspace(ws_dir, copied_files)
        if files:
            result_meta["workspace"] = ws_id
            result_meta["files"] = files

        llm_msg = db.add_message(f"@{mention}", full_text, "llm", meta=result_meta, msg_id=msg_id)
        await manager.broadcast({"type": "stream_end", "id": msg_id, "message": llm_msg})

        # Token budget: count only output tokens (actual cost driver).
        # Exempt local Ollama models (free local inference) from budget tracking.
        from .providers import OllamaProvider
        is_local_ollama = isinstance(provider, OllamaProvider) and provider.is_local
        tokens_spent = result_meta.get("out_tokens", 0) if not is_local_ollama else 0
        state["cumulative_tokens"] += tokens_spent
        
        if state["cumulative_tokens"] > max_token_budget:
            alert_text = (
                f"⚠️ **[Zero-Trust Cost Governance Alert]** AI-to-AI exchange chain terminated. "
                f"Cumulative output tokens spent ({state['cumulative_tokens']:,}) exceeded the hard-cap budget limit of ({max_token_budget:,}). "
                f"Halting execution to prevent OpEx runaway."
            )
            alert_msg = db.add_message("system", alert_text, "system")
            await manager.broadcast(alert_msg)
            state["halted"] = True
            break

        if current_depth < max_exchanges:
            # Exclude the current model from immediately triggering itself,
            # and pass a fresh seen set to allow back-and-forth AI discussions up to the limit count.
            next_mentions = [m for m in parse_mentions(full_text) if m != mention]
            await trigger_mentions(next_mentions, seen=set(), current_depth=current_depth + 1, state=state)
            if state["halted"]:
                break
        else:
            # Inform user if models wanted to keep talking but hit the configured exchange limit
            next_mentions = [m for m in parse_mentions(full_text) if m != mention]
            if next_mentions:
                limit_text = (
                    f"🛑 **[Exchange Limit Reached]** AI-to-AI discussion halted. "
                    f"The conversation reached the configured maximum exchange limit of ({max_exchanges})."
                )
                limit_msg = db.add_message("system", limit_text, "system")
                await manager.broadcast(limit_msg)
                state["halted"] = True
                break
