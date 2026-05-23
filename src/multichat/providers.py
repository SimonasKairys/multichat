import asyncio
import json
import re
import httpx
from . import config as cfg_module

MENTION_RE = re.compile(r'@([\w][\w\-\.:]*(?:/[\w][\w\-\.:]*)*)')

_BASE_PROMPT = (
    "You are participating in a group chat with humans and possibly other AI models. "
    "Keep responses as short and brief as possible to save tokens. Deliver exact details with minimal conversational filler, fluff, or introductory/concluding explanations."
)

_FILE_TOOLS_PROMPT = (
    " You are running as an autonomous AI agent in a developer workspace environment with access to the local project files. "
    "The project files are structured as follows: backend code is in `./src/multichat/` (e.g., `./src/multichat/core.py`, `./src/multichat/providers.py`, `./src/multichat/config.py`, `./src/multichat/database.py`), the frontend is `./static/index.html`, and tests are in `./tests/test_multichat.py`. "
    "You have full read and write permissions to all files in your current working directory. Always access files using relative paths (e.g. `src/multichat/core.py`). "
    "DO NOT try to access absolute system paths like `/root/src/multichat/core.py`. "
    "When asked to review, write, or check code, you can use your tools to list, search, or read files in the current workspace directory to review and verify implementations."
)

_NO_TOOLS_PROMPT = (
    " You do NOT have file system access, code execution, or any external tools in this chat — you can only read the messages in this conversation and reply with text. "
    "If a user asks you to read, review, or describe a file, you MUST say you cannot access files rather than fabricate contents. Do NOT invent file contents, function names, or implementation details you have not been shown directly in the conversation."
)

def _system_prompt(has_file_tools: bool) -> str:
    return _BASE_PROMPT + (_FILE_TOOLS_PROMPT if has_file_tools else _NO_TOOLS_PROMPT)

SYSTEM_PROMPT = _BASE_PROMPT + _FILE_TOOLS_PROMPT

def _get_chain_instruction(context: list[dict], current_depth: int, max_exchanges: int, self_name: str = "") -> str:
    instr = f"\n[AI-to-AI Exchange Tracking: Max limit is {max_exchanges}. Current exchange depth is {current_depth} of {max_exchanges}."
    if current_depth >= max_exchanges:
        instr += " This is the FINAL exchange in this turn; DO NOT mention any other AI models (@claude, @agy, @ollama, @openrouter, etc.) as no further triggers will execute. Wrap up the conversation."
    else:
        instr += f" You have {max_exchanges - current_depth} exchanges remaining before the chain stops. You may mention other models if needed."
    instr += "]"
    if self_name:
        instr += (
            f"\n[Your identity: You ARE @{self_name}. The handle @{self_name} refers to YOU, not some other system or assistant. "
            f"Do NOT report on @{self_name}'s status, do NOT describe @{self_name} in the third person, do NOT say things like '@{self_name} inactive' or '@{self_name} unavailable'. "
            f"When you see @{self_name} in a message, treat it as someone addressing you directly. Just respond to the actual content of their message (greeting, question, request) conversationally as yourself.]"
        )

    last_sender = None
    for m in reversed(context):
        if m["type"] == "llm" and m["text"].startswith("Error"):
            continue
        last_sender = m["sender"]
        break

    if last_sender:
        if not last_sender.startswith("@"):
            last_sender = f"@{last_sender}"
        instr += f"\n[Rule: You are responding directly to {last_sender}. You MUST begin your response by tagging/addressing them (e.g., '{last_sender} ...' or 'Responding to {last_sender}: ...').]"
    instr += "\n[CRITICAL: Keep your response as short, direct, and concise as possible. Avoid any chit-chat, filler, or introductory/concluding remarks to conserve token budget.]"
    return instr

def _sanitize_name(sender: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', sender.lstrip('@'))[:64] or '_'

def parse_mentions(text: str) -> list[str]:
    return list(dict.fromkeys(m.lower() for m in MENTION_RE.findall(text)))

def _build_context_text(context: list[dict]) -> str:
    lines = []
    for m in context:
        if m["type"] == "llm" and m["text"].startswith("Error"):
            continue
        lines.append(f"[{m['sender']}]: {m['text']}")
    return "\n".join(lines)

async def _run_cli(*args: str, stdin_text: str, timeout: int = 120, cwd: str | None = None) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_text.encode()),
            timeout=timeout,
        )
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError("Timed out after 120 s.")
    if proc.returncode != 0:
        stdout_str = stdout.decode().strip()
        try:
            data = json.loads(stdout_str)
            if isinstance(data, dict) and ("result" in data or "response" in data):
                return stdout_str
        except Exception:
            pass
        raise RuntimeError(stderr.decode().strip()[:300] or f"exit {proc.returncode}")
    return stdout.decode()

def _err(model: str, msg: str) -> dict:
    return {"text": f"Error: {msg}", "model": model, "in_tokens": 0, "out_tokens": 0}

class ClaudeCLIProvider:
    def __init__(self, model: str):
        self.model = model

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = "") -> dict:
        prompt = _build_context_text(context) + "\n\nRespond to the latest message above."
        try:
            raw = await _run_cli(
                "claude", "-p",
                "--no-session-persistence",
                "--output-format", "json",
                "--model", self.model,
                "--system-prompt", SYSTEM_PROMPT + _get_chain_instruction(context, current_depth, max_exchanges, self_name),
                stdin_text=prompt,
                cwd=cwd,
            )
            data = json.loads(raw)
            if data.get("is_error"):
                return _err(self.model, data.get("result", "Unknown CLI error"))
            text = data.get("result", "")
            model_usage = data.get("modelUsage", {})
            model_name = self.model
            if model_usage:
                model_name = max(model_usage.items(), key=lambda x: x[1].get("costUSD", 0))[0]
            usage = data.get("usage", {})
            in_tok = usage.get("input_tokens", 0) + usage.get("cache_read_input_tokens", 0)
            out_tok = usage.get("output_tokens", 0)
            return {"text": text, "model": model_name, "in_tokens": in_tok, "out_tokens": out_tok}
        except asyncio.TimeoutError:
            return _err(self.model, "Timed out after 120 s.")
        except FileNotFoundError:
            return _err(self.model, "'claude' CLI not found.")
        except Exception as e:
            return _err(self.model, str(e))

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = ""):
        res = await self.respond(context, cwd, current_depth, max_exchanges, self_name)
        if res["text"].startswith("Error"):
            yield {"type": "error", "text": res["text"]}
        else:
            text = res["text"]
            chunk_size = 30
            for i in range(0, len(text), chunk_size):
                yield {"type": "content", "text": text[i:i+chunk_size]}
                await asyncio.sleep(0.01)
            yield {"type": "meta", "model": res["model"], "in_tokens": res["in_tokens"], "out_tokens": res["out_tokens"]}

class AgyCLIProvider:
    # Map AGY internal model placeholders to human-readable names
    _MODEL_MAP = {
        "MODEL_PLACEHOLDER_M26": "Gemini 3.5 Flash (Medium)",
        "MODEL_PLACEHOLDER_M132": "Gemini 3.5 Flash (Medium)",
        "MODEL_PLACEHOLDER_M27": "Gemini 3.5 Flash (High)",
        "MODEL_PLACEHOLDER_M133": "Gemini 3.5 Flash (High)",
        "MODEL_PLACEHOLDER_M24": "Gemini 3.1 Pro (Low)",
        "MODEL_PLACEHOLDER_M124": "Gemini 3.1 Pro (Low)",
        "MODEL_PLACEHOLDER_M25": "Gemini 3.1 Pro (High)",
        "MODEL_PLACEHOLDER_M125": "Gemini 3.1 Pro (High)",
        "MODEL_PLACEHOLDER_M20": "Claude Sonnet 4.6 (Thinking)",
        "MODEL_PLACEHOLDER_M120": "Claude Sonnet 4.6 (Thinking)",
        "MODEL_PLACEHOLDER_M21": "Claude Opus 4.6 (Thinking)",
        "MODEL_PLACEHOLDER_M121": "Claude Opus 4.6 (Thinking)",
        "MODEL_PLACEHOLDER_M30": "GPT-OSS 120B (Medium)",
        "MODEL_PLACEHOLDER_M130": "GPT-OSS 120B (Medium)",
    }

    def __init__(self):
        pass

    @staticmethod
    def _detect_model_raw() -> str:
        """Read the active model placeholder from AGY state file."""
        from pathlib import Path
        state_path = Path.home() / ".gemini" / "antigravity" / "antigravity_state.pbtxt"
        try:
            if state_path.exists():
                text = state_path.read_text()
                for line in text.splitlines():
                    if "last_selected_agent_model:" in line:
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return "MODEL_PLACEHOLDER_M27"

    @staticmethod
    def _detect_model() -> str:
        """Read the active model from AGY state file."""
        try:
            placeholder = AgyCLIProvider._detect_model_raw()
            return AgyCLIProvider._MODEL_MAP.get(placeholder, f"agy ({placeholder})")
        except Exception:
            pass
        return "agy"

    @staticmethod
    def _write_model(placeholder: str) -> bool:
        """Write the active model placeholder to AGY state file."""
        from pathlib import Path
        state_path = Path.home() / ".gemini" / "antigravity" / "antigravity_state.pbtxt"
        try:
            if state_path.exists():
                text = state_path.read_text()
                lines = text.splitlines()
                updated = False
                for i, line in enumerate(lines):
                    if "last_selected_agent_model:" in line:
                        lines[i] = f"last_selected_agent_model: {placeholder}"
                        updated = True
                        break
                if not updated:
                    lines.append(f"last_selected_agent_model: {placeholder}")
                state_path.write_text("\n".join(lines) + "\n")
                return True
        except Exception:
            pass
        return False

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = "") -> dict:
        prompt = _build_context_text(context)
        detected_model = self._detect_model()
        args = [
            "agy",
            "--dangerously-skip-permissions",
            "-p", f"Respond to the latest message above. Be concise.{_get_chain_instruction(context, current_depth, max_exchanges, self_name)}",
        ]
        try:
            text = await _run_cli(*args, stdin_text=prompt, cwd=cwd or "/tmp")  # nosec B108
            text = text.strip()
            return {"text": text, "model": detected_model, "in_tokens": 0, "out_tokens": 0}
        except asyncio.TimeoutError:
            return _err("agy", "Timed out after 120 s.")
        except FileNotFoundError:
            return _err("agy", "'agy' CLI not found.")
        except Exception as e:
            return _err("agy", str(e))

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = ""):
        res = await self.respond(context, cwd, current_depth, max_exchanges, self_name)
        if res["text"].startswith("Error"):
            yield {"type": "error", "text": res["text"]}
        else:
            text = res["text"]
            chunk_size = 30
            for i in range(0, len(text), chunk_size):
                yield {"type": "content", "text": text[i:i+chunk_size]}
                await asyncio.sleep(0.01)
            yield {"type": "meta", "model": res["model"], "in_tokens": res["in_tokens"], "out_tokens": res["out_tokens"]}

class OllamaProvider:
    def __init__(self, host: str, model: str):
        self.host = host.rstrip("/")
        self.model = model

    @property
    def is_local(self) -> bool:
        """Return True if the Ollama host points to a local machine (exempt from token budget)."""
        from urllib.parse import urlparse
        parsed = urlparse(self.host)
        hostname = (parsed.hostname or "").lower()
        return hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1")  # nosec B104 — detection allowlist, not a bind call

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = "") -> dict:
        system_content = _system_prompt(has_file_tools=False) + _get_chain_instruction(context, current_depth, max_exchanges, self_name)
        messages = [{"role": "system", "content": system_content}]
        for m in context:
            role = "user" if m["type"] == "user" else "assistant"
            messages.append({"role": role, "content": m["text"], "name": _sanitize_name(m["sender"])})
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{self.host}/api/chat",
                    json={"model": self.model, "messages": messages, "stream": False},
                )
                resp.raise_for_status()
                data = resp.json()
                return {
                    "text":      data["message"]["content"],
                    "model":     data.get("model", self.model),
                    "in_tokens": data.get("prompt_eval_count", 0),
                    "out_tokens": data.get("eval_count", 0),
                }
        except httpx.ConnectError:
            return _err(self.model, f"Cannot reach Ollama at {self.host}.")
        except Exception as e:
            return _err(self.model, str(e))

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = ""):
        system_content = _system_prompt(has_file_tools=False) + _get_chain_instruction(context, current_depth, max_exchanges, self_name)
        messages = [{"role": "system", "content": system_content}]
        for m in context:
            role = "user" if m["type"] == "user" else "assistant"
            messages.append({"role": role, "content": m["text"], "name": _sanitize_name(m["sender"])})
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                async with client.stream(
                    "POST",
                    f"{self.host}/api/chat",
                    json={"model": self.model, "messages": messages, "stream": True},
                ) as response:
                    response.raise_for_status()
                    in_tok = out_tok = 0
                    model_name = self.model
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            yield {"type": "content", "text": data["message"]["content"]}
                        if data.get("done"):
                            in_tok = data.get("prompt_eval_count", 0)
                            out_tok = data.get("eval_count", 0)
                            model_name = data.get("model", self.model)
                    yield {"type": "meta", "model": model_name, "in_tokens": in_tok, "out_tokens": out_tok}
        except httpx.ConnectError:
            yield {"type": "error", "text": f"Cannot reach Ollama at {self.host}."}
        except Exception as e:
            yield {"type": "error", "text": str(e)}

class OpenRouterProvider:
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = "") -> dict:
        system_content = _system_prompt(has_file_tools=False) + _get_chain_instruction(context, current_depth, max_exchanges, self_name)
        messages = [{"role": "system", "content": system_content}]
        for m in context:
            role = "user" if m["type"] == "user" else "assistant"
            messages.append({"role": role, "content": m["text"], "name": _sanitize_name(m["sender"])})
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.model, "messages": messages},
                )
                resp.raise_for_status()
                data = resp.json()
                usage = data.get("usage", {})
                return {
                    "text":       data["choices"][0]["message"]["content"],
                    "model":      data.get("model", self.model),
                    "in_tokens":  usage.get("prompt_tokens", 0),
                    "out_tokens": usage.get("completion_tokens", 0),
                }
        except httpx.HTTPStatusError as e:
            return _err(self.model, f"HTTP {e.response.status_code}: {e.response.text[:200]}")
        except Exception as e:
            return _err(self.model, str(e))

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1, self_name: str = ""):
        system_content = _system_prompt(has_file_tools=False) + _get_chain_instruction(context, current_depth, max_exchanges, self_name)
        messages = [{"role": "system", "content": system_content}]
        for m in context:
            role = "user" if m["type"] == "user" else "assistant"
            messages.append({"role": role, "content": m["text"], "name": _sanitize_name(m["sender"])})
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                async with client.stream(
                    "POST",
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.model, "messages": messages, "stream": True},
                ) as response:
                    response.raise_for_status()
                    in_tok = out_tok = 0
                    model_name = self.model
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:].strip()
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                choices = data.get("choices", [])
                                if choices and "delta" in choices[0] and "content" in choices[0]["delta"]:
                                    yield {"type": "content", "text": choices[0]["delta"]["content"]}
                                if "model" in data:
                                    model_name = data["model"]
                                if "usage" in data and data["usage"]:
                                    in_tok = data["usage"].get("prompt_tokens", 0)
                                    out_tok = data["usage"].get("completion_tokens", 0)
                            except Exception:
                                pass
                    yield {"type": "meta", "model": model_name, "in_tokens": in_tok, "out_tokens": out_tok}
        except Exception as e:
            yield {"type": "error", "text": str(e)}

def get_provider(mention: str):
    cfg = cfg_module.load()
    name = mention.lower().strip().rstrip(":.")

    claude_aliases = {"claude", "sonnet", "opus", "haiku"}
    is_claude = name in claude_aliases or name.startswith("claude:") or name.startswith("claude-")
    if is_claude:
        pc = cfg.get("claude", {})
        if not pc.get("enabled"):
            return None
        if name.startswith("claude:"):
            model = name.split(":", 1)[1]
            if not model:
                model = pc.get("model", "claude-sonnet-4-6")
        elif name in ("sonnet", "opus", "haiku") or name.startswith("claude-"):
            model = name
        else:
            model = pc.get("model", "claude-sonnet-4-6")
        return ClaudeCLIProvider(model)

    if name == "agy":
        pa = cfg.get("agy", {})
        if not pa.get("enabled"):
            return None
        return AgyCLIProvider()

    if name == "ollama" or name.startswith("ollama:"):
        po = cfg.get("ollama", {})
        if not po.get("enabled"):
            return None
        model = name.split(":", 1)[1] if ":" in name else po.get("model", "llama3.2")
        if not model:
            model = po.get("model", "llama3.2")
        return OllamaProvider(po.get("host", "http://localhost:11434"), model)

    if name == "openrouter" or name.startswith("openrouter/"):
        por = cfg.get("openrouter", {})
        if not por.get("enabled") or not por.get("api_key"):
            return None
        model = name.split("/", 1)[1] if "/" in name else por.get("model", "")
        if not model:
            model = por.get("model", "")
        return OpenRouterProvider(por["api_key"], model)

    return None
