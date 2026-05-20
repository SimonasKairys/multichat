import asyncio
import json
import re
import httpx
from . import config as cfg_module

MENTION_RE = re.compile(r'@([\w][\w\-\.:]*(?:/[\w][\w\-\.:]*)*)')

SYSTEM_PROMPT = (
    "You are participating in a group chat with humans and possibly other AI models. "
    "You are running as an autonomous AI agent in a developer workspace environment with access to the local project files. "
    "All project files are located directly in your current working directory (e.g., `./main.py`, `./providers.py`, `./config.py`, `./database.py`). "
    "You have full read and write permissions to all files in your current working directory. Always access files using relative paths (e.g. `main.py`). "
    "DO NOT try to access absolute system paths like `/root/main.py` or `/root/database.py`. "
    "When asked to review, write, or check code, you can use your tools to list, search, or read files in the current workspace directory "
    "to review and verify implementations. "
    "Keep responses as short and brief as possible to save tokens. Deliver exact details with minimal conversational filler, fluff, or introductory/concluding explanations."
)

def _get_chain_instruction(context: list[dict], current_depth: int, max_exchanges: int) -> str:
    instr = f"\n[AI-to-AI Exchange Tracking: Max limit is {max_exchanges}. Current exchange depth is {current_depth} of {max_exchanges}."
    if current_depth >= max_exchanges:
        instr += " This is the FINAL exchange in this turn; DO NOT mention any other AI models (@claude, @gemini, @ollama, @openrouter, etc.) as no further triggers will execute. Wrap up the conversation."
    else:
        instr += f" You have {max_exchanges - current_depth} exchanges remaining before the chain stops. You may mention other models if needed."
    instr += "]"
    
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

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1) -> dict:
        prompt = _build_context_text(context) + "\n\nRespond to the latest message above."
        try:
            raw = await _run_cli(
                "claude", "-p",
                "--no-session-persistence",
                "--output-format", "json",
                "--model", self.model,
                "--system-prompt", SYSTEM_PROMPT + _get_chain_instruction(context, current_depth, max_exchanges),
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

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1):
        res = await self.respond(context, cwd, current_depth, max_exchanges)
        if res["text"].startswith("Error"):
            yield {"type": "error", "text": res["text"]}
        else:
            text = res["text"]
            chunk_size = 30
            for i in range(0, len(text), chunk_size):
                yield {"type": "content", "text": text[i:i+chunk_size]}
                await asyncio.sleep(0.01)
            yield {"type": "meta", "model": res["model"], "in_tokens": res["in_tokens"], "out_tokens": res["out_tokens"]}

class GeminiCLIProvider:
    def __init__(self, model: str):
        self.model = model

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1) -> dict:
        prompt = _build_context_text(context)
        args = [
            "gemini",
            "--skip-trust",
            "-p", f"Respond to the latest message above. Be concise.{_get_chain_instruction(context, current_depth, max_exchanges)}",
            "--output-format", "json",
        ]
        if self.model:
            args += ["-m", self.model]
        try:
            raw = await _run_cli(*args, stdin_text=prompt, cwd=cwd or "/tmp")
            data = json.loads(raw)
            text = data.get("response", "")
            model_name = self.model
            in_tok = out_tok = 0
            for mname, mdata in data.get("stats", {}).get("models", {}).items():
                if "main" in mdata.get("roles", {}):
                    model_name = mname
                    tokens = mdata.get("tokens", {})
                    in_tok  = tokens.get("input", 0)
                    out_tok = tokens.get("candidates", 0)
                    break
            return {"text": text, "model": model_name, "in_tokens": in_tok, "out_tokens": out_tok}
        except asyncio.TimeoutError:
            return _err(self.model, "Timed out after 120 s.")
        except FileNotFoundError:
            return _err(self.model, "'gemini' CLI not found.")
        except Exception as e:
            return _err(self.model, str(e))

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1):
        res = await self.respond(context, cwd, current_depth, max_exchanges)
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
        return hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1")

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1) -> dict:
        system_content = SYSTEM_PROMPT + _get_chain_instruction(context, current_depth, max_exchanges)
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

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1):
        system_content = SYSTEM_PROMPT + _get_chain_instruction(context, current_depth, max_exchanges)
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

    async def respond(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1) -> dict:
        system_content = SYSTEM_PROMPT + _get_chain_instruction(context, current_depth, max_exchanges)
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

    async def respond_stream(self, context: list[dict], cwd: str | None = None, current_depth: int = 0, max_exchanges: int = 1):
        system_content = SYSTEM_PROMPT + _get_chain_instruction(context, current_depth, max_exchanges)
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

    if name == "gemini" or name.startswith("gemini:") or name.startswith("gemini-"):
        pg = cfg.get("gemini", {})
        if not pg.get("enabled"):
            return None
        if name.startswith("gemini:"):
            model = name.split(":", 1)[1]
            if not model:
                model = pg.get("model", "gemini-3.5-flash-high")
        elif name.startswith("gemini-"):
            model = name
        else:
            model = pg.get("model", "gemini-3.5-flash-high")
        return GeminiCLIProvider(model)

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
