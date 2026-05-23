import json
import os
from pathlib import Path
import copy

# Resolve CONFIG_PATH relative to project root
CONFIG_PATH = Path(__file__).parent.parent.parent / "config.json"

DEFAULTS: dict = {
    "max_exchanges": 1,
    "max_token_budget": 100000,
    "context_limit": 20,
    "claude": {
        "enabled": True,
        "model": "claude-sonnet-4-6",
    },
    "agy": {
        "enabled": True,
        "model": "MODEL_PLACEHOLDER_M27",
    },
    "ollama": {
        "enabled": False,
        "host": "http://localhost:11434",
        "model": "llama3.2",
    },
    "openrouter": {
        "enabled": False,
        "api_key": "",
        "model": "meta-llama/llama-3.1-8b-instruct:free",
    },
}

def load() -> dict:
    if not CONFIG_PATH.exists():
        return copy.deepcopy(DEFAULTS)
    try:
        data = json.loads(CONFIG_PATH.read_text())
        for key, val in DEFAULTS.items():
            if isinstance(val, dict):
                data.setdefault(key, {})
                for subkey, subval in val.items():
                    data[key].setdefault(subkey, subval)
            else:
                data.setdefault(key, val)

        env_key = os.environ.get("OPENROUTER_API_KEY")
        if env_key:
            data.setdefault("openrouter", {})["api_key"] = env_key

        return data
    except Exception:
        return copy.deepcopy(DEFAULTS)

def save(cfg: dict) -> None:
    clean_cfg = copy.deepcopy(cfg)
    # Write atomically with 0o600 perms so the API key isn't world-readable.
    tmp_path = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(clean_cfg, f, indent=2)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    os.replace(tmp_path, CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass
