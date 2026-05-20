import json
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
    "gemini": {
        "enabled": True,
        "model": "gemini-3.5-flash-high",
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
        
        import os
        env_key = os.environ.get("OPENROUTER_API_KEY")
        if env_key:
            data.setdefault("openrouter", {})["api_key"] = env_key
            
        return data
    except Exception:
        return copy.deepcopy(DEFAULTS)

def save(cfg: dict) -> None:
    clean_cfg = copy.deepcopy(cfg)
    if "openrouter" in clean_cfg and "api_key" in clean_cfg["openrouter"]:
        clean_cfg["openrouter"]["api_key"] = ""
    CONFIG_PATH.write_text(json.dumps(clean_cfg, indent=2))
