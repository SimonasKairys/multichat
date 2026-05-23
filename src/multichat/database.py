import json
import sqlite3
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Resolve DB_PATH relative to project root
DB_PATH = Path(__file__).parent.parent.parent / "data" / "chat.db"

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id        TEXT PRIMARY KEY,
                sender    TEXT NOT NULL,
                text      TEXT NOT NULL,
                type      TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                meta      TEXT,
                prev_hash TEXT,
                hash      TEXT
            )
        """)
        try:
            conn.execute("ALTER TABLE messages ADD COLUMN meta TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE messages ADD COLUMN prev_hash TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE messages ADD COLUMN hash TEXT")
        except sqlite3.OperationalError:
            pass

def add_message(sender: str, text: str, msg_type: str, meta: dict | None = None, msg_id: str | None = None) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        last_msg = conn.execute(
            "SELECT hash FROM messages ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        prev_hash = last_msg["hash"] if last_msg else None

        hash_payload = "|".join([prev_hash or "", sender, text, timestamp, msg_type])
        curr_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

        msg = {
            "id": msg_id or str(uuid.uuid4()),
            "sender": sender,
            "text": text,
            "type": msg_type,
            "timestamp": timestamp,
            "meta": meta,
            "prev_hash": prev_hash,
            "hash": curr_hash,
        }
        conn.execute(
            "INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (msg["id"], msg["sender"], msg["text"], msg["type"], msg["timestamp"],
             json.dumps(meta) if meta else None, msg["prev_hash"], msg["hash"]),
        )
    return msg

def get_messages(limit: int = 100) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM messages ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    result = []
    for r in reversed(rows):
        d = dict(r)
        if d.get("meta"):
            d["meta"] = json.loads(d["meta"])
        result.append(d)
    return result

def clear_messages() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM messages")

def get_context(limit: int = 20) -> list[dict]:
    """Last N non-system messages as LLM conversation context."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT sender, text, type FROM messages "
            "WHERE type IN ('user', 'llm') ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in reversed(rows)]

def verify_log_chain() -> dict:
    """Verifies the cryptographic integrity of the entire database log chain."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM messages ORDER BY rowid ASC").fetchall()

    expected_prev_hash = None
    corrupted_messages = []

    for r in rows:
        d = dict(r)

        if d.get("prev_hash") != expected_prev_hash:
            corrupted_messages.append({
                "id": d["id"],
                "sender": d["sender"],
                "timestamp": d["timestamp"],
                "error": f"Sequence discontinuity: expected prev_hash '{expected_prev_hash or 'None'}', got '{d.get('prev_hash') or 'None'}'"
            })

        payload = "|".join([d.get("prev_hash") or "", d["sender"], d["text"], d["timestamp"], d["type"]])
        calculated_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if d.get("hash") != calculated_hash:
            corrupted_messages.append({
                "id": d["id"],
                "sender": d["sender"],
                "timestamp": d["timestamp"],
                "error": f"SHA-256 mismatch: calculated '{calculated_hash}', recorded '{d.get('hash')}'"
            })

        expected_prev_hash = d.get("hash")

    return {
        "valid": len(corrupted_messages) == 0,
        "total_messages": len(rows),
        "corrupted_count": len(corrupted_messages),
        "corrupted_details": corrupted_messages
    }
