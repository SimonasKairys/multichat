import asyncio
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
        self.active_tokens: dict[str, str] = {}  # username -> token
        self.tasks: dict[str, asyncio.Task] = {}  # per-user

    async def connect(self, username: str, ws: WebSocket):
        await ws.accept()
        self.active_connections[username] = ws

    def disconnect(self, username: str):
        self.active_connections.pop(username, None)
        self.active_tokens.pop(username, None)
        self._cancel_user_task(username)

    async def broadcast(self, data: dict):
        dead = []
        for u, ws in list(self.active_connections.items()):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(u)
        for u in dead:
            self.active_connections.pop(u, None)

    async def broadcast_users(self):
        await self.broadcast({"type": "users", "users": list(self.active_connections.keys())})

    def start_llm_task(self, username: str, coro) -> asyncio.Task:
        self._cancel_user_task(username)
        task = asyncio.create_task(coro)
        self.tasks[username] = task
        # Cleanup on finish — no stale entries (Claude's suggestion)
        task.add_done_callback(lambda t: self.tasks.pop(username, None) if self.tasks.get(username) is t else None)
        return task

    def _cancel_user_task(self, username: str):
        task = self.tasks.get(username)
        if task and not task.done():
            task.cancel()

    def stop_all_tasks(self):
        for task in list(self.tasks.values()):
            if not task.done():
                task.cancel()
        self.tasks.clear()

manager = ConnectionManager()
