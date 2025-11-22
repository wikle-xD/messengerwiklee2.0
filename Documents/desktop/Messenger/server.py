import sys
import json
import os
import threading
import time
import asyncio
import hashlib
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
try:
    from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
    from PySide6.QtCore import Qt
except Exception:
    QApplication = QWidget = QVBoxLayout = QLabel = QPushButton = None
    Qt = None

HAS_QT = QApplication is not None and QWidget is not None and QVBoxLayout is not None

DATA_PATH = os.path.join(os.path.dirname(__file__), "users.json")
_lock = threading.Lock()

app = FastAPI(title="Desktop Messenger Server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple admin token
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")


def _read_db() -> Dict[str, Any]:
    with _lock:
        if not os.path.exists(DATA_PATH):
            return {"users": [], "messages": []}
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {"users": [], "messages": []}


def _write_db(data: Dict[str, Any]):
    temp_path = DATA_PATH + ".tmp"
    with _lock:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(temp_path, DATA_PATH)


def _hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def _next_user_id(users: List[Dict[str, Any]]) -> int:
    return (max([u["id"] for u in users], default=0) + 1) if users else 1


class AuthPayload(BaseModel):
    username: str
    password: str


class FriendRequestPayload(BaseModel):
    from_id: int
    to_username: str


class FriendRespondPayload(BaseModel):
    to_id: int
    from_id: int
    accept: bool


class SendMessagePayload(BaseModel):
    from_id: int
    to_id: int
    text: str


@app.post("/register")
def register(payload: AuthPayload):
    db = _read_db()
    username = payload.username.strip()
    password = payload.password
    if not username or not password:
        raise HTTPException(status_code=400,
                            detail="Username and password required")
    if any(u["username"].lower() == username.lower() for u in db["users"]):
        raise HTTPException(status_code=409, detail="Username already exists")
    uid = _next_user_id(db["users"])
    user = {
        "id": uid,
        "username": username,
        "password": _hash_password(password),
        "friends": [],
        "incoming_requests": [],
        "outgoing_requests": [],
        "last_seen": time.time(),
    }
    db["users"].append(user)
    _write_db(db)
    return {"id": uid, "username": username}


@app.post("/login")
def login(payload: AuthPayload):
    db = _read_db()
    username = payload.username.strip()
    password = payload.password
    hpw = _hash_password(password)
    for u in db["users"]:
        if u["username"].lower() == username.lower() and u["password"] == hpw:
            u.setdefault("last_seen", time.time())
            u["last_seen"] = time.time()
            _write_db(db)
            return {"id": u["id"], "username": u["username"]}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/users/search")
def search_users(q: str, requester_id: int | None = None):
    db = _read_db()
    ql = q.strip().lower()
    results = []
    for u in db["users"]:
        if ql in u["username"].lower():
            if requester_id is None or u["id"] != requester_id:
                results.append({"id": u["id"], "username": u["username"]})
    return results


@app.post("/friends/request")
def send_friend_request(payload: FriendRequestPayload):
    db = _read_db()
    from_user = next((u for u in db["users"] if u["id"] == payload.from_id),
                     None)
    to_user = next((u for u in db["users"]
                    if u["username"].lower() == payload.to_username.lower()),
                   None)
    if not from_user or not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    if to_user["id"] == from_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot friend yourself")
    if to_user["id"] in from_user["friends"]:
        return {"status": "already_friends"}
    if to_user["id"] in from_user["outgoing_requests"]:
        return {"status": "already_sent"}
    if from_user["id"] in to_user["incoming_requests"]:
        return {"status": "already_pending"}
    from_user["outgoing_requests"].append(to_user["id"])
    to_user["incoming_requests"].append(from_user["id"])
    _write_db(db)
    return {"status": "sent"}


@app.post("/friends/respond")
def respond_friend_request(payload: FriendRespondPayload):
    db = _read_db()
    to_user = next((u for u in db["users"] if u["id"] == payload.to_id), None)
    from_user = next((u for u in db["users"] if u["id"] == payload.from_id),
                     None)
    if not from_user or not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.from_id not in to_user["incoming_requests"]:
        raise HTTPException(status_code=400, detail="No such request")
    to_user["incoming_requests"].remove(payload.from_id)
    if payload.to_id in from_user["outgoing_requests"]:
        from_user["outgoing_requests"].remove(payload.to_id)
    if payload.accept:
        if payload.from_id not in to_user["friends"]:
            to_user["friends"].append(payload.from_id)
        if payload.to_id not in from_user["friends"]:
            from_user["friends"].append(payload.to_id)
        status = "accepted"
    else:
        status = "declined"
    _write_db(db)
    return {"status": status}


@app.get("/notifications/{user_id}")
def notifications(user_id: int):
    db = _read_db()
    u = next((u for u in db["users"] if u["id"] == user_id), None)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    incoming = [{
        "id":
        fr_id,
        "username":
        next((x["username"] for x in db["users"] if x["id"] == fr_id), "")
    } for fr_id in u.get("incoming_requests", [])]
    return {"incoming_requests": incoming}


@app.get("/chats/{user_id}")
def list_chats(user_id: int):
    db = _read_db()
    u = next((u for u in db["users"] if u["id"] == user_id), None)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    peers = set(u.get("friends", []))
    for m in db.get("messages", []):
        if m["from_id"] == user_id:
            peers.add(m["to_id"])
        if m["to_id"] == user_id:
            peers.add(m["from_id"])
    now = time.time()
    chats = []
    for uid in peers:
        if uid == user_id:
            continue
        peer = next((x for x in db["users"] if x["id"] == uid), None)
        if not peer:
            continue
        online = (now - peer.get("last_seen", 0)) < 20
        chats.append({
            "id": uid,
            "username": peer.get("username", ""),
            "online": online
        })
    chats.sort(key=lambda x: x["username"].lower())
    return chats


@app.get("/messages/{user_id}/{peer_id}")
def get_messages(user_id: int, peer_id: int):
    db = _read_db()
    msgs = [
        m for m in db.get("messages", [])
        if (m["from_id"] == user_id and m["to_id"] == peer_id) or (
            m["from_id"] == peer_id and m["to_id"] == user_id)
    ]
    msgs.sort(key=lambda m: m["ts"])
    return msgs


@app.post("/messages/send")
def send_message(payload: SendMessagePayload):
    db = _read_db()
    from_user = next((u for u in db["users"] if u["id"] == payload.from_id),
                     None)
    to_user = next((u for u in db["users"] if u["id"] == payload.to_id), None)
    if not from_user or not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Empty message")
    msg = {
        "from_id": payload.from_id,
        "to_id": payload.to_id,
        "text": text,
        "ts": time.time(),
    }
    db.setdefault("messages", []).append(msg)
    _write_db(db)
    return {"status": "sent"}


@app.get("/")
def root():
    return {"status": "ok"}


def _require_admin(x_admin_token: str | None):
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Admin token required")


@app.get("/admin/users")
def admin_users(x_admin_token: str | None = Header(default=None,
                                                   alias="X-Admin-Token")):
    _require_admin(x_admin_token)
    db = _read_db()
    out = []
    for u in db.get("users", []):
        out.append({
            "id": u.get("id"),
            "username": u.get("username"),
            "friends_count": len(u.get("friends", [])),
            "incoming_count": len(u.get("incoming_requests", [])),
            "outgoing_count": len(u.get("outgoing_requests", [])),
        })
    return {"users": out}


@app.get("/admin/requests")
def admin_requests(x_admin_token: str | None = Header(default=None,
                                                      alias="X-Admin-Token")):
    _require_admin(x_admin_token)
    db = _read_db()
    results: list[dict] = []
    # Build incoming requests list with names
    id_to_user = {u["id"]: u for u in db.get("users", [])}
    for u in db.get("users", []):
        for from_id in u.get("incoming_requests", []):
            results.append({
                "to_id":
                u["id"],
                "to_username":
                u.get("username"),
                "from_id":
                from_id,
                "from_username":
                id_to_user.get(from_id, {}).get("username", ""),
            })
    return {"requests": results}


class AdminResetPayload(BaseModel):
    user_id: int
    new_password: str


@app.post("/admin/reset_password")
def admin_reset_password(payload: AdminResetPayload,
                         x_admin_token: str | None = Header(
                             default=None, alias="X-Admin-Token")):
    _require_admin(x_admin_token)
    if not payload.new_password:
        raise HTTPException(status_code=400, detail="Password required")
    db = _read_db()
    user = next(
        (u for u in db.get("users", []) if u.get("id") == payload.user_id),
        None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["password"] = _hash_password(payload.new_password)
    _write_db(db)
    return {"status": "ok"}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int,
                      x_admin_token: str | None = Header(
                          default=None, alias="X-Admin-Token")):
    _require_admin(x_admin_token)
    db = _read_db()
    users = db.get("users", [])
    target = next((u for u in users if u.get("id") == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Remove friendships and requests involving this user
    for u in users:
        if user_id in u.get("friends", []):
            u["friends"].remove(user_id)
        if user_id in u.get("incoming_requests", []):
            u["incoming_requests"].remove(user_id)
        if user_id in u.get("outgoing_requests", []):
            u["outgoing_requests"].remove(user_id)
    # Remove the user
    db["users"] = [u for u in users if u.get("id") != user_id]
    # Optionally, prune messages to/from user
    db["messages"] = [
        m for m in db.get("messages", [])
        if m.get("from_id") != user_id and m.get("to_id") != user_id
    ]
    _write_db(db)
    return {"status": "deleted"}


class HeartbeatPayload(BaseModel):
    user_id: int


@app.post("/presence/heartbeat")
def presence_heartbeat(payload: HeartbeatPayload):
    db = _read_db()
    user = next((u for u in db["users"] if u["id"] == payload.user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["last_seen"] = time.time()
    _write_db(db)
    return {"status": "ok"}


class UvicornThread(threading.Thread):

    def __init__(self, host: str = "127.0.0.1", port: int = 8000):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self._server: uvicorn.Server | None = None

    def run(self):
        # Run uvicorn server in this thread with its own event loop
        config = uvicorn.Config(app,
                                host=self.host,
                                port=self.port,
                                log_level="info")
        self._server = uvicorn.Server(config)
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
        except RuntimeError:
            pass
        self._server.run()

    def stop(self):
        if self._server is not None:
            self._server.should_exit = True


if HAS_QT:

    class ServerWindow(QWidget):

        def __init__(self, server_thread: UvicornThread):
            super().__init__()
            self._server_thread = server_thread
            self.setWindowTitle("Messenger Server")
            self.setMinimumSize(360, 160)
            self.setStyleSheet("""
                QWidget { background-color:#0b1220; color:#e2e8f0; font-family:Segoe UI, Arial; }
                QLabel { color:#cbd5e1; font-size:14px; }
                #Title { color:#f8fafc; font-size:18px; font-weight:700; }
                QPushButton { background:#ef4444; color:white; border:none; padding:8px 12px; border-radius:8px; font-weight:600; }
                """)
            v = QVBoxLayout(self)
            title = QLabel("Сервер запущен")
            title.setObjectName("Title")
            replit_domain = os.getenv("REPLIT_DOMAINS", "http://127.0.0.1:8000")
            info = QLabel(
                f"Адрес: https://{replit_domain}:8000\nЗакройте это окно, чтобы остановить сервер."
            )
            info.setTextFormat(Qt.PlainText)
            v.addWidget(title)
            v.addWidget(info)
            v.addStretch(1)
            btn = QPushButton("Остановить сервер и закрыть")
            btn.clicked.connect(self.close)
            v.addWidget(btn)

        def closeEvent(self, event):
            # On window close, stop the server and wait briefly
            try:
                self._server_thread.stop()
                self._server_thread.join(timeout=3)
            finally:
                event.accept()

    def main():
        # Start server in background thread and show control window
        srv = UvicornThread(host="0.0.0.0", port=8000)
        srv.start()

        app_qt = QApplication(sys.argv)
        w = ServerWindow(srv)
        w.show()
        sys.exit(app_qt.exec())

    if __name__ == "__main__":
        main()
else:
    # No Qt available: if launched directly, just run uvicorn in foreground.
    if __name__ == "__main__":
        uvicorn.run(app, host="0.0.0.0", port=8000)
