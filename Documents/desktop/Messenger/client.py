import sys
import threading
import time
from typing import Optional, List, Dict

import requests
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QStackedWidget, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QTextEdit, QSplitter, QToolBar, QDialog,
    QStyle, QFrame
)

API_BASE = "https://d1794e44-b7ab-4aac-a6fc-e23f76fd0461-00-1t4nyu2lxy5ia.picard.replit.dev:8000"


def api_post(path: str, json_body: dict):
    r = requests.post(f"{API_BASE}{path}", json=json_body, timeout=10)
    if r.status_code >= 400:
        raise Exception(r.json().get("detail", r.text))
    return r.json()


def api_get(path: str, params: dict | None = None):
    r = requests.get(f"{API_BASE}{path}", params=params or {}, timeout=10)
    if r.status_code >= 400:
        raise Exception(r.json().get("detail", r.text))
    return r.json()


class LoginRegisterPage(QWidget):
    def __init__(self, on_auth_success):
        super().__init__()
        self.on_auth_success = on_auth_success

        self.setStyleSheet("""
            QWidget { background-color:#0b1220; color:#e2e8f0; font-size:14px; }
            QLineEdit { background:#0f172a; border:1px solid #1f2937; border-radius:12px; padding:12px; color:#e2e8f0; }
            QPushButton { background:#6366f1; border:none; padding:12px 14px; border-radius:12px; color:white; font-weight:700; }
            QPushButton:hover:!disabled { background:#5457ee; }
            QPushButton:disabled { background:#334155; color:#94a3b8; }
            QLabel { color:#cbd5e1; }
            #Card { background:#0b1220; border:1px solid #1f2937; border-radius:18px; padding:16px; }
        """)

        title = QLabel("Desktop Messenger")
        title.setStyleSheet("font-size:24px; font-weight:700; color:#f8fafc;")
        subtitle = QLabel("Вход или регистрация")
        subtitle.setStyleSheet("color:#94a3b8; margin-bottom:12px;")

        self.username = QLineEdit()
        self.username.setPlaceholderText("Имя пользователя")
        self.password = QLineEdit()
        self.password.setPlaceholderText("Пароль")
        self.password.setEchoMode(QLineEdit.Password)

        self.login_btn = QPushButton("Войти")
        self.register_btn = QPushButton("Зарегистрироваться")
        self.login_btn.setEnabled(False)
        self.register_btn.setEnabled(False)

        self.username.textChanged.connect(self._update_btns)
        self.password.textChanged.connect(self._update_btns)
        self.login_btn.clicked.connect(self._login)
        self.register_btn.clicked.connect(self._register)

        form = QVBoxLayout()
        form.addWidget(title)
        form.addWidget(subtitle)
        form.addWidget(self.username)
        form.addWidget(self.password)
        form.addSpacing(8)
        buttons = QHBoxLayout()
        buttons.addWidget(self.login_btn)
        buttons.addWidget(self.register_btn)
        form.addLayout(buttons)

        card = QFrame(objectName="Card")
        card.setLayout(form)
        card_layout = QVBoxLayout()
        card_layout.addStretch(1)
        card_layout.addWidget(card)
        card_layout.addStretch(1)

        container = QHBoxLayout()
        container.addStretch(1)
        container.addLayout(card_layout)
        container.addStretch(1)
        self.setLayout(container)

    def _update_btns(self):
        ok = bool(self.username.text().strip()) and bool(self.password.text())
        self.login_btn.setEnabled(ok)
        self.register_btn.setEnabled(ok)

    def _login(self):
        try:
            data = api_post("/login", {"username": self.username.text().strip(), "password": self.password.text()})
            self.on_auth_success(data)
        except Exception as e:
            self._show_error(str(e))

    def _register(self):
        try:
            data = api_post("/register", {"username": self.username.text().strip(), "password": self.password.text()})
            self.on_auth_success(data)
        except Exception as e:
            self._show_error(str(e))

    def _show_error(self, msg: str):
        d = QDialog(self)
        d.setWindowTitle("Ошибка")
        v = QVBoxLayout(d)
        v.addWidget(QLabel(msg))
        ok = QPushButton("OK")
        ok.clicked.connect(d.accept)
        v.addWidget(ok)
        d.exec()


class MessengerPage(QWidget):
    def __init__(self, user: Dict):
        super().__init__()
        self.user = user
        self.current_peer: Optional[Dict] = None

        self.setStyleSheet("""
            QWidget { background-color:#0b1220; color:#e2e8f0; font-size:14px; }
            QLineEdit { background:#0f172a; border:1px solid #1f2937; border-radius:12px; padding:12px; color:#e2e8f0; }
            QPushButton { background:#22c55e; border:none; padding:10px 14px; border-radius:12px; color:#052e16; font-weight:700; }
            QPushButton:hover:!disabled { background:#16a34a; }
            QPushButton:disabled { background:#14532d; color:#134e4a; }
            QListWidget { background:#0f172a; border:1px solid #1f2937; border-radius:12px; }
            QListWidget::item { padding:10px; border-radius:8px; }
            QListWidget::item:selected { background:#1f2937; }
            QTextEdit { background:#0f172a; border:1px solid #1f2937; border-radius:12px; color:#e2e8f0; }
            QToolBar { background:#0b1220; border:0; spacing:8px; }
        """)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск пользователя по имени…")
        self.search.returnPressed.connect(self.search_users)
        self.search_btn = QPushButton("Найти")
        self.search_btn.setEnabled(False)
        self.search.textChanged.connect(lambda: self.search_btn.setEnabled(bool(self.search.text().strip())))
        self.search_btn.clicked.connect(self.search_users)
        self.bell = QAction(self.style().standardIcon(QStyle.SP_MessageBoxInformation), "Уведомления", self)
        self.bell.triggered.connect(self.show_notifications)
        toolbar.addWidget(QLabel(f"👤 {self.user['username']}"))
        toolbar.addSeparator()
        toolbar.addWidget(self.search)
        toolbar.addWidget(self.search_btn)
        toolbar.addAction(self.bell)

        self.chats = QListWidget()
        self.chats.itemClicked.connect(self._open_chat)

        self.messages = QTextEdit()
        self.messages.setReadOnly(True)
        self.input = QLineEdit()
        self.input.setPlaceholderText("Напишите сообщение…")
        self.send_btn = QPushButton("Отправить")
        self.send_btn.setEnabled(False)
        self.input.textChanged.connect(lambda: self.send_btn.setEnabled(bool(self.input.text().strip())))
        self.send_btn.clicked.connect(self._send_message)

        left = QVBoxLayout()
        left.addWidget(QLabel("Чаты"))
        left.addWidget(self.chats)
        left_w = QWidget()
        left_w.setLayout(left)

        right = QVBoxLayout()
        self.chat_title = QLabel("Выберите чат")
        right.addWidget(self.chat_title)
        right.addWidget(self.messages, 1)
        bottom = QHBoxLayout()
        bottom.addWidget(self.input, 1)
        bottom.addWidget(self.send_btn)
        right.addLayout(bottom)
        right_w = QWidget()
        right_w.setLayout(right)

        splitter = QSplitter()
        splitter.addWidget(left_w)
        splitter.addWidget(right_w)
        splitter.setSizes([240, 560])

        layout = QVBoxLayout(self)
        layout.addWidget(toolbar)
        layout.addWidget(splitter, 1)

        self._refresh_chats()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1500)
        # Presence heartbeat timer
        self.heartbeat = QTimer(self)
        self.heartbeat.timeout.connect(self._send_heartbeat)
        self.heartbeat.start(10000)

    def _tick(self):
        self._refresh_chats(silent=True)
        self._refresh_notifications_icon()
        if self.current_peer:
            self._load_messages(self.current_peer["id"], silent=True)

    def _refresh_notifications_icon(self):
        try:
            n = api_get(f"/notifications/{self.user['id']}")
            count = len(n.get("incoming_requests", []))
            self.bell.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxWarning if count else QStyle.SP_DialogNoButton))
            self.bell.setToolTip(f"Уведомления: {count}")
        except Exception:
            pass

    def _send_heartbeat(self):
        try:
            api_post("/presence/heartbeat", {"user_id": self.user['id']})
        except Exception:
            pass

    def _refresh_chats(self, silent: bool = False):
        try:
            chats = api_get(f"/chats/{self.user['id']}")
            sel_id = self.current_peer["id"] if self.current_peer else None
            self.chats.clear()
            for ch in chats:
                prefix = "●" if ch.get("online") else "○"
                item = QListWidgetItem(f"{prefix} {ch['username']}")
                item.setData(Qt.UserRole, ch)
                if ch.get("online"):
                    item.setForeground(Qt.green)
                else:
                    item.setForeground(Qt.gray)
                self.chats.addItem(item)
                if sel_id and ch["id"] == sel_id:
                    self.chats.setCurrentItem(item)
            if not silent and not chats:
                self.messages.setPlainText("Здесь появятся ваши диалоги. Найдите пользователя, чтобы начать.")
        except Exception as e:
            if not silent:
                self.messages.setPlainText(f"Ошибка загрузки чатов: {e}")

    def _open_chat(self, item: QListWidgetItem):
        ch = item.data(Qt.UserRole)
        self.current_peer = ch
        online_txt = " • в сети" if ch.get("online") else " • не в сети"
        self.chat_title.setText(f"Чат с {ch['username']}{online_txt}")
        self._load_messages(ch["id"]) 

    def _load_messages(self, peer_id: int, silent: bool = False):
        try:
            msgs = api_get(f"/messages/{self.user['id']}/{peer_id}")
            # Build nice chat bubbles HTML
            html_parts = [
                "<html><head><style>"
                "body{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',Arial;font-size:14px;}"
                ".row{display:flex;margin:8px 0;}"
                ".me{justify-content:flex-end;}"
                ".peer{justify-content:flex-start;}"
                ".bubble{max-width:70%;padding:10px 12px;border-radius:14px;line-height:1.35;word-wrap:break-word;white-space:pre-wrap;}"
                ".bubble.me{background:#22c55e;color:#052e16;border-bottom-right-radius:4px;}"
                ".bubble.peer{background:#1f2937;color:#e5e7eb;border-bottom-left-radius:4px;}"
                "</style></head><body>"
            ]
            for m in msgs:
                is_me = m["from_id"] == self.user['id']
                cls_row = "me" if is_me else "peer"
                cls_bub = "me" if is_me else "peer"
                text = (m["text"]
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;"))
                html_parts.append(
                    f"<div class='row {cls_row}'><div class='bubble {cls_bub}'>{text}</div></div>"
                )
            html_parts.append("</body></html>")
            self.messages.setHtml("".join(html_parts))
            self.messages.verticalScrollBar().setValue(self.messages.verticalScrollBar().maximum())
        except Exception as e:
            if not silent:
                self.messages.setPlainText(f"Ошибка загрузки сообщений: {e}")

    def _send_message(self):
        if not self.current_peer:
            return
        text = self.input.text().strip()
        if not text:
            return
        try:
            api_post("/messages/send", {"from_id": self.user['id'], "to_id": self.current_peer['id'], "text": text})
            self.input.clear()
            self._load_messages(self.current_peer['id'])
        except Exception as e:
            self.messages.setPlainText(f"Не удалось отправить: {e}")

    def search_users(self):
        q = self.search.text().strip()
        if not q:
            return
        try:
            res = api_get("/users/search", params={"q": q, "requester_id": self.user['id']})
            dlg = QDialog(self)
            dlg.setWindowTitle("Результаты поиска")
            v = QVBoxLayout(dlg)
            lst = QListWidget()
            for u in res:
                item = QListWidgetItem(u["username"]) 
                item.setData(Qt.UserRole, u)
                lst.addItem(item)
            v.addWidget(lst)
            h = QHBoxLayout()
            btn_open = QPushButton("Открыть чат")
            btn_add = QPushButton("Добавить в друзья")
            h.addWidget(btn_open)
            h.addWidget(btn_add)
            v.addLayout(h)

            def do_open():
                it = lst.currentItem()
                if not it:
                    return
                u = it.data(Qt.UserRole)
                self.current_peer = u
                self.chat_title.setText(f"Чат с {u['username']}")
                self._load_messages(u['id'])
                self._refresh_chats()
                dlg.accept()

            def do_add():
                it = lst.currentItem()
                if not it:
                    return
                u = it.data(Qt.UserRole)
                try:
                    api_post("/friends/request", {"from_id": self.user['id'], "to_username": u['username']})
                    btn_add.setText("Запрос отправлен")
                    btn_add.setEnabled(False)
                except Exception as e:
                    btn_add.setText(str(e))

            btn_open.clicked.connect(do_open)
            btn_add.clicked.connect(do_add)
            dlg.exec()
        except Exception as e:
            self.messages.setPlainText(f"Ошибка поиска: {e}")

    def show_notifications(self):
        try:
            n = api_get(f"/notifications/{self.user['id']}")
            reqs = n.get("incoming_requests", [])
            dlg = QDialog(self)
            dlg.setWindowTitle("Уведомления")
            v = QVBoxLayout(dlg)
            lst = QListWidget()
            for r in reqs:
                it = QListWidgetItem(f"Заявка в друзья от {r['username']}")
                it.setData(Qt.UserRole, r)
                lst.addItem(it)
            v.addWidget(lst)
            h = QHBoxLayout()
            btn_accept = QPushButton("Принять")
            btn_decline = QPushButton("Отклонить")
            h.addWidget(btn_accept)
            h.addWidget(btn_decline)
            v.addLayout(h)

            def respond(accept: bool):
                it = lst.currentItem()
                if not it:
                    return
                r = it.data(Qt.UserRole)
                try:
                    api_post("/friends/respond", {"to_id": self.user['id'], "from_id": r['id'], "accept": accept})
                    lst.takeItem(lst.row(it))
                    self._refresh_chats()
                except Exception as e:
                    pass

            btn_accept.clicked.connect(lambda: respond(True))
            btn_decline.clicked.connect(lambda: respond(False))
            dlg.exec()
        except Exception:
            pass



class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Desktop Messenger")
        self.setMinimumSize(900, 600)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_page = LoginRegisterPage(self._on_auth)
        self.stack.addWidget(self.login_page)

    def _on_auth(self, user: Dict):
        page = MessengerPage(user)
        self.stack.addWidget(page)
        self.stack.setCurrentWidget(page)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
