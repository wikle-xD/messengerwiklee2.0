import sys
import hashlib
import json
from typing import List, Dict, Optional, Tuple

import requests
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QToolBar, QMessageBox, QInputDialog, QDialog, QListWidget, 
    QListWidgetItem, QDialogButtonBox, QFormLayout
)

API_BASE = "https://d1794e44-b7ab-4aac-a6fc-e23f76fd0461-00-1t4nyu2lxy5ia.picard.replit.dev:8000"
ADMIN_TOKEN = None

def hash_password(password: str) -> str:
    """Hash a password for storing."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a stored password against one provided by user"""
    return stored_password == hash_password(provided_password)

def load_users() -> List[Dict]:
    """Load users from users.json"""
    try:
        with open('users.json', 'r') as f:
            data = json.load(f)
            return data.get('users', [])
    except Exception as e:
        print(f"Error loading users: {e}")
        return []

def find_admin_user() -> Optional[Dict]:
    """Find the first admin user"""
    users = load_users()
    return next((user for user in users if user.get('is_admin', False)), None)

def api_get(path: str, token: str) -> Dict:
    if not token:
        raise Exception("Not authenticated. Please log in as admin.")
    r = requests.get(f"{API_BASE}{path}", headers={"X-Admin-Token": token}, timeout=10)
    if r.status_code >= 400:
        try:
            raise Exception(r.json().get("detail", r.text))
        except Exception:
            raise Exception(r.text)
    return r.json()

def api_post(path: str, token: str, json_body: dict) -> Dict:
    if not token:
        raise Exception("Not authenticated. Please log in as admin.")
    r = requests.post(f"{API_BASE}{path}", headers={"X-Admin-Token": token}, json=json_body, timeout=10)
    if r.status_code >= 400:
        try:
            raise Exception(r.json().get("detail", r.text))
        except Exception:
            raise Exception(r.text)
    return r.json()

def api_delete(path: str, token: str) -> Dict:
    if not token:
        raise Exception("Not authenticated. Please log in as admin.")
    r = requests.delete(f"{API_BASE}{path}", headers={"X-Admin-Token": token}, timeout=10)
    if r.status_code >= 400:
        try:
            raise Exception(r.json().get("detail", r.text))
        except Exception:
            raise Exception(r.text)
    return r.json()


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Authentication")
        self.setMinimumWidth(300)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        
        form.addRow("Username:", self.username)
        form.addRow("Password:", self.password)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addLayout(form)
        layout.addWidget(buttons)
    
    def get_credentials(self) -> Tuple[str, str]:
        return self.username.text().strip(), self.password.text()

class AdminWindow(QMainWindow):
    def __init__(self, admin_token: str):
        super().__init__()
        self.admin_token = admin_token
        self.setWindowTitle("Messenger Admin Panel")
        self.setMinimumSize(980, 620)

        self.token_edit = QLineEdit()
        self.token_edit.setPlaceholderText("ADMIN_TOKEN (по умолчанию admin123)")
        self.token_edit.setEchoMode(QLineEdit.Password)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск пользователя…")
        self.search_edit.textChanged.connect(self._apply_filter)

        self.refresh_btn = QPushButton("Обновить пользователей")
        self.refresh_btn.clicked.connect(self._load_users)

        self.requests_btn = QPushButton("Заявки в друзья")
        self.requests_btn.clicked.connect(self._show_requests)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.addWidget(QLabel("🔑 Токен:"))
        toolbar.addWidget(self.token_edit)
        toolbar.addSeparator()
        toolbar.addWidget(self.search_edit)
        toolbar.addSeparator()
        toolbar.addWidget(self.refresh_btn)
        toolbar.addWidget(self.requests_btn)
        self.addToolBar(toolbar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Имя", "Друзья", "Вх. заявки", "Исх. заявки", "Действия"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)

        central = QWidget()
        lay = QVBoxLayout(central)
        lay.addWidget(self.table)
        self.setCentralWidget(central)

        self._data: List[Dict] = []

        # Style (dark)
        self.setStyleSheet(
            """
            QWidget { background:#0b1220; color:#e2e8f0; font-size:14px; }
            QLineEdit { background:#0f172a; border:1px solid #1f2937; border-radius:10px; padding:8px; color:#e2e8f0; }
            QPushButton { background:#6366f1; border:none; padding:8px 10px; border-radius:10px; color:white; font-weight:600; }
            QPushButton:hover { background:#5457ee; }
            QToolBar { background:#0b1220; border:0; spacing:8px; }
            QTableWidget { background:#0f172a; border:1px solid #1f2937; border-radius:10px; }
            QHeaderView::section { background:#111827; color:#cbd5e1; padding:6px; border:none; }
            """
        )

    def _token(self) -> str:
        t = self.token_edit.text().strip()
        return t or "admin123"

    def _apply_filter(self):
        q = self.search_edit.text().strip().lower()
        self.table.setRowCount(0)
        for u in self._data:
            if q and q not in u["username"].lower():
                continue
            self._append_row(u)

    def _append_row(self, u: Dict):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(str(u.get("id"))))
        self.table.setItem(r, 1, QTableWidgetItem(u.get("username", "")))
        self.table.setItem(r, 2, QTableWidgetItem(str(u.get("friends_count", 0))))
        self.table.setItem(r, 3, QTableWidgetItem(str(u.get("incoming_count", 0))))
        self.table.setItem(r, 4, QTableWidgetItem(str(u.get("outgoing_count", 0))))

        # Actions cell
        cell = QWidget()
        h = QHBoxLayout(cell)
        h.setContentsMargins(0, 0, 0, 0)
        btn_reset = QPushButton("Сброс пароля")
        btn_delete = QPushButton("Удалить")
        btn_delete.setStyleSheet("QPushButton{background:#ef4444;} QPushButton:hover{background:#dc2626}")
        btn_reset.clicked.connect(lambda: self._reset_password(u))
        btn_delete.clicked.connect(lambda: self._delete_user(u))
        h.addWidget(btn_reset)
        h.addWidget(btn_delete)
        h.addStretch(1)
        self.table.setCellWidget(r, 5, cell)

    def _load_users(self):
        try:
            res = api_get("/admin/users", self._token())
            self._data = res.get("users", [])
            self.table.setRowCount(0)
            for u in self._data:
                self._append_row(u)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _show_requests(self):
        try:
            res = api_get("/admin/requests", self._token())
            reqs = res.get("requests", [])
            dlg = QDialog(self)
            dlg.setWindowTitle("Заявки в друзья")
            v = QVBoxLayout(dlg)
            lst = QListWidget()
            for r in reqs:
                item = QListWidgetItem(f"{r['from_username']} -> {r['to_username']}")
                lst.addItem(item)
            v.addWidget(lst)
            ok = QPushButton("Закрыть")
            ok.clicked.connect(dlg.accept)
            v.addWidget(ok)
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _reset_password(self, u: Dict):
        new_pw, ok = QInputDialog.getText(self, "Сброс пароля", f"Новый пароль для {u['username']}")
        if not ok or not (new_pw or "").strip():
            return
        try:
            api_post("/admin/reset_password", self._token(), {"user_id": u["id"], "new_password": new_pw})
            QMessageBox.information(self, "Готово", "Пароль сброшен")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _delete_user(self, u: Dict):
        if QMessageBox.question(self, "Удаление", f"Удалить пользователя {u['username']}?") != QMessageBox.Yes:
            return
        try:
            api_delete(f"/admin/users/{u['id']}", self._token())
            self._load_users()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


def main():
    app = QApplication(sys.argv)
    
    # Check for admin user
    admin_user = find_admin_user()
    if not admin_user:
        QMessageBox.critical(None, "Error", "No admin user found. Please create an admin user first.")
        return 1
    
    # Show login dialog
    login_dialog = LoginDialog()
    if login_dialog.exec() != QDialog.Accepted:
        return 0
    
    username, password = login_dialog.get_credentials()
    
    # Verify credentials
    users = load_users()
    user = next((u for u in users if u['username'].lower() == username.lower()), None)
    
    if not user or not verify_password(user['password'], password) or not user.get('is_admin', False):
        QMessageBox.critical(None, "Error", "Invalid username or password, or user is not an admin.")
        return 1
    
    # If we get here, authentication was successful
    # In a real app, you would get a proper token from the server
    admin_token = f"admin-token-{username}"
    
    window = AdminWindow(admin_token)
    window.show()
    return app.exec()


if __name__ == "__main__":
    main()
