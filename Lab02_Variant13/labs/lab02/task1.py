"""Модель користувачів, сеансів та аудиту."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
)


class User:
    """Користувач із перевіркою email та приватними даними пароля."""

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Email має бути рядком")
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Некоректний формат email")
        self._email = value

    def set_password(self, password: str) -> None:
        if not isinstance(password, str):
            raise TypeError("Пароль має бути рядком")
        if not password:
            raise ValueError("Пароль не може бути порожнім")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not isinstance(password, str):
            raise TypeError("Пароль має бути рядком")
        if not self.__password_hash:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return f"User({self.username}, {self.email}, role={self.role}, active={self.active})"


class Admin(User):
    """Адміністратор є користувачем із додатковими правами."""

    def __init__(self, username: str, email: str, permissions=None):
        super().__init__(username, email, role="admin")
        self.permissions = set(permissions) if permissions is not None else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"{super().__str__()}, permissions={sorted(self.permissions)}"


class Session:
    """Сеанс із часовими мітками UTC."""

    def __init__(self, ip: str):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути додатним")
        return datetime.now(timezone.utc) - self.last_activity <= timedelta(
            seconds=timeout_sec
        )


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.logs: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self.logs.append(AuditRecord(datetime.now(timezone.utc), username, action))

    def show_all(self) -> None:
        for record in self.logs:
            print(
                f"{record.timestamp.isoformat()} | {record.username} | {record.action}"
            )


class UserAccount:
    """Композиція користувача, сеансу й журналу."""

    def __init__(self, user: User, audit_log: AuditLog | None = None):
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if (
            self.user.active
            and self.user.username == username
            and self.user.check_password(password)
        ):
            self.session = Session(ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True
        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        return bool(
            self.user.active
            and self.session is not None
            and self.session.is_active(SESSION_TIMEOUT_SEC)
        )

    def logout(self) -> None:
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str):
        fields = {
            "user": self.user,
            "email": self.user.email,
            "username": self.user.username,
            "role": self.user.role,
            "active": self.user.active,
        }
        if key not in fields:
            raise KeyError(key)
        return fields[key]

    def __setitem__(self, key: str, value) -> None:
        types = {"user": User, "email": str, "active": bool}
        if key not in types:
            raise KeyError(key)
        if not isinstance(value, types[key]):
            raise TypeError(f"Некоректний тип для {key}")
        if key == "user":
            self.session = None
            self.user = value
        else:
            setattr(self.user, key, value)
            if key == "active" and not value:
                self.session = None
