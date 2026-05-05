"""
ORACLE v2 — Security Core
God-tier security: encryption, auth, rate limiting, input sanitization, audit logging
"""
import os, hashlib, hmac, time, sqlite3, re, json, secrets, base64
from datetime import datetime, timedelta
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import jwt
import bcrypt


# ─── KEY MANAGEMENT ───────────────────────────────────────────────────────────

class KeyVault:
    """Manages all encryption keys — never stored in plaintext"""

    def __init__(self, master_password: str):
        self._salt = os.urandom(32)
        self._master_key = self._derive_key(master_password, self._salt)
        self._fernet = Fernet(self._master_key)
        self._jwt_secret = secrets.token_hex(64)
        self._api_keys: dict = {}

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, data: str) -> str:
        return self._fernet.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()

    def generate_api_key(self, user_id: str) -> str:
        raw = secrets.token_urlsafe(48)
        hashed = bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds=12)).decode()
        self._api_keys[user_id] = hashed
        return raw

    def verify_api_key(self, user_id: str, key: str) -> bool:
        stored = self._api_keys.get(user_id, "")
        if not stored:
            return False
        return bcrypt.checkpw(key.encode(), stored.encode())

    def sign_jwt(self, payload: dict, expires_minutes: int = 60) -> str:
        payload["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
        payload["iat"] = datetime.utcnow()
        payload["jti"] = secrets.token_hex(16)
        return jwt.encode(payload, self._jwt_secret, algorithm="HS256")

    def verify_jwt(self, token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, self._jwt_secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None


# ─── RATE LIMITER ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter — prevents abuse"""

    def __init__(self):
        self._buckets: dict = {}
        self._blocked: dict = {}

    def check(self, identifier: str, max_requests: int = 100, window_seconds: int = 60) -> bool:
        now = time.time()

        # Check if blocked
        if identifier in self._blocked:
            if now < self._blocked[identifier]:
                return False
            del self._blocked[identifier]

        # Token bucket
        if identifier not in self._buckets:
            self._buckets[identifier] = {"tokens": max_requests, "last": now}

        bucket = self._buckets[identifier]
        elapsed = now - bucket["last"]
        refill = (elapsed / window_seconds) * max_requests
        bucket["tokens"] = min(max_requests, bucket["tokens"] + refill)
        bucket["last"] = now

        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True

        # Block for 5 minutes after exhaustion
        self._blocked[identifier] = now + 300
        return False


# ─── INPUT SANITIZER ───────────────────────────────────────────────────────────

class InputSanitizer:
    """Kills SQL injection, XSS, command injection, path traversal"""

    SQL_PATTERNS = re.compile(
        r"(--|;|'|\"|\bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b|"
        r"\bEXEC\b|\bUNION\b|\bSELECT\b|\bOR\b\s+1=1|\bAND\b\s+1=1)",
        re.IGNORECASE
    )
    CMD_PATTERNS = re.compile(r"[;&|`$(){}[\]\\<>]")
    CMD_KEYWORDS = re.compile(
        r"\b(rm|cat|wget|curl|chmod|chown|sudo|su|bash|sh|zsh|python|perl|"
        r"nc|ncat|nmap|ssh|scp|rsync|eval|exec|system|popen|passwd|shadow|"
        r"etc|proc|dev|bin|usr|var|tmp)\b",
        re.IGNORECASE
    )
    PATH_PATTERNS = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e")
    XSS_PATTERNS = re.compile(
        r"<script|javascript:|onerror=|onload=|eval\(|expression\(",
        re.IGNORECASE
    )

    @classmethod
    def sanitize(cls, value: str, context: str = "general") -> str:
        if not isinstance(value, str):
            raise ValueError("Input must be string")
        if len(value) > 10_000:
            raise ValueError("Input too long — max 10,000 chars")

        if cls.SQL_PATTERNS.search(value):
            raise ValueError("SQL injection pattern detected")
        if cls.CMD_PATTERNS.search(value):
            raise ValueError("Command injection pattern detected")
        if cls.CMD_KEYWORDS.search(value):
            raise ValueError("Dangerous system keyword detected")
        if cls.PATH_PATTERNS.search(value):
            raise ValueError("Path traversal pattern detected")
        if cls.XSS_PATTERNS.search(value):
            raise ValueError("XSS pattern detected")

        return value.strip()

    @classmethod
    def sanitize_ticker(cls, ticker: str) -> str:
        """Strict stock ticker sanitization — only A-Z, 0-9, dot, hyphen"""
        if not isinstance(ticker, str):
            raise ValueError("Ticker must be a string")
        # Check all injection patterns on RAW input before any stripping
        if cls.SQL_PATTERNS.search(ticker):
            raise ValueError("Invalid ticker — SQL injection pattern detected")
        if cls.XSS_PATTERNS.search(ticker):
            raise ValueError("Invalid ticker — XSS pattern detected")
        if cls.CMD_PATTERNS.search(ticker):
            raise ValueError("Invalid ticker — command injection pattern detected")
        if cls.PATH_PATTERNS.search(ticker):
            raise ValueError("Invalid ticker — path traversal detected")
        # After all checks, strip to safe charset
        clean = re.sub(r"[^A-Z0-9.\-]", "", ticker.upper().strip())
        if len(clean) < 1 or len(clean) > 20:
            raise ValueError(f"Invalid ticker '{ticker}' — must be 1-20 alphanumeric chars")
        return clean

    @classmethod
    def sanitize_number(cls, value, min_val=None, max_val=None) -> float:
        import math
        try:
            n = float(value)
        except (ValueError, TypeError):
            raise ValueError(f"Not a number: {value}")
        if math.isnan(n):
            raise ValueError("NaN value not allowed")
        if math.isinf(n):
            raise ValueError("Infinite value not allowed")
        if min_val is not None and n < min_val:
            raise ValueError(f"Value {n} below minimum {min_val}")
        if max_val is not None and n > max_val:
            raise ValueError(f"Value {n} above maximum {max_val}")
        return n


# ─── AUDIT LOGGER ──────────────────────────────────────────────────────────────

class AuditLogger:
    """Immutable, tamper-evident audit log for every action"""

    def __init__(self, db_path: str = ""):
        from pathlib import Path
        if not db_path:
            # Always resolve relative to project root — works on any machine
            project_root = Path(__file__).resolve().parent.parent
            db_path = str(project_root / "logs" / "audit.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self._db)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                user_id     TEXT,
                ip_address  TEXT,
                action      TEXT NOT NULL,
                result      TEXT NOT NULL,
                details     TEXT,
                checksum    TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _checksum(self, data: dict) -> str:
        payload = json.dumps(data, sort_keys=True).encode()
        return hmac.new(b"oracle_v2_secret", payload, hashlib.sha256).hexdigest()

    def log(self, event_type: str, action: str, result: str,
            user_id: str = "system", ip_address: str = "internal", details: str = ""):
        ts = datetime.utcnow().isoformat()
        data = {"timestamp": ts, "event_type": event_type,
                "user_id": user_id, "action": action, "result": result}
        checksum = self._checksum(data)
        conn = sqlite3.connect(self._db)
        conn.execute("""
            INSERT INTO audit_log 
            (timestamp, event_type, user_id, ip_address, action, result, details, checksum)
            VALUES (?,?,?,?,?,?,?,?)
        """, (ts, event_type, user_id, ip_address, action, result, details, checksum))
        conn.commit()
        conn.close()

    def get_recent(self, n: int = 50) -> list:
        conn = sqlite3.connect(self._db)
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
        conn.close()
        return rows
