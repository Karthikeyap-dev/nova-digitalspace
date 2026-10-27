from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("NOVA_DATA_DIR", BASE_DIR / "data")).resolve()
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "nova.sqlite3"
FRONTEND_DIR = BASE_DIR / "frontend"
MAX_UPLOAD_BYTES = int(os.getenv("NOVA_MAX_UPLOAD_MB", "100")) * 1024 * 1024
STORAGE_LIMIT = int(os.getenv("NOVA_STORAGE_LIMIT_GB", "10")) * 1024**3
SESSION_DAYS = int(os.getenv("NOVA_SESSION_DAYS", "7"))
COOKIE_SECURE = os.getenv("NOVA_COOKIE_SECURE", "false").lower() == "true"
ALLOW_REGISTRATION = os.getenv("NOVA_ALLOW_REGISTRATION", "true").lower() == "true"
PUBLIC_DEPLOYMENT = os.getenv("NOVA_PUBLIC_DEPLOYMENT", "false").lower() == "true"
ALLOWED_HOSTS = [x.strip() for x in os.getenv("NOVA_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if x.strip()]
STARTED_AT = datetime.now(timezone.utc)
PASSWORD_HASHER = PasswordHasher()

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


def initialize_database() -> None:
    with db() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            vault_salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            content_type TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vault_entries (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            iv TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contact_messages (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        # Upgrade databases created by the earlier single-user starter.
        # Existing records are deliberately left unowned rather than exposed to
        # whichever account happens to register first.
        for table in ("files", "vault_entries"):
            columns = table_columns(connection, table)
            if "user_id" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN user_id TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_files_user_created ON files(user_id, created_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_vault_user_created ON vault_entries(user_id, created_at DESC)")
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))


initialize_database()
app = FastAPI(
    title="Nova Personal Digital Space",
    version="2.0.0",
    description="Multi-user personal workspace with private file storage and client-side encrypted vault records.",
    docs_url=None if PUBLIC_DEPLOYMENT else "/docs",
    redoc_url=None if PUBLIC_DEPLOYMENT else "/redoc",
    openapi_url=None if PUBLIC_DEPLOYMENT else "/openapi.json",
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


# Lightweight per-process rate limiter. For multi-worker/public deployments, use a
# shared reverse-proxy or Redis rate limiter as described in README.md.
_rate_events: dict[str, deque[float]] = defaultdict(deque)

def rate_limit(request: Request, bucket: str, limit: int, window_seconds: int, subject: str = "") -> None:
    ip = request.client.host if request.client else "unknown"
    key = f"{bucket}:{ip}:{subject}"
    now = time.monotonic()
    events = _rate_events[key]
    while events and events[0] <= now - window_seconds:
        events.popleft()
    if len(events) >= limit:
        raise HTTPException(429, "Too many requests. Please wait and try again.", headers={"Retry-After": str(window_seconds)})
    events.append(now)


@app.middleware("http")
async def security_headers_and_origin_check(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin:
            from urllib.parse import urlsplit
            parsed = urlsplit(origin)
            expected_host = request.headers.get("host", "").lower()
            origin_host = (parsed.netloc or "").lower()
            if parsed.scheme not in {"http", "https"} or origin_host != expected_host:
                return Response("Cross-origin request rejected", status_code=403)
        if request.headers.get("x-nova-request") != "1":
            return Response("Missing request verification header", status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


class RegisterRequest(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Display name is required")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class EncryptedVaultEntry(BaseModel):
    iv: str = Field(min_length=16, max_length=128)
    ciphertext: str = Field(min_length=16, max_length=20000)


class ContactMessage(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    subject: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=10000)


class UserContext(BaseModel):
    id: str
    email: str
    display_name: str
    vault_salt: str


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: str, response: Response) -> None:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    with db() as connection:
        connection.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                           (hash_session_token(token), user_id, expires.isoformat(timespec="seconds"), now_iso()))
    response.set_cookie(
        key="nova_session", value=token, httponly=True, secure=COOKIE_SECURE,
        samesite="strict", max_age=SESSION_DAYS * 24 * 60 * 60, path="/"
    )


def get_current_user(request: Request) -> UserContext:
    token = request.cookies.get("nova_session")
    if not token or len(token) > 200:
        raise HTTPException(401, "Please sign in to continue")
    with db() as connection:
        row = connection.execute(
            "SELECT u.id,u.email,u.display_name,u.vault_salt,s.expires_at "
            "FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
            (hash_session_token(token),),
        ).fetchone()
        if not row:
            raise HTTPException(401, "Please sign in to continue")
        if row["expires_at"] <= now_iso():
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (hash_session_token(token),))
            raise HTTPException(401, "Your session expired. Please sign in again")
    return UserContext(id=row["id"], email=row["email"], display_name=row["display_name"], vault_salt=row["vault_salt"])


CurrentUser = Annotated[UserContext, Depends(get_current_user)]


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/auth/config")
def auth_config():
    return {"registration_enabled": ALLOW_REGISTRATION}


@app.post("/api/auth/register", status_code=201)
def register(payload: RegisterRequest, request: Request, response: Response):
    rate_limit(request, "register", 5, 3600)
    if not ALLOW_REGISTRATION:
        raise HTTPException(403, "Registration is currently disabled")
    email = str(payload.email).strip().lower()
    user_id = str(uuid.uuid4())
    salt = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    password_hash = PASSWORD_HASHER.hash(payload.password)
    try:
        with db() as connection:
            connection.execute(
                "INSERT INTO users(id,email,display_name,password_hash,vault_salt,created_at) VALUES(?,?,?,?,?,?)",
                (user_id, email, payload.display_name, password_hash, salt, now_iso()),
            )
    except sqlite3.IntegrityError:
        # Avoid disclosing whether a specific account exists.
        raise HTTPException(400, "Unable to create account with those details")
    create_session(user_id, response)
    return {"id": user_id, "email": email, "display_name": payload.display_name}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    rate_limit(request, "login", 10, 900)
    email = str(payload.email).strip().lower()
    with db() as connection:
        row = connection.execute("SELECT id,password_hash FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
    # A fixed dummy hash keeps the common invalid-user path closer to the password-check path.
    if row is None:
        PASSWORD_HASHER.hash("dummy-password-used-to-reduce-account-enumeration")
        raise HTTPException(401, "Invalid email or password")
    try:
        PASSWORD_HASHER.verify(row["password_hash"], payload.password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(401, "Invalid email or password")
    if PASSWORD_HASHER.check_needs_rehash(row["password_hash"]):
        with db() as connection:
            connection.execute("UPDATE users SET password_hash=? WHERE id=?", (PASSWORD_HASHER.hash(payload.password), row["id"]))
    create_session(row["id"], response)
    return {"ok": True}


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    token = request.cookies.get("nova_session")
    if token:
        with db() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (hash_session_token(token),))
    response.delete_cookie("nova_session", path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return None


@app.get("/api/me")
def me(user: CurrentUser):
    return {"id": user.id, "email": user.email, "display_name": user.display_name}


@app.get("/api/status")
def status(user: CurrentUser):
    with db() as connection:
        total = connection.execute("SELECT COALESCE(SUM(size),0) AS n FROM files WHERE user_id=?", (user.id,)).fetchone()["n"]
    elapsed = int((datetime.now(timezone.utc) - STARTED_AT).total_seconds())
    hours, remainder = divmod(elapsed, 3600)
    minutes, _ = divmod(remainder, 60)
    return {"ok": True, "storage_used": total, "storage_limit": STORAGE_LIMIT, "uptime": f"{hours}h {minutes}m"}


@app.get("/api/files")
def list_files(user: CurrentUser):
    with db() as connection:
        rows = connection.execute(
            "SELECT id,filename,size,content_type,created_at FROM files WHERE user_id=? ORDER BY created_at DESC",
            (user.id,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/files", status_code=201)
async def upload_file(request: Request, user: CurrentUser, file: Annotated[UploadFile, File()]):
    rate_limit(request, "upload", 120, 3600, user.id)
    filename = Path(file.filename or "upload").name.replace("\x00", "")[:255]
    if not filename or filename in {".", ".."}:
        raise HTTPException(400, "Invalid filename")
    file_id = str(uuid.uuid4())
    stored_name = f"{user.id}_{file_id}.bin"
    destination = UPLOAD_DIR / stored_name
    size = 0
    try:
        with destination.open("xb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit")
                out.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    try:
        with db() as connection:
            used = connection.execute("SELECT COALESCE(SUM(size),0) AS n FROM files WHERE user_id=?", (user.id,)).fetchone()["n"]
            if used + size > STORAGE_LIMIT:
                raise HTTPException(413, "Your storage quota is reached; delete files or increase NOVA_STORAGE_LIMIT_GB")
            connection.execute(
                "INSERT INTO files(id,user_id,filename,stored_name,size,content_type,created_at) VALUES(?,?,?,?,?,?,?)",
                (file_id, user.id, filename, stored_name, size, file.content_type, now_iso()),
            )
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return {"id": file_id, "filename": filename, "size": size}


@app.get("/api/files/{file_id}/download")
def download_file(file_id: str, request: Request, user: CurrentUser):
    rate_limit(request, "download", 600, 3600, user.id)
    with db() as connection:
        row = connection.execute("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, user.id)).fetchone()
    if not row:
        raise HTTPException(404, "File not found")
    path = UPLOAD_DIR / row["stored_name"]
    if not path.is_file():
        raise HTTPException(404, "Stored file is missing")
    return FileResponse(path, filename=row["filename"], media_type="application/octet-stream", headers={"X-Content-Type-Options": "nosniff"})


@app.delete("/api/files/{file_id}", status_code=204)
def delete_file(file_id: str, request: Request, user: CurrentUser):
    rate_limit(request, "delete-file", 120, 3600, user.id)
    with db() as connection:
        row = connection.execute("SELECT stored_name FROM files WHERE id=? AND user_id=?", (file_id, user.id)).fetchone()
        if not row:
            raise HTTPException(404, "File not found")
        (UPLOAD_DIR / row["stored_name"]).unlink(missing_ok=True)
        connection.execute("DELETE FROM files WHERE id=? AND user_id=?", (file_id, user.id))
    return None


@app.get("/api/vault/salt")
def vault_salt(user: CurrentUser):
    return {"salt": user.vault_salt}


@app.get("/api/vault")
def list_vault_entries(user: CurrentUser):
    with db() as connection:
        rows = connection.execute(
            "SELECT id,iv,ciphertext,created_at FROM vault_entries WHERE user_id=? ORDER BY created_at DESC",
            (user.id,),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/vault", status_code=201)
def create_vault_entry(entry: EncryptedVaultEntry, request: Request, user: CurrentUser):
    rate_limit(request, "vault-write", 120, 3600, user.id)
    entry_id, created_at = str(uuid.uuid4()), now_iso()
    with db() as connection:
        connection.execute(
            "INSERT INTO vault_entries(id,user_id,iv,ciphertext,created_at) VALUES(?,?,?,?,?)",
            (entry_id, user.id, entry.iv, entry.ciphertext, created_at),
        )
    return {"id": entry_id, "created_at": created_at}


@app.delete("/api/vault/{entry_id}", status_code=204)
def delete_vault_entry(entry_id: str, request: Request, user: CurrentUser):
    rate_limit(request, "vault-delete", 120, 3600, user.id)
    with db() as connection:
        cursor = connection.execute("DELETE FROM vault_entries WHERE id=? AND user_id=?", (entry_id, user.id))
        if cursor.rowcount == 0:
            raise HTTPException(404, "Vault entry not found")
    return None


@app.post("/api/contact", status_code=201)
def create_contact_message(message: ContactMessage, request: Request):
    rate_limit(request, "contact", 5, 3600)
    message_id = str(uuid.uuid4())
    with db() as connection:
        connection.execute(
            "INSERT INTO contact_messages(id,name,email,subject,message,created_at) VALUES(?,?,?,?,?,?)",
            (message_id, message.name.strip(), str(message.email), message.subject.strip(), message.message.strip(), now_iso()),
        )
    return {"id": message_id, "saved": True}


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
