"""FastAPI router: login (OAuth done by the page), server-side session, scan jobs and inventory.

Mount it into any FastAPI app:

    from sfdcautocert.api import create_router
    app.include_router(create_router(base="/cert-manager"), prefix="/cert-manager")

The browser never calls Salesforce. After the OAuth redirect the page hands the access token to
POST {base}/api/session; from then on the token lives only in this process (HttpOnly session cookie
-> in-memory entry) and every Salesforce call (Metadata / Tooling API, TLS scans) is made here.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Cookie, Header, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .service import Inventory
from .sf.auth import Session

STATIC = Path(__file__).parent / "static"
COOKIE = "cm_sid"
SESSION_TTL = 2 * 60 * 60
MAX_SESSIONS = 500
SF_HOST_SUFFIXES = (".salesforce.com", ".force.com", ".salesforce-setup.com", ".cloudforce.com")


def normalize_instance_url(url: str) -> str:
    """Only ever talk to Salesforce hosts: the token is sent to this URL."""
    u = urlparse(url.strip())
    host = (u.hostname or "").lower()
    if u.scheme != "https" or u.username or u.password or u.port not in (None, 443):
        raise ValueError("instance_url must be a plain https URL")
    if not any(host.endswith(s) for s in SF_HOST_SUFFIXES):
        raise ValueError("instance_url is not a Salesforce host")
    return f"https://{host}"


def _userinfo(instance_url: str, token: str) -> dict:
    req = urllib.request.Request(f"{instance_url}/services/oauth2/userinfo",
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


@dataclass
class Entry:
    session: Session
    user: dict
    inventory: Inventory
    expires: float


class Sessions:
    def __init__(self, ttl: float = SESSION_TTL, maxsize: int = MAX_SESSIONS):
        self._d: dict[str, Entry] = {}
        self._lock = threading.Lock()
        self.ttl, self.maxsize = ttl, maxsize

    def _purge(self) -> None:
        now = time.time()
        for k in [k for k, e in self._d.items() if e.expires < now]:
            del self._d[k]
        while len(self._d) >= self.maxsize:  # oldest first
            del self._d[min(self._d, key=lambda k: self._d[k].expires)]

    def create(self, entry: Entry) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            entry.expires = time.time() + self.ttl
            self._d[sid] = entry
        return sid

    def get(self, sid: Optional[str]) -> Optional[Entry]:
        if not sid:
            return None
        with self._lock:
            e = self._d.get(sid)
            if e and e.expires < time.time():
                del self._d[sid]
                return None
            return e

    def delete(self, sid: Optional[str]) -> None:
        with self._lock:
            self._d.pop(sid or "", None)


class SessionBody(BaseModel):
    access_token: str
    instance_url: str


def create_router(base: str = "", client_id: Optional[str] = None, dev_inventory: Optional[Inventory] = None,
                  api_version: str = "62.0", userinfo: Callable[[str, str], dict] = _userinfo) -> APIRouter:
    """base: URL path prefix the router is mounted under (used by the page and as cookie path).
    dev_inventory: single pre-authenticated inventory for local development (no login)."""
    router = APIRouter()
    sessions = Sessions()
    base = base.rstrip("/")
    page = (STATIC / "index.html").read_text(encoding="utf-8").replace("__BASE__", json.dumps(base)[1:-1])

    def entry_or_401(sid: Optional[str]) -> Entry:
        e = sessions.get(sid)
        if e is None and dev_inventory is not None:
            return Entry(Session("", ""), {"username": dev_inventory.org_label}, dev_inventory, 0)
        if e is None:
            raise HTTPException(401, "not authenticated")
        return e

    def need_header(x_requested_with: Optional[str]) -> None:
        if x_requested_with != "cert-manager":  # a cross-site form post cannot set this header
            raise HTTPException(403, "missing X-Requested-With header")

    def no_store(resp: Response) -> None:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"

    @router.get("", response_class=HTMLResponse, include_in_schema=False)
    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index():
        return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                           "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"})

    @router.get("/api/config")
    def config(response: Response):
        no_store(response)
        return {"clientId": client_id or os.environ.get("SF_CLIENT_ID", ""), "dev": dev_inventory is not None}

    @router.post("/api/session")
    def create_session(body: SessionBody, response: Response, x_requested_with: Optional[str] = Header(None)):
        need_header(x_requested_with)
        no_store(response)
        try:
            instance_url = normalize_instance_url(body.instance_url)
        except ValueError as e:
            raise HTTPException(400, str(e))
        try:
            user = userinfo(instance_url, body.access_token)
        except Exception:
            raise HTTPException(401, "Salesforce rejected the access token")
        session = Session(body.access_token, instance_url)
        inv = Inventory(lambda: session, org_label=user.get("preferred_username") or user.get("email") or "",
                        api_version=api_version)
        sid = sessions.create(Entry(session, user, inv, 0))
        response.set_cookie(COOKIE, sid, max_age=SESSION_TTL, httponly=True, secure=True, samesite="strict",
                            path=base or "/")
        inv.refresh_async()
        return {"authenticated": True, "username": inv.org_label}

    @router.get("/api/me")
    def me(response: Response, cm_sid: Optional[str] = Cookie(None)):
        no_store(response)
        try:
            e = entry_or_401(cm_sid)
        except HTTPException:
            return {"authenticated": False}
        u = e.user
        return {"authenticated": True, "username": e.inventory.org_label, "org_id": u.get("organization_id"),
                "instance_url": e.session.instance_url or None}

    @router.get("/api/inventory")
    def inventory(response: Response, cm_sid: Optional[str] = Cookie(None)):
        no_store(response)
        return entry_or_401(cm_sid).inventory.snapshot()

    @router.post("/api/refresh", status_code=202)
    def refresh(response: Response, cm_sid: Optional[str] = Cookie(None),
                x_requested_with: Optional[str] = Header(None)):
        need_header(x_requested_with)
        no_store(response)
        entry_or_401(cm_sid).inventory.refresh_async()
        return {"started": True}

    @router.post("/api/logout")
    def logout(response: Response, cm_sid: Optional[str] = Cookie(None),
               x_requested_with: Optional[str] = Header(None)):
        need_header(x_requested_with)
        sessions.delete(cm_sid)
        response.delete_cookie(COOKIE, path=base or "/")
        return {"authenticated": False}

    return router
