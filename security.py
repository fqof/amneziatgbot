import re
import time
import math
import sqlite3
import threading
import logging
from collections import defaultdict
from flask import request, redirect, abort

from config import settings

logger = logging.getLogger(__name__)

_DB_PATH = "bans.db"
_DB_LOCK = threading.Lock()
_db_conn: sqlite3.Connection | None = None

_BLOCKED_IPS: dict[str, float] = {}
_BLOCK_STRIKES: dict[str, int] = defaultdict(int)
_BLOCKED_LOCK = threading.Lock()

_SCAN_STORE: dict[str, list[float]] = defaultdict(list)
_SCAN_LOCK = threading.Lock()

_REQ_STORE: dict[str, list[float]] = defaultdict(list)
_REQ_LOCK = threading.Lock()

_404_STORE: dict[str, list[float]] = defaultdict(list)
_404_LOCK = threading.Lock()

_HOME_URL = "/"

_BLOCK_DURATIONS = [3600, 86400, 604800]
_SCAN_THRESHOLD = 8
_SCAN_WINDOW    = 60
_RATE_LIMIT     = 60
_RATE_WINDOW    = 10
_404_LIMIT      = 10
_404_WINDOW     = 60

# IP-адреса, которые никогда не блокируются
_WHITELIST_IPS: set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
}

# Пути, которые пропускаются до любых проверок
_WHITELIST_PATHS_RE = re.compile(
    r"^/(favicon\.ico|robots\.txt|sitemap\.xml)$",
    re.IGNORECASE,
)

_KNOWN_UA_RE = re.compile(r"^Mozilla/5\.0 \(.+?\) .+", re.IGNORECASE)

_BAD_UA_RE = re.compile(
    r"(zgrab|masscan|nmap|sqlmap|nikto|dirbuster|gobuster|wfuzz|nuclei|"
    r"shodan|censys|binaryedge|stretchoid|internetmeasurement|infrawat|"
    r"odin|libredtail|python-requests|go-http-client|libwww-perl|"
    r"java/\d|okhttp|httpx|scrapy|axios|pycurl|aiohttp|"
    r"curl/|wget/|lwp-|peach|zmeu|morfeus|winhttp|"
    r"openvas|nessus|acunetix|appscan|burpsuite|"
    r"qualys|rapid7|tenable|w3af|skipfish|"
    r"ruby|perl|php/|python/|go/\d|rust/|"
    r"esearch-web|infrawatch|xfa\d|hello,\s*world)",
    re.IGNORECASE,
)

_BAD_PATH_RE = re.compile(
    r"(wp-admin|wp-login|wp-content|wp-includes|wp-json|"
    r"phpmyadmin|pma/|myadmin/|mysqladmin/|"
    r"\.env|\.git/|\.svn/|\.hg/|\.DS_Store|"
    r"config\.php|configuration\.php|settings\.php|"
    r"setup\.php|install\.php|upgrade\.php|"
    r"xmlrpc\.php|xmlrpc/|"
    r"/cgi-bin/|/bin/sh|/bin/bash|/etc/passwd|/etc/shadow|/proc/self|"
    r"gpon|diag_form|diag_Form|HNAP\d|evox/about|"
    r"geoserver|webui/|/sdk\b|/odinhttpcall|"
    r"phpstudy|phpinfo|eval-stdin|"
    r"actuator/|\.well-known/acme|"
    r"admin/config|admin/setup|admin/install|"
    r"solr/|jmx-console|web-console|invoker/|"
    r"telescope/|horizon/|_debugbar/|"
    r"\.aws/|\.ssh/|id_rsa|authorized_keys|"
    r"backup\.|dump\.|\.bak|\.sql|\.tar|\.zip|\.gz|"
    r"shell\.php|cmd\.php|r57|c99|b374k|webshell|"
    r"crossdomain\.xml|clientaccesspolicy\.xml)",
    re.IGNORECASE,
)

_INJECTION_RE = re.compile(
    r"(%00|%0[aAdD]|\.\./|\.\.\\|"
    r"%%32%65|%2e%2e|\.%2e|%2e\.|"
    r"allow_url_include|auto_prepend_file|"
    r"php://input|php://filter|data://|expect://|"
    r"union\s+select|select\s+from|drop\s+table|"
    r"<script|javascript:|vbscript:|"
    r"base64_decode|eval\(|assert\(|"
    r"wget\s+http|curl\s+http|"
    r"\/\*.*\*\/|0x[0-9a-f]{4,})",
    re.IGNORECASE,
)

_BINARY_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]")


# ---------------------------------------------------------------------------
# БД
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.execute("PRAGMA journal_mode=WAL")
        _db_conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip      TEXT PRIMARY KEY,
                until   REAL NOT NULL,
                strikes INTEGER NOT NULL DEFAULT 1,
                reason  TEXT,
                updated REAL NOT NULL
            )
        """)
        _db_conn.commit()
    return _db_conn


def _load_bans():
    now = time.time()
    with _DB_LOCK:
        db = _get_db()
        cur = db.execute("SELECT ip, until, strikes FROM blocked_ips WHERE until > ?", (now,))
        rows = cur.fetchall()
    with _BLOCKED_LOCK:
        for row in rows:
            _BLOCKED_IPS[row["ip"]] = row["until"]
            _BLOCK_STRIKES[row["ip"]] = row["strikes"]
    if rows:
        logger.info("Загружено %d активных блокировок из bans.db", len(rows))


def _persist_ban(ip: str, until: float, strikes: int, reason: str):
    with _DB_LOCK:
        db = _get_db()
        db.execute("""
            INSERT INTO blocked_ips (ip, until, strikes, reason, updated)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                until   = excluded.until,
                strikes = excluded.strikes,
                reason  = excluded.reason,
                updated = excluded.updated
        """, (ip, until, strikes, reason, time.time()))
        db.commit()


def _remove_expired_bans():
    with _DB_LOCK:
        db = _get_db()
        db.execute("DELETE FROM blocked_ips WHERE until <= ?", (time.time(),))
        db.commit()


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _get_ip() -> str:
    if getattr(settings, "TRUST_PROXY_HEADERS", False):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _path_entropy(path: str) -> float:
    if not path:
        return 0.0
    freq = defaultdict(int)
    for c in path:
        freq[c] += 1
    length = len(path)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ---------------------------------------------------------------------------
# Блокировка
# ---------------------------------------------------------------------------

def _is_blocked(ip: str) -> bool:
    with _BLOCKED_LOCK:
        until = _BLOCKED_IPS.get(ip)
        if until is None:
            return False
        if time.time() < until:
            return True
        del _BLOCKED_IPS[ip]
    return False


def _block_ip(ip: str, reason: str = ""):
    with _BLOCKED_LOCK:
        strikes = _BLOCK_STRIKES[ip]
        _BLOCK_STRIKES[ip] += 1
        duration = _BLOCK_DURATIONS[min(strikes, len(_BLOCK_DURATIONS) - 1)]
        until = time.time() + duration
        _BLOCKED_IPS[ip] = until
        new_strikes = _BLOCK_STRIKES[ip]

    _persist_ban(ip, until, new_strikes, reason)
    logger.warning(
        "Заблокирован IP %s на %ds (удар %d). Причина: %s",
        ip, duration, new_strikes, reason,
    )


def unblock_ip(ip: str):
    """Ручная разблокировка IP (для админки или CLI)."""
    with _BLOCKED_LOCK:
        _BLOCKED_IPS.pop(ip, None)
        _BLOCK_STRIKES.pop(ip, None)
    with _DB_LOCK:
        db = _get_db()
        db.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        db.commit()
    logger.info("IP %s разблокирован вручную", ip)


# ---------------------------------------------------------------------------
# Счётчики
# ---------------------------------------------------------------------------

def _record_and_check(
    store: dict,
    lock: threading.Lock,
    ip: str,
    threshold: int,
    window: int,
) -> bool:
    now = time.time()
    with lock:
        store[ip] = [t for t in store[ip] if now - t < window]
        store[ip].append(now)
        return len(store[ip]) >= threshold


def _is_rate_exceeded(ip: str) -> bool:
    return _record_and_check(_REQ_STORE, _REQ_LOCK, ip, _RATE_LIMIT, _RATE_WINDOW)


def _is_scan_threshold(ip: str) -> bool:
    return _record_and_check(_SCAN_STORE, _SCAN_LOCK, ip, _SCAN_THRESHOLD, _SCAN_WINDOW)


def _is_404_flood(ip: str) -> bool:
    return _record_and_check(_404_STORE, _404_LOCK, ip, _404_LIMIT, _404_WINDOW)


# ---------------------------------------------------------------------------
# Классификация запроса
# ---------------------------------------------------------------------------

def _classify_request() -> str | None:
    ua       = request.headers.get("User-Agent", "")
    raw_path = request.environ.get("RAW_URI", "") or request.full_path or request.path
    qs       = request.query_string.decode("utf-8", errors="replace")
    full     = raw_path + ("?" + qs if qs else "")

    if _BINARY_RE.search(raw_path):
        return "binary_path"
    if _BAD_UA_RE.search(ua):
        return "bad_ua"
    if not ua or (len(ua) < 10 and not _KNOWN_UA_RE.match(ua)):
        return "empty_ua"
    if _BAD_PATH_RE.search(raw_path):
        return "bad_path"
    if _INJECTION_RE.search(full):
        return "injection"
    if _path_entropy(raw_path) > 4.5 and len(raw_path) > 40:
        return "high_entropy"
    if request.method not in ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"):
        return "bad_method"
    if request.method == "POST" and not ua:
        return "post_no_ua"
    return None


# ---------------------------------------------------------------------------
# Основной хук
# ---------------------------------------------------------------------------

def check_scanner(app, home_url: str = "/"):
    global _HOME_URL
    _HOME_URL = home_url

    _get_db()
    _load_bans()
    _remove_expired_bans()

    @app.before_request
    def _guard():
        ip = _get_ip()

        # 1. Белый список IP — пропускаем без проверок
        if ip in _WHITELIST_IPS:
            return

        # 2. Белый список путей — пропускаем без проверок
        if _WHITELIST_PATHS_RE.match(request.path):
            return

        # 3. Уже заблокирован?
        if _is_blocked(ip):
            abort(403)

        # 4. Превышение частоты запросов
        if _is_rate_exceeded(ip):
            _block_ip(ip, "rate_limit")
            abort(429)

        # 5. Классификация подозрительного запроса
        reason = _classify_request()
        if reason:
            if _is_scan_threshold(ip):
                _block_ip(ip, reason)
                abort(403)
            abort(400)

    @app.errorhandler(400)
    def _bad_request(_e):
        return "", 400

    @app.errorhandler(404)
    def _not_found(_e):
        ip = _get_ip()
        if ip in _WHITELIST_IPS:
            return redirect(_HOME_URL, code=301)
        if _is_404_flood(ip):
            _block_ip(ip, "404_flood")
            abort(403)
        return redirect(_HOME_URL, code=301)

    @app.errorhandler(429)
    def _too_many(_e):
        return "", 429

    @app.errorhandler(403)
    def _forbidden(_e):
        return "", 403