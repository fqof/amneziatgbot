import asyncio
import hashlib
import hmac
import json
import logging
import re
import threading
import time
import urllib.parse
from collections import defaultdict
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, g
from config import settings
from database import Database
from amnezia_client import AmneziaClient
from shared import get_shared_ping

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
from security import check_scanner; check_scanner(app, "/")

_db: Database | None = None
_amnezia: AmneziaClient | None = None

VPN_NAME_RE = re.compile(r"^[a-zA-Z\u0430-\u044f\u0410-\u042f\u0451\u04010-9]{1,16}$")

_loop = asyncio.new_event_loop()

def _start_background_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

_loop_thread = threading.Thread(target=_start_background_loop, args=(_loop,), daemon=True)
_loop_thread.start()


def run_async(coro):
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result()

def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database(settings.DB_PATH, settings.DB_ENCRYPTION_KEY)
        run_async(_db.init())
    return _db

def get_amnezia() -> AmneziaClient:
    global _amnezia
    if _amnezia is None:
        _amnezia = AmneziaClient(
            settings.AMNEZIA_API_URL,
            settings.AMNEZIA_API_KEY,
            settings.AMNEZIA_PROTOCOL,
        )
    return _amnezia


class _RateLimiter:
    def __init__(self):
        self._hits: dict[tuple, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            cutoff = now - window
            while hits and hits[0] < cutoff:
                hits.pop(0)
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

_rate_limiter = _RateLimiter()

def rate_limit(limit: int = 30, window: int = 60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                if getattr(settings, "TRUST_PROXY_HEADERS", False) and request.headers.get("X-Forwarded-For")
                else (request.remote_addr or "unknown")
            )
            key = f"{ip}:{request.endpoint}"
            if not _rate_limiter.is_allowed(key, limit, window):
                logger.warning("Rate limit exceeded: %s -> %s", ip, request.endpoint)
                return jsonify({"error": "Слишком много запросов. Попробуйте через минуту."}), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator


def validate_telegram_init_data(init_data: str) -> dict | None:
    try:
        parsed = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
        received_hash = parsed.pop("hash", None)
        if not received_hash:
            return None

        auth_date = int(parsed.get("auth_date", 0))
        if time.time() - auth_date > 3600:
            logger.warning("Отклонено: устаревший auth_date (%d сек)", int(time.time()) - auth_date)
            return None

        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
        secret_key = hmac.new(b"WebAppData", settings.BOT_TOKEN.encode(), hashlib.sha256).digest()
        expected_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(received_hash, expected_hash):
            logger.warning("Отклонено: неверная подпись initData")
            return None

        user = json.loads(parsed.get("user", "{}"))
        if not user.get("id"):
            return None

        return user
    except Exception as e:
        logger.error("initData validation error: %s", e)
        return None


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if settings.MINIAPP_DEV_MODE:
            g.tg_user = {
                "id": settings.ADMIN_IDS[0] if settings.ADMIN_IDS else 0,
                "first_name": "DevUser",
            }
            return f(*args, **kwargs)

        init_data = request.headers.get("X-Telegram-Init-Data", "").strip()
        if not init_data:
            return jsonify({"error": "Unauthorized"}), 401

        user = validate_telegram_init_data(init_data)
        if user is None:
            return jsonify({"error": "Unauthorized"}), 401

        if settings.BOT_MODE == "admin" and user["id"] not in settings.ADMIN_IDS:
            return jsonify({"error": "Access denied"}), 403

        db = get_db()
        if run_async(db.get_user_banned(user["id"])):
            return jsonify({"error": "Banned"}), 403

        g.tg_user = user
        return f(*args, **kwargs)
    return wrapper


def require_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH"):
            if not request.is_json:
                return jsonify({"error": "Content-Type должен быть application/json"}), 415
            if request.content_length and request.content_length > 4096:
                return jsonify({"error": "Тело запроса слишком большое"}), 413
        return f(*args, **kwargs)
    return wrapper


import random
import string as _string
_SLUG_CHARS = _string.ascii_lowercase + _string.digits

def _gen_slug() -> str:
    return "".join(random.choices(_SLUG_CHARS, k=5))

def _get_or_create_slug(db: Database, profile_id: int) -> str:
    existing = run_async(db.get_short_link_by_profile(profile_id))
    if existing:
        return existing
    for _ in range(20):
        slug = _gen_slug()
        if not run_async(db.get_short_link_by_slug(slug)):
            run_async(db.get_or_create_short_link(profile_id, slug))
            return slug
    slug = "".join(random.choices(_SLUG_CHARS, k=6))
    run_async(db.get_or_create_short_link(profile_id, slug))
    return slug


def fmt_bytes(b: float) -> str:
    if not b: return "0 Б"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024: return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} ТБ"

def find_peer(clients_data: dict | None, vpn_name: str) -> dict | None:
    if not clients_data: return None
    for item in clients_data.get("items", []):
        if item.get("username") == vpn_name:
            peers = item.get("peers", [])
            return peers[0] if peers else None
    return None

def profile_to_json(profile: dict, peer: dict | None = None) -> dict:
    result = {
        "id": profile["id"],
        "vpn_name": profile["vpn_name"],
        "created_at": profile.get("created_at", ""),
        "disabled": profile.get("disabled", False),
        "via_key": profile.get("via_key", False),
    }
    if peer:
        tr = peer.get("traffic", {})
        last_hs = peer.get("lastHandshake", 0)
        result["peer"] = {
            "online": peer.get("online", False),
            "status": peer.get("status", ""),
            "rx": fmt_bytes(float(tr.get("received", 0) or 0)),
            "tx": fmt_bytes(float(tr.get("sent", 0) or 0)),
            "rx_bytes": float(tr.get("received", 0) or 0),
            "tx_bytes": float(tr.get("sent", 0) or 0),
            "protocol": peer.get("protocol", ""),
            "last_handshake": last_hs,
        }
    return result


@app.route("/api/me", methods=["GET"])
@require_auth
@rate_limit(limit=30, window=60)
def api_me():
    uid = g.tg_user["id"]
    db = get_db()
    amnezia = get_amnezia()

    is_admin = uid in settings.ADMIN_IDS
    max_profiles = None if is_admin else settings.MAX_PROFILES_PER_USER

    profiles = run_async(db.get_profiles(uid))
    can_create = True if is_admin else run_async(db.can_create_profile(uid, settings.MAX_PROFILES_PER_USER))
    clients = run_async(amnezia.get_all_clients())

    result = []
    for p in profiles:
        peer = find_peer(clients, p["vpn_name"])
        result.append(profile_to_json(p, peer))

    return jsonify({
        "profiles": result,
        "can_create": can_create,
        "max_profiles": max_profiles,
        "is_admin": is_admin,
        "user": {
            "id": uid,
            "name": g.tg_user.get("first_name", ""),
        },
    })


@app.route("/api/create", methods=["POST"])
@require_auth
@require_json
@rate_limit(limit=5, window=60)
def api_create():
    uid = g.tg_user["id"]
    db = get_db()
    amnezia = get_amnezia()

    is_admin = uid in settings.ADMIN_IDS

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()[:16]

    if not name:
        return jsonify({"error": "Имя не может быть пустым"}), 400
    if not VPN_NAME_RE.match(name):
        return jsonify({"error": "Только буквы (латиница/кириллица) и цифры, до 16 символов"}), 400

    if not is_admin and not run_async(db.can_create_profile(uid, settings.MAX_PROFILES_PER_USER)):
        return jsonify({"error": f"Достигнут лимит профилей ({settings.MAX_PROFILES_PER_USER})"}), 400

    if run_async(db.is_vpn_name_taken(name)):
        return jsonify({"error": "Имя уже занято, выберите другое"}), 409

    result = run_async(amnezia.create_user(name))
    if result is None:
        return jsonify({"error": "Ошибка API Amnezia. Попробуйте позже."}), 502

    peer_id = result.get("client", {}).get("id")
    profile_id = run_async(db.add_profile(uid, name, peer_id, json.dumps(result, ensure_ascii=False), via_key=False))

    return jsonify({"ok": True, "profile_id": profile_id, "vpn_name": name})


@app.route("/api/profile/<int:profile_id>", methods=["DELETE"])
@require_auth
@rate_limit(limit=10, window=60)
def api_delete_profile(profile_id: int):
    uid = g.tg_user["id"]
    db = get_db()
    amnezia = get_amnezia()

    profile = run_async(db.get_profile_by_id(profile_id))
    if not profile or profile["telegram_id"] != uid:
        return jsonify({"error": "Профиль не найден"}), 404

    peer_id = profile.get("peer_id")
    if peer_id:
        run_async(amnezia.delete_user(peer_id))

    run_async(db.delete_profile(profile_id))
    return jsonify({"ok": True})


@app.route("/api/config/<int:profile_id>", methods=["GET"])
@require_auth
@rate_limit(limit=20, window=60)
def api_config(profile_id: int):
    uid = g.tg_user["id"]
    db = get_db()
    amnezia = get_amnezia()

    profile = run_async(db.get_profile_by_id(profile_id))
    if not profile or profile["telegram_id"] != uid:
        return jsonify({"error": "Профиль не найден"}), 404
    if profile.get("disabled"):
        return jsonify({"error": "Профиль отключён администратором"}), 403

    config_str = None
    raw = profile.get("raw_response")
    if raw:
        try:
            config_str = json.loads(raw).get("client", {}).get("config")
        except Exception:
            pass

    if not config_str:
        config_str = run_async(amnezia.get_client_config(profile.get("peer_id") or profile["vpn_name"]))

    if not config_str:
        return jsonify({"error": "Конфиг недоступен. Обратитесь к администратору."}), 404

    slug = _get_or_create_slug(db, profile_id)
    domain = getattr(settings, "SHORT_LINK_DOMAIN", "fqof.ru").rstrip("/")
    short_url = f"https://{domain}/c/{slug}"

    return jsonify({
        "config": config_str,
        "vpn_name": profile["vpn_name"],
        "filename": f"{profile['vpn_name']}.vpn",
        "short_link": short_url,
    })


@app.route("/api/ping", methods=["GET"])
@rate_limit(limit=10, window=60)
def api_ping():
    ping_host = settings.VPN_HOST or settings.AMNEZIA_API_URL.split("//")[-1].split(":")[0] or "127.0.0.1"
    ms = get_shared_ping(ping_host, settings.AMNEZIA_API_URL)
    return jsonify({"ping_ms": ms})


@app.route("/api/server", methods=["GET"])
@require_auth
@rate_limit(limit=15, window=60)
def api_server():
    amnezia = get_amnezia()
    info    = run_async(amnezia.get_server_info())
    load    = run_async(amnezia.get_server_load())
    online  = run_async(amnezia.health_check())
    clients_data = run_async(amnezia.get_all_clients())

    result = {"online": online}

    if info:
        result["region"] = info.get("region") or info.get("serverRegion") or "—"
        pr = info.get("protocols") or info.get("protocolsEnabled") or []
        if isinstance(pr, str): pr = [pr]
        result["protocols"] = pr
        result["max_peers"] = info.get("maxPeers") or "—"

    peers_count = 0
    online_peers = 0
    if clients_data:
        for item in clients_data.get("items", []):
            for peer in item.get("peers", []):
                peers_count += 1
                if peer.get("online"):
                    online_peers += 1
    if peers_count == 0 and info:
        peers_count = info.get("peersCount") or info.get("clientsCount") or 0

    result["peers_count"]  = peers_count
    result["online_peers"] = online_peers

    if load:
        mem    = load.get("memory", {})
        dsk    = load.get("disk", {})
        docker = (load.get("docker", {}).get("containers") or [{}])[0]

        mem_total = mem.get("totalBytes", 0) or 1
        mem_used  = mem.get("usedBytes", 0)

        result["load"] = {
            "cpu":        round(docker.get("cpuPercent", 0) or 0, 1),
            "ram":        round(mem_used / mem_total * 100, 1),
            "disk":       round(dsk.get("usedPercent", 0) or 0, 1),
            "uptime_sec": int(load.get("uptimeSec", 0)),
            "net_rx":     docker.get("netRxBytes", 0),
            "net_tx":     docker.get("netTxBytes", 0),
        }

    result["is_admin"] = g.tg_user["id"] in settings.ADMIN_IDS
    return jsonify(result)


@app.route("/api/validate_hash", methods=["POST"])
@require_json
@rate_limit(limit=20, window=60)
def api_validate_hash():
    data      = request.get_json(silent=True) or {}
    init_data = request.headers.get("X-Telegram-Init-Data", data.get("initData", ""))
    user      = validate_telegram_init_data(init_data)
    if user is None:
        return jsonify({"valid": False}), 401
    return jsonify({"valid": True, "user": user})


from web_service import generate_secret_key as _gen_secret_key

@app.route("/api/mykey", methods=["GET"])
@require_auth
@rate_limit(limit=15, window=60)
def api_mykey():
    uid = g.tg_user["id"]
    db  = get_db()

    if run_async(db.get_user_key_blocked(uid)):
        return jsonify({"error": "Создание ключей заблокировано администратором"}), 403

    existing = run_async(db.get_secret_key_by_user(uid))
    domain   = getattr(settings, "SHORT_LINK_DOMAIN", "fqof.ru").rstrip("/")

    if existing and not existing.get("revoked"):
        return jsonify({
            "key":        existing["key_value"],
            "used":       bool(existing.get("used")),
            "revoked":    bool(existing.get("revoked")),
            "created_at": existing.get("created_at", ""),
            "site_url":   f"https://{domain}",
        })

    key_val = _gen_secret_key()
    run_async(db.create_secret_key(uid, key_val))
    return jsonify({
        "key": key_val, "used": False, "revoked": False,
        "created_at": "", "site_url": f"https://{domain}",
    })


@app.route("/api/newkey", methods=["POST"])
@require_auth
@require_json
@rate_limit(limit=5, window=300)
def api_newkey():
    uid    = g.tg_user["id"]
    db     = get_db()
    domain = getattr(settings, "SHORT_LINK_DOMAIN", "fqof.ru").rstrip("/")

    if run_async(db.get_user_key_blocked(uid)):
        return jsonify({"error": "Создание ключей заблокировано администратором"}), 403

    key_val = _gen_secret_key()
    run_async(db.create_secret_key(uid, key_val))
    return jsonify({
        "key": key_val, "used": False, "revoked": False,
        "created_at": "", "site_url": f"https://{domain}",
    })


MINIAPP_CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Geologica:wght@300;400;600;700&display=swap');

:root {
  --bg:      #080b10;
  --s1:      #0e1117;
  --s2:      #141820;
  --s3:      #1c2130;
  --border:  #1f2535;
  --border2: #2a3348;

  --text:    #e8edf5;
  --text2:   #8892a4;
  --text3:   #4a5568;
  --white:   #ffffff;
  --green:   #3ddc84;
  --green2:  #2ab86d;
  --red:     #ff5252;
  --amber:   #f5a623;
  --blue:    #4a9eff;

  --green-bg: rgba(61,220,132,0.09);
  --red-bg:   rgba(255,82,82,0.09);
  --blue-bg:  rgba(74,158,255,0.09);
  --amber-bg: rgba(245,166,35,0.09);

  --radius:   14px;
  --radius-s: 10px;
  --radius-xs: 6px;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Geologica', system-ui, sans-serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  overflow: hidden;
  touch-action: manipulation;
}

#app {
  display: flex; flex-direction: column;
  height: 100vh; height: 100dvh;
  max-width: 480px; margin: 0 auto;
  overflow: hidden;
}

#content {
  flex: 1; overflow-y: auto;
  -webkit-overflow-scrolling: touch;
  padding-bottom: 24px;
}

.page {
  display: flex; flex-direction: column;
  gap: 12px; padding: 14px 14px 0;
  animation: fadeUp 0.2s ease both;
}
.page.hidden { display: none; }

@keyframes fadeUp {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}

.app-header {
  flex-shrink: 0;
  background: rgba(8,11,16,0.96);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  padding: 13px 14px 11px;
  display: flex; flex-direction: column; gap: 10px;
}

.header-top {
  display: flex; align-items: center;
  justify-content: space-between;
}

.logo {
  display: flex; align-items: center; gap: 9px;
}
.logo-emoji { font-size: 22px; line-height: 1; }
.logo-name  { font-size: 16px; font-weight: 700; color: var(--white); letter-spacing: -0.3px; }

.user-chip {
  display: flex; align-items: center; gap: 6px;
  background: var(--s2); border: 1px solid var(--border);
  border-radius: 20px; padding: 4px 12px;
  font-size: 12px; font-weight: 500; color: var(--text2);
}
.chip-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--text3); flex-shrink: 0;
  transition: background 0.3s;
}
.chip-dot.on  { background: var(--green); box-shadow: 0 0 5px var(--green); }
.chip-dot.off { background: var(--red); }

.srv-bar {
  display: flex; align-items: center;
  justify-content: space-between;
  background: var(--s2); border: 1px solid var(--border);
  border-radius: var(--radius-s);
  padding: 8px 12px; font-size: 12px;
}
.srv-left {
  display: flex; align-items: center;
  gap: 8px; color: var(--text2); font-weight: 500;
}
.srv-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--text3); flex-shrink: 0;
  transition: background 0.3s;
}
.srv-dot.on {
  background: var(--green);
  animation: pulse 2.2s infinite;
}
@keyframes pulse {
  0%   { box-shadow: 0 0 0 0 rgba(61,220,132,0.45); }
  70%  { box-shadow: 0 0 0 6px rgba(61,220,132,0); }
  100% { box-shadow: 0 0 0 0 transparent; }
}
.srv-right { color: var(--text3); font: 11px var(--mono); }

.section-label {
  font-size: 10px; font-weight: 700;
  letter-spacing: 1.8px; text-transform: uppercase;
  color: var(--text3);
}

.row-between {
  display: flex; align-items: center;
  justify-content: space-between;
}

.card {
  background: var(--s1); border: 1px solid var(--border);
  border-radius: var(--radius); overflow: hidden;
  transition: border-color 0.15s;
}

.card-body { padding: 14px; display: flex; flex-direction: column; gap: 10px; }

.card-title-row {
  display: flex; align-items: center; gap: 8px;
}
.card-name {
  font-size: 15px; font-weight: 700;
  color: var(--white); flex: 1; letter-spacing: -0.2px;
}
.card-meta {
  display: flex; gap: 10px;
  font: 11px var(--mono); color: var(--text3);
  flex-wrap: wrap;
}
.card-date { font: 11px var(--mono); color: var(--text3); }
.card-hs   { font-size: 11px; color: var(--text3); }

.card-foot {
  display: flex;
  border-top: 1px solid var(--border);
}
.foot-btn {
  flex: 1; padding: 12px 8px;
  font: 600 12px var(--sans);
  color: var(--text2);
  background: transparent; border: none;
  border-right: 1px solid var(--border);
  cursor: pointer; transition: background 0.15s, color 0.15s;
}
.foot-btn:last-child { border-right: none; }
.foot-btn:hover { background: var(--s2); color: var(--text); }
.foot-btn.prim  { color: var(--white); }
.foot-btn.del:hover { background: var(--red-bg); color: var(--red); }
.foot-btn:disabled { opacity: 0.4; pointer-events: none; }

.badge {
  font: 600 10px var(--mono);
  border-radius: var(--radius-xs);
  padding: 3px 7px; text-transform: uppercase;
  letter-spacing: 0.3px; flex-shrink: 0;
}
.badge-g  { background: var(--green-bg); color: var(--green); }
.badge-r  { background: var(--red-bg);   color: var(--red);   }
.badge-gr { background: var(--s3);       color: var(--text3); }
.badge-b  { background: var(--blue-bg);  color: var(--blue);  }
.badge-a  { background: var(--amber-bg); color: var(--amber); }

.status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  flex-shrink: 0; transition: background 0.3s;
}
.status-dot.on  { background: var(--green); box-shadow: 0 0 5px var(--green); }
.status-dot.off { background: var(--red); }
.status-dot.dis { background: var(--text3); }

.btn {
  display: inline-flex; align-items: center;
  justify-content: center; gap: 8px;
  width: 100%; border: none;
  border-radius: var(--radius-s);
  font: 600 14px var(--sans);
  padding: 14px; cursor: pointer;
  transition: background 0.15s, transform 0.1s, box-shadow 0.15s;
}
.btn:active   { transform: scale(0.975); }
.btn:disabled { opacity: 0.45; pointer-events: none; }

.btn-group { display: flex; gap: 8px; }

.btn-primary {
  background: var(--green); color: #04100a;
  box-shadow: 0 4px 18px rgba(61,220,132,0.22);
}
.btn-primary:hover {
  background: var(--green2);
  box-shadow: 0 4px 22px rgba(61,220,132,0.38);
}

.btn-outline {
  background: transparent;
  border: 1px solid var(--border2); color: var(--text2);
}
.btn-outline:hover { background: var(--s2); color: var(--text); }

.btn-ghost {
  background: transparent; color: var(--text3);
  padding: 10px; font-size: 13px;
}

.btn-danger {
  background: var(--red-bg); color: var(--red);
  border: 1px solid rgba(255,82,82,0.28);
}
.btn-danger:hover { background: rgba(255,82,82,0.16); }

.btn-refresh {
  background: var(--s2); border: 1px solid var(--border);
  color: var(--text2); padding: 7px 12px;
  font: 600 12px var(--sans); border-radius: var(--radius-s);
  display: flex; align-items: center; gap: 6px;
  width: auto; cursor: pointer; transition: 0.15s;
}
.btn-refresh:hover { background: var(--s3); color: var(--text); }

.add-card {
  border: 1px dashed var(--border2);
  border-radius: var(--radius); padding: 16px;
  display: flex; align-items: center;
  justify-content: center; gap: 8px;
  cursor: pointer; color: var(--text3);
  font: 600 13px var(--sans); background: transparent;
  transition: 0.18s; width: 100%;
}
.add-card:hover {
  border-color: var(--green);
  color: var(--green);
  background: var(--green-bg);
}
.add-plus { font-size: 20px; font-weight: 300; line-height: 1; }

.field { display: flex; flex-direction: column; gap: 7px; margin-bottom: 14px; }
.field-label {
  font-size: 10px; font-weight: 700;
  letter-spacing: 1.5px; text-transform: uppercase; color: var(--text3);
}
.input {
  background: var(--s2); border: 1px solid var(--border);
  border-radius: var(--radius-s); color: var(--text);
  font: 15px var(--mono); padding: 13px 14px; outline: none;
  width: 100%; transition: border-color 0.2s, box-shadow 0.2s;
}
.input::placeholder { color: var(--text3); }
.input:focus {
  border-color: var(--border2);
  box-shadow: 0 0 0 3px rgba(61,220,132,0.07);
}
.input.err { border-color: var(--red); }
.field-hint { font-size: 11px; color: var(--text3); }
.field-hint.err { color: var(--red); }

.link-box {
  background: var(--s2); border: 1px solid var(--border);
  border-radius: var(--radius-s);
  padding: 26px 14px 14px; font: 12px/1.65 var(--mono);
  color: var(--text2); word-break: break-all;
  position: relative; cursor: pointer;
  transition: border-color 0.18s, background 0.18s;
  max-height: 180px; overflow-y: auto;
}
.link-box:hover { border-color: var(--border2); background: var(--s3); }
.link-box.highlight { color: var(--white); font-weight: 600; font-size: 14px; }
.copy-hint {
  font-size: 9px; color: var(--text3);
  text-transform: uppercase; letter-spacing: 0.8px;
  position: absolute; top: 8px; right: 10px;
}

.stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.stat-item {
  background: var(--s2); border: 1px solid var(--border);
  border-radius: var(--radius-s); padding: 13px;
  display: flex; flex-direction: column; gap: 6px;
}
.stat-label {
  font: 700 10px var(--sans);
  letter-spacing: 1.5px; text-transform: uppercase; color: var(--text3);
}
.stat-value {
  font: 700 22px var(--mono); color: var(--white);
}
.stat-sub { font-size: 11px; color: var(--text3); }

.meter { height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; margin-top: 4px; }
.meter-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
.meter-fill.low  { background: var(--green); }
.meter-fill.mid  { background: var(--amber); }
.meter-fill.high { background: var(--red);   }

.g-section {
  background: var(--s2); border: 1px solid var(--border);
  border-radius: var(--radius-s); overflow: hidden;
}
.dl-link {
  display: flex; align-items: center; justify-content: space-between;
  padding: 13px 14px; border-bottom: 1px solid var(--border);
  text-decoration: none; color: var(--white);
  font: 600 13px var(--sans); transition: background 0.15s;
}
.dl-link:hover { background: var(--s3); }
.dl-link:last-child { border-bottom: none; }
.dl-left { display: flex; align-items: center; gap: 9px; }
.dl-arrow { color: var(--text3); font-size: 14px; }

.g-head {
  padding: 13px 14px; display: flex;
  justify-content: space-between; cursor: pointer;
  font: 600 13px var(--sans); color: var(--white);
  user-select: none; transition: background 0.15s;
}
.g-head:hover { background: var(--s3); }
.g-arrow { transition: transform 0.2s; color: var(--text3); }
.g-arrow.open { transform: rotate(90deg); }
.g-body { display: none; padding: 0 14px 14px; gap: 10px; flex-direction: column; }
.g-body.open { display: flex; }

.step { display: flex; gap: 10px; font-size: 12px; color: var(--text2); align-items: flex-start; line-height: 1.55; }
.step-n {
  width: 20px; height: 20px; border-radius: 50%;
  background: var(--s3); border: 1px solid var(--border2);
  display: flex; align-items: center; justify-content: center;
  font: 700 10px var(--mono); flex-shrink: 0; color: var(--text2);
}
code {
  background: var(--s3); padding: 2px 6px;
  border-radius: var(--radius-xs); font-family: var(--mono);
  font-size: 11px; color: var(--green);
}
.g-note {
  background: var(--amber-bg);
  border-left: 3px solid var(--amber);
  padding: 9px 12px; font-size: 11px; color: var(--text2);
  border-radius: 0 var(--radius-xs) var(--radius-xs) 0; line-height: 1.55;
}

.overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.75);
  backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
  z-index: 100; display: flex; align-items: flex-end;
  opacity: 0; pointer-events: none; transition: opacity 0.25s;
}
.overlay.open { opacity: 1; pointer-events: all; }

.sheet {
  background: var(--s1); border: 1px solid var(--border);
  border-bottom: none; border-radius: 20px 20px 0 0;
  padding: 16px 20px 36px; width: 100%;
  max-height: 92vh; max-height: 92dvh;
  overflow-y: auto;
  transform: translateY(100%);
  transition: transform 0.3s cubic-bezier(0.32,0.72,0,1);
  display: flex; flex-direction: column; gap: 16px;
}
.overlay.open .sheet { transform: translateY(0); }

.sheet-handle {
  width: 36px; height: 4px;
  background: var(--border2); border-radius: 2px; margin: 0 auto;
}
.sheet-title {
  font-size: 18px; font-weight: 700; color: var(--white);
  text-align: center; letter-spacing: -0.3px;
}
.confirm-text { font-size: 13px; color: var(--text2); line-height: 1.6; text-align: center; }

.short-link-box {
  background: var(--blue-bg); border: 1px solid rgba(74,158,255,0.2);
  border-radius: var(--radius-s); padding: 26px 14px 14px;
  font: 600 13px var(--mono); color: var(--blue);
  word-break: break-all; position: relative;
  cursor: pointer; transition: 0.18s;
}
.short-link-box:hover { border-color: rgba(74,158,255,0.4); }

.nav {
  flex-shrink: 0;
  background: rgba(8,11,16,0.97);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border-top: 1px solid var(--border);
  display: flex;
  padding-bottom: env(safe-area-inset-bottom, 0px);
}
.nav-btn {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; padding: 10px 8px; gap: 4px;
  cursor: pointer; background: none; border: none;
  color: var(--text3); font: 600 9px var(--sans);
  text-transform: uppercase; letter-spacing: 0.8px;
  transition: color 0.15s;
}
.nav-btn.active { color: var(--green); }
.nav-icon { font-size: 19px; line-height: 1; }

.empty {
  text-align: center; padding: 52px 20px;
  color: var(--text3); display: flex;
  flex-direction: column; gap: 10px; align-items: center;
}
.empty-icon  { font-size: 40px; opacity: 0.45; }
.empty-title { font-size: 14px; font-weight: 600; color: var(--text2); }

.shimmer {
  background: linear-gradient(90deg, var(--s1) 25%, var(--s2) 50%, var(--s1) 75%);
  background-size: 200% 100%;
  animation: shim 1.3s infinite;
  border-radius: var(--radius); height: 96px;
  border: 1px solid var(--border);
}
@keyframes shim {
  from { background-position: 200% 0; }
  to   { background-position: -200% 0; }
}

.toast {
  position: fixed; bottom: 80px; left: 50%;
  transform: translateX(-50%) translateY(8px);
  background: var(--s3); border: 1px solid var(--border2);
  border-radius: 24px; padding: 9px 20px;
  font: 600 12px var(--sans); color: var(--text);
  z-index: 999; opacity: 0;
  transition: opacity 0.22s, transform 0.22s;
  pointer-events: none;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
  white-space: nowrap;
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
.toast.err  { border-color: rgba(255,82,82,0.4); color: var(--red); }

.via-key-badge {
  font: 600 9px var(--sans); border-radius: 4px;
  padding: 2px 6px; background: var(--amber-bg);
  color: var(--amber); text-transform: uppercase; letter-spacing: 0.5px;
}

.key-card-body { padding: 14px; display: flex; flex-direction: column; gap: 12px; }
.key-desc { font-size: 12px; color: var(--text2); line-height: 1.6; }
"""


MINIAPP_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>FQof VPN</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<script>
  (function() {
    var devMode = {{ 'true' if dev_mode else 'false' }};
    var tgApp = window.Telegram && window.Telegram.WebApp;
    if (!devMode && (!tgApp || !tgApp.initData)) {
      document.documentElement.style.display = 'none';
      window.location.replace("https://google.com/");
    }
  })();
</script>
<style>
__MINIAPP_CSS__
</style>
</head>
<body>
<div id="app">

  <header class="app-header">
    <div class="header-top">
      <div class="logo">
        <span class="logo-emoji">🤮</span>
        <span class="logo-name">FQof VPN</span>
      </div>
      <div class="user-chip">
        <div class="chip-dot" id="chip-dot"></div>
        <span id="user-name">...</span>
      </div>
    </div>
    <div class="srv-bar">
      <div class="srv-left">
        <div class="srv-dot" id="srv-dot"></div>
        <span id="srv-text">Проверяю...</span>
      </div>
      <div class="srv-right" id="srv-ping"></div>
    </div>
  </header>

  <main id="content">

    <div id="page-profiles" class="page">
      <div class="row-between">
        <div class="section-label">Ваши профили</div>
        <button class="btn-refresh" onclick="loadProfiles(true)">↻ Обновить</button>
      </div>
      <div id="profiles-list" style="display:flex; flex-direction:column; gap:8px;">
        <div class="shimmer"></div>
        <div class="shimmer" style="opacity:0.5"></div>
      </div>
      <button id="add-btn" class="add-card" style="display:none" onclick="openCreate()">
        <span class="add-plus">+</span> Добавить профиль
      </button>
    </div>

    <div id="page-key" class="page hidden">
      <div class="section-label">Секретный ключ</div>
      <div class="card">
        <div class="key-card-body">
          <div class="key-desc">
            Поделитесь этим ключом с другом — он вставит его на сайте и получит свой профиль.<br>
            Ключ одноразовый: один ключ — один профиль.
          </div>
          <div id="key-status-badge" class="badge badge-gr" style="display:none; text-align:center; padding:6px 0;"></div>
          <div class="link-box highlight" onclick="copyKey()">
            <span class="copy-hint">нажать для копирования</span>
            <span id="key-value">Загружаю...</span>
          </div>
          <div class="btn-group">
            <button class="btn btn-primary" onclick="copyKey()">📋 Скопировать</button>
            <button class="btn btn-outline" onclick="openSite()">🌐 Сайт</button>
          </div>
        </div>
        <div class="card-foot" style="padding:8px;">
          <button class="btn btn-danger" onclick="confirmNewKey()" style="width:100%">🔄 Создать новый ключ</button>
        </div>
      </div>
    </div>

    <div id="page-server" class="page hidden">
      <div class="row-between">
        <div class="section-label">Статус сервера</div>
        <button class="btn-refresh" onclick="loadServerPage()">↻ Обновить</button>
      </div>
      <div id="server-content">
        <div class="shimmer"></div>
        <div class="shimmer" style="opacity:0.5; margin-top:8px;"></div>
      </div>
    </div>

    <div id="page-guide" class="page hidden">
      <div class="section-label">Скачать AmneziaVPN</div>
      <div class="g-section">
        <a class="dl-link" href="https://apps.apple.com/app/amneziavpn/id1600529900" target="_blank" rel="noopener noreferrer">
          <div class="dl-left"><span>🍎</span> iOS — App Store</div><span class="dl-arrow">↗</span>
        </a>
        <a class="dl-link" href="https://play.google.com/store/apps/details?id=org.amnezia.vpn" target="_blank" rel="noopener noreferrer">
          <div class="dl-left"><span>🤖</span> Android — Google Play</div><span class="dl-arrow">↗</span>
        </a>
        <a class="dl-link" href="https://github.com/amnezia-vpn/amnezia-client/releases/download/4.8.14.5/AmneziaVPN_4.8.14.5_x64.exe" target="_blank" rel="noopener noreferrer">
          <div class="dl-left"><span>🖥</span> Windows — GitHub</div><span class="dl-arrow">↗</span>
        </a>
      </div>

      <div class="section-label" style="margin-top:4px;">Способы подключения</div>

      <div class="g-section">
        <div class="g-head" onclick="toggleG(this)">
          <div style="display:flex; gap:8px;"><span>📋</span> Способ 1 — Ключ (vpn://)</div>
          <span class="g-arrow">›</span>
        </div>
        <div class="g-body">
          <div class="step"><div class="step-n">1</div><div>Открой <strong>AmneziaVPN</strong> → нажми <strong>«+»</strong>.</div></div>
          <div class="step"><div class="step-n">2</div><div>Выбери <strong>«Ввод ключа»</strong>.</div></div>
          <div class="step"><div class="step-n">3</div><div>Вставь строку, начинающуюся с <code>vpn://…</code></div></div>
          <div class="step"><div class="step-n">4</div><div>Нажми <strong>«Добавить»</strong> и разреши VPN.</div></div>
          <div class="g-note"><strong>Важно:</strong> строку копировать целиком — не удаляй <code>vpn://</code>.</div>
        </div>
      </div>

      <div class="g-section">
        <div class="g-head" onclick="toggleG(this)">
          <div style="display:flex; gap:8px;"><span>📁</span> Способ 2 — Файл (.vpn)</div>
          <span class="g-arrow">›</span>
        </div>
        <div class="g-body">
          <div class="step"><div class="step-n">1</div><div>Скачай конфиг кнопкой <strong>«📥 .vpn»</strong>.</div></div>
          <div class="step"><div class="step-n">2</div><div>В AmneziaVPN нажми <strong>«+»</strong> → <strong>«Файл с настройками»</strong>.</div></div>
          <div class="step"><div class="step-n">3</div><div>Выбери скачанный файл → <strong>«Импорт»</strong>.</div></div>
        </div>
      </div>
    </div>

  </main>

  <nav class="nav">
    <button class="nav-btn active" id="nav-profiles" onclick="switchTab('profiles', this)">
      <span class="nav-icon">🔑</span>Профили
    </button>
    <button class="nav-btn" id="nav-key" onclick="openKeyTab(this)">
      <span class="nav-icon">🗝</span>Ключ
    </button>
    <button class="nav-btn" id="nav-server" style="display:none" onclick="openServerTab(this)">
      <span class="nav-icon">📡</span>Сервер
    </button>
    <button class="nav-btn" id="nav-guide" onclick="switchTab('guide', this)">
      <span class="nav-icon">📖</span>Инструкция
    </button>
  </nav>

</div>

<div id="modal-create" class="overlay">
  <div class="sheet">
    <div class="sheet-handle"></div>
    <div class="sheet-title">Новый профиль</div>
    <div class="field">
      <label class="field-label">Имя профиля</label>
      <input class="input" id="name-input" type="text"
             placeholder="например: phone" maxlength="16" autocomplete="off">
      <div class="field-hint" id="name-hint">Буквы (a–z, а–я) и цифры, до 16 символов</div>
    </div>
    <div style="display:flex; flex-direction:column; gap:8px;">
      <button class="btn btn-primary" id="create-btn" onclick="doCreate()">Создать профиль</button>
      <button class="btn btn-ghost" onclick="closeO('modal-create')">Отмена</button>
    </div>
  </div>
</div>

<div id="modal-config" class="overlay">
  <div class="sheet">
    <div class="sheet-handle"></div>
    <div class="sheet-title" id="cfg-title">Конфигурация</div>
    <div class="link-box" onclick="copyConfig()">
      <span class="copy-hint">нажать для копирования</span>
      <span id="cfg-content">Загружаю...</span>
    </div>
    <div id="short-link-wrap" style="display:none;">
      <div class="field-label" style="margin-bottom:7px;">Короткая ссылка (24 часа)</div>
      <div class="short-link-box" onclick="copyShortLink()">
        <span class="copy-hint">нажать для копирования</span>
        <span id="short-link-content"></span>
      </div>
    </div>
    <div class="g-note">AmneziaVPN → <strong>«+»</strong> → Вставить из буфера</div>
    <div class="btn-group">
      <button class="btn btn-primary" onclick="copyConfig()">📋 Скопировать</button>
      <button class="btn btn-outline" onclick="dlConfig()">📥 .vpn</button>
    </div>
    <button class="btn btn-ghost" onclick="closeO('modal-config')">Закрыть</button>
  </div>
</div>

<div id="modal-del" class="overlay">
  <div class="sheet">
    <div class="sheet-handle"></div>
    <div class="sheet-title">Удалить профиль?</div>
    <div class="confirm-text" id="del-text"></div>
    <div class="btn-group">
      <button class="btn btn-danger" id="del-btn" onclick="doDelete()">Удалить</button>
      <button class="btn btn-outline" onclick="closeO('modal-del')">Отмена</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const tg = window.Telegram?.WebApp;
if (tg?.initData) { tg.ready(); tg.expand(); }

let currentConfig = null, currentCfgName = null, currentShortLink = null;
let pendingDelId = null, pendingDelName = null;
let _currentKey = null, _siteUrl = null, _keyLoaded = false;
let _serverLoaded = false, _isAdmin = false;
let _toastTimer;

const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const safeNum = v => {
  const n = parseFloat(v);
  if (isNaN(n)) return 0;
  return Math.round(n > 1 ? Math.min(n, 100) : n * 100);
};

const authH = () => {
  const h = { 'Content-Type': 'application/json' };
  if (tg?.initData) h['X-Telegram-Init-Data'] = tg.initData;
  return h;
};

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { ...authH(), ...(opts.headers || {}) } });
  if (r.status === 429) throw new Error('Слишком много запросов — подождите немного.');
  if (!r.ok) {
    const e = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
    throw new Error(e.error || `HTTP ${r.status}`);
  }
  return r.json();
}

const showToast = (msg, isErr = false) => {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), isErr ? 3200 : 2200);
};

const copyText = (text, msg) => {
  if (!text) return;
  navigator.clipboard?.writeText(text)
    .then(() => { showToast(msg); tg?.HapticFeedback?.impactOccurred('medium'); })
    .catch(() => {
      const el = document.createElement('textarea');
      el.value = text; document.body.appendChild(el);
      el.select(); document.execCommand('copy');
      el.remove(); showToast(msg);
    });
};

function switchTab(name, btn) {
  document.querySelectorAll('#content .page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + name)?.classList.remove('hidden');
  btn.classList.add('active');
  document.getElementById('content').scrollTop = 0;
}

function openKeyTab(btn) {
  switchTab('key', btn);
  if (!_keyLoaded) loadKey();
}

function openServerTab(btn) {
  if (!_isAdmin) { showToast('🔒 Только для администраторов', true); return; }
  switchTab('server', btn);
  if (!_serverLoaded) loadServerPage();
}

const openO  = id => document.getElementById(id).classList.add('open');
const closeO = id => document.getElementById(id).classList.remove('open');

document.querySelectorAll('.overlay').forEach(o => {
  o.addEventListener('click', e => { if (e.target === o) o.classList.remove('open'); });
});

async function updatePing() {
  try {
    const { ping_ms: ms } = await api('/api/ping');
    const color = ms > 300 ? 'var(--red)' : ms > 150 ? 'var(--amber)' : 'var(--green)';
    const el = document.getElementById('srv-ping');
    if (el) el.innerHTML = `<span style="color:${color}; font-family:var(--mono)">${ms} ms</span>`;
  } catch (_) {}
}

async function loadServer() {
  try {
    const d = await api('/api/server');
    const dot  = document.getElementById('srv-dot');
    const chip = document.getElementById('chip-dot');
    const txt  = document.getElementById('srv-text');
    if (d.online) {
      dot.className  = 'srv-dot on';
      chip.className = 'chip-dot on';
      txt.textContent = d.region || 'Сервер онлайн';
    } else {
      dot.className  = 'srv-dot';
      chip.className = 'chip-dot off';
      txt.textContent = 'Сервер недоступен';
    }
  } catch {
    document.getElementById('srv-text').textContent = 'Нет данных';
  }
  await updatePing();
  setInterval(updatePing, 180_000);
}

function meterClass(v) { return v >= 80 ? 'high' : v >= 50 ? 'mid' : 'low'; }

const fmtBytes = b => {
  if (!b) return '0 Б';
  const u = ['Б','КБ','МБ','ГБ','ТБ']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(1) + ' ' + u[i];
};

const fmtUptime = s => {
  if (!s) return '—';
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}д ${h}ч`;
  if (h) return `${h}ч ${m}м`;
  return `${m}м`;
};

const fmtHandshake = ts => {
  if (!ts) return 'никогда';
  const delta = Math.floor(Date.now() / 1000) - ts;
  if (delta < 0)     return 'только что';
  if (delta < 60)    return `${delta} сек. назад`;
  if (delta < 3600)  return `${Math.floor(delta / 60)} мин. назад`;
  if (delta < 86400) return `${Math.floor(delta / 3600)} ч. назад`;
  return `${Math.floor(delta / 86400)} д. назад`;
};

async function loadServerPage() {
  if (!_isAdmin) {
    document.getElementById('server-content').innerHTML =
      '<div class="empty"><div class="empty-icon">🔒</div><div class="empty-title">Только для администраторов</div></div>';
    return;
  }
  document.getElementById('server-content').innerHTML =
    '<div class="shimmer"></div><div class="shimmer" style="opacity:0.5;margin-top:8px"></div>';
  _serverLoaded = true;
  try {
    const [d, ping] = await Promise.all([
      api('/api/server'),
      api('/api/ping').catch(() => ({ ping_ms: 0 })),
    ]);
    const ms   = ping.ping_ms || 0;
    const load = d.load || {};
    const cpu  = safeNum(load.cpu);
    const ram  = safeNum(load.ram);
    const disk = safeNum(load.disk);
    const pingColor = ms > 300 ? 'var(--red)' : ms > 150 ? 'var(--amber)' : 'var(--green)';

    document.getElementById('server-content').innerHTML = `
      <div class="card">
        <div class="card-body">
          <div class="card-title-row">
            <div class="status-dot ${d.online ? 'on' : 'off'}"></div>
            <div class="card-name">${esc(d.region || 'Сервер')}</div>
            <span class="badge ${d.online ? 'badge-g' : 'badge-r'}">${d.online ? 'Online' : 'Offline'}</span>
          </div>
          ${d.protocols?.length ? `<div class="card-meta"><span>🔌 ${esc(d.protocols.join(', '))}</span></div>` : ''}
        </div>
      </div>

      <div class="stat-grid">
        <div class="stat-item">
          <div class="stat-label">Пинг</div>
          <div class="stat-value" style="color:${pingColor}">${ms}</div>
          <div class="stat-sub">мс</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Клиенты</div>
          <div class="stat-value">${d.online_peers ?? 0}<span style="font-size:14px;color:var(--text3)">/${d.peers_count ?? 0}</span></div>
          <div class="stat-sub">онлайн / всего</div>
        </div>
      </div>

      ${d.load ? `
      <div class="stat-grid">
        <div class="stat-item">
          <div class="stat-label">CPU</div>
          <div class="stat-value">${cpu}<span style="font-size:14px;color:var(--text3)">%</span></div>
          <div class="meter"><div class="meter-fill ${meterClass(cpu)}" style="width:${cpu}%"></div></div>
        </div>
        <div class="stat-item">
          <div class="stat-label">RAM</div>
          <div class="stat-value">${ram}<span style="font-size:14px;color:var(--text3)">%</span></div>
          <div class="meter"><div class="meter-fill ${meterClass(ram)}" style="width:${ram}%"></div></div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Диск</div>
          <div class="stat-value">${disk}<span style="font-size:14px;color:var(--text3)">%</span></div>
          <div class="meter"><div class="meter-fill ${meterClass(disk)}" style="width:${disk}%"></div></div>
        </div>
        <div class="stat-item">
          <div class="stat-label">Uptime</div>
          <div class="stat-value" style="font-size:16px">${fmtUptime(d.load.uptime_sec)}</div>
        </div>
      </div>
      <div class="stat-grid">
        <div class="stat-item">
          <div class="stat-label">⬇ Входящий</div>
          <div class="stat-value" style="font-size:16px;color:var(--green)">${fmtBytes(d.load.net_rx)}</div>
        </div>
        <div class="stat-item">
          <div class="stat-label">⬆ Исходящий</div>
          <div class="stat-value" style="font-size:16px;color:var(--blue)">${fmtBytes(d.load.net_tx)}</div>
        </div>
      </div>` : ''}
    `;
  } catch (e) {
    document.getElementById('server-content').innerHTML =
      `<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-title">${esc(e.message)}</div></div>`;
  }
}

async function loadProfiles(forceRefresh = false) {
  if (!forceRefresh) {
    document.getElementById('profiles-list').innerHTML =
      '<div class="shimmer"></div><div class="shimmer" style="opacity:0.5"></div>';
  }
  try {
    const data = await api('/api/me');
    document.getElementById('user-name').textContent = data.user?.name || 'VPN';

    _isAdmin = !!data.is_admin;
    const srvBtn = document.getElementById('nav-server');
    if (srvBtn) srvBtn.style.display = _isAdmin ? '' : 'none';

    const ownProfiles = data.profiles.filter(p => !p.via_key);
    const keyProfiles = data.profiles.filter(p => p.via_key);

    document.getElementById('add-btn').style.display = data.can_create ? '' : 'none';

    if (!data.profiles.length) {
      document.getElementById('profiles-list').innerHTML =
        '<div class="empty"><div class="empty-icon">🔐</div><div class="empty-title">Профилей нет</div></div>';
      return;
    }

    const renderCard = p => {
      const peer = p.peer;
      let dotCls = 'dis', lbl = 'Неизвестно', bdg = 'badge-gr', meta = [], hsLine = '';

      if (p.disabled) {
        lbl = 'Отключён'; bdg = 'badge-r';
      } else if (peer) {
        dotCls = peer.online ? 'on' : 'off';
        lbl    = peer.online ? 'Онлайн' : 'Офлайн';
        bdg    = peer.online ? 'badge-g' : 'badge-r';
        if (peer.rx && peer.rx !== '0 Б') meta.push(`⬇ ${peer.rx}`);
        if (peer.tx && peer.tx !== '0 Б') meta.push(`⬆ ${peer.tx}`);
        if (peer.protocol) meta.push(peer.protocol);
        if (peer.last_handshake) hsLine = `<div class="card-hs">🕐 ${fmtHandshake(peer.last_handshake)}</div>`;
      }

      const metaHtml = meta.length
        ? `<div class="card-meta">${meta.map(s => `<span>${esc(s)}</span>`).join('')}</div>` : '';
      const dateHtml = p.created_at
        ? `<div class="card-date">Создан: ${p.created_at.slice(0, 10)}</div>` : '';
      const keyBadge = p.via_key ? `<span class="via-key-badge">по ключу</span>` : '';

      return `
        <div class="card">
          <div class="card-body">
            <div class="card-title-row">
              <div class="status-dot ${dotCls}"></div>
              <div class="card-name">${esc(p.vpn_name)}</div>
              ${keyBadge}
              <span class="badge ${bdg}">${lbl}</span>
            </div>
            ${metaHtml}${hsLine}${dateHtml}
          </div>
          <div class="card-foot">
            <button class="foot-btn prim" onclick="getConfig(${p.id},'${esc(p.vpn_name)}')" ${p.disabled ? 'disabled' : ''}>📥 Конфиг</button>
            <button class="foot-btn del"  onclick="confirmDel(${p.id},'${esc(p.vpn_name)}')">🗑 Удалить</button>
          </div>
        </div>`;
    };

    let html = ownProfiles.map(renderCard).join('');
    if (keyProfiles.length) {
      html += `<div class="section-label" style="margin-top:4px;">Выданные по ключу</div>`;
      html += keyProfiles.map(renderCard).join('');
    }
    document.getElementById('profiles-list').innerHTML = html;

    if (forceRefresh) showToast('✓ Обновлено');

  } catch (e) {
    document.getElementById('profiles-list').innerHTML =
      `<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-title">${esc(e.message)}</div></div>`;
    showToast('❌ ' + e.message, true);
  }
}

function openCreate() {
  const inp  = document.getElementById('name-input');
  const hint = document.getElementById('name-hint');
  inp.value  = '';
  inp.className = 'input';
  hint.textContent = 'Буквы (a–z, а–я) и цифры, до 16 символов';
  hint.className   = 'field-hint';
  openO('modal-create');
  setTimeout(() => inp.focus(), 300);
}

document.getElementById('name-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') doCreate();
});

async function doCreate() {
  const name = document.getElementById('name-input').value.trim();
  const inp  = document.getElementById('name-input');
  const hint = document.getElementById('name-hint');
  const btn  = document.getElementById('create-btn');

  const err = msg => {
    hint.textContent = msg;
    hint.className   = 'field-hint err';
    inp.className    = 'input err';
  };

  if (!name) return err('Введите имя');
  if (!/^[a-zA-Zа-яА-Я0-9ёЁ]{1,16}$/.test(name)) return err('Только буквы и цифры, до 16 символов');

  btn.disabled    = true;
  btn.textContent = 'Создаю...';
  try {
    await api('/api/create', { method: 'POST', body: JSON.stringify({ name }) });
    closeO('modal-create');
    showToast('✓ Профиль создан');
    tg?.HapticFeedback?.notificationOccurred('success');
    await loadProfiles();
  } catch (e) {
    err(e.message);
    tg?.HapticFeedback?.notificationOccurred('error');
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Создать профиль';
  }
}

async function getConfig(id, name) {
  openO('modal-config');
  document.getElementById('cfg-title').textContent    = name;
  document.getElementById('cfg-content').textContent  = 'Загружаю...';
  document.getElementById('short-link-wrap').style.display = 'none';
  currentConfig = currentShortLink = null;
  currentCfgName = name;

  try {
    const d = await api(`/api/config/${id}`);
    currentConfig    = d.config;
    currentShortLink = d.short_link;
    document.getElementById('cfg-content').textContent = d.config;
    if (d.short_link) {
      document.getElementById('short-link-content').textContent = d.short_link;
      document.getElementById('short-link-wrap').style.display = 'block';
    }
    tg?.HapticFeedback?.impactOccurred('light');
  } catch (e) {
    document.getElementById('cfg-content').textContent = '❌ ' + e.message;
    showToast('❌ ' + e.message, true);
  }
}

const copyConfig    = () => copyText(currentConfig,    '📋 Конфиг скопирован');
const copyShortLink = () => copyText(currentShortLink, '🔗 Ссылка скопирована');

function dlConfig() {
  if (!currentConfig) return;
  const a  = document.createElement('a');
  a.href   = URL.createObjectURL(new Blob([currentConfig], { type: 'text/plain' }));
  a.download = (currentCfgName || 'config') + '.vpn';
  a.click();
  showToast('📥 Скачивание...');
}

function confirmDel(id, name) {
  pendingDelId   = id;
  pendingDelName = name;
  document.getElementById('del-text').innerHTML =
    `Профиль <strong>${esc(name)}</strong> будет удалён без возможности восстановления.`;
  openO('modal-del');
}

async function doDelete() {
  if (!pendingDelId) return;
  const btn = document.getElementById('del-btn');
  btn.disabled    = true;
  btn.textContent = 'Удаляю...';
  try {
    await api(`/api/profile/${pendingDelId}`, { method: 'DELETE' });
    closeO('modal-del');
    showToast('🗑 Профиль удалён');
    tg?.HapticFeedback?.notificationOccurred('warning');
    await loadProfiles();
  } catch (e) {
    showToast('❌ ' + e.message, true);
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Удалить';
    pendingDelId    = null;
  }
}

const toggleG = head => {
  const body = head.nextElementSibling;
  const open = body.classList.toggle('open');
  head.querySelector('.g-arrow').classList.toggle('open', open);
};

async function loadKey() {
  document.getElementById('key-value').textContent = 'Загружаю...';
  document.getElementById('key-status-badge').style.display = 'none';
  try {
    const d = await api('/api/mykey');
    _currentKey = d.key;
    _siteUrl    = d.site_url;
    _keyLoaded  = true;
    document.getElementById('key-value').textContent = d.key;
    const badge = document.getElementById('key-status-badge');
    badge.style.display = 'block';
    if (d.used) {
      badge.textContent = '✅ Ключ уже был использован';
      badge.className   = 'badge badge-r';
    } else {
      badge.textContent = '⏳ Ключ активен (не использован)';
      badge.className   = 'badge badge-g';
    }
  } catch (e) {
    document.getElementById('key-value').textContent = '❌ ' + e.message;
    _currentKey = null;
  }
}

const copyKey  = () => copyText(_currentKey, '📋 Ключ скопирован');
const openSite = () => _siteUrl && window.open(_siteUrl, '_blank');

function confirmNewKey() {
  const msg = 'Создать новый ключ? Старый ключ будет аннулирован.';
  tg?.showConfirm
    ? tg.showConfirm(msg, res => res && doNewKey())
    : confirm(msg) && doNewKey();
}

async function doNewKey() {
  document.getElementById('key-value').textContent = 'Генерирую...';
  try {
    const d = await api('/api/newkey', { method: 'POST', body: '{}' });
    _currentKey = d.key;
    _siteUrl    = d.site_url;
    document.getElementById('key-value').textContent = d.key;
    const badge = document.getElementById('key-status-badge');
    badge.textContent   = '⏳ Новый ключ активен';
    badge.className     = 'badge badge-g';
    badge.style.display = 'block';
    showToast('🔄 Новый ключ создан');
    tg?.HapticFeedback?.notificationOccurred('success');
  } catch (e) {
    showToast('❌ ' + e.message, true);
    document.getElementById('key-value').textContent = _currentKey || '—';
  }
}

loadProfiles();
loadServer();
</script>
</body>
</html>"""


@app.route("/")
def index():
    content = MINIAPP_HTML.replace("__MINIAPP_CSS__", MINIAPP_CSS)
    return render_template_string(content, dev_mode=settings.MINIAPP_DEV_MODE)


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed"}), 405

@app.errorhandler(500)
def internal_error(e):
    logger.error("Internal server error: %s", e)
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == "__main__":
    host  = getattr(settings, "MINIAPP_HOST", "0.0.0.0")
    port  = getattr(settings, "MINIAPP_PORT", 5000)
    debug = getattr(settings, "MINIAPP_DEV_MODE", False)
    logger.info("Mini App запущен на http://%s:%s", host, port)
    app.run(host=host, port=port, debug=debug, threaded=True)
