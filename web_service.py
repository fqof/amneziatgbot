import asyncio
import html
import json
import logging
import random
import re
import string
import threading
import traceback
import time
from collections import defaultdict
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string, make_response
from config import settings
from database import Database
from amnezia_client import AmneziaClient
from shared import generate_dynamic_token, verify_dynamic_token, get_shared_ping

logger = logging.getLogger(__name__)

web_app = Flask(__name__)
web_app.config["JSON_AS_ASCII"] = False
from security import check_scanner; check_scanner(web_app, "/")

SLUG_CHARS = string.ascii_lowercase + string.digits
SECRET_KEY_CHARS = string.ascii_letters + string.digits

_PROFILE_NAME_RE = re.compile(r"^[a-zA-Z\u0430-\u044f\u0410-\u042f\u0451\u04010-9]{1,16}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9]{32}$")
_SLUG_RE = re.compile(r"^[a-z0-9]{5,6}$")

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()
_RATE_LIMIT = 10
_RATE_WINDOW = 60

# ---------------------------------------------------------------------------
# Template loader
# ---------------------------------------------------------------------------

_PAGES_DIR = Path(__file__).parent / "pages"

def _load(filename: str) -> str:
    return (_PAGES_DIR / filename).read_text(encoding="utf-8")

# Load all static assets once at startup
_SHARED_CSS         = _load("_shared.css")
_SHARED_JS          = _load("_shared.js")
_INSTRUCTION_BLOCK  = _load("_instruction.html")
_TPL_INDEX          = _load("index.html")
_TPL_CONFIG         = _load("config.html")
_TPL_ERROR          = _load("error.html")

def _render(template: str, **kwargs) -> str:
    """Replace __KEY__ placeholders and inject shared assets."""
    result = (
        template
        .replace("__SHARED_CSS__",        _SHARED_CSS)
        .replace("__SHARED_JS__",         _SHARED_JS)
        .replace("__INSTRUCTION_BLOCK__", _INSTRUCTION_BLOCK)
    )
    for key, value in kwargs.items():
        result = result.replace(f"__{key}__", value)
    return result

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        timestamps = _rate_store[ip]
        _rate_store[ip] = [t for t in timestamps if now - t < _RATE_WINDOW]
        if len(_rate_store[ip]) >= _RATE_LIMIT:
            return False
        _rate_store[ip].append(now)
        return True

def _security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return response

web_app.after_request(_security_headers)

def _sanitize_key(raw: str) -> str | None:
    if not raw or not isinstance(raw, str): return None
    key = raw.strip()[:64]
    return key if _KEY_RE.match(key) else None

def _sanitize_name(raw: str) -> str | None:
    if not raw or not isinstance(raw, str): return None
    name = raw.strip()[:16]
    return name if _PROFILE_NAME_RE.match(name) else None

# ---------------------------------------------------------------------------
# Slug / key generators
# ---------------------------------------------------------------------------

def generate_slug() -> str:
    return "".join(random.choices(SLUG_CHARS, k=5))

def generate_secret_key() -> str:
    return "".join(random.choices(SECRET_KEY_CHARS, k=32))

# ---------------------------------------------------------------------------
# Async event loop (background thread)
# ---------------------------------------------------------------------------

_db: Database | None = None
_amnezia: AmneziaClient | None = None
_loop = asyncio.new_event_loop()
_DB_TIMEOUT = 10

def _start_bg_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

_loop_thread = threading.Thread(target=_start_bg_loop, args=(_loop,), daemon=True)
_loop_thread.start()

def run_async(coro, timeout: float = _DB_TIMEOUT):
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    try: return future.result(timeout=timeout)
    except TimeoutError:
        future.cancel()
        raise RuntimeError(f"Database timeout after {timeout}s")

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

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@web_app.route("/robots.txt")
def robots_txt():
    resp = make_response("User-agent: *\nDisallow: /\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp


@web_app.route("/")
def web_index():
    content = _render(_TPL_INDEX, DYNAMIC_TOKEN=generate_dynamic_token())
    return render_template_string(content)


@web_app.route("/api/ping")
def api_ping():
    ping_host = (
        settings.VPN_HOST
        or settings.AMNEZIA_API_URL.split("//")[-1].split(":")[0]
        or "127.0.0.1"
    )
    ms = get_shared_ping(ping_host, settings.AMNEZIA_API_URL)
    return jsonify({"ping_ms": ms})


@web_app.route("/connect", methods=["POST"])
def web_connect():
    ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if getattr(settings, "TRUST_PROXY_HEADERS", False) and request.headers.get("X-Forwarded-For")
        else (request.remote_addr or "unknown")
    )
    if not _check_rate_limit(ip):
        return jsonify({"error": "Слишком много запросов. Подождите минуту."}), 429

    client_token = request.headers.get("X-Dynamic-Token", "")
    if not client_token or not verify_dynamic_token(client_token, max_age_seconds=300):
        return jsonify({"error": "Сессия устарела. Пожалуйста, обновите страницу."}), 403

    if "application/json" not in request.headers.get("Content-Type", ""):
        return jsonify({"error": "Ожидается JSON"}), 400

    if not request.is_json:
        return jsonify({"error": "Ожидается JSON"}), 400

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Некорректный запрос"}), 400

    key = _sanitize_key(data.get("key", ""))
    if not key:
        return jsonify({"error": "Некорректный формат ключа"}), 400

    name = _sanitize_name(data.get("name", ""))
    if not name:
        return jsonify({"error": "Некорректное имя профиля (только буквы и цифры, до 16 символов)"}), 400

    try:
        db      = get_db()
        amnezia = get_amnezia()

        key_record = run_async(db.get_secret_key_by_value(key))
        if not key_record:
            return jsonify({"error": "Ключ не найден"}), 403
        if key_record.get("revoked"):
            return jsonify({"error": "Ключ отозван"}), 403
        if key_record.get("used"):
            return jsonify({"error": "Ключ уже использован"}), 403

        tg_id = key_record["telegram_id"]

        if run_async(db.get_user_key_blocked(tg_id)):
            return jsonify({"error": "Создание профилей заблокировано администратором"}), 403

        max_key = settings.MAX_KEY_PROFILES_PER_USER
        if not run_async(db.can_create_key_profile(tg_id, max_key)):
            return jsonify({"error": f"Достигнут лимит профилей по ключу ({max_key})"}), 400

        if run_async(db.is_vpn_name_taken(name)):
            return jsonify({"error": "Имя профиля уже занято, выберите другое"}), 409

        result = run_async(amnezia.create_user(name), timeout=30)
        if result is None:
            return jsonify({"error": "Ошибка сервера. Попробуйте позже."}), 502

        peer_id    = result.get("client", {}).get("id")
        config_str = result.get("client", {}).get("config", "")

        profile_id = run_async(db.add_profile(
            tg_id, name, peer_id,
            json.dumps(result, ensure_ascii=False),
            via_key=True,
        ))
        run_async(db.set_key_used(key_record["id"]))

        slug = _unique_slug(db)
        run_async(db.get_or_create_short_link(profile_id, slug))
        domain    = settings.SHORT_LINK_DOMAIN.rstrip("/")
        short_url = f"https://{domain}/c/{slug}"

        return jsonify({
            "ok": True,
            "config":     config_str,
            "short_link": short_url,
            "vpn_name":   name,
            "profile_id": profile_id,
        })

    except RuntimeError as e:
        logger.error("web_connect runtime error: %s", e)
        return jsonify({"error": "Сервер временно недоступен. Попробуйте позже."}), 503
    except Exception as e:
        logger.error("web_connect unexpected error: %s\n%s", e, traceback.format_exc())
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500


def _unique_slug(db: Database) -> str:
    for _ in range(20):
        slug = generate_slug()
        if not run_async(db.get_short_link_by_slug(slug)):
            return slug
    return "".join(random.choices(SLUG_CHARS, k=6))


@web_app.route("/c/<slug>")
def web_short_link(slug: str):
    clean_slug = slug.strip()[:10]
    if not _SLUG_RE.match(clean_slug):
        return render_template_string(_error_page("Ссылка недействительна")), 404

    try:
        db   = get_db()
        link = run_async(db.get_short_link_by_slug(clean_slug))
        if not link:
            return render_template_string(
                _error_page("Ссылка не найдена (истёк срок действия или удалена)")
            ), 404

        profile = run_async(db.get_profile_by_id(link["profile_id"]))
        if not profile:
            return render_template_string(_error_page("Профиль удалён")), 404
        if profile.get("disabled"):
            return render_template_string(_error_page("Профиль отключён администратором")), 403

        config_str = None
        raw = profile.get("raw_response")
        if raw:
            try:
                config_str = json.loads(raw).get("client", {}).get("config")
            except Exception:
                pass

        if not config_str:
            amnezia = get_amnezia()
            try:
                config_str = run_async(
                    amnezia.get_client_config(profile.get("peer_id") or profile["vpn_name"]),
                    timeout=15,
                )
            except Exception:
                pass

        if not config_str:
            return render_template_string(_error_page("Конфигурация недоступна")), 503

        return render_template_string(
            _config_page(profile["vpn_name"], config_str)
        )

    except RuntimeError:
        return render_template_string(
            _error_page("Сервер временно недоступен, попробуйте позже")
        ), 503
    except Exception as e:
        logger.error("web_short_link error: %s\n%s", e, traceback.format_exc())
        return render_template_string(_error_page("Внутренняя ошибка сервера")), 500


# ---------------------------------------------------------------------------
# Page builders
# ---------------------------------------------------------------------------

def _error_page(msg: str) -> str:
    return _render(_TPL_ERROR, ERROR_MESSAGE=html.escape(msg))


def _config_page(vpn_name: str, config: str) -> str:
    return _render(
        _TPL_CONFIG,
        VPN_NAME=html.escape(vpn_name),
        CONFIG_ESCAPED=html.escape(config),
        CONFIG_JSON=json.dumps(config),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = getattr(settings, "WEB_HOST", "0.0.0.0")
    port = getattr(settings, "WEB_PORT", 5001)
    logger.info("Web Service запущен на http://%s:%s", host, port)
    web_app.run(host=host, port=port, debug=False, threaded=True)
