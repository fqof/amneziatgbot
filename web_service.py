import asyncio
import base64
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

_PROFILE_NAME_RE = re.compile(r"^[a-zA-Z\u0430-\u044f\u0410-\u042f\u04510-9]{1,16}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9]{32}$")
_SLUG_RE = re.compile(r"^[a-z0-9]{5,6}$")

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()
_RATE_LIMIT = 10
_RATE_WINDOW = 60

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

def generate_slug() -> str:
    return "".join(random.choices(SLUG_CHARS, k=5))

def generate_secret_key() -> str:
    return "".join(random.choices(SECRET_KEY_CHARS, k=32))

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


def _get_obfuscated_mtproto_js() -> str:
    raw = getattr(settings, "MTPROTO_LINKS", "") or ""
    links = [x.strip() for x in raw.split(",") if x.strip()]
    if not links:
        return "null"
    parts = [f'atob("{base64.b64encode(lnk.encode()).decode()}")' for lnk in links]
    return f'[{", ".join(parts)}]'

_SHARED_CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Geologica:wght@300;400;600;700&display=swap');

:root {
  --bg:      #080b10;
  --s1:      #0e1117;
  --s2:      #141820;
  --s3:      #1c2130;
  --border:  #1f2535;
  --border2: #2a3348;
  --glow:    rgba(61,220,132,0.08);

  --text:    #e8edf5;
  --text2:   #8892a4;
  --text3:   #4a5568;
  --white:   #ffffff;
  --green:   #3ddc84;
  --green2:  #2ab86d;
  --red:     #ff5252;
  --amber:   #f5a623;
  --blue:    #4a9eff;
  --blue2:   #2979d9;

  --radius:  14px;
  --radius-s: 10px;
  --radius-xs: 6px;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Geologica', system-ui, sans-serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  min-height: 100vh;
  display: flex;
  justify-content: center;
  /* Subtle grid texture */
  background-image:
    linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
  background-size: 40px 40px;
}

.wrap {
  width: 100%; max-width: 460px;
  padding: 52px 20px 60px;
  display: flex; flex-direction: column;
  gap: 14px; align-items: center;
}

.header {
  text-align: center;
  display: flex; flex-direction: column;
  gap: 10px; margin-bottom: 4px;
}
.logo {
  font-size: 44px;
  filter: drop-shadow(0 0 16px rgba(61,220,132,0.3));
  animation: float 3s ease-in-out infinite;
}
@keyframes float {
  0%,100% { transform: translateY(0); }
  50%      { transform: translateY(-5px); }
}
.header h1 {
  font-size: 24px; font-weight: 700;
  color: var(--white);
  letter-spacing: -0.5px;
}
.header p { font-size: 13px; color: var(--text3); line-height: 1.6; }

.ping-badge {
  display: inline-flex; align-items: center; gap: 8px;
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 5px 14px;
  font: 600 12px var(--mono);
  color: var(--text2);
  transition: 0.3s;
}
.ping-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--text3);
  transition: background 0.4s;
}
.ping-dot.good { background: var(--green); box-shadow: 0 0 6px var(--green); }
.ping-dot.warn { background: var(--amber); box-shadow: 0 0 6px var(--amber); }
.ping-dot.bad  { background: var(--red);   box-shadow: 0 0 6px var(--red);   }

.card {
  width: 100%;
  background: var(--s1);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 24px;
  display: flex; flex-direction: column; gap: 18px;
  box-shadow: 0 4px 32px rgba(0,0,0,0.4);
  animation: fadeUp 0.35s ease both;
}
@keyframes fadeUp {
  from { opacity:0; transform: translateY(12px); }
  to   { opacity:1; transform: translateY(0); }
}

.card-title {
  font-size: 11px; font-weight: 700;
  color: var(--text3); letter-spacing: 1.5px;
  text-transform: uppercase;
}
.card-title.success { color: var(--green); }

.field { display: flex; flex-direction: column; gap: 7px; }
.label {
  font-size: 10px; font-weight: 700;
  letter-spacing: 1.5px; text-transform: uppercase;
  color: var(--text3);
}
.label-row { display: flex; justify-content: space-between; align-items: center; }

.input {
  background: var(--s2);
  border: 1px solid var(--border);
  border-radius: var(--radius-s);
  color: var(--text);
  font: 14px var(--mono);
  padding: 13px 15px;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  width: 100%;
}
.input::placeholder { color: var(--text3); }
.input:focus {
  border-color: var(--border2);
  box-shadow: 0 0 0 3px rgba(61,220,132,0.07);
}

.hint { font-size: 11px; color: var(--text3); }

.btn {
  width: 100%; border: none;
  border-radius: var(--radius-s);
  font: 600 14px var(--sans);
  padding: 14px;
  cursor: pointer;
  transition: background 0.18s, transform 0.1s, box-shadow 0.18s;
  display: flex; align-items: center; justify-content: center; gap: 8px;
}
.btn:active { transform: scale(0.975); }
.btn:disabled { opacity: 0.45; pointer-events: none; }

.btn-primary {
  background: var(--green);
  color: #04100a;
  box-shadow: 0 4px 20px rgba(61,220,132,0.25);
}
.btn-primary:hover {
  background: var(--green2);
  box-shadow: 0 4px 24px rgba(61,220,132,0.4);
}

.btn-outline {
  background: transparent;
  border: 1px solid var(--border2);
  color: var(--text2);
}
.btn-outline:hover { background: var(--s2); color: var(--text); }

.btn-tg {
  background: rgba(74,158,255,0.1);
  border: 1px solid rgba(74,158,255,0.25);
  color: var(--blue);
  font-size: 13px;
}
.btn-tg:hover { background: rgba(74,158,255,0.18); border-color: rgba(74,158,255,0.45); }

.link-box {
  background: var(--s2);
  border: 1px solid var(--border);
  border-radius: var(--radius-s);
  padding: 12px 14px 12px 14px;
  padding-top: 26px;
  font: 12px/1.65 var(--mono);
  color: var(--text2);
  word-break: break-all;
  position: relative;
  cursor: pointer;
  transition: border-color 0.18s, background 0.18s;
}
.link-box:hover { border-color: var(--border2); background: var(--s3); }
.copy-hint {
  font-size: 9px; color: var(--text3);
  text-transform: uppercase; letter-spacing: 0.8px;
  position: absolute; top: 8px; right: 10px;
}
.truncate {
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  overflow: hidden;
}
.truncate.open { -webkit-line-clamp: unset; display: block; }
.toggle-btn {
  font-size: 10px; font-weight: 700; color: var(--green);
  cursor: pointer; text-transform: uppercase; letter-spacing: 1px;
  background: none; border: none; padding: 0; flex-shrink: 0;
  transition: color 0.15s;
}
.toggle-btn:hover { color: var(--green2); }

.divider {
  border-top: 1px solid var(--border);
  padding-top: 18px; margin-top: 4px;
  display: flex; flex-direction: column; gap: 12px;
}
.section-heading {
  font-size: 13px; font-weight: 600; color: var(--white);
}

.g-section {
  background: var(--s2);
  border: 1px solid var(--border);
  border-radius: var(--radius-s);
  overflow: hidden;
}
.dl-link {
  display: flex; align-items: center;
  justify-content: space-between;
  padding: 13px 14px;
  border-bottom: 1px solid var(--border);
  text-decoration: none; color: var(--white);
  font-size: 13px; font-weight: 600;
  transition: background 0.15s;
}
.dl-link:hover { background: var(--s3); }
.dl-link:last-child { border-bottom: none; }
.dl-left { display: flex; align-items: center; gap: 10px; }
.dl-arrow { color: var(--text3); font-size: 14px; }

.g-head {
  padding: 13px 14px;
  display: flex; justify-content: space-between;
  cursor: pointer;
  font-size: 13px; font-weight: 600; color: var(--white);
  user-select: none;
  transition: background 0.15s;
}
.g-head:hover { background: var(--s3); }
.g-arrow { transition: transform 0.22s; color: var(--text3); }
.g-arrow.open { transform: rotate(90deg); }
.g-body {
  display: none; padding: 0 14px 14px;
  gap: 10px; flex-direction: column;
}
.g-body.open { display: flex; }
.step {
  display: flex; gap: 10px;
  font-size: 12px; color: var(--text2);
  align-items: flex-start; line-height: 1.55;
}
.step-n {
  width: 20px; height: 20px; border-radius: 50%;
  background: var(--s3); border: 1px solid var(--border2);
  display: flex; align-items: center; justify-content: center;
  font-size: 10px; font-weight: 700; flex-shrink: 0;
  color: var(--text2);
}
code {
  background: var(--s3); padding: 2px 6px;
  border-radius: var(--radius-xs);
  font-family: var(--mono); font-size: 11px;
  color: var(--green);
}
.g-note {
  background: rgba(245,166,35,0.07);
  border-left: 3px solid var(--amber);
  padding: 9px 12px;
  font-size: 11px; color: var(--text2);
  border-radius: 0 var(--radius-xs) var(--radius-xs) 0;
  line-height: 1.55;
}

.tg-section {
  width: 100%;
  display: flex; flex-direction: column;
  gap: 6px; align-items: center;
}
.tg-label {
  font-size: 10px; color: var(--text3);
  text-align: center; letter-spacing: 0.5px;
}

.error-card {
  background: rgba(255,82,82,0.08);
  border: 1px solid rgba(255,82,82,0.25);
  color: var(--red);
  padding: 13px 16px;
  border-radius: var(--radius-s);
  font-size: 13px;
  display: none; width: 100%;
  text-align: center; line-height: 1.5;
}
.error-card.show { display: block; }

.toast {
  position: fixed; bottom: 24px; left: 50%;
  transform: translateX(-50%) translateY(8px);
  background: var(--s3);
  border: 1px solid var(--border2);
  border-radius: 24px;
  padding: 9px 20px;
  font: 600 12px var(--sans);
  color: var(--text);
  opacity: 0;
  transition: opacity 0.22s, transform 0.22s;
  pointer-events: none;
  white-space: nowrap;
  z-index: 1000;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
"""

_SHARED_JS = """
  let _toastTimer;
  const showToast = (msg) => {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
  };

  const copyText = (text, msg) => {
    if (!text) return;
    navigator.clipboard?.writeText(text)
      .then(() => showToast(msg || '📋 Скопировано!'))
      .catch(() => {
        const el = document.createElement('textarea');
        el.value = text; document.body.appendChild(el);
        el.select(); document.execCommand('copy');
        el.remove(); showToast(msg || '📋 Скопировано!');
      });
  };

  const toggleG = (head) => {
    const body = head.nextElementSibling;
    const arr = head.querySelector('.g-arrow');
    body.classList.toggle('open');
    arr.classList.toggle('open', body.classList.contains('open'));
  };

  const openMtproto = (links) => {
    if (!links || !links.length) return;
    window.location.href = links[Math.floor(Math.random() * links.length)];
  };

  async function fetchPing() {
    try {
      const r = await fetch('/api/ping');
      if (!r.ok) return;
      const { ping_ms: ms } = await r.json();
      const dot = document.getElementById('ping-dot');
      const txt = document.getElementById('ping-text');
      if (!dot || !txt) return;
      txt.textContent = ms + ' ms';
      dot.className = 'ping-dot ' + (ms < 100 ? 'good' : ms < 250 ? 'warn' : 'bad');
    } catch (_) {}
  }
"""

_INSTRUCTION_BLOCK = """
  <div class="divider">
    <div class="section-heading">📖 Инструкция по подключению</div>
    <label class="label">Скачать AmneziaVPN</label>
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
    <div class="g-section">
      <div class="g-head" onclick="toggleG(this)">
        <div>📋 Как подключиться?</div><span class="g-arrow">›</span>
      </div>
      <div class="g-body">
        <div class="step"><div class="step-n">1</div><div>Откройте <strong>AmneziaVPN</strong> и нажмите <strong>«+»</strong>.</div></div>
        <div class="step"><div class="step-n">2</div><div>Нажмите <strong>«Вставить»</strong> — строка <code>vpn://</code> вставится автоматически.</div></div>
        <div class="step"><div class="step-n">3</div><div>Нажмите <strong>Продолжить → Подключиться</strong>.</div></div>
        <div class="g-note"><strong>Важно:</strong> строка начинается с <code>vpn://</code> — не удаляйте приставку.</div>
      </div>
    </div>
  </div>
"""


WEB_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSIuOWVtIiBmb250LXNpemU9IjkwIiBmb250LWZhbWlseT0ic2VyaWYiPvCfpK48L3RleHQ+PC9zdmc+">
<title>🤮 FQof</title>
<style>
__SHARED_CSS__
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">🤮</div>
    <h1>FQof</h1>
    <p>Введите ключ для получения конфигурации</p>
  </div>

  <div class="ping-badge">
    <div class="ping-dot" id="ping-dot"></div>
    <span id="ping-text">— ms</span>
  </div>

  <div class="error-card" id="error-card"></div>

  <div id="main-content" style="width:100%">
    <div class="card" id="form-card">
      <div class="card-title">Авторизация</div>
      <div class="field">
        <label class="label">Ключ доступа</label>
        <input class="input" id="key-input" type="text"
               placeholder="32 символа" maxlength="32"
               autocomplete="off" spellcheck="false">
        <span class="hint">Ключ выдаётся индивидуально</span>
      </div>
      <div class="field">
        <label class="label">Имя профиля</label>
        <input class="input" id="name-input" type="text"
               placeholder="например: phone" maxlength="16"
               autocomplete="off" spellcheck="false">
        <span class="hint">до 16 символов, только буквы и цифры</span>
      </div>
      <button class="btn btn-primary" id="connect-btn" onclick="doConnect()">
        Получить конфигурацию
      </button>
    </div>
  </div>

  <div class="tg-section" id="tg-section" style="display:none">
    <button class="btn btn-tg" id="tg-btn" onclick="openMtproto(_mp)" style="max-width:420px">🟢 Telegram без VPN</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
  const DYNAMIC_TOKEN = '__DYNAMIC_TOKEN__';
  const _mp = __MTPROTO_LINKS__;

  let _config = '', _shortLink = '';

__SHARED_JS__
  (function () {
    if (_mp && _mp.length) document.getElementById('tg-section').style.display = 'flex';
  })();

  const showError = (msg) => {
    const el = document.getElementById('error-card');
    if (!msg) { el.classList.remove('show'); return; }
    el.textContent = msg;
    el.classList.add('show');
  };

  const toggleConfig = () => {
    const t = document.getElementById('config-text');
    const btn = document.getElementById('cfg-toggle');
    const isOpen = t.classList.toggle('open');
    btn.textContent = isOpen ? 'Свернуть' : 'Развернуть';
  };

  async function doConnect() {
    showError(false);
    const key  = document.getElementById('key-input').value.trim();
    const name = document.getElementById('name-input').value.trim();
    const btn  = document.getElementById('connect-btn');

    if (!key)  return showError('Введите ключ');
    if (!/^[A-Za-z0-9]{32}$/.test(key)) return showError('Некорректный формат ключа');
    if (!name) return showError('Введите имя профиля');
    if (!/^[a-zA-Zа-яА-ЯёЁ0-9]{1,16}$/.test(name))
      return showError('Имя: только буквы и цифры, до 16 символов');

    btn.disabled = true;
    btn.textContent = 'Подключаю…';

    try {
      const resp = await fetch('/connect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Dynamic-Token': DYNAMIC_TOKEN,
        },
        body: JSON.stringify({ key, name }),
      });
      const data = await resp.json();
      if (!resp.ok || data.error) throw new Error(data.error || 'Ошибка сервера');

      _config    = data.config;
      _shortLink = data.short_link;

      const tgHtml = (_mp && _mp.length) ? `
        <button class="btn btn-tg" onclick="openMtproto(_mp)">🟢 Telegram без VPN</button>
      ` : '';

      document.getElementById('main-content').innerHTML = `
        <div class="card" id="result-block">
          <div class="card-title success">✓ Конфигурация готова</div>

          <div class="field">
            <div class="label-row">
              <label class="label">Строка vpn://</label>
              <button class="toggle-btn" id="cfg-toggle" onclick="toggleConfig()">Развернуть</button>
            </div>
            <div class="link-box" onclick="copyText(_config, '📋 Конфиг скопирован!')">
              <span class="copy-hint">нажать для копирования</span>
              <span id="config-text" class="truncate">${_config}</span>
            </div>
            <button class="btn btn-outline" onclick="copyText(_config, '📋 Конфиг скопирован!')">
              📋 Скопировать vpn://
            </button>
          </div>

          <div class="field">
            <label class="label">Короткая ссылка (на 24 часа)</label>
            <div class="link-box" onclick="copyText(_shortLink, '🔗 Ссылка скопирована!')">
              <span class="copy-hint">нажать для копирования</span>
              <span id="short-link-text">${_shortLink}</span>
            </div>
            <button class="btn btn-outline" onclick="copyText(_shortLink, '🔗 Ссылка скопирована!')">
              📋 Скопировать ссылку
            </button>
          </div>

          ${tgHtml}

          __INSTRUCTION_BLOCK__
        </div>
      `;

      window.scrollTo({ top: 0, behavior: 'smooth' });

    } catch (e) {
      showError(e.message === 'Failed to fetch'
        ? 'Сетевая ошибка. Попробуйте ещё раз.'
        : e.message);
      btn.disabled = false;
      btn.textContent = 'Получить конфигурацию';
    }
  }

  document.addEventListener('keydown', e => {
    if (e.key === 'Enter' && document.getElementById('key-input')) doConnect();
  });

  fetchPing();
  setInterval(fetchPing, 180_000);
</script>
</body>
</html>"""

@web_app.route("/robots.txt")
def robots_txt():
    resp = make_response("User-agent: *\nDisallow: /\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp


@web_app.route("/")
def web_index():
    dyn_token  = generate_dynamic_token()
    mtproto_js = _get_obfuscated_mtproto_js()
    content = (
        WEB_HTML
        .replace("__SHARED_CSS__",        _SHARED_CSS)
        .replace("__SHARED_JS__",         _SHARED_JS)
        .replace("__INSTRUCTION_BLOCK__", _INSTRUCTION_BLOCK)
        .replace("__DYNAMIC_TOKEN__",     dyn_token)
        .replace("__MTPROTO_LINKS__",     mtproto_js)
    )
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
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
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

def _error_page(msg: str) -> str:
    safe = html.escape(msg)
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>⚠️ Ошибка</title>
<style>
{_SHARED_CSS}
body {{ align-items: center; justify-content: center; }}
.box {{ text-align: center; padding: 40px 24px; display: flex; flex-direction: column; gap: 16px; }}
.emo {{ font-size: 52px; }}
.msg {{ color: var(--text3); font-size: 14px; line-height: 1.6; max-width: 300px; }}
.back {{ color: var(--green); font-size: 13px; text-decoration: none; }}
.back:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="box">
  <div class="emo">⚠️</div>
  <p class="msg">{safe}</p>
  <a class="back" href="/">← На главную</a>
</div>
</body>
</html>"""


def _config_page(vpn_name: str, config: str) -> str:
    safe_name = html.escape(vpn_name)
    safe_cfg  = html.escape(config)
    mtproto_js = _get_obfuscated_mtproto_js()

    tg_block = f"""
    <div class="tg-section" id="tg-section" style="display:none">
      <button class="btn btn-tg" onclick="openMtproto(_mp)">🟢 Telegram без VPN</button>
    </div>
    """

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSIuOWVtIiBmb250LXNpemU9IjkwIiBmb250LWZhbWlseT0ic2VyaWYiPvCfpK48L3RleHQ+PC9zdmc+">
  <title>🤮 {safe_name} — FQof</title>
  <style>
{_SHARED_CSS}
  </style>
</head>
<body>
<div class="wrap">

  <div class="header">
    <div class="logo">🤮</div>
    <h1>FQof</h1>
  </div>

  <div class="ping-badge">
    <div class="ping-dot" id="ping-dot"></div>
    <span id="ping-text">— ms</span>
  </div>

  <div class="card">
    <div class="card-title success">📋 Профиль: {safe_name}</div>

    <div class="field">
      <div class="label-row">
        <label class="label">Строка конфигурации</label>
        <button class="toggle-btn" id="cfg-toggle" onclick="toggleCfg()">Развернуть</button>
      </div>
      <div class="link-box" onclick="copyText(_config, '📋 Конфиг скопирован!')">
        <span class="copy-hint">нажать для копирования</span>
        <span id="cfg-text" class="truncate">{safe_cfg}</span>
      </div>
      <button class="btn btn-outline" onclick="copyText(_config, '📋 Конфиг скопирован!')">
        📋 Скопировать vpn://
      </button>
    </div>

    {tg_block}

    {_INSTRUCTION_BLOCK}
  </div>

</div>
<div class="toast" id="toast"></div>

<script>
  const _mp = {mtproto_js};
  const _config = {json.dumps(config)};

{_SHARED_JS}

  function toggleCfg() {{
    const t   = document.getElementById('cfg-text');
    const btn = document.getElementById('cfg-toggle');
    const isOpen = t.classList.toggle('open');
    btn.textContent = isOpen ? 'Свернуть' : 'Развернуть';
  }}

  (function () {{
    if (_mp && _mp.length) document.getElementById('tg-section').style.display = 'flex';
  }})();

  fetchPing();
  setInterval(fetchPing, 180_000);
</script>
</body>
</html>"""


if __name__ == "__main__":
    host = getattr(settings, "WEB_HOST", "0.0.0.0")
    port = getattr(settings, "WEB_PORT", 5001)
    logger.info("Web Service запущен на http://%s:%s", host, port)
    web_app.run(host=host, port=port, debug=False, threaded=True)
