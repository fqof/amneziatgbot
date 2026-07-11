"""
obfuscator.py — потокобезопасная обфускация HTML/JS/CSS
для web_service.py и miniapp_service.py.

Использование:
    from obfuscator import obfuscate_page

    html = obfuscate_page(raw_html, cache_key="web_index")

Зависимости (устанавливаются один раз):
    npm install -g javascript-obfuscator html-minifier-terser

Переменные окружения:
    OBFUSCATE=1                   # 0 — отключить (режим отладки)
    JS_OBFUSCATION_LEVEL=medium   # low | medium | high
    OBFUSCATOR_TIMEOUT=30         # таймаут CLI-инструментов (сек)
"""

import hashlib
import logging
import os
import re
import subprocess
import tempfile
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────── настройки ───────────────────────────

JS_OBFUSCATION_LEVEL: str = os.getenv("JS_OBFUSCATION_LEVEL", "medium")
TOOL_TIMEOUT: int          = int(os.getenv("OBFUSCATOR_TIMEOUT", "30"))
ENABLED: bool              = os.getenv("OBFUSCATE", "1") not in ("0", "false", "no")
MINIFY_CSS: bool           = True   # минифицировать CSS через html-minifier-terser

# ─────────────────────────── пресеты JS ──────────────────────────

_JS_PRESETS: dict[str, list[str]] = {
    "low": [
        "--compact", "true",
        "--rename-globals", "true",
        "--identifier-names-generator", "hexadecimal",
        "--string-array", "true",
        "--string-array-encoding", "base64",
        "--control-flow-flattening", "false",
        "--dead-code-injection", "false",
        "--numbers-to-expressions", "false",
        "--split-strings", "false",
    ],
    "medium": [
        "--compact", "true",
        "--rename-globals", "true",
        "--identifier-names-generator", "hexadecimal",
        "--string-array", "true",
        "--string-array-encoding", "base64",
        "--string-array-threshold", "0.75",
        "--control-flow-flattening", "true",
        "--control-flow-flattening-threshold", "0.4",
        "--dead-code-injection", "false",
        "--numbers-to-expressions", "true",
        "--split-strings", "true",
        "--split-strings-chunk-length", "8",
        "--transform-object-keys", "true",
    ],
    "high": [
        "--compact", "true",
        "--rename-globals", "true",
        "--identifier-names-generator", "hexadecimal",
        "--string-array", "true",
        "--string-array-encoding", "base64",
        "--string-array-threshold", "1",
        "--control-flow-flattening", "true",
        "--control-flow-flattening-threshold", "0.75",
        "--dead-code-injection", "true",
        "--dead-code-injection-threshold", "0.3",
        "--numbers-to-expressions", "true",
        "--split-strings", "true",
        "--split-strings-chunk-length", "5",
        "--transform-object-keys", "true",
        "--unicode-escape-sequence", "true",
    ],
}

# ─────────────────────────── кеш ─────────────────────────────────

class _Cache:
    """Потокобезопасный кеш готовых страниц в памяти."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._lock  = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._store[key] = value

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


_cache = _Cache()

# ─────────────────────────── утилиты ─────────────────────────────

def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# ─────────────────────────── JS ───────────────────────────────────

# Имена функций, вызываемых из HTML-атрибутов (onclick, onchange и т.д.)
# Они экспортируются через window.X = _внутренняя, поэтому внешнее имя
# НЕ переименовывается — это нормально и не является уязвимостью.
_RE_INLINE_HANDLER = re.compile(
    r'on(?:click|change|submit|keydown|keyup|input|focus|blur|load|input)'
    r'\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Нет смысла оборачивать уже обёрнутые IIFE или модули
_RE_ALREADY_IIFE = re.compile(r'^\s*[\(;]?\s*\(function\s*\(', re.DOTALL)


def _wrap_for_window_export(js: str, public_names: list[str]) -> str:
    """
    Оборачивает JS в IIFE и экспортирует публичные функции в window,
    чтобы javascript-obfuscator мог переименовать внутренние имена
    не затрагивая вызовы из HTML-атрибутов onclick="...".
    """
    if not public_names or _RE_ALREADY_IIFE.match(js):
        return js

    exports = "\n".join(f"  window['{n}'] = typeof {n} !== 'undefined' ? {n} : window['{n}'];"
                        for n in public_names)
    return f"(function(){{\n{js}\n{exports}\n}})();"


def obfuscate_js(js_code: str,
                 level: str = JS_OBFUSCATION_LEVEL,
                 public_names: Optional[list[str]] = None) -> str:
    """
    Обфусцирует JS-код через javascript-obfuscator (CLI).
    public_names — имена, доступные из onclick="..." в HTML.
    При ошибке возвращает исходный код.
    """
    if not js_code.strip():
        return js_code

    # Оборачиваем, чтобы переименование глобалов работало безопасно
    if public_names:
        js_to_obf = _wrap_for_window_export(js_code, public_names)
    else:
        js_to_obf = js_code

    preset = _JS_PRESETS.get(level, _JS_PRESETS["medium"])

    in_fd,  in_path  = tempfile.mkstemp(suffix=".js")
    out_path = in_path.replace(".js", "-obfuscated.js")

    try:
        with os.fdopen(in_fd, "w", encoding="utf-8") as f:
            f.write(js_to_obf)

        cmd = ["javascript-obfuscator", in_path, "--output", out_path] + preset
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT
        )
        if result.returncode != 0:
            logger.warning("js-obfuscator stderr: %s", result.stderr[:400])
            return js_code

        if not os.path.exists(out_path):
            logger.warning("js-obfuscator: выходной файл не создан")
            return js_code

        with open(out_path, encoding="utf-8") as f:
            obfuscated = f.read()

        return obfuscated if obfuscated.strip() else js_code

    except subprocess.TimeoutExpired:
        logger.error("js-obfuscator: таймаут %ds", TOOL_TIMEOUT)
        return js_code
    except Exception as exc:
        logger.error("js-obfuscator: %s", exc)
        return js_code
    finally:
        for p in (in_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ─────────────────────────── CSS ──────────────────────────────────

def minify_css(css_code: str) -> str:
    """Минифицирует CSS через html-minifier-terser."""
    if not css_code.strip():
        return css_code

    # html-minifier-terser принимает HTML-файл с флагом --minify-css
    # Оборачиваем CSS в <style> тег
    wrapped = f"<style>{css_code}</style>"

    in_fd, in_path = tempfile.mkstemp(suffix=".html")
    out_path = in_path + ".min.html"

    try:
        with os.fdopen(in_fd, "w", encoding="utf-8") as f:
            f.write(wrapped)

        cmd = [
            "html-minifier-terser",
            "--minify-css", "true",
            "--collapse-whitespace",
            "--remove-comments",
            in_path,
            "-o", out_path,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT
        )
        if result.returncode != 0:
            logger.warning("css-minifier stderr: %s", result.stderr[:400])
            return css_code

        if not os.path.exists(out_path):
            return css_code

        with open(out_path, encoding="utf-8") as f:
            content = f.read()

        # Извлекаем CSS из <style>...</style>
        m = re.search(r"<style>(.*?)</style>", content, re.DOTALL | re.IGNORECASE)
        if m:
            minified = m.group(1)
            return minified if minified.strip() else css_code
        return css_code

    except subprocess.TimeoutExpired:
        logger.error("css-minifier: таймаут")
        return css_code
    except Exception as exc:
        logger.error("css-minifier: %s", exc)
        return css_code
    finally:
        for p in (in_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ─────────────────────────── HTML ─────────────────────────────────

_RE_STYLE  = re.compile(r"(<style[^>]*>)(.*?)(</style>)",   re.DOTALL | re.IGNORECASE)
_RE_SCRIPT = re.compile(r"(<script(?:\s[^>]*)?>)(.*?)(</script>)", re.DOTALL | re.IGNORECASE)
_RE_JINJA  = re.compile(r"\{\{.*?\}\}|\{%-?.*?-?%\}",       re.DOTALL)

# Извлекаем имена из onclick/onXxx атрибутов во всём HTML
_RE_ON_ATTR = re.compile(
    r'\bon\w+\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_RE_FUNC_NAME = re.compile(r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(')


def _collect_public_names(html: str) -> list[str]:
    """Собирает имена функций, вызываемых из HTML-атрибутов на всей странице."""
    names: set[str] = set()
    for attr_val in _RE_ON_ATTR.findall(html):
        for fn_name in _RE_FUNC_NAME.findall(attr_val):
            names.add(fn_name)
    # Убираем JS-встроенные функции, не нуждающиеся в экспорте
    _builtins = {"alert", "confirm", "prompt", "parseInt", "parseFloat",
                 "encodeURIComponent", "decodeURIComponent", "setTimeout",
                 "clearTimeout", "setInterval", "clearInterval", "fetch",
                 "console", "window", "document", "navigator"}
    return sorted(names - _builtins)


def obfuscate_html(html: str) -> str:
    """
    Обфусцирует JS и минифицирует CSS внутри HTML-строки.
    • Блоки с Jinja-тегами ({{...}}, {%...%}) пропускаются.
    • Имена, используемые в onclick/onXxx, экспортируются через window
      для сохранения совместимости.
    """
    # Собираем все публичные имена из HTML до обработки
    public_names = _collect_public_names(html)
    if public_names:
        logger.debug("obfuscator: публичные имена из HTML: %s", public_names)

    def _process_style(m: re.Match) -> str:
        open_tag, css, close_tag = m.group(1), m.group(2), m.group(3)
        if not MINIFY_CSS:
            return m.group(0)
        result = minify_css(css)
        return open_tag + result + close_tag

    def _process_script(m: re.Match) -> str:
        open_tag, js, close_tag = m.group(1), m.group(2), m.group(3)
        # Пропускаем: внешние src=, пустые, Jinja-блоки
        if "src=" in open_tag.lower():
            return m.group(0)
        if not js.strip():
            return m.group(0)
        if _RE_JINJA.search(js):
            logger.debug("obfuscator: пропущен <script> с Jinja-тегами")
            return m.group(0)
        obfuscated = obfuscate_js(js, public_names=public_names)
        return open_tag + obfuscated + close_tag

    html = _RE_STYLE.sub(_process_style, html)
    html = _RE_SCRIPT.sub(_process_script, html)
    return html


# ─────────────────────────── публичный API ───────────────────────

def obfuscate_page(html: str, cache_key: Optional[str] = None) -> str:
    """
    Главная точка входа. Принимает готовый HTML (после render_template_string),
    обфусцирует JS/CSS и возвращает результат.

    cache_key — произвольная строка-тег; результат кешируется и повторно
    не пересчитывается. Кеш привязан к хешу контента: изменился шаблон
    → другой хеш → автоматически новая обфускация.

    Пример:
        @app.route("/")
        def index():
            raw = render_template_string(TEMPLATE, **ctx)
            return obfuscate_page(raw, cache_key="web_index")
    """
    if not ENABLED:
        return html

    content_hash = _content_hash(html)
    full_key     = f"{cache_key}:{content_hash}" if cache_key else content_hash

    cached = _cache.get(full_key)
    if cached is not None:
        logger.debug("obfuscator: cache hit [%s]", full_key)
        return cached

    logger.info("obfuscator: обфусцирую [%s] (%d байт)...", full_key, len(html))
    result = obfuscate_html(html)
    _cache.set(full_key, result)
    logger.info("obfuscator: готово [%s] %d → %d байт", full_key, len(html), len(result))
    return result


def warm_up(pages: dict[str, str]) -> None:
    """
    Прогревает кеш в фоновых потоках при старте приложения.

    pages = {"web_index": html_string, "miniapp_index": html2, ...}

    Вызывайте один раз в конце файла сервиса, ДО web_app.run() / app.run().
    Прогрев выполняется параллельно и не блокирует запуск.
    """
    if not ENABLED:
        return

    def _worker(key: str, html: str) -> None:
        try:
            obfuscate_page(html, cache_key=key)
            logger.info("obfuscator: прогрев [%s] завершён", key)
        except Exception as exc:
            logger.error("obfuscator warm_up [%s]: %s", key, exc)

    threads = [
        threading.Thread(
            target=_worker, args=(k, v),
            daemon=True, name=f"obf-warmup-{k}",
        )
        for k, v in pages.items()
    ]
    for t in threads:
        t.start()
    logger.info("obfuscator: прогрев запущен для %d страниц", len(threads))


def cache_clear() -> None:
    """Сбрасывает весь кеш (например, при обновлении конфигурации)."""
    _cache.clear()
    logger.info("obfuscator: кеш очищен")
