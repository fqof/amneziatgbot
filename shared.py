import html
import time
import hmac
import hashlib
import subprocess
import re
from math import ceil
from typing import Any
from aiogram import Bot
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    Message,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ReplyKeyboardMarkup,
    KeyboardButton,
    WebAppInfo,
)

from config import settings
from database import MAX_PROFILES_PER_USER

PAGE_SIZE = 10


def generate_dynamic_token() -> str:
    ts = int(time.time())
    msg = f"{ts}".encode('utf-8')
    sig = hmac.new(settings.DB_ENCRYPTION_KEY.encode(), msg, hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def verify_dynamic_token(token: str, max_age_seconds: int = 300) -> bool:
    if not token or '.' not in token:
        return False
    try:
        ts_str, sig = token.split('.', 1)
        ts = int(ts_str)
        if int(time.time()) - ts > max_age_seconds:
            return False
        expected_sig = hmac.new(settings.DB_ENCRYPTION_KEY.encode(), ts_str.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)
    except Exception:
        return False


_ping_cache = {"ms": 0, "ts": 0}
_PING_TTL = 180


def get_shared_ping(host: str, api_url: str) -> int:
    now = time.monotonic()
    if _ping_cache["ms"] == 0 or (now - _ping_cache["ts"]) >= _PING_TTL:
        ms = 0
        try:
            res = subprocess.run(["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True, timeout=5)
            m = re.search(r"time=(\d+\.?\d*)\s*ms", res.stdout)
            if m:
                ms = round(float(m.group(1)))
        except Exception:
            pass

        if ms == 0:
            try:
                t0 = time.monotonic()
                import urllib.request
                urllib.request.urlopen(api_url + "/healthz", timeout=3)
                ms = round((time.monotonic() - t0) * 1000)
            except Exception:
                pass

        _ping_cache["ms"] = ms
        _ping_cache["ts"] = now

    return _ping_cache["ms"]


def is_admin(user_id: int) -> bool:
    return user_id in settings.ADMIN_IDS


def is_allowed(user_id: int) -> bool:
    return True if settings.BOT_MODE != "admin" else is_admin(user_id)


def fmt_bytes(b: float) -> str:
    if not b:
        return "0 Б"
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} ТБ"


def fmt_handshake(ts: int) -> str:
    if not ts:
        return "никогда"
    delta = int(time.time()) - ts
    if delta < 0:
        return "только что"
    if delta < 60:
        return f"{delta} сек. назад"
    if delta < 3600:
        return f"{delta // 60} мин. назад"
    if delta < 86400:
        return f"{delta // 3600} ч. назад"
    return f"{delta // 86400} д. назад"


def user_link(tg_id: int, display: str | None = None) -> str:
    label = html.escape(display) if display else str(tg_id)
    return f'<a href="tg://user?id={tg_id}">{label}</a>'


def menu_text(user_data: dict | None, notice: str = "") -> str:
    prefix = f"<i>{html.escape(notice)}</i>\n\n" if notice else ""

    if user_data is None:
        return f"{prefix}🏠 <b>Главное меню</b>\n\n❌ Профилей нет"

    profiles = user_data.get("profiles", [])
    banned = user_data.get("banned", False)

    if not profiles:
        return f"{prefix}🏠 <b>Главное меню</b>\n\n❌ Профилей нет"

    lines = []
    for p in profiles:
        name = html.escape(p["vpn_name"])
        icon = "🚫" if banned or p.get("disabled") else "✅"
        lines.append(f"{icon} <b>{name}</b>")

    status_block = "\n".join(lines)
    can_add = len(profiles) < MAX_PROFILES_PER_USER
    limit_note = "" if can_add else f"\n<i>Лимит профилей: {MAX_PROFILES_PER_USER}</i>"

    return (
        f"{prefix}🏠 <b>Главное меню</b>\n\n"
        f"📋 Ваши профили:\n{status_block}{limit_note}"
    )


async def safe_edit(msg: Message, text: str, reply_markup=None, parse_mode=ParseMode.HTML) -> None:
    try:
        await msg.edit_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    except TelegramBadRequest as e:
        if "message is not modified" not in str(e):
            raise


async def delete_messages(bot: Bot, chat_id: int, msg_ids: list[int]) -> None:
    import asyncio
    chunk_size = 5
    for i in range(0, len(msg_ids), chunk_size):
        chunk = msg_ids[i:i + chunk_size]
        for mid in chunk:
            try:
                await bot.delete_message(chat_id, mid)
            except Exception:
                pass
        if i + chunk_size < len(msg_ids):
            await asyncio.sleep(0.05)


async def push_side_msg(state: FSMContext, msg_id: int) -> None:
    data = await state.get_data()
    ids: list[int] = data.get("side_msgs", [])
    ids.append(msg_id)
    await state.update_data(side_msgs=ids)


async def pop_side_msgs(state: FSMContext) -> list[int]:
    data = await state.get_data()
    ids: list[int] = data.get("side_msgs", [])
    await state.update_data(side_msgs=[])
    return ids


def find_peer_in_clients(clients_data: dict | None, username: str) -> dict | None:
    if not clients_data:
        return None
    for item in clients_data.get("items", []):
        if item.get("username") == username:
            peers = item.get("peers", [])
            return peers[0] if peers else None
    return None


def count_online_peers(clients_data: dict | None) -> tuple[int, int]:
    if not clients_data:
        return 0, 0
    total = online = 0
    for item in clients_data.get("items", []):
        for peer in item.get("peers", []):
            total += 1
            if peer.get("online"):
                online += 1
    return online, total


def paginate_users(users: list[dict], page: int) -> tuple[list[dict], int]:
    total_pages = max(1, ceil(len(users) / PAGE_SIZE))
    page = max(0, min(page, total_pages - 1))
    start = page * PAGE_SIZE
    return users[start:start + PAGE_SIZE], total_pages


def build_users_page_text(users_page: list[dict], page: int,
                           total_pages: int, total: int,
                           global_offset: int) -> str:
    rows = []
    for i, u in enumerate(users_page, global_offset + 1):
        banned_tag = "  🚫" if u.get("banned") else ""
        profiles = u.get("profiles", [])
        profile_names = ", ".join(html.escape(p["vpn_name"]) for p in profiles) or "—"
        tg_id = u['telegram_id']
        link = user_link(tg_id)
        rows.append(
            f"{i}. {link}{banned_tag}\n"
            f"   📋 <b>{profile_names}</b>\n"
            f"   🗓 {u.get('created_at', '—')}"
        )
    body = "\n\n".join(rows) if rows else "Список пуст."
    header = (
        f"👥 <b>Пользователи</b> — {total} чел. "
        f"<i>(стр. {page + 1}/{total_pages})</i>"
    )
    footer = "<i>👁 — карточка · 🚫/✅ — бан</i>"
    return f"{header}\n\n{body}\n\n{footer}"


def kb_reply_menu(admin: bool = False) -> ReplyKeyboardMarkup:
    miniapp_url = getattr(settings, "MINIAPP_URL", "").strip()

    user_row = []
    if miniapp_url:
        user_row.append(
            KeyboardButton(text="🚀 Открыть приложение", web_app=WebAppInfo(url=miniapp_url))
        )
    else:
        user_row.append(KeyboardButton(text="🏠 Главное меню"))

    rows = [user_row]

    if admin:
        rows.append([KeyboardButton(text="🔧 Панель управления")])

    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, persistent=True)


def kb_main(admin: bool = False) -> InlineKeyboardMarkup:
    rows = []

    rows.append([
        InlineKeyboardButton(
            text="🚀 Открыть меню",
            web_app=WebAppInfo(url=getattr(settings, "MINIAPP_URL", "").strip() or "https://pgkqawg.fqof.ru/"),
        ),
    ])

    if admin:
        rows.append([
            InlineKeyboardButton(text="🔧 Панель управления", callback_data="admin_panel"),
        ])

    return InlineKeyboardMarkup(inline_keyboard=rows)


def kb_profile_select(profiles: list[dict], action: str) -> InlineKeyboardMarkup:
    rows = []
    for p in profiles:
        name = html.escape(p["vpn_name"])
        dis = " 🚫" if p.get("disabled") else ""
        rows.append([
            InlineKeyboardButton(
                text=f"📋 {name}{dis}",
                callback_data=f"{action}_profile:{p['id']}",
            )
        ])
    rows.append([InlineKeyboardButton(text="🔙 Назад", callback_data="back_main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def kb_my_profiles(profiles: list[dict]) -> InlineKeyboardMarkup:
    rows = []
    for p in profiles:
        name = html.escape(p["vpn_name"])
        dis = " 🚫" if p.get("disabled") else ""
        rows.append([
            InlineKeyboardButton(
                text=f"👁 {name}{dis}",
                callback_data=f"my_info_profile:{p['id']}",
            ),
            InlineKeyboardButton(
                text="🗑",
                callback_data=f"user_del_profile:{p['id']}",
            ),
        ])
    rows.append([InlineKeyboardButton(text="🔙 В главное меню", callback_data="back_main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def kb_user_del_confirm(profile_id: int, vpn_name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="🗑 Удалить",
                callback_data=f"user_del_profile_do:{profile_id}",
            ),
            InlineKeyboardButton(text="❌ Отмена", callback_data="my_profiles"),
        ],
    ])


def kb_admin_panel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="👥 Пользователи", callback_data="admin_list:0"),
            InlineKeyboardButton(text="📈 Статистика",   callback_data="admin_stats:0"),
        ],
        [
            InlineKeyboardButton(text="🔍 Поиск",        callback_data="admin_search"),
            InlineKeyboardButton(text="📢 Рассылка",     callback_data="admin_broadcast"),
        ],
        [
            InlineKeyboardButton(text="🔒 Блокировки",   callback_data="admin_ban_menu"),
            InlineKeyboardButton(text="🔎 Пиры Amnezia", callback_data="admin_all_peers"),
        ],
        [
            InlineKeyboardButton(text="🗝 Секретные ключи", callback_data="admin_keys"),
        ],
        [
            InlineKeyboardButton(text="📋 Экспорт CSV",  callback_data="admin_export_csv"),
        ],
        [
            InlineKeyboardButton(text="🔙 В главное меню", callback_data="back_main"),
        ],
    ])


def kb_admin_ban_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="🚫 Заблокировать всех", callback_data="admin_ban_all"),
            InlineKeyboardButton(text="✅ Разблокировать всех", callback_data="admin_unban_all"),
        ],
        [
            InlineKeyboardButton(text="🔙 Назад в панель", callback_data="admin_panel"),
        ],
    ])


def kb_cancel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отменить", callback_data="cancel")],
    ])


def kb_confirm_create(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Создать",  callback_data=f"confirm_create:{name}"),
            InlineKeyboardButton(text="❌ Отменить", callback_data="cancel"),
        ],
    ])


def kb_back() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔙 В главное меню", callback_data="back_main")],
    ])


def kb_back_to_panel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔧 Панель управления", callback_data="admin_panel")],
        [InlineKeyboardButton(text="🏠 В главное меню",    callback_data="back_main")],
    ])


def kb_server_status() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Обновить", callback_data="server_status")],
        [InlineKeyboardButton(text="🔙 В главное меню", callback_data="back_main")],
    ])


def kb_admin_list(users_page: list[dict], page: int, total_pages: int) -> InlineKeyboardMarkup:
    rows = []
    for u in users_page:
        banned    = u.get("banned", False)
        ban_icon  = "✅" if banned else "🚫"
        ban_label = "Разбан" if banned else "Бан"
        tg_id     = u["telegram_id"]
        rows.append([
            InlineKeyboardButton(
                text=f"👁 {tg_id}",
                callback_data=f"admin_user_card:{tg_id}:{page}",
            ),
            InlineKeyboardButton(
                text=f"{ban_icon} {ban_label}",
                callback_data=f"admin_ban_toggle:{tg_id}:{page}",
            ),
        ])

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="◀️", callback_data=f"admin_list:{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"· {page + 1}/{total_pages} ·", callback_data="noop"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton(text="▶️", callback_data=f"admin_list:{page + 1}"))
    if nav:
        rows.append(nav)

    rows.append([
        InlineKeyboardButton(text="🔍 Поиск", callback_data="admin_search"),
        InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel"),
    ])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def kb_user_card(tg_id: int, banned: bool, page: int, profiles: list[dict]) -> InlineKeyboardMarkup:
    ban_text = "✅ Разбанить" if banned else "🚫 Заблокировать"
    rows = [
        [
            InlineKeyboardButton(
                text=ban_text,
                callback_data=f"admin_ban_toggle:{tg_id}:{page}",
            ),
            InlineKeyboardButton(
                text="✉️ Написать",
                callback_data=f"admin_msg_user:{tg_id}:{page}",
            ),
        ],
        [
            InlineKeyboardButton(
                text="🔗 Профиль в Telegram",
                url=f"tg://user?id={tg_id}",
            ),
        ],
    ]

    for p in profiles:
        name = html.escape(p["vpn_name"])
        dis = p.get("disabled", False)
        tog_icon = "✅ Вкл" if dis else "⏸ Откл"
        rows.append([
            InlineKeyboardButton(
                text=f"🗑 {name}",
                callback_data=f"admin_del_profile:{p['id']}:{tg_id}:{page}",
            ),
            InlineKeyboardButton(
                text=tog_icon,
                callback_data=f"admin_toggle_profile:{p['id']}:{tg_id}:{page}",
            ),
            InlineKeyboardButton(
                text="📊 Стат",
                callback_data=f"admin_profile_stat:{p['id']}:{tg_id}:{page}",
            ),
        ])

    rows.append([
        InlineKeyboardButton(text="🔄 Обновить", callback_data=f"admin_user_card:{tg_id}:{page}"),
        InlineKeyboardButton(text="◀️ К списку", callback_data=f"admin_list:{page}"),
    ])
    rows.append([
        InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel"),
    ])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def build_user_card_text(u: dict, peers_info: dict | None = None) -> str:
    tg_id = u["telegram_id"]
    banned = u.get("banned", False)
    profiles = u.get("profiles", [])
    created_at = u.get("created_at", "—")
    username = u.get("username") or u.get("tg_username") or ""

    link = user_link(tg_id, f"@{username}" if username else None)
    ban_status = "🚫 Заблокирован" if banned else "✅ Активен"

    lines = [
        f"👤 <b>Карточка пользователя</b>",
        f"",
        f"🆔 ID: {link}",
        f"📌 Статус: {ban_status}",
        f"🗓 Зарегистрирован: {created_at}",
        f"",
        f"📋 <b>Профили ({len(profiles)}/{MAX_PROFILES_PER_USER}):</b>",
    ]

    if profiles:
        for p in profiles:
            name = html.escape(p["vpn_name"])
            dis_icon = "⏸" if p.get("disabled") else "🟢"
            peer_line = f"  {dis_icon} <b>{name}</b>"
            if peers_info and name in peers_info:
                pi = peers_info[name]
                online = pi.get("online", False)
                hs = fmt_handshake(pi.get("lastHandshake", 0))
                rx = fmt_bytes(float(pi.get("traffic", {}).get("received", 0) or 0))
                tx = fmt_bytes(float(pi.get("traffic", {}).get("sent", 0) or 0))
                conn = "🟢" if online else "🔴"
                peer_line += f" {conn} · ⬇{rx} ⬆{tx} · {hs}"
            lines.append(peer_line)
    else:
        lines.append("  — нет профилей")

    return "\n".join(lines)


def kb_del_profile_confirm(profile_id: int, tg_id: int, page: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="🗑 Подтвердить удаление",
                callback_data=f"admin_del_profile_do:{profile_id}:{tg_id}:{page}",
            ),
        ],
        [
            InlineKeyboardButton(text="↩️ Отмена", callback_data=f"admin_user_card:{tg_id}:{page}"),
        ],
    ])


def kb_broadcast_confirm() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📢 Отправить всем", callback_data="admin_broadcast_do"),
            InlineKeyboardButton(text="❌ Отменить",        callback_data="cancel"),
        ],
    ])


def kb_stats_refresh() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Обновить", callback_data="admin_stats:0")],
        [InlineKeyboardButton(text="🔧 Панель",   callback_data="admin_panel")],
    ])
