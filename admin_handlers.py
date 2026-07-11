import asyncio
import csv
import html
import io
import json
import logging
import re
from datetime import datetime, timezone
from math import ceil

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery, Message,
    InlineKeyboardMarkup, InlineKeyboardButton,
    BufferedInputFile,
)

from config import settings
from database import Database, MAX_PROFILES_PER_USER
from amnezia_client import AmneziaClient
from shared import (
    is_admin,
    fmt_bytes, fmt_handshake,
    safe_edit, delete_messages, push_side_msg, pop_side_msgs,
    find_peer_in_clients, count_online_peers,
    paginate_users, build_users_page_text, PAGE_SIZE,
    kb_admin_panel, kb_admin_ban_menu, kb_cancel, kb_back, kb_back_to_panel,
    kb_admin_list, kb_user_card, kb_del_profile_confirm,
    kb_broadcast_confirm, kb_stats_refresh,
    menu_text, kb_main, user_link,
)

logger = logging.getLogger(__name__)

MAX_BROADCAST_LEN = 4096
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z\u0430-\u044f\u0410-\u042f\u0451\u04010-9]{1,16}$")


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _sanitize(text: str, max_len: int = 4096) -> str:
    if not text:
        return ""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text[:max_len].strip()


# ───────────────────────────── FSM ──────────────────────────────────

class BroadcastStates(StatesGroup):
    waiting_for_text = State()


class SearchStates(StatesGroup):
    waiting_for_query = State()


class MessageUserStates(StatesGroup):
    waiting_for_text = State()


# ──────────────────────── Панель управления ──────────────────────────

async def cb_admin_panel(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    users = await db.get_all_users_with_profiles()
    total = len(users)
    banned = sum(1 for u in users if u.get("banned"))
    active = total - banned
    total_profiles = sum(len(u.get("profiles", [])) for u in users)

    api_ok = await amnezia.health_check()
    api_status = "🟢 API онлайн" if api_ok else "🔴 API недоступен"

    await safe_edit(
        callback.message,
        f"🔧 <b>Панель управления</b>\n\n"
        f"👥 Пользователей: <b>{total}</b>  "
        f"(акт.: <b>{active}</b>, заблок.: <b>{banned}</b>)\n"
        f"📋 Профилей всего: <b>{total_profiles}</b>\n"
        f"{api_status}",
        reply_markup=kb_admin_panel(),
    )
    await callback.answer()


# ──────────────────────── Список пользователей ───────────────────────

async def cb_admin_list(callback: CallbackQuery, db: Database):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    page = _safe_int(callback.data.split(":")[1] if ":" in callback.data else "0")

    users = await db.get_all_users_with_profiles()
    users_page, total_pgs = paginate_users(users, page)
    global_offset = page * PAGE_SIZE

    await safe_edit(
        callback.message,
        build_users_page_text(users_page, page, total_pgs, len(users), global_offset),
        reply_markup=kb_admin_list(users_page, page, total_pgs),
    )
    await callback.answer()


# ──────────────────────── Карточка пользователя ──────────────────────

async def cb_admin_user_card(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    if len(parts) < 3:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return
    tg_id = _safe_int(parts[1], -1)
    page = _safe_int(parts[2], 0)

    if tg_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    user_data = await db.get_user(tg_id)
    if not user_data:
        await callback.answer("❌ Пользователь не найден.", show_alert=True)
        return

    await safe_edit(callback.message, "⏳ Загружаю карточку…")
    await callback.answer()

    banned = user_data.get("banned", False)
    created_at = user_data.get("created_at", "—")
    profiles = user_data.get("profiles", [])

    # Получаем данные Amnezia для каждого профиля
    clients = await amnezia.get_all_clients()

    profile_lines = []
    for p in profiles:
        name = html.escape(p["vpn_name"])
        dis = p.get("disabled", False)
        dis_tag = " ⏸" if dis else ""
        peer = find_peer_in_clients(clients, p["vpn_name"])

        # Обновляем IP
        if peer:
            ep = peer.get("endpoint") or ""
            if ep:
                ip_only = ep.split(":")[0]
                if ip_only and ip_only != p.get("last_ip"):
                    await db.set_last_ip(p["id"], ip_only)
                    p["last_ip"] = ip_only

        last_ip = html.escape(p.get("last_ip") or "—")

        if peer:
            online = peer.get("online", False)
            ps = peer.get("status", "active")
            tr = peer.get("traffic", {})
            rx = fmt_bytes(float(tr.get("received", 0) or 0))
            tx = fmt_bytes(float(tr.get("sent", 0) or 0))
            hs = fmt_handshake(peer.get("lastHandshake", 0))

            if ps == "disabled" or dis:
                net_s = "🚫"
            elif online:
                net_s = "🟢"
            else:
                net_s = "🔴"

            profile_lines.append(
                f"  {net_s} <b>{name}</b>{dis_tag}\n"
                f"     ⬇️{rx} ⬆️{tx} · {hs}\n"
                f"     IP: <code>{last_ip}</code>"
            )
        else:
            profile_lines.append(
                f"  ❓ <b>{name}</b>{dis_tag}\n"
                f"     IP: <code>{last_ip}</code>"
            )

    profiles_block = "\n\n".join(profile_lines) if profile_lines else "  нет профилей"
    account_status = "🚫 <b>Заблокирован</b>" if banned else "✅ Активен"

    await safe_edit(
        callback.message,
        f"👤 <b>Карточка пользователя</b>\n\n"
        f"TG ID: {user_link(tg_id)}\n"
        f"Статус: {account_status}\n"
        f"Зарегистрирован: {created_at}\n"
        f"Профилей: <b>{len(profiles)}/{MAX_PROFILES_PER_USER}</b>\n\n"
        f"<b>📋 Профили:</b>\n{profiles_block}",
        reply_markup=kb_user_card(tg_id, banned, page, profiles),
    )


# ──────────────────────── Статистика (по telegram_id) ────────────────

async def cb_admin_stats(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    page = _safe_int(callback.data.split(":")[1] if ":" in callback.data else "0")

    await safe_edit(callback.message, "⏳ Собираю статистику…")
    await callback.answer()

    users = await db.get_all_users_with_profiles()
    clients = await amnezia.get_all_clients()

    total_users = len(users)
    banned_users = sum(1 for u in users if u.get("banned"))
    active_users = total_users - banned_users
    total_profiles = sum(len(u.get("profiles", [])) for u in users)
    online_cnt, total_peers = count_online_peers(clients)

    # Считаем трафик по telegram_id
    traffic_by_tgid: dict[int, float] = {}
    total_rx = total_tx = 0.0

    if clients:
        # Словарь vpn_name -> telegram_id
        name_to_tgid: dict[str, int] = {}
        for u in users:
            for p in u.get("profiles", []):
                name_to_tgid[p["vpn_name"]] = u["telegram_id"]

        for item in clients.get("items", []):
            uname = item.get("username", "")
            tg_id = name_to_tgid.get(uname)
            for peer in item.get("peers", []):
                t = peer.get("traffic", {})
                r = float(t.get("received", 0) or 0)
                s = float(t.get("sent", 0) or 0)
                total_rx += r
                total_tx += s
                if tg_id:
                    traffic_by_tgid[tg_id] = traffic_by_tgid.get(tg_id, 0.0) + r + s

    # Топ по трафику (telegram_id)
    top_users = sorted(traffic_by_tgid.items(), key=lambda x: x[1], reverse=True)

    now = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")

    if page == 0:
        top_lines = "\n".join(
            f"  {i+1}. {user_link(tgid)} — {fmt_bytes(tb)}"
            for i, (tgid, tb) in enumerate(top_users[:5])
        ) or "  нет данных"

        recent = users[:5]
        recent_lines = "\n".join(
            f"  • {user_link(u['telegram_id'])} · {len(u.get('profiles',[]))} проф. — {u.get('created_at', '—')}"
            for u in recent
        ) or "  нет данных"

        text = (
            f"📈 <b>Статистика</b>  <i>({now})</i>\n\n"
            f"👥 Пользователей: <b>{total_users}</b>  "
            f"(акт.: <b>{active_users}</b> · заблок.: <b>{banned_users}</b>)\n"
            f"📋 Профилей: <b>{total_profiles}</b>\n"
            f"📡 Пиров: <b>{total_peers}</b>  онлайн: <b>{online_cnt}</b>\n\n"
            f"📶 Трафик:\n"
            f"  ⬇️ {fmt_bytes(total_rx)}   ⬆️ {fmt_bytes(total_tx)}\n\n"
            f"🏆 Топ-5 по трафику (TG ID):\n{top_lines}\n\n"
            f"🕐 Последние регистрации:\n{recent_lines}"
        )

    elif page == 1:
        chunk = top_users[:25]
        lines = "\n".join(
            f"  {i+1}. {user_link(tgid)} — {fmt_bytes(tb)}"
            for i, (tgid, tb) in enumerate(chunk)
        ) or "  нет данных"
        text = (
            f"🏆 <b>Топ по трафику (TG ID)</b>  <i>({now})</i>\n\n"
            f"{lines}"
        )

    elif page == 2:
        banned_list = [u for u in users if u.get("banned")]
        if banned_list:
            lines = "\n".join(
                f"  • {user_link(u['telegram_id'])}  "
                f"({len(u.get('profiles',[]))} проф.)"
                for u in banned_list[:30]
            )
        else:
            lines = "  Нет заблокированных."
        text = (
            f"🚫 <b>Заблокированные</b> ({len(banned_list)})  <i>({now})</i>\n\n"
            f"{lines}"
        )

    else:
        page = 0
        text = "❌ Страница не найдена."

    total_pages = 3
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="◀️", callback_data=f"admin_stats:{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"· {page + 1}/{total_pages} ·", callback_data="noop"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton(text="▶️", callback_data=f"admin_stats:{page + 1}"))

    kb = InlineKeyboardMarkup(inline_keyboard=[
        nav,
        [InlineKeyboardButton(text="🔄 Обновить", callback_data=f"admin_stats:{page}")],
        [InlineKeyboardButton(text="🔧 Панель",   callback_data="admin_panel")],
    ])

    await safe_edit(callback.message, text, reply_markup=kb)


# ──────────────────────── Статистика профиля ─────────────────────────

async def cb_admin_profile_stat(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    """Детальная статистика конкретного профиля из карточки пользователя."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    # admin_profile_stat:{profile_id}:{tg_id}:{page}
    if len(parts) < 4:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    profile_id = _safe_int(parts[1], -1)
    tg_id = _safe_int(parts[2], -1)
    page = _safe_int(parts[3], 0)

    profile = await db.get_profile_by_id(profile_id)
    if not profile:
        await callback.answer("❌ Профиль не найден.", show_alert=True)
        return

    await safe_edit(callback.message, "⏳ Загружаю статистику…")
    await callback.answer()

    vpn_name = profile["vpn_name"]
    clients = await amnezia.get_all_clients()
    peer = find_peer_in_clients(clients, vpn_name)

    dis = profile.get("disabled", False)
    last_ip = html.escape(profile.get("last_ip") or "—")
    created_at = profile.get("created_at", "—")

    if peer:
        online = peer.get("online", False)
        ps = peer.get("status", "active")
        tr = peer.get("traffic", {})
        rx = fmt_bytes(float(tr.get("received", 0) or 0))
        tx = fmt_bytes(float(tr.get("sent", 0) or 0))
        hs = fmt_handshake(peer.get("lastHandshake", 0))
        proto = peer.get("protocol") or "—"

        if ps == "disabled" or dis:
            net_s = "🚫 Отключён"
        elif online:
            net_s = "🟢 Онлайн"
        else:
            net_s = "🔴 Офлайн"

        conn_block = (
            f"Сетевой статус: {net_s}\n"
            f"Протокол: <code>{html.escape(proto)}</code>\n"
            f"Последнее подключение: {hs}\n"
            f"⬇️ Получено: <b>{rx}</b>   ⬆️ Отправлено: <b>{tx}</b>"
        )
    else:
        conn_block = "<i>Пир не найден в Amnezia API</i>"

    status_text = "⏸ Отключён" if dis else "✅ Активен"

    await safe_edit(
        callback.message,
        f"📊 <b>Статистика профиля: {html.escape(vpn_name)}</b>\n\n"
        f"TG ID владельца: {user_link(tg_id)}\n"
        f"Статус профиля: {status_text}\n"
        f"Создан: {created_at}\n"
        f"Последний IP: <code>{last_ip}</code>\n\n"
        f"{conn_block}",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(
                text="◀️ К карточке",
                callback_data=f"admin_user_card:{tg_id}:{page}",
            )],
            [InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel")],
        ]),
    )


# ──────────────────────── Отключение/включение профиля ───────────────

async def cb_admin_toggle_profile(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    """Включить/отключить конкретный профиль пользователя."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    # admin_toggle_profile:{profile_id}:{tg_id}:{page}
    if len(parts) < 4:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    profile_id = _safe_int(parts[1], -1)
    tg_id = _safe_int(parts[2], -1)
    page = _safe_int(parts[3], 0)

    if profile_id < 0 or tg_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    profile = await db.get_profile_by_id(profile_id)
    if not profile:
        await callback.answer("❌ Профиль не найден.", show_alert=True)
        return

    currently_disabled = profile.get("disabled", False)
    new_disabled = not currently_disabled
    new_amnezia_status = "active" if currently_disabled else "disabled"
    action_text = "включён ✅" if currently_disabled else "отключён ⏸"

    # Обновляем в Amnezia
    peer_id = profile.get("peer_id")
    api_ok = False
    if peer_id:
        api_ok = await amnezia.update_user(peer_id, status=new_amnezia_status)

    # Обновляем в БД
    await db.set_profile_disabled(profile_id, new_disabled)

    # Уведомляем пользователя
    try:
        notify_text = (
            f"✅ Ваш профиль <b>{html.escape(profile['vpn_name'])}</b> <b>восстановлен</b>."
            if currently_disabled
            else f"⏸ Ваш профиль <b>{html.escape(profile['vpn_name'])}</b> <b>отключён</b> администратором."
        )
        await callback.bot.send_message(tg_id, notify_text, parse_mode=ParseMode.HTML)
    except Exception:
        pass

    api_note = "" if api_ok else " <i>(только в БД)</i>"
    await callback.answer(f"Профиль {html.escape(profile['vpn_name'])}: {action_text}{api_note}")

    # Обновляем карточку
    user_data = await db.get_user(tg_id)
    if not user_data:
        return
    banned = user_data.get("banned", False)
    profiles = user_data.get("profiles", [])

    clients = await amnezia.get_all_clients()
    profile_lines = _build_profile_lines(profiles, clients)
    profiles_block = "\n\n".join(profile_lines) if profile_lines else "  нет профилей"
    account_status = "🚫 <b>Заблокирован</b>" if banned else "✅ Активен"

    await safe_edit(
        callback.message,
        f"👤 <b>Карточка пользователя</b>\n\n"
        f"TG ID: {user_link(tg_id)}\n"
        f"Статус: {account_status}\n"
        f"Зарегистрирован: {user_data.get('created_at', '—')}\n"
        f"Профилей: <b>{len(profiles)}/{MAX_PROFILES_PER_USER}</b>\n\n"
        f"<b>📋 Профили:</b>\n{profiles_block}",
        reply_markup=kb_user_card(tg_id, banned, page, profiles),
    )


def _build_profile_lines(profiles: list[dict], clients: dict | None) -> list[str]:
    lines = []
    for p in profiles:
        name = html.escape(p["vpn_name"])
        dis = p.get("disabled", False)
        dis_tag = " ⏸" if dis else ""
        peer = find_peer_in_clients(clients, p["vpn_name"])
        last_ip = html.escape(p.get("last_ip") or "—")

        if peer:
            online = peer.get("online", False)
            ps = peer.get("status", "active")
            tr = peer.get("traffic", {})
            rx = fmt_bytes(float(tr.get("received", 0) or 0))
            tx = fmt_bytes(float(tr.get("sent", 0) or 0))
            hs = fmt_handshake(peer.get("lastHandshake", 0))
            if ps == "disabled" or dis:
                net_s = "🚫"
            elif online:
                net_s = "🟢"
            else:
                net_s = "🔴"
            lines.append(
                f"  {net_s} <b>{name}</b>{dis_tag}\n"
                f"     ⬇️{rx} ⬆️{tx} · {hs}\n"
                f"     IP: <code>{last_ip}</code>"
            )
        else:
            lines.append(
                f"  ❓ <b>{name}</b>{dis_tag}\n"
                f"     IP: <code>{last_ip}</code>"
            )
    return lines


# ──────────────────────── Удаление профиля ───────────────────────────

async def cb_admin_del_profile(callback: CallbackQuery, db: Database):
    """Запрос подтверждения удаления профиля."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    # admin_del_profile:{profile_id}:{tg_id}:{page}
    if len(parts) < 4:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    profile_id = _safe_int(parts[1], -1)
    tg_id = _safe_int(parts[2], -1)
    page = _safe_int(parts[3], 0)

    profile = await db.get_profile_by_id(profile_id)
    if not profile:
        await callback.answer("❌ Профиль не найден.", show_alert=True)
        return

    vpn_name = profile["vpn_name"]
    await safe_edit(
        callback.message,
        f"🗑 <b>Удаление профиля</b>\n\n"
        f"Профиль: <b>{html.escape(vpn_name)}</b>\n"
        f"TG ID: {user_link(tg_id)}\n\n"
        f"⚠️ Пир будет удалён из Amnezia.",
        reply_markup=kb_del_profile_confirm(profile_id, tg_id, page),
    )
    await callback.answer()


async def cb_admin_del_profile_do(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    """Фактическое удаление профиля."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    # admin_del_profile_do:{profile_id}:{tg_id}:{page}
    if len(parts) < 4:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    profile_id = _safe_int(parts[1], -1)
    tg_id = _safe_int(parts[2], -1)
    page = _safe_int(parts[3], 0)

    if profile_id < 0 or tg_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    profile = await db.get_profile_by_id(profile_id)
    if not profile:
        await callback.answer("❌ Профиль не найден.", show_alert=True)
        return

    vpn_name = profile["vpn_name"]
    await safe_edit(callback.message, f"⏳ Удаляю профиль <b>{html.escape(vpn_name)}</b>…")
    await callback.answer()

    try:
        peer_id = profile.get("peer_id")
        api_ok = False
        if peer_id:
            api_ok = await amnezia.delete_user(peer_id)

        await db.delete_profile(profile_id)

        try:
            await callback.bot.send_message(
                tg_id,
                f"⚠️ Ваш VPN-профиль <b>{html.escape(vpn_name)}</b> был <b>удалён</b> администратором.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

        api_note = "" if api_ok else "\n<i>(Пир не найден в Amnezia — удалён только из БД)</i>"

        # Возвращаем обновлённую карточку
        user_data = await db.get_user(tg_id)
        if user_data:
            banned = user_data.get("banned", False)
            profiles = user_data.get("profiles", [])
            clients = await amnezia.get_all_clients()
            profile_lines = _build_profile_lines(profiles, clients)
            profiles_block = "\n\n".join(profile_lines) if profile_lines else "  нет профилей"
            account_status = "🚫 <b>Заблокирован</b>" if banned else "✅ Активен"

            await safe_edit(
                callback.message,
                f"✅ Профиль <b>{html.escape(vpn_name)}</b> удалён.{api_note}\n\n"
                f"👤 <b>Карточка пользователя</b>\n\n"
                f"TG ID: {user_link(tg_id)}\n"
                f"Статус: {account_status}\n"
                f"Профилей: <b>{len(profiles)}/{MAX_PROFILES_PER_USER}</b>\n\n"
                f"<b>📋 Профили:</b>\n{profiles_block}",
                reply_markup=kb_user_card(tg_id, banned, page, profiles),
            )
        else:
            # Пользователь без профилей — возвращаемся в список
            users = await db.get_all_users_with_profiles()
            total_pgs = max(1, ceil(len(users) / PAGE_SIZE))
            page = min(page, total_pgs - 1)
            users_page, total_pgs = paginate_users(users, page)
            await safe_edit(
                callback.message,
                f"✅ Профиль удалён.{api_note}\n\n"
                + build_users_page_text(users_page, page, total_pgs, len(users), page * PAGE_SIZE),
                reply_markup=kb_admin_list(users_page, page, total_pgs),
            )

    except Exception as e:
        logger.error("Ошибка удаления профиля: %s", e)
        await safe_edit(callback.message, "❌ Ошибка при удалении.", reply_markup=kb_back_to_panel())


# ──────────────────────── Все пиры Amnezia ────────────────────────────

async def cb_admin_all_peers(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await safe_edit(callback.message, "⏳ Загружаю пиры из Amnezia API…")
    await callback.answer()

    clients = await amnezia.get_all_clients()
    all_profiles = await db.get_all_profiles()
    db_names = {p["vpn_name"] for p in all_profiles}

    if not clients:
        await safe_edit(
            callback.message,
            "❌ <b>Не удалось получить данные из Amnezia API</b>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel")],
            ]),
        )
        return

    orphan_lines = []
    total_api = 0
    for item in clients.get("items", []):
        uname = item.get("username", "—")
        for peer in item.get("peers", []):
            total_api += 1
            if uname not in db_names:
                pid = peer.get("id", "—")
                online = "🟢" if peer.get("online") else "🔴"
                t = peer.get("traffic", {})
                rx = fmt_bytes(float(t.get("received", 0) or 0))
                orphan_lines.append(
                    f"{online} <b>{html.escape(uname)}</b>\n"
                    f"   ID: <code>{html.escape(str(pid))}</code>  ⬇️{rx}"
                )

    body = "\n\n".join(orphan_lines[:20]) if orphan_lines else "✅ Осиротевших пиров нет."
    await safe_edit(
        callback.message,
        f"🔎 <b>Пиры Amnezia вне БД</b>\n\n"
        f"Всего пиров в API: <b>{total_api}</b>  "
        f"В БД: <b>{len(db_names)}</b>\n"
        f"Осиротевших: <b>{len(orphan_lines)}</b>\n\n"
        f"{body}",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data="admin_all_peers")],
            [InlineKeyboardButton(text="🔧 Панель",   callback_data="admin_panel")],
        ]),
    )


# ──────────────────────── Поиск ──────────────────────────────────────

async def cb_admin_search(callback: CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await state.set_state(SearchStates.waiting_for_query)
    await state.update_data(menu_msg_id=callback.message.message_id)
    await safe_edit(
        callback.message,
        "🔍 <b>Поиск пользователя</b>\n\n"
        "Введите имя профиля (частично) или Telegram ID:",
        reply_markup=kb_cancel(),
    )
    await callback.answer()


async def process_search_query(message: Message, state: FSMContext, db: Database):
    if not is_admin(message.from_user.id):
        await state.clear()
        return

    query = _sanitize(message.text or "", 200)
    chat_id = message.chat.id
    bot = message.bot

    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    menu_msg_id = data.get("menu_msg_id")

    async def edit_menu(text: str, kb=None):
        kb = kb or kb_cancel()
        if menu_msg_id:
            try:
                await bot.edit_message_text(
                    text, chat_id=chat_id, message_id=menu_msg_id,
                    reply_markup=kb, parse_mode=ParseMode.HTML,
                )
                return
            except Exception:
                pass
        sent = await bot.send_message(chat_id, text, reply_markup=kb, parse_mode=ParseMode.HTML)
        await state.update_data(menu_msg_id=sent.message_id)

    if not query:
        await edit_menu("⚠️ Введите запрос:")
        return

    results = await db.search_users(query)
    await state.clear()

    if not results:
        await edit_menu(
            f"🔍 По запросу «<b>{html.escape(query)}</b>» ничего не найдено.",
            kb=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="◀️ К списку", callback_data="admin_list:0")],
                [InlineKeyboardButton(text="🔧 Панель",   callback_data="admin_panel")],
            ]),
        )
        return

    rows_text = []
    for u in results[:20]:
        banned_tag = "  🚫" if u.get("banned") else ""
        profile_names = ", ".join(p["vpn_name"] for p in u.get("profiles", [])) or "—"
        rows_text.append(
            f"• {user_link(u['telegram_id'])}{banned_tag}\n"
            f"  Профили: <b>{html.escape(profile_names)}</b>\n"
            f"  C: {u.get('created_at', '—')}"
        )

    action_rows = [
        [InlineKeyboardButton(
            text=f"👁 ID {u['telegram_id']}",
            callback_data=f"admin_user_card:{u['telegram_id']}:0",
        )]
        for u in results[:5]
    ]
    action_rows.append([
        InlineKeyboardButton(text="◀️ К списку", callback_data="admin_list:0"),
        InlineKeyboardButton(text="🔧 Панель",   callback_data="admin_panel"),
    ])

    await edit_menu(
        f"🔍 <b>Найдено: {len(results)}</b> по запросу «{html.escape(query)}»\n\n"
        + "\n\n".join(rows_text),
        kb=InlineKeyboardMarkup(inline_keyboard=action_rows),
    )


# ──────────────────────── Бан / разбан ───────────────────────────────

async def cb_admin_ban_toggle(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    # admin_ban_toggle:{tg_id}:{page}
    if len(parts) < 3:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    tg_id = _safe_int(parts[1], -1)
    page = _safe_int(parts[2], 0)

    if tg_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    currently_banned = await db.get_user_banned(tg_id)
    new_status_amnezia = "active" if currently_banned else "disabled"
    action_text = "разбанен ✅" if currently_banned else "заблокирован 🚫"

    # Обновляем все профили в Amnezia
    profiles = await db.get_profiles(tg_id)
    api_ok = True
    for p in profiles:
        peer_id = p.get("peer_id")
        if peer_id:
            ok = await amnezia.update_user(peer_id, status=new_status_amnezia)
            if not ok:
                api_ok = False

    await db.set_user_banned(tg_id, not currently_banned)

    try:
        notify_text = (
            "✅ Ваш аккаунт <b>восстановлен</b>. VPN снова доступен."
            if currently_banned
            else "🚫 Ваш аккаунт <b>заблокирован</b> администратором."
        )
        await callback.bot.send_message(tg_id, notify_text, parse_mode=ParseMode.HTML)
    except Exception:
        pass

    api_note = "" if api_ok else " <i>(только в БД)</i>"
    await callback.answer(f"ID {tg_id}: {action_text}{api_note}")

    users = await db.get_all_users_with_profiles()
    users_page, total_pgs = paginate_users(users, page)
    global_offset = page * PAGE_SIZE

    await safe_edit(
        callback.message,
        build_users_page_text(users_page, page, total_pgs, len(users), global_offset),
        reply_markup=kb_admin_list(users_page, page, total_pgs),
    )


# ──────────────────────── Подменю блокировок ─────────────────────────

async def cb_admin_ban_menu(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return
    await safe_edit(
        callback.message,
        "🔒 <b>Блокировки</b>\n\n"
        "• <b>Заблокировать всех</b> — отключит VPN у всех активных пользователей.\n"
        "• <b>Разблокировать всех</b> — восстановит доступ всем.",
        reply_markup=kb_admin_ban_menu(),
    )
    await callback.answer()


async def cb_admin_ban_all_confirm(callback: CallbackQuery):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await safe_edit(
        callback.message,
        "⚠️ <b>Массовый бан</b>\n\n"
        "Вы собираетесь заблокировать <b>всех</b> пользователей.\n"
        "Это действие обратимо через «Разбан всех».",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🚫 Заблокировать всех", callback_data="admin_ban_all_do")],
            [InlineKeyboardButton(text="❌ Отмена", callback_data="admin_panel")],
        ]),
    )
    await callback.answer()


async def cb_admin_ban_all_do(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await safe_edit(callback.message, "⏳ Блокирую всех пользователей…")
    await callback.answer()

    users = await db.get_all_users_with_profiles()
    ok = fail = 0
    for u in users:
        if u.get("banned"):
            continue
        try:
            await db.set_user_banned(u["telegram_id"], True)
            for p in u.get("profiles", []):
                peer_id = p.get("peer_id")
                if peer_id:
                    await amnezia.update_user(peer_id, status="disabled")
            ok += 1
        except Exception:
            fail += 1

    await safe_edit(
        callback.message,
        f"✅ Заблокировано: <b>{ok}</b>  Ошибок: <b>{fail}</b>",
        reply_markup=kb_back_to_panel(),
    )


async def cb_admin_unban_all_do(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await safe_edit(callback.message, "⏳ Разблокирую всех пользователей…")
    await callback.answer()

    users = await db.get_all_users_with_profiles()
    ok = fail = 0
    for u in users:
        if not u.get("banned"):
            continue
        try:
            await db.set_user_banned(u["telegram_id"], False)
            for p in u.get("profiles", []):
                if not p.get("disabled"):
                    peer_id = p.get("peer_id")
                    if peer_id:
                        await amnezia.update_user(peer_id, status="active")
            ok += 1
        except Exception:
            fail += 1

    await safe_edit(
        callback.message,
        f"✅ Разблокировано: <b>{ok}</b>  Ошибок: <b>{fail}</b>",
        reply_markup=kb_back_to_panel(),
    )


# ──────────────────────── Личное сообщение пользователю ──────────────

async def cb_admin_msg_user(callback: CallbackQuery, state: FSMContext, db: Database):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    # admin_msg_user:{tg_id}:{page}
    if len(parts) < 3:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return
    tg_id = _safe_int(parts[1], -1)
    page = _safe_int(parts[2], 0)

    if tg_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    user_data = await db.get_user(tg_id)
    if not user_data:
        await callback.answer("❌ Пользователь не найден.", show_alert=True)
        return

    await state.set_state(MessageUserStates.waiting_for_text)
    await state.update_data(
        menu_msg_id=callback.message.message_id,
        target_tg_id=tg_id,
        return_page=page,
    )
    await safe_edit(
        callback.message,
        f"✉️ <b>Сообщение пользователю</b>\n\n"
        f"TG ID: {user_link(tg_id)}\n\n"
        f"Введите текст сообщения:",
        reply_markup=kb_cancel(),
    )
    await callback.answer()


async def process_msg_user_text(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        await state.clear()
        return

    text = _sanitize(message.text or "", MAX_BROADCAST_LEN)
    chat_id = message.chat.id
    bot = message.bot

    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    menu_msg_id = data.get("menu_msg_id")
    tg_id = data.get("target_tg_id")
    page = data.get("return_page", 0)

    if not text:
        if menu_msg_id:
            try:
                await bot.edit_message_text(
                    "⚠️ Пустое сообщение. Введите текст:",
                    chat_id=chat_id, message_id=menu_msg_id,
                    reply_markup=kb_cancel(), parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
        return

    await state.clear()

    try:
        await bot.send_message(tg_id, text, parse_mode=ParseMode.HTML)
        result_text = f"✅ Сообщение отправлено пользователю {user_link(tg_id)}."
    except Exception as e:
        logger.error("Ошибка отправки сообщения %d: %s", tg_id, e)
        result_text = f"❌ Не удалось отправить сообщение {user_link(tg_id)}."

    if menu_msg_id:
        try:
            await bot.edit_message_text(
                result_text,
                chat_id=chat_id, message_id=menu_msg_id,
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(
                        text="◀️ К карточке",
                        callback_data=f"admin_user_card:{tg_id}:{page}",
                    )],
                    [InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel")],
                ]),
                parse_mode=ParseMode.HTML,
            )
            return
        except Exception:
            pass

    await bot.send_message(chat_id, result_text, parse_mode=ParseMode.HTML)


# ──────────────────────── Рассылка ───────────────────────────────────

async def cb_admin_broadcast(callback: CallbackQuery, state: FSMContext, db: Database):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    tg_ids = await db.get_all_telegram_ids()
    await state.set_state(BroadcastStates.waiting_for_text)
    await state.update_data(menu_msg_id=callback.message.message_id)
    await safe_edit(
        callback.message,
        f"📢 <b>Рассылка</b>\n\n"
        f"Сообщение получат <b>{len(tg_ids)}</b> пользователей.\n\n"
        f"Введите текст рассылки (поддерживается HTML-разметка):",
        reply_markup=kb_cancel(),
    )
    await callback.answer()


async def process_broadcast_text(message: Message, state: FSMContext, db: Database):
    if not is_admin(message.from_user.id):
        await state.clear()
        return

    text = _sanitize(message.text or "", MAX_BROADCAST_LEN)
    chat_id = message.chat.id
    bot = message.bot

    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    mid = data.get("menu_msg_id")

    if not text:
        if mid:
            try:
                await bot.edit_message_text(
                    "⚠️ Пустое сообщение. Введите текст рассылки:",
                    chat_id=chat_id, message_id=mid,
                    reply_markup=kb_cancel(), parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
        return

    await state.update_data(broadcast_text=text)
    preview = html.escape(text[:300]) + ("…" if len(text) > 300 else "")
    confirm_text = (
        f"📢 <b>Предпросмотр рассылки</b>\n\n"
        f"<blockquote>{preview}</blockquote>\n\n"
        f"Отправить всем пользователям?"
    )

    if mid:
        try:
            await bot.edit_message_text(
                confirm_text, chat_id=chat_id, message_id=mid,
                reply_markup=kb_broadcast_confirm(), parse_mode=ParseMode.HTML,
            )
            return
        except Exception:
            pass

    sent = await bot.send_message(
        chat_id, confirm_text,
        reply_markup=kb_broadcast_confirm(), parse_mode=ParseMode.HTML,
    )
    await state.update_data(menu_msg_id=sent.message_id)


async def cb_admin_broadcast_do(callback: CallbackQuery, state: FSMContext, db: Database):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    data = await state.get_data()
    text = data.get("broadcast_text", "")
    if not text:
        await callback.answer("❌ Текст не найден.", show_alert=True)
        return

    tg_ids = await db.get_all_telegram_ids()
    await safe_edit(callback.message, f"📤 Рассылаю {len(tg_ids)} пользователям…")
    await callback.answer()
    await state.clear()

    ok = fail = 0
    for tg_id in tg_ids:
        try:
            await callback.bot.send_message(tg_id, text, parse_mode=ParseMode.HTML)
            ok += 1
        except Exception:
            fail += 1
        await asyncio.sleep(0.05)

    user_data = await db.get_user(callback.from_user.id)
    admin = is_admin(callback.from_user.id)
    has_profiles = bool(user_data and user_data.get("profiles"))
    can_create = not user_data or await db.can_create_profile(callback.from_user.id)
    await safe_edit(
        callback.message,
        menu_text(user_data, f"✅ Рассылка завершена: отправлено {ok}, ошибок {fail}"),
        reply_markup=kb_main(has_profiles, can_create, admin),
    )
    await state.update_data(menu_msg_id=callback.message.message_id)


# ──────────────────────── Экспорт CSV ────────────────────────────────

async def cb_admin_export_csv(callback: CallbackQuery, state: FSMContext, db: Database):
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await callback.answer("⏳ Формирую CSV…")
    profiles = await db.get_all_profiles()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "profile_id", "telegram_id", "vpn_name",
        "peer_id", "last_ip", "disabled", "created_at"
    ])
    for p in profiles:
        writer.writerow([
            p.get("id", ""),
            p["telegram_id"],
            p["vpn_name"],
            p.get("peer_id", ""),
            p.get("last_ip", ""),
            "yes" if p.get("disabled") else "no",
            p.get("created_at", ""),
        ])

    fname = f"vpn_profiles_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    sent = await callback.message.answer_document(
        BufferedInputFile(buf.getvalue().encode("utf-8"), filename=fname),
        caption=f"📋 <b>Экспорт профилей</b> — {len(profiles)} записей",
        parse_mode=ParseMode.HTML,
    )
    await push_side_msg(state, sent.message_id)


# ──────────────────────── Управление секретными ключами ──────────────

async def _delete_user_profiles_from_amnezia(
    tg_id: int, db: Database, amnezia: AmneziaClient
) -> tuple[int, int]:
    """
    Удаляет все VPN-профили пользователя из Amnezia API и из БД.
    Возвращает (успешно_удалено, ошибок).
    """
    profiles = await db.get_profiles(tg_id)
    ok = fail = 0
    for p in profiles:
        peer_id = p.get("peer_id")
        try:
            if peer_id:
                await amnezia.delete_user(peer_id)
            await db.delete_profile(p["id"])
            ok += 1
        except Exception as e:
            logger.warning("Не удалось удалить профиль %s (tg=%d): %s", p["vpn_name"], tg_id, e)
            fail += 1
    return ok, fail


async def cb_admin_keys(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    """Список всех секретных ключей."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    await safe_edit(callback.message, "⏳ Загружаю ключи…")
    await callback.answer()

    keys = await db.get_all_secret_keys()

    if not keys:
        await safe_edit(
            callback.message,
            "🗝 <b>Секретные ключи</b>\n\nКлючей нет.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel")],
            ]),
        )
        return

    lines = []
    for k in keys[:30]:
        tg_id = k["telegram_id"]
        key_short = k["key_value"][:8] + "…"
        used = "✅ использован" if k.get("used") else "⏳ активен"
        revoked = " 🚫 отозван" if k.get("revoked") else ""
        created = k.get("created_at", "—")[:10]
        lines.append(
            f"• {user_link(tg_id)} — <code>{html.escape(key_short)}</code>"
            f"\n  {used}{revoked} · {created}"
        )

    kb_rows = []
    for k in keys[:15]:
        if not k.get("revoked"):
            tg_id = k["telegram_id"]
            kb_rows.append([
                InlineKeyboardButton(
                    text=f"🚫 Отозвать ключ {tg_id}",
                    callback_data=f"admin_key_revoke:{k['id']}:{tg_id}",
                ),
                InlineKeyboardButton(
                    text=f"{'✅ Разреш' if await db.get_user_key_blocked(tg_id) else '🔒 Запрет'} ключи",
                    callback_data=f"admin_key_block:{tg_id}",
                ),
            ])

    kb_rows.append([InlineKeyboardButton(text="🔧 Панель", callback_data="admin_panel")])

    await safe_edit(
        callback.message,
        f"🗝 <b>Секретные ключи</b> ({len(keys)} шт.)\n\n"
        + "\n\n".join(lines),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows),
    )


async def cb_admin_key_revoke(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    """Отзыв конкретного ключа + удаление всех VPN-профилей пользователя."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    if len(parts) < 3:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    key_id = _safe_int(parts[1], -1)
    tg_id = _safe_int(parts[2], -1)

    if key_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    ok = await db.revoke_secret_key(key_id)
    if ok:
        # Удаляем все VPN-профили пользователя из Amnezia и БД
        deleted_ok, deleted_fail = await _delete_user_profiles_from_amnezia(tg_id, db, amnezia)
        note = f" Профилей удалено: {deleted_ok}" + (f", ошибок: {deleted_fail}" if deleted_fail else "")
        await callback.answer(f"✅ Ключ пользователя {tg_id} отозван.{note}", show_alert=bool(deleted_ok or deleted_fail))
        try:
            await callback.bot.send_message(
                tg_id,
                "🔑 Ваш секретный ключ был <b>отозван</b> администратором.\n"
                "Все ваши VPN-профили были <b>удалены</b>.\n"
                "Создайте новый ключ через /mykey",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
    else:
        await callback.answer("❌ Ключ не найден.")

    # Перезагружаем список
    await cb_admin_keys(callback, db, amnezia)


async def cb_admin_key_block(callback: CallbackQuery, db: Database, amnezia: AmneziaClient):
    """Блокирует/разблокирует возможность создавать ключи для пользователя.
    При блокировке — удаляет все VPN-профили пользователя."""
    if not is_admin(callback.from_user.id):
        await callback.answer("⛔ Нет доступа.", show_alert=True)
        return

    parts = callback.data.split(":")
    if len(parts) < 2:
        await callback.answer("❌ Некорректные данные.", show_alert=True)
        return

    tg_id = _safe_int(parts[1], -1)
    if tg_id < 0:
        await callback.answer("❌ Некорректный ID.", show_alert=True)
        return

    currently_blocked = await db.get_user_key_blocked(tg_id)
    await db.set_user_can_create_key(tg_id, currently_blocked)  # инвертируем

    if not currently_blocked:
        # Блокируем — удаляем все профили
        deleted_ok, deleted_fail = await _delete_user_profiles_from_amnezia(tg_id, db, amnezia)
        note = f" Профилей удалено: {deleted_ok}" + (f", ошибок: {deleted_fail}" if deleted_fail else "")
        action = f"🔒 Создание ключей запрещено.{note}"
        try:
            await callback.bot.send_message(
                tg_id,
                "🔒 Создание секретных ключей для вашего аккаунта <b>заблокировано</b> администратором.\n"
                "Все ваши VPN-профили были <b>удалены</b>.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
    else:
        action = "✅ Создание ключей разрешено"
        try:
            await callback.bot.send_message(
                tg_id,
                "✅ Создание секретных ключей для вашего аккаунта <b>разрешено</b>.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

    await callback.answer(f"ID {tg_id}: {action}", show_alert=not currently_blocked)
    await cb_admin_keys(callback, db, amnezia)


# ──────────────────────── Регистрация ────────────────────────────────

def register_admin_handlers(dp: Dispatcher) -> None:
    # FSM
    dp.message.register(process_broadcast_text, BroadcastStates.waiting_for_text, F.text)
    dp.message.register(process_search_query,   SearchStates.waiting_for_query,    F.text)
    dp.message.register(process_msg_user_text,  MessageUserStates.waiting_for_text, F.text)

    # Callback-кнопки
    dp.callback_query.register(cb_admin_panel,             F.data == "admin_panel")
    dp.callback_query.register(cb_admin_list,              F.data.startswith("admin_list:"))
    dp.callback_query.register(cb_admin_user_card,         F.data.startswith("admin_user_card:"))
    dp.callback_query.register(cb_admin_stats,             F.data.startswith("admin_stats"))
    dp.callback_query.register(cb_admin_all_peers,         F.data == "admin_all_peers")
    dp.callback_query.register(cb_admin_search,            F.data == "admin_search")
    dp.callback_query.register(cb_admin_ban_toggle,        F.data.startswith("admin_ban_toggle:"))
    dp.callback_query.register(cb_admin_ban_menu,          F.data == "admin_ban_menu")
    dp.callback_query.register(cb_admin_ban_all_confirm,   F.data == "admin_ban_all")
    dp.callback_query.register(cb_admin_ban_all_do,        F.data == "admin_ban_all_do")
    dp.callback_query.register(cb_admin_unban_all_do,      F.data == "admin_unban_all")
    dp.callback_query.register(cb_admin_msg_user,          F.data.startswith("admin_msg_user:"))
    dp.callback_query.register(cb_admin_toggle_profile,    F.data.startswith("admin_toggle_profile:"))
    dp.callback_query.register(cb_admin_del_profile,       F.data.startswith("admin_del_profile:"))
    dp.callback_query.register(cb_admin_del_profile_do,    F.data.startswith("admin_del_profile_do:"))
    dp.callback_query.register(cb_admin_profile_stat,      F.data.startswith("admin_profile_stat:"))
    dp.callback_query.register(cb_admin_broadcast,         F.data == "admin_broadcast")
    dp.callback_query.register(cb_admin_broadcast_do,      F.data == "admin_broadcast_do")
    dp.callback_query.register(cb_admin_export_csv,        F.data == "admin_export_csv")
    dp.callback_query.register(cb_admin_keys,              F.data == "admin_keys")
    dp.callback_query.register(cb_admin_key_revoke,        F.data.startswith("admin_key_revoke:"))
    dp.callback_query.register(cb_admin_key_block,         F.data.startswith("admin_key_block:"))