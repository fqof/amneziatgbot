import aiosqlite
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

try:
    from config import settings as _settings
    MAX_PROFILES_PER_USER: int = _settings.MAX_PROFILES_PER_USER
except Exception:
    MAX_PROFILES_PER_USER: int = 3


class Database:
    def __init__(self, db_path: str, encryption_key: str):
        self.db_path = db_path
        self.fernet = Fernet(encryption_key.encode("utf-8"))
        self._conn: Optional[aiosqlite.Connection] = None

    def _encrypt(self, data: str | None) -> str | None:
        if not data:
            return data
        return self.fernet.encrypt(data.encode("utf-8")).decode("utf-8")

    def _decrypt(self, data: str | None) -> str | None:
        if not data:
            return data
        try:
            return self.fernet.decrypt(data.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return data

    async def _column_exists(self, table: str, column: str) -> bool:
        async with self._conn.execute(f"PRAGMA table_info({table})") as cur:
            rows = await cur.fetchall()
            return any(row[1] == column for row in rows)

    async def _table_exists(self, table: str) -> bool:
        async with self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ) as cur:
            return await cur.fetchone() is not None

    async def _add_column_if_missing(self, table: str, column: str, definition: str) -> bool:
        if not await self._column_exists(table, column):
            try:
                await self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                )
                await self._conn.commit()
                logger.info("Добавлена колонка %s.%s", table, column)
                return True
            except Exception as e:
                logger.warning("Не удалось добавить колонку %s.%s: %s", table, column, e)
        return False

    async def init(self):
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row

        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA synchronous=NORMAL;")
        await self._conn.execute("PRAGMA foreign_keys=ON;")

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                telegram_id INTEGER PRIMARY KEY,
                banned      INTEGER NOT NULL DEFAULT 0,
                key_blocked INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS vpn_profiles (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id  INTEGER NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
                vpn_name     TEXT    NOT NULL UNIQUE,
                peer_id      TEXT,
                raw_response TEXT,
                last_ip      TEXT,
                disabled     INTEGER NOT NULL DEFAULT 0,
                via_key      INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_profiles_tgid ON vpn_profiles(telegram_id)")

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS secret_keys (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id  INTEGER NOT NULL REFERENCES users(telegram_id) ON DELETE CASCADE,
                key_value    TEXT    NOT NULL UNIQUE,
                used         INTEGER NOT NULL DEFAULT 0,
                revoked      INTEGER NOT NULL DEFAULT 0,
                can_create   INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT DEFAULT (datetime('now', 'localtime')),
                used_at      TEXT
            )
        """)
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_secret_keys_tgid ON secret_keys(telegram_id)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_secret_keys_value ON secret_keys(key_value)")

        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS short_links (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id  INTEGER NOT NULL REFERENCES vpn_profiles(id) ON DELETE CASCADE,
                slug        TEXT    NOT NULL UNIQUE,
                created_at  TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_short_links_slug ON short_links(slug)")
        await self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_short_links_profile ON short_links(profile_id)")

        await self._conn.commit()

        await self._auto_migrate_schema()
        await self._migrate_from_old_schema()
        await self._encrypt_plain_data()

        logger.info("Database initialized: %s", self.db_path)

    async def _auto_migrate_schema(self):
        await self._add_column_if_missing("users", "key_blocked", "INTEGER NOT NULL DEFAULT 0")
        await self._add_column_if_missing("vpn_profiles", "disabled", "INTEGER NOT NULL DEFAULT 0")
        await self._add_column_if_missing("vpn_profiles", "last_ip", "TEXT")
        await self._add_column_if_missing("vpn_profiles", "raw_response", "TEXT")
        await self._add_column_if_missing("vpn_profiles", "via_key", "INTEGER NOT NULL DEFAULT 0")

        if await self._table_exists("secret_keys"):
            await self._add_column_if_missing("secret_keys", "used_at", "TEXT")
            await self._add_column_if_missing("secret_keys", "revoked", "INTEGER NOT NULL DEFAULT 0")
            await self._add_column_if_missing("secret_keys", "can_create", "INTEGER NOT NULL DEFAULT 1")

    async def _migrate_from_old_schema(self):
        if not await self._table_exists("vpn_users"):
            return

        logger.info("Обнаружена старая таблица vpn_users, выполняю миграцию…")
        async with self._conn.execute("SELECT * FROM vpn_users") as cur:
            rows = await cur.fetchall()

        migrated = 0
        col_names = [d[0] for d in cur.description] if rows else []

        for row in rows:
            row_dict = dict(zip(col_names, row)) if col_names else dict(row)
            tg_id = row_dict.get("telegram_id")
            vpn_name = row_dict.get("vpn_name")
            peer_id = row_dict.get("peer_id")
            raw_resp = row_dict.get("raw_response")
            banned = row_dict.get("banned", 0)
            last_ip_val = row_dict.get("last_ip")
            created_at = row_dict.get("created_at")

            try:
                await self._conn.execute(
                    "INSERT OR IGNORE INTO users (telegram_id, banned, created_at) VALUES (?, ?, ?)",
                    (tg_id, banned, created_at),
                )
                enc_peer = peer_id if (peer_id and peer_id.startswith("gAAAAA")) else self._encrypt(peer_id)
                enc_raw = raw_resp if (raw_resp and raw_resp.startswith("gAAAAA")) else self._encrypt(raw_resp)
                enc_ip = last_ip_val if (last_ip_val and last_ip_val.startswith("gAAAAA")) else self._encrypt(last_ip_val)

                await self._conn.execute(
                    """INSERT OR IGNORE INTO vpn_profiles
                       (telegram_id, vpn_name, peer_id, raw_response, last_ip, created_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (tg_id, vpn_name, enc_peer, enc_raw, enc_ip, created_at),
                )
                migrated += 1
            except Exception as e:
                logger.warning("Миграция строки tg=%s: %s", tg_id, e)

        await self._conn.commit()
        await self._conn.execute("ALTER TABLE vpn_users RENAME TO vpn_users_migrated")
        await self._conn.commit()
        logger.info("Миграция завершена: перенесено %d записей.", migrated)

    async def _encrypt_plain_data(self):
        async with self._conn.execute(
            "SELECT id, peer_id, raw_response, last_ip FROM vpn_profiles"
        ) as cur:
            rows = await cur.fetchall()

        for row in rows:
            pid = row["peer_id"]
            raw = row["raw_response"]
            lip = row["last_ip"]
            needs_update = False
            if pid and not pid.startswith("gAAAAA"):
                pid = self._encrypt(pid)
                needs_update = True
            if raw and not raw.startswith("gAAAAA"):
                raw = self._encrypt(raw)
                needs_update = True
            if lip and not lip.startswith("gAAAAA"):
                lip = self._encrypt(lip)
                needs_update = True
            if needs_update:
                await self._conn.execute(
                    "UPDATE vpn_profiles SET peer_id=?, raw_response=?, last_ip=? WHERE id=?",
                    (pid, raw, lip, row["id"]),
                )
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()
            logger.info("Database connection closed.")

    def _profile_row_to_dict(self, row: aiosqlite.Row) -> dict:
        d = dict(row)
        d["peer_id"] = self._decrypt(d.get("peer_id"))
        d["raw_response"] = self._decrypt(d.get("raw_response"))
        d["last_ip"] = self._decrypt(d.get("last_ip"))
        d["disabled"] = bool(d.get("disabled", 0))
        d["via_key"] = bool(d.get("via_key", 0))
        return d

    async def ensure_user(self, telegram_id: int) -> None:
        await self._conn.execute("INSERT OR IGNORE INTO users (telegram_id) VALUES (?)", (telegram_id,))
        await self._conn.commit()

    async def get_user_banned(self, telegram_id: int) -> bool:
        async with self._conn.execute("SELECT banned FROM users WHERE telegram_id=?", (telegram_id,)) as cur:
            row = await cur.fetchone()
            return bool(row["banned"]) if row else False

    async def set_user_banned(self, telegram_id: int, banned: bool) -> None:
        await self._conn.execute("UPDATE users SET banned=? WHERE telegram_id=?", (1 if banned else 0, telegram_id))
        await self._conn.commit()

    async def get_all_telegram_ids(self) -> list[int]:
        async with self._conn.execute("SELECT telegram_id FROM users") as cur:
            return [r[0] for r in await cur.fetchall()]

    async def get_profiles(self, telegram_id: int) -> list[dict]:
        async with self._conn.execute("SELECT * FROM vpn_profiles WHERE telegram_id=? ORDER BY created_at", (telegram_id,)) as cur:
            return [self._profile_row_to_dict(r) for r in await cur.fetchall()]

    async def get_profile_by_id(self, profile_id: int) -> Optional[dict]:
        async with self._conn.execute("SELECT * FROM vpn_profiles WHERE id=?", (profile_id,)) as cur:
            row = await cur.fetchone()
            return self._profile_row_to_dict(row) if row else None

    async def get_profile_by_name(self, vpn_name: str) -> Optional[dict]:
        async with self._conn.execute("SELECT * FROM vpn_profiles WHERE vpn_name=?", (vpn_name,)) as cur:
            row = await cur.fetchone()
            return self._profile_row_to_dict(row) if row else None

    async def count_profiles(self, telegram_id: int) -> int:
        async with self._conn.execute(
            "SELECT COUNT(*) FROM vpn_profiles WHERE telegram_id=? AND via_key=0", (telegram_id,)
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def count_key_profiles(self, telegram_id: int) -> int:
        async with self._conn.execute(
            "SELECT COUNT(*) FROM vpn_profiles WHERE telegram_id=? AND via_key=1", (telegram_id,)
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

    async def can_create_profile(self, telegram_id: int, max_profiles: int) -> bool:
        return await self.count_profiles(telegram_id) < max_profiles

    async def can_create_key_profile(self, telegram_id: int, max_key_profiles: int) -> bool:
        return await self.count_key_profiles(telegram_id) < max_key_profiles

    async def is_vpn_name_taken(self, vpn_name: str) -> bool:
        async with self._conn.execute("SELECT 1 FROM vpn_profiles WHERE vpn_name=?", (vpn_name,)) as cur:
            return await cur.fetchone() is not None

    async def add_profile(self, telegram_id: int, vpn_name: str, peer_id: Optional[str], raw_response: str, via_key: bool = False) -> int:
        await self.ensure_user(telegram_id)
        cur = await self._conn.execute(
            """INSERT INTO vpn_profiles (telegram_id, vpn_name, peer_id, raw_response, via_key) VALUES (?, ?, ?, ?, ?)""",
            (telegram_id, vpn_name, self._encrypt(peer_id), self._encrypt(raw_response), 1 if via_key else 0),
        )
        await self._conn.commit()
        logger.info("Added profile: tg=%d name=%s id=%d via_key=%s", telegram_id, vpn_name, cur.lastrowid, via_key)
        return cur.lastrowid

    async def delete_profile(self, profile_id: int) -> bool:
        cur = await self._conn.execute("DELETE FROM vpn_profiles WHERE id=?", (profile_id,))
        await self._conn.commit()
        return cur.rowcount > 0

    async def delete_profile_by_name(self, vpn_name: str) -> bool:
        cur = await self._conn.execute("DELETE FROM vpn_profiles WHERE vpn_name=?", (vpn_name,))
        await self._conn.commit()
        return cur.rowcount > 0

    async def delete_all_profiles(self, telegram_id: int) -> int:
        cur = await self._conn.execute("DELETE FROM vpn_profiles WHERE telegram_id=?", (telegram_id,))
        await self._conn.commit()
        return cur.rowcount

    async def set_profile_disabled(self, profile_id: int, disabled: bool) -> None:
        await self._conn.execute("UPDATE vpn_profiles SET disabled=? WHERE id=?", (1 if disabled else 0, profile_id))
        await self._conn.commit()

    async def set_last_ip(self, profile_id: int, ip: str) -> None:
        await self._conn.execute("UPDATE vpn_profiles SET last_ip=? WHERE id=?", (self._encrypt(ip), profile_id))
        await self._conn.commit()

    async def get_all_users_with_profiles(self) -> list[dict]:
        async with self._conn.execute("SELECT * FROM users ORDER BY created_at DESC") as cur:
            user_rows = await cur.fetchall()
        result = []
        for u in user_rows:
            profiles = await self.get_profiles(u["telegram_id"])
            result.append({
                "telegram_id": u["telegram_id"],
                "banned": bool(u["banned"]),
                "created_at": u["created_at"],
                "profiles": profiles,
            })
        return result

    async def get_all_profiles(self) -> list[dict]:
        async with self._conn.execute("SELECT * FROM vpn_profiles ORDER BY created_at DESC") as cur:
            return [self._profile_row_to_dict(r) for r in await cur.fetchall()]

    async def search_users(self, query: str) -> list[dict]:
        q = f"%{query.lower()}%"
        async with self._conn.execute(
            """SELECT DISTINCT u.telegram_id, u.banned, u.created_at
               FROM users u
               LEFT JOIN vpn_profiles p ON p.telegram_id = u.telegram_id
               WHERE LOWER(p.vpn_name) LIKE ? OR CAST(u.telegram_id AS TEXT) = ?
               ORDER BY u.created_at DESC""",
            (q, query),
        ) as cur:
            user_rows = await cur.fetchall()

        result = []
        for u in user_rows:
            profiles = await self.get_profiles(u["telegram_id"])
            result.append({
                "telegram_id": u["telegram_id"],
                "banned": bool(u["banned"]),
                "created_at": u["created_at"],
                "profiles": profiles,
            })
        return result

    async def get_user(self, telegram_id: int) -> Optional[dict]:
        async with self._conn.execute("SELECT * FROM users WHERE telegram_id=?", (telegram_id,)) as cur:
            row = await cur.fetchone()
        if not row: return None
        profiles = await self.get_profiles(telegram_id)
        return {
            "telegram_id": telegram_id,
            "banned": bool(row["banned"]),
            "created_at": row["created_at"],
            "profiles": profiles,
        }

    async def create_secret_key(self, telegram_id: int, key_value: str) -> int:
        await self.ensure_user(telegram_id)
        await self._conn.execute("DELETE FROM secret_keys WHERE telegram_id=?", (telegram_id,))
        cur = await self._conn.execute(
            "INSERT INTO secret_keys (telegram_id, key_value) VALUES (?, ?)",
            (telegram_id, key_value),
        )
        await self._conn.commit()
        return cur.lastrowid

    async def get_secret_key_by_value(self, key_value: str) -> Optional[dict]:
        async with self._conn.execute("SELECT * FROM secret_keys WHERE key_value=?", (key_value,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_secret_key_by_user(self, telegram_id: int) -> Optional[dict]:
        async with self._conn.execute("SELECT * FROM secret_keys WHERE telegram_id=?", (telegram_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def revoke_secret_key(self, key_id: int) -> bool:
        cur = await self._conn.execute("UPDATE secret_keys SET revoked=1 WHERE id=?", (key_id,))
        await self._conn.commit()
        return cur.rowcount > 0

    async def revoke_secret_key_by_user(self, telegram_id: int) -> bool:
        cur = await self._conn.execute("DELETE FROM secret_keys WHERE telegram_id=?", (telegram_id,))
        await self._conn.commit()
        return cur.rowcount > 0

    async def set_key_used(self, key_id: int) -> None:
        await self._conn.execute(
            "UPDATE secret_keys SET used=1, used_at=datetime('now','localtime') WHERE id=?",
            (key_id,),
        )
        await self._conn.commit()

    async def get_all_secret_keys(self) -> list[dict]:
        async with self._conn.execute("SELECT * FROM secret_keys ORDER BY created_at DESC") as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def set_user_can_create_key(self, telegram_id: int, allowed: bool) -> None:
        await self.ensure_user(telegram_id)
        await self._conn.execute(
            "UPDATE users SET key_blocked=? WHERE telegram_id=?",
            (0 if allowed else 1, telegram_id),
        )
        await self._conn.commit()

    async def get_user_key_blocked(self, telegram_id: int) -> bool:
        async with self._conn.execute("SELECT key_blocked FROM users WHERE telegram_id=?", (telegram_id,)) as cur:
            row = await cur.fetchone()
            if not row: return False
            keys = row.keys() if hasattr(row, "keys") else []
            return bool(row["key_blocked"]) if "key_blocked" in keys else False

    async def _cleanup_expired_short_links(self):
        try:
            await self._conn.execute(
                "DELETE FROM short_links WHERE datetime(created_at) <= datetime('now', 'localtime', '-1 day')"
            )
            await self._conn.commit()
        except Exception as e:
            logger.error("Error cleaning up short links: %s", e)

    async def get_or_create_short_link(self, profile_id: int, slug: str) -> str:
        await self._cleanup_expired_short_links()
        async with self._conn.execute(
            "SELECT slug FROM short_links WHERE profile_id=?", (profile_id,)
        ) as cur:
            row = await cur.fetchone()
            if row: return row["slug"]
        await self._conn.execute(
            "INSERT OR IGNORE INTO short_links (profile_id, slug) VALUES (?, ?)",
            (profile_id, slug),
        )
        await self._conn.commit()
        return slug

    async def get_short_link_by_slug(self, slug: str) -> Optional[dict]:
        await self._cleanup_expired_short_links()
        async with self._conn.execute("SELECT * FROM short_links WHERE slug=?", (slug,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_short_link_by_profile(self, profile_id: int) -> Optional[str]:
        await self._cleanup_expired_short_links()
        async with self._conn.execute("SELECT slug FROM short_links WHERE profile_id=?", (profile_id,)) as cur:
            row = await cur.fetchone()
            return row["slug"] if row else None
