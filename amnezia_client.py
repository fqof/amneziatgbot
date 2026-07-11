"""
Асинхронный клиент для Amnezia Admin API.

Подтверждённые эндпоинты:
  GET    /clients     → {total, items:[{username, peers:[{id,name,status,...}]}]}
  POST   /clients     → {message, client:{id, config, protocol}}
  PATCH  /clients     → обновить (clientId, status, ...)
  DELETE /clients     → удалить  (clientId, protocol)
  GET    /server      → инфо о сервере
  GET    /server/load → нагрузка (cpu, ram, disk)
  GET    /healthz     → healthcheck
"""

import logging
import asyncio
from typing import Optional, Any
import aiohttp

from config import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
MAX_RETRIES = 3
RETRY_DELAY = 2.0


class AmneziaClient:
    def __init__(self, base_url: str, api_key: str, protocol: str = "amneziawg2"):
        self.base_url = base_url.rstrip("/")
        self.api_key  = api_key
        self.protocol = protocol
        self._session: Optional[aiohttp.ClientSession] = None

    def _get_headers(self) -> dict:
        return {
            "x-api-key":    self.api_key,
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=getattr(settings, "AMNEZIA_VERIFY_SSL", True))
            self._session = aiohttp.ClientSession(
                headers=self._get_headers(),
                timeout=REQUEST_TIMEOUT,
                connector=connector,
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _request(self, method: str, path: str, **kwargs) -> Optional[Any]:
        url     = f"{self.base_url}{path}"
        session = await self._get_session()

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status in (200, 201):
                        ct = resp.headers.get("Content-Type", "")
                        return await resp.json() if "application/json" in ct else await resp.read()
                    text = await resp.text()
                    logger.warning("API %s %s → %d: %s (попытка %d/%d)",
                                   method, path, resp.status, text[:300], attempt, MAX_RETRIES)
                    if resp.status < 500:
                        return None
            except aiohttp.ClientConnectorError as e:
                logger.error("Не удалось подключиться: %s (попытка %d/%d)", e, attempt, MAX_RETRIES)
            except asyncio.TimeoutError:
                logger.error("Таймаут (попытка %d/%d)", attempt, MAX_RETRIES)
            except Exception as e:
                logger.error("Ошибка API: %s (попытка %d/%d)", e, attempt, MAX_RETRIES)

            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY)
        return None

    async def get_all_clients(self) -> Optional[dict]:
        """GET /clients → {total, items:[{username, peers:[...]}]}"""
        return await self._request("GET", "/clients")

    async def create_user(self, client_name: str) -> Optional[dict]:
        """POST /clients → {message, client:{id, config, protocol}}"""
        payload = {"clientName": client_name, "protocol": self.protocol}
        logger.info("Создаю клиента: %s (%s)", client_name, self.protocol)
        result = await self._request("POST", "/clients", json=payload)
        logger.info("Ответ POST /clients для %s: %s", client_name, result)
        return result

    async def update_user(self, client_id: str, **kwargs) -> bool:
        """PATCH /clients — обновить статус, срок и т.д."""
        payload = {"clientId": client_id, **kwargs}
        result  = await self._request("PATCH", "/clients", json=payload)
        return result is not None

    async def delete_user(self, client_id: str) -> bool:
        """DELETE /clients — удалить пира по clientId (PublicKey)."""
        payload = {"clientId": client_id, "protocol": self.protocol}
        result  = await self._request("DELETE", "/clients", json=payload)
        return result is not None

    async def get_client_config(self, username_or_id: str) -> Optional[str]:
        """
        Пытается получить строку vpn://... для пользователя.
        Сначала ищем в GET /clients (поле config внутри peer), затем
        пробуем прямой путь /clients/{id}/config если API его поддержит.
        """
        clients = await self.get_all_clients()
        if clients:
            for item in clients.get("items", []):
                if item.get("username") == username_or_id:
                    for peer in item.get("peers", []):
                        if peer.get("config"):
                            return peer["config"]

        # Fallback: прямой URL (может не существовать)
        session = await self._get_session()
        for path in (f"/clients/{username_or_id}/config", f"/clients/{username_or_id}"):
            try:
                async with session.get(f"{self.base_url}{path}") as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "")
                        if "application/json" in ct:
                            data = await resp.json()
                            return data.get("config") or data.get("client", {}).get("config")
                        return (await resp.read()).decode("utf-8", errors="replace")
            except Exception as e:
                logger.debug("Fallback %s: %s", path, e)

        return None

    async def get_server_info(self) -> Optional[dict]:
        """GET /server → инфо о сервере."""
        return await self._request("GET", "/server")

    async def get_server_load(self) -> Optional[dict]:
        """GET /server/load → нагрузка (cpu, ram, disk)."""
        return await self._request("GET", "/server/load")

    async def health_check(self) -> bool:
        """GET /healthz."""
        result = await self._request("GET", "/healthz")
        return result is not None