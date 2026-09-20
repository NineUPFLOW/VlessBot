"""Сбор VLESS-ссылок из Telegram-каналов через Telethon userbot."""
from __future__ import annotations

import asyncio
import logging
import os
import re
from urllib.parse import parse_qs, unquote, urlparse

from telethon import TelegramClient
from telethon.errors import FloodWaitError
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.types import (
    MessageEntityCode,
    MessageEntityPre,
    MessageMediaWebPage,
)

log = logging.getLogger(__name__)

# ~22 источника (без @)
TELEGRAM_SOURCES: list[str] = [
    "RaViraNet",
    "vless_configs",
    "free_vless",
    "vless_list",
    "vlessfree",
    "v2ray_configs_pool",
    "proxy_mtp_ru",
    "vless_v2ray_iran",
    "configs_vless",
    "vless_iran_free",
    "v2rayng_config",
    "vless_shadow",
    "free_v2ray_configs",
    "proxy_vless_free",
    "vless_iran_plus",
    "vless_keys",
    "configs_free_vless",
    "vless_tunnel",
    "vless_shop_free",
    "free_configs_vless",
    "v2ray_vless_free",
    "vless_public_free",
]

RE_VLESS = re.compile(r"vless://[^\s<>\"'\)\]]+")
RE_MARKDOWN = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
RE_HTML_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def _parse_vless(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    try:
        parsed = urlparse(line)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port
        if not uuid or not host or not port:
            return None
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        name = unquote(parsed.fragment) if parsed.fragment else ""
        security = (params.get("security") or "").lower()
        if security not in ("reality", "tls"):
            return None
        return {
            "protocol": "VLESS",
            "uuid": uuid,
            "ip": host,
            "port": int(port),
            "params": params,
            "security": security,
            "sni": params.get("sni") or params.get("host"),
            "pbk": params.get("pbk"),
            "fp": params.get("fp"),
            "flow": params.get("flow"),
            "type": params.get("type", "tcp"),
            "raw": line,
            "name": name,
        }
    except Exception as e:  # noqa: BLE001
        log.debug("vless parse error: %s (%s)", e, line[:80])
        return None


def _extract_vless_from_text(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for _text, url in RE_MARKDOWN.findall(text):
        if url.startswith("vless://"):
            found.append(url)
    for url in RE_HTML_HREF.findall(text):
        if url.startswith("vless://"):
            found.append(url)
    found.extend(RE_VLESS.findall(text))
    return found


def _extract_from_message(msg) -> list[str]:
    found: list[str] = []
    text = getattr(msg, "message", None) or ""
    if text:
        found.extend(_extract_vless_from_text(text))

        entities = getattr(msg, "entities", None) or []
        for ent in entities:
            if isinstance(ent, (MessageEntityCode, MessageEntityPre)):
                snippet = text[ent.offset : ent.offset + ent.length]
                found.extend(_extract_vless_from_text(snippet))

    reply_markup = getattr(msg, "reply_markup", None)
    if reply_markup is not None:
        try:
            for row in reply_markup.rows:
                for button in row.buttons:
                    url = getattr(button, "url", None)
                    if url and url.startswith("vless://"):
                        found.append(url)
        except Exception:  # noqa: BLE001
            pass

    media = getattr(msg, "media", None)
    if isinstance(media, MessageMediaWebPage):
        wp = getattr(media, "webpage", None)
        if wp is not None:
            wp_url = getattr(wp, "url", None)
            if wp_url and wp_url.startswith("vless://"):
                found.append(wp_url)

    return found


async def _fetch_from_source(client: TelegramClient, source: str) -> list[dict]:
    results: list[dict] = []
    try:
        try:
            await client(JoinChannelRequest(source))
        except Exception:  # noqa: BLE001
            pass  # уже подписаны / приватный / и т.п.

        entity = await client.get_entity(source)

        message_count = 0
        thread_ids: set[int] = set()

        async for msg in client.iter_messages(entity, limit=200):
            message_count += 1
            reply_to = getattr(msg, "reply_to", None)
            top_id = getattr(reply_to, "reply_to_top_id", None) if reply_to else None
            if top_id:
                thread_ids.add(top_id)
            for raw in _extract_from_message(msg):
                parsed = _parse_vless(raw)
                if parsed:
                    parsed["source"] = source
                    results.append(parsed)

        for tid in list(thread_ids)[:5]:
            try:
                async for msg in client.iter_messages(
                    entity, limit=50, reply_to=tid
                ):
                    for raw in _extract_from_message(msg):
                        parsed = _parse_vless(raw)
                        if parsed:
                            parsed["source"] = source
                            results.append(parsed)
            except Exception as e:  # noqa: BLE001
                log.debug("thread read error @%s/%s: %s", source, tid, e)

        log.info(
            "Telegram @%s: %d сообщений, %d тем → %d VLESS",
            source,
            message_count,
            len(thread_ids),
            len(results),
        )
    except FloodWaitError as e:
        wait = min(e.seconds, 60)
        log.warning("FloodWait @%s: %ds", source, e.seconds)
        await asyncio.sleep(wait)
    except Exception as e:  # noqa: BLE001
        log.warning("Source @%s failed: %s", source, e)

    return results


async def fetch_all_vless() -> list[dict]:
    api_id_raw = os.environ.get("API_ID", "").strip()
    api_hash = os.environ.get("API_HASH", "").strip()
    session_str = os.environ.get("TG_SESSION", "").strip()
    if not (api_id_raw and api_hash and session_str):
        log.error("API_ID / API_HASH / TG_SESSION не заданы")
        return []
    try:
        api_id = int(api_id_raw)
    except ValueError:
        log.error("API_ID не число")
        return []

    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    all_items: list[dict] = []
    try:
        await client.start()
        for src in TELEGRAM_SOURCES:
            items = await _fetch_from_source(client, src)
            all_items.extend(items)
            await asyncio.sleep(2)
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    # дедуп по (uuid, ip, port)
    seen: set[tuple] = set()
    unique: list[dict] = []
    for it in all_items:
        key = (it["uuid"], it["ip"], it["port"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(it)

    log.info("Всего VLESS из Telegram: %d (уникальных)", len(unique))
    return unique
