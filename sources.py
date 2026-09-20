"""Сбор VLESS-ключей: GitHub-подписки + Telegram через Telethon."""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp
from telethon import TelegramClient
from telethon.errors import FloodWaitError
from telethon.sessions import StringSession
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.types import (
    MessageEntityCode,
    MessageEntityPre,
    MessageMediaWebPage,
)

logger = logging.getLogger(__name__)

MAX_PER_SUB = 10000

SUBSCRIPTION_URLS: list[str] = [
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/vless",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
]

TELEGRAM_CHANNELS: list[str] = [
    "dbproxy",
    "Beshkan",
    "v2ray_vless_free",
    "free_vless",
    "v2ray_configs_pool",
    "Custom_V2ray_Config",
    "V2rayOutfit",
    "npv2ray",
    "vlessiran_free",
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
    except Exception as e:
        logger.debug("vless parse error: %s (%s)", e, line[:80])
        return None


def _extract_vless_from_text(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for _t, url in RE_MARKDOWN.findall(text):
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
        except Exception:
            pass

    media = getattr(msg, "media", None)
    if isinstance(media, MessageMediaWebPage):
        wp = getattr(media, "webpage", None)
        if wp is not None:
            wp_url = getattr(wp, "url", None)
            if wp_url and wp_url.startswith("vless://"):
                found.append(wp_url)

    return found


def _try_base64_decode(text: str) -> str:
    stripped = "".join(text.split())
    if len(stripped) < 32:
        return text
    try:
        decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4)).decode(
            "utf-8", errors="ignore"
        )
        if "vless://" in decoded:
            return decoded
    except Exception:
        pass
    return text


async def _fetch_subscription(session: aiohttp.ClientSession, url: str) -> list[dict]:
    results: list[dict] = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                logger.warning("Sub %s → HTTP %d", url, resp.status)
                return []
            text = await resp.text()
    except Exception as e:
        logger.warning("Sub %s failed: %s", url, e)
        return []

    text = _try_base64_decode(text)
    source_tag = url.rsplit("/", 1)[-1]

    for raw in RE_VLESS.findall(text):
        p = _parse_vless(raw)
        if p:
            p["source"] = source_tag
            results.append(p)
            if len(results) >= MAX_PER_SUB:
                logger.info("Sub %s — обрезано на %d", source_tag, MAX_PER_SUB)
                break

    logger.info("Sub %s → %d VLESS", source_tag, len(results))
    return results


async def fetch_from_subscriptions() -> list[dict]:
    connector = aiohttp.TCPConnector(limit=8, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector, timeout=aiohttp.ClientTimeout(total=30)
    ) as session:
        tasks = [_fetch_subscription(session, url) for url in SUBSCRIPTION_URLS]
        chunks = await asyncio.gather(*tasks, return_exceptions=True)

    out: list[dict] = []
    for c in chunks:
        if isinstance(c, list):
            out.extend(c)
    logger.info("Из подписок: %d VLESS", len(out))
    return out


async def _fetch_from_source(
    client: TelegramClient, source: str, retry: bool = True
) -> list[dict]:
    results: list[dict] = []
    try:
        try:
            await client(JoinChannelRequest(source))
        except Exception:
            pass

        entity = await client.get_entity(source)
        message_count = 0
        thread_ids: set[int] = set()

        async for msg in client.iter_messages(entity, limit=150):
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
                async for msg in client.iter_messages(entity, limit=40, reply_to=tid):
                    for raw in _extract_from_message(msg):
                        parsed = _parse_vless(raw)
                        if parsed:
                            parsed["source"] = source
                            results.append(parsed)
            except Exception as e:
                logger.debug("thread @%s/%s: %s", source, tid, e)

        logger.info(
            "TG @%s: %d сообщений, %d тем → %d VLESS",
            source,
            message_count,
            len(thread_ids),
            len(results),
        )
    except FloodWaitError as e:
        wait = min(e.seconds, 60)
        logger.warning("FloodWait @%s: %ds", source, e.seconds)
        await asyncio.sleep(wait)
        if retry:
            try:
                return await _fetch_from_source(client, source, retry=False)
            except Exception:
                pass
    except Exception as e:
        logger.warning("Source @%s failed: %s", source, e)

    return results


async def fetch_from_telegram(channels: list[str]) -> list[dict]:
    api_id_raw = os.environ.get("API_ID", "").strip()
    api_hash = os.environ.get("API_HASH", "").strip()
    session_str = os.environ.get("TG_SESSION", "").strip()
    if not (api_id_raw and api_hash and session_str):
        logger.warning("Telegram пропущен: нет API_ID/API_HASH/TG_SESSION")
        return []
    try:
        api_id = int(api_id_raw)
    except ValueError:
        return []

    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    all_items: list[dict] = []
    try:
        await client.start()
        for src in channels:
            items = await _fetch_from_source(client, src)
            all_items.extend(items)
            await asyncio.sleep(2)
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    logger.info("Из Telegram: %d VLESS", len(all_items))
    return all_items


async def fetch_all_vless() -> list[dict]:
    sub_task = asyncio.create_task(fetch_from_subscriptions())
    tg_task = asyncio.create_task(fetch_from_telegram(TELEGRAM_CHANNELS))

    sub_items, tg_items = await asyncio.gather(sub_task, tg_task)
    all_items = sub_items + tg_items

    # Дедуп #1: (uuid, ip, port)
    seen: set[tuple] = set()
    unique: list[dict] = []
    for it in all_items:
        key = (it["uuid"], it["ip"], it["port"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(it)

    # Дедуп #2: (ip, port)
    seen_addr: set[tuple] = set()
    deduped: list[dict] = []
    for it in unique:
        addr = (it["ip"], it["port"])
        if addr in seen_addr:
            continue
        seen_addr.add(addr)
        deduped.append(it)

    logger.info(
        "Итог: подписки=%d, telegram=%d, уникальных=%d (после дедупа по addr)",
        len(sub_items),
        len(tg_items),
        len(deduped),
    )
    return deduped
