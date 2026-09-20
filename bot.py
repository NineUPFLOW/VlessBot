"""Точка входа: сбор VLESS → проверка → публикация."""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections import defaultdict, deque

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import (
    TelegramAPIError,
    TelegramForbiddenError,
    TelegramRetryAfter,
)

import checker
import formatter
import state
from sources import fetch_all_vless

PUBLISH_COUNT = 10
SEND_DELAY = 3
MAX_SEND_RETRIES = 3
CONCURRENCY = 20
MAX_VLESS_CHECK = 500
PER_SOURCE_LIMIT = 200


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    for noisy in (
        "telethon",
        "telethon.client",
        "telethon.network",
        "telethon.extensions",
        "asyncio",
        "aiogram.event",
        "aiohttp.access",
    ):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)


log = logging.getLogger("bot")


async def send_status(bot: Bot, text: str) -> None:
    chat_id = os.environ.get("CHAT_ID")
    topic_id_raw = os.environ.get("TOPIC_ID", "").strip()
    if not chat_id:
        return
    kwargs: dict = {"chat_id": int(chat_id), "text": text}
    if topic_id_raw:
        try:
            kwargs["message_thread_id"] = int(topic_id_raw)
        except ValueError:
            pass
    try:
        await bot.send_message(**kwargs)
    except TelegramAPIError as e:
        log.warning("send_status: %s", e)


async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict) -> dict | None:
    async with sem:
        try:
            result = await checker.process_vless(raw)
        except Exception as e:
            log.debug("process_vless %s: %s", raw.get("ip"), e)
            result = None
        try:
            state.mark_seen(raw)
        except Exception as e:
            log.debug("mark_seen: %s", e)
        return result


async def check_group(raws: list[dict]) -> list[dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_with_semaphore(sem, r) for r in raws]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return [r for r in results if r is not None]


def _dedup_by_address(keys: list[dict]) -> list[dict]:
    """Дедуп по (ip, port). Один сервер = одна запись."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for k in keys:
        addr = (k.get("ip"), k.get("port"))
        if addr in seen:
            continue
        seen.add(addr)
        out.append(k)
    return out


def _balance_by_source(keys: list[dict], total_limit: int) -> list[dict]:
    """Берём по PER_SOURCE_LIMIT из каждого источника, круговым обходом."""
    by_source: dict[str, deque] = defaultdict(deque)
    for k in keys:
        by_source[k.get("source", "unknown")].append(k)

    result: list[dict] = []
    exhausted: set[str] = set()
    while len(result) < total_limit and by_source:
        progressed = False
        for src in list(by_source.keys()):
            if src in exhausted:
                continue
            if not by_source[src]:
                exhausted.add(src)
                continue
            src_taken = sum(1 for r in result if r.get("source") == src)
            if src_taken >= PER_SOURCE_LIMIT:
                exhausted.add(src)
                continue
            result.append(by_source[src].popleft())
            progressed = True
            if len(result) >= total_limit:
                break
        if not progressed:
            break
    return result


def sort_key(key: dict):
    probe = bool(key.get("probe_resistant"))
    reality = (key.get("security") or "").lower() == "reality"
    vision = (key.get("flow") or "") == "xtls-rprx-vision"
    ping = key.get("ping", 99999)

    if probe and reality:
        group = 0
    elif reality:
        group = 1
    elif vision:
        group = 2
    else:
        group = 3
    return (group, ping)


async def send_with_retry(
    bot: Bot, chat_id: int, text: str, thread_id: int | None
) -> bool:
    kwargs: dict = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    if thread_id is not None:
        kwargs["message_thread_id"] = thread_id

    for attempt in range(MAX_SEND_RETRIES):
        try:
            await bot.send_message(**kwargs)
            return True
        except TelegramRetryAfter as e:
            await asyncio.sleep(int(e.retry_after) + 1)
        except TelegramForbiddenError as e:
            log.error("Bot forbidden in chat %s: %s", chat_id, e)
            return False
        except TelegramAPIError as e:
            log.warning("send failed (%d): %s", attempt + 1, e)
            await asyncio.sleep(2)
    return False


async def run(bot: Bot) -> None:
    state.init_db()
    state.cleanup()

    log.info("Сбор VLESS-ключей...")
    raws = await fetch_all_vless()
    if not raws:
        await send_status(bot, "⚠️ Источники пусты")
        return

    # Дедуп #1: по (uuid, ip, port)
    seen1: set[tuple] = set()
    deduped: list[dict] = []
    for r in raws:
        k = (r.get("uuid"), r.get("ip"), r.get("port"))
        if k in seen1:
            continue
        seen1.add(k)
        deduped.append(r)
    log.info("После дедупа по (uuid,ip,port): %d", len(deduped))

    # Дедуп #2: по (ip, port)
    deduped = _dedup_by_address(deduped)
    log.info("После дедупа по (ip,port): %d", len(deduped))

    unseen = state.filter_unseen(deduped)
    log.info("Не видели ранее: %d", len(unseen))

    to_check = _balance_by_source(unseen, MAX_VLESS_CHECK)

    src_counts: dict[str, int] = defaultdict(int)
    for k in to_check:
        src_counts[k.get("source", "unknown")] += 1
    log.info("Выборка по источникам (топ-15):")
    for src, n in sorted(src_counts.items(), key=lambda x: -x[1])[:15]:
        log.info("  %s: %d", src, n)

    log.info(
        "Проверяем %d ключей (CONCURRENCY=%d, MAX_PING_MS=%d)...",
        len(to_check),
        CONCURRENCY,
        checker.MAX_PING_MS,
    )

    working = await check_group(to_check)
    log.info("Проверка: %d → %d рабочих (TCP ok)", len(to_check), len(working))

    if working:
        reality_n = sum(1 for p in working if (p.get("security") or "") == "reality")
        vision_n = sum(
            1 for p in working if (p.get("flow") or "") == "xtls-rprx-vision"
        )
        tls_n = sum(1 for p in working if p.get("tls_ok"))
        sni_alive_n = sum(1 for p in working if p.get("probe_resistant"))
        log.info(
            "Breakdown: Reality=%d, Vision=%d, TLS-OK=%d, SNI-alive=%d",
            reality_n,
            vision_n,
            tls_n,
            sni_alive_n,
        )

    if not working:
        await send_status(
            bot,
            "⚠️ Ни один VLESS-ключ не прошёл TCP-проверку\n\n"
            f"Проверено: {len(to_check)}\n"
            f"Все недоступны или пинг > {checker.MAX_PING_MS} мс.",
        )
        return

    fresh = state.filter_unpublished(working)
    if not fresh:
        await send_status(
            bot,
            "💤 Все рабочие VLESS уже публиковались\n\n"
            f"Рабочих: {len(working)}\nЖду новых ключей.",
        )
        return

    fresh.sort(key=sort_key)
    log.info("Топ-10:")
    for p in fresh[:10]:
        log.info(
            "  #%s %s:%s ping=%sms sni_alive=%s tls=%s reality=%s vision=%s",
            p.get("id"),
            p.get("ip"),
            p.get("port"),
            p.get("ping"),
            p.get("probe_resistant"),
            p.get("tls_ok"),
            p.get("security"),
            p.get("flow"),
        )

    to_publish = fresh[:PUBLISH_COUNT]

    chat_id = int(os.environ["CHAT_ID"])
    thread_id: int | None = None
    topic_raw = os.environ.get("TOPIC_ID", "").strip()
    if topic_raw:
        try:
            thread_id = int(topic_raw)
        except ValueError:
            pass

    published = 0
    for i, p in enumerate(to_publish):
        text = formatter.format_message(p)
        if await send_with_retry(bot, chat_id, text, thread_id):
            state.mark_published(p)
            published += 1
            log.info("Опубликован #%s", p.get("id"))
        if i < len(to_publish) - 1:
            await asyncio.sleep(SEND_DELAY)

    log.info("Опубликовано: %d", published)


async def main() -> int:
    _setup_logging()
    token = os.environ.get("BOT_TOKEN", "").strip()
    if not token:
        log.error("BOT_TOKEN не задан")
        return 1
    if not os.environ.get("CHAT_ID", "").strip():
        log.error("CHAT_ID не задан")
        return 1

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    try:
        await run(bot)
    except Exception as e:
        log.exception("Fatal: %s", e)
        return 1
    finally:
        await checker.close_http_session()
        await bot.session.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
