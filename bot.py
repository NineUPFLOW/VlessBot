"""Точка входа: оркестрация цикла сбора → проверки → публикации."""
from __future__ import annotations

import asyncio
import logging
import os
import sys

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramRetryAfter, TelegramAPIError

import checker
import formatter
import state
from sources import fetch_all_vless

PUBLISH_COUNT = 10
SEND_DELAY = 3
MAX_SEND_RETRIES = 3
CONCURRENCY = 20
MAX_VLESS_CHECK = 500


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
        log.warning("CHAT_ID не задан, статус не отправлен")
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
        log.warning("send_status failed: %s", e)


async def check_with_semaphore(sem: asyncio.Semaphore, raw: dict) -> dict | None:
    async with sem:
        try:
            result = await checker.process_vless(raw)
        except Exception as e:  # noqa: BLE001
            log.debug("process_vless error %s: %s", raw.get("ip"), e)
            result = None
        try:
            state.mark_seen(raw)
        except Exception as e:  # noqa: BLE001
            log.debug("mark_seen error: %s", e)
        return result


async def check_group(raws: list[dict]) -> list[dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_with_semaphore(sem, r) for r in raws]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return [r for r in results if r is not None]


def sort_key(p: dict):
    probe = bool(p.get("probe_resistant"))
    reality = (p.get("security") or "").lower() == "reality"
    vision = (p.get("flow") or "") == "xtls-rprx-vision"
    ping = p.get("ping", 99999)

    if probe and reality:
        group = 0
    elif reality:
        group = 1
    elif vision:
        group = 2
    else:
        group = 3
    return (group, ping)


async def send_with_retry(bot: Bot, chat_id: int, text: str, thread_id: int | None) -> bool:
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
            wait = int(e.retry_after) + 1
            log.warning("RetryAfter %ss", wait)
            await asyncio.sleep(wait)
        except TelegramAPIError as e:
            log.warning("send failed (attempt %d): %s", attempt + 1, e)
            await asyncio.sleep(2)
    return False


async def run(bot: Bot) -> None:
    state.init_db()
    state.cleanup()

    log.info("Сбор VLESS из Telegram-источников...")
    raws = await fetch_all_vless()
    if not raws:
        await send_status(bot, "⚠️ Источники пусты")
        return

    # дедуп по (uuid, ip, port)
    seen_keys: set[tuple] = set()
    deduped: list[dict] = []
    for r in raws:
        k = (r.get("uuid"), r.get("ip"), r.get("port"))
        if k in seen_keys:
            continue
        seen_keys.add(k)
        deduped.append(r)

    unseen = state.filter_unseen(deduped)
    log.info("Не видели ранее: %d из %d", len(unseen), len(deduped))

    to_check = unseen[:MAX_VLESS_CHECK]
    log.info("Проверяем %d ключей (CONCURRENCY=%d)...", len(to_check), CONCURRENCY)
    working = await check_group(to_check)
    log.info("Рабочих прокси: %d", len(working))

    if not working:
        await send_status(bot, "⚠️ Ни один прокси не прошёл проверку")
        return

    fresh = state.filter_unpublished(working)
    if not fresh:
        await send_status(
            bot,
            "💤 Все рабочие прокси уже публиковались\n\n"
            f"Проверено рабочих: {len(working)}\n"
            "Все они были опубликованы недавно.\n\n"
            "Жду появления новых прокси в источниках.",
        )
        return

    fresh.sort(key=sort_key)
    log.info("Топ-10 после сортировки:")
    for p in fresh[:10]:
        log.info(
            "  #%s %s %s ping=%sms probe=%s reality=%s vision=%s",
            p.get("id"),
            p.get("ip"),
            p.get("port"),
            p.get("ping"),
            p.get("probe_resistant"),
            p.get("security"),
            p.get("flow"),
        )

    to_publish = fresh[:PUBLISH_COUNT]

    chat_id_raw = os.environ.get("CHAT_ID", "").strip()
    if not chat_id_raw:
        log.error("CHAT_ID не задан")
        return
    chat_id = int(chat_id_raw)
    thread_id: int | None = None
    topic_raw = os.environ.get("TOPIC_ID", "").strip()
    if topic_raw:
        try:
            thread_id = int(topic_raw)
        except ValueError:
            thread_id = None

    published_count = 0
    for i, p in enumerate(to_publish):
        text = formatter.format_message(p)
        ok = await send_with_retry(bot, chat_id, text, thread_id)
        if ok:
            state.mark_published(p)
            published_count += 1
            log.info("Опубликован #%s (%s:%s)", p.get("id"), p.get("ip"), p.get("port"))
        if i < len(to_publish) - 1:
            await asyncio.sleep(SEND_DELAY)

    log.info("Опубликовано: %d", published_count)


async def main() -> int:
    _setup_logging()
    token = os.environ.get("BOT_TOKEN", "").strip()
    if not token:
        log.error("BOT_TOKEN не задан")
        return 1

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    try:
        await run(bot)
    except Exception as e:  # noqa: BLE001
        log.exception("Fatal error: %s", e)
        return 1
    finally:
        await checker.close_http_session()
        await bot.session.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
