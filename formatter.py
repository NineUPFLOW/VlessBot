"""Оформление сообщений для Telegram."""
from __future__ import annotations

import html
from datetime import datetime
from zoneinfo import ZoneInfo

MSK = ZoneInfo("Europe/Moscow")


def _trunc(value: str, max_len: int) -> str:
    if value is None:
        return ""
    value = str(value)
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def _proto_label(p: dict) -> str:
    parts = ["🔹 VLESS"]
    if (p.get("security") or "").lower() == "reality":
        parts.append("Reality")
    if (p.get("flow") or "") == "xtls-rprx-vision":
        parts.append("XTLS-Vision")
    if p.get("probe_resistant"):
        parts.append("🛡 PROBE")
    return " · ".join(parts)


def format_message(p: dict) -> str:
    now = datetime.now(MSK).strftime("%H:%M:%S")

    pid = p.get("id", 0)
    flag = p.get("flag") or "🌐"
    country = _trunc(p.get("country") or "Unknown", 26)
    name = _trunc(p.get("name") or "", 40)

    header = f"🚀 #{pid} | {flag} {country}"
    if p.get("probe_resistant"):
        header += " ⬜ БЕЛЫЙ IP"

    proto_label = _proto_label(p)
    ping = p.get("ping", "?")
    city = _trunc(p.get("city") or "—", 16)
    provider = _trunc(p.get("provider") or "—", 22)

    title_line = f"{flag} {country}"
    if name:
        title_line += f" | {name}"

    raw = p.get("raw", "")
    tag = p.get("source") or ""
    tag_part = f" | @{tag}" if tag else ""

    lines = [
        html.escape(header),
        "",
        "┌ 🏷 Название: " + html.escape(title_line),
        f"├ 🔗 Протокол: {html.escape(proto_label)}",
        f"├ 📡 Пинг: {html.escape(str(ping))} ms",
        f"├ 🌍 Город: {html.escape(city)}",
        f"└ 🏢 Провайдер: {html.escape(provider)}",
        "",
        "<b>🔑 Ключ для подключения:</b>",
        f"<code>{html.escape(raw)}</code>",
        "",
        f"⏱ Проверено: {now}{html.escape(tag_part)}",
    ]
    return "\n".join(lines)
