"""Оформление сообщений о VLESS-ключах."""
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
    return value[:max_len - 1] + "…"


def _vless_kind(p: dict) -> str:
    """VLESS + Reality/TLS + XTLS-Vision."""
    parts = ["VLESS"]
    sec = (p.get("security") or "").lower()
    if sec == "reality":
        parts.append("Reality")
    elif sec == "tls":
        parts.append("TLS")
    if (p.get("flow") or "") == "xtls-rprx-vision":
        parts.append("XTLS-Vision")
    return " · ".join(parts)


def _transport(p: dict) -> str:
    return {
        "tcp": "TCP", "raw": "RAW", "ws": "WebSocket",
        "grpc": "gRPC", "http": "HTTP/2", "xhttp": "XHTTP",
    }.get((p.get("type") or "tcp").lower(), (p.get("type") or "tcp").upper())


def _tls_marker(p: dict) -> str:
    if not p.get("sni"):
        return "—"
    return "✅ OK" if p.get("tls_ok") else "⚠️ fail (Reality-маскировка)"


def _mask_label(p: dict) -> str:
    sni = p.get("sni") or "—"
    sec = (p.get("security") or "").lower()
    if sec == "reality":
        return f"🎭 Reality → {html.escape(_trunc(sni, 40))}"
    if sec == "tls":
        return f"🔐 SNI → {html.escape(_trunc(sni, 40))}"
    return "—"


def format_message(p: dict) -> str:
    now = datetime.now(MSK).strftime("%H:%M:%S")
    pid = p.get("id", 0)
    flag = p.get("flag") or "🌐"
    country = _trunc(p.get("country") or "Unknown", 26)
    name = _trunc(p.get("name") or "", 40)

    header = f"🚀 #{pid} | {flag} {country}"
    if p.get("probe_resistant"):
        header += " ⬜ БЕЛЫЙ IP"

    kind = _vless_kind(p)
    transport = _transport(p)
    ping = p.get("ping", "?")
    city = _trunc(p.get("city") or "—", 16)
    provider = _trunc(p.get("provider") or "—", 22)

    title = f"{flag} {country}"
    title += f" | {name}" if name else f" | {kind}"

    raw = p.get("raw", "")
    tag = p.get("source") or ""
    tag_part = f" | @{tag}" if tag else ""

    lines = [
        html.escape(header), "",
        "┌ 🏷 Название: " + html.escape(title),
        f"├ 🔗 Тип: {html.escape(kind)}",
        f"├ 🌐 Транспорт: {html.escape(transport)}",
        f"├ 📡 Пинг: {html.escape(str(ping))} ms",
        f"├ 🌍 Гео: {html.escape(city)} · {html.escape(provider)}",
        f"├ 🔒 TLS-хендшейк: {html.escape(_tls_marker(p))}",
        f"└ {_mask_label(p)}", "",
        "<b>🔑 VLESS-ключ для подключения:</b>",
        f"<code>{html.escape(raw)}</code>", "",
        f"⏱ Проверено: {now}{html.escape(tag_part)}",
    ]
    return "\n".join(lines)
