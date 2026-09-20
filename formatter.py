"""Оформление сообщений о VLESS-ключах. Только правда: никаких «белых IP»."""
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


def _vless_kind(p: dict) -> str:
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
    return "✅ OK" if p.get("tls_ok") else "⚠️ fail"


def _mask_label(p: dict) -> str:
    """Под какой домен маскируется VLESS + статус SNI-домена.
    ✅ = SNI-домен отвечает из US-раннера (не значит что не заблокирован в РФ)
    ⚠️ = SNI-домен не отвечает."""
    sni = p.get("sni") or "—"
    sec = (p.get("security") or "").lower()
    sni_alive = p.get("probe_resistant", False)
    sni_status = "🟢" if sni_alive else "🔴"

    if sec == "reality":
        return f"🎭 Reality → {html.escape(_trunc(sni, 36))} {sni_status}"
    if sec == "tls":
        return f"🔐 SNI → {html.escape(_trunc(sni, 36))} {sni_status}"
    return f"🎭 SNI → {html.escape(_trunc(sni, 36))} {sni_status}"


def format_message(p: dict) -> str:
    now = datetime.now(MSK).strftime("%H:%M:%S")

    pid = p.get("id", 0)
    flag = p.get("flag") or "🌐"
    country = _trunc(p.get("country") or "Unknown", 30)

    # Шапка — без «БЕЛЫЙ IP» (это былa ложь)
    header = f"🚀 #{pid} | {flag} {country}"

    kind = _vless_kind(p)
    transport = _transport(p)
    ping = p.get("ping", "?")
    city = _trunc(p.get("city") or "—", 24)
    provider = _trunc(p.get("provider") or "—", 30)
    tls_marker = _tls_marker(p)
    mask = _mask_label(p)

    raw = p.get("raw", "")

    lines = [
        html.escape(header),
        "",
        f"┌ 🔗 Тип: {html.escape(kind)}",
        f"├ 🌐 Транспорт: {html.escape(transport)}",
        f"├ 📡 Пинг: {html.escape(str(ping))} ms (из 🇺🇸 US-раннера)",
        f"├ 🌍 Гео: {html.escape(city)} · {html.escape(provider)}",
        f"├ 🔒 TLS-хендшейк: {html.escape(tls_marker)}",
        f"└ {mask}",
        "",
        "<b>🔑 VLESS-ключ:</b>",
        f"<code>{html.escape(raw)}</code>",
        "",
        f"⏱ Проверено: {now} МСК",
    ]
    return "\n".join(lines)
