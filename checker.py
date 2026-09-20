"""Проверка VLESS-конфигов: TCP (жёсткий фильтр), TLS/probe (информационно), гео."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
import time
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

# ── Лимиты (подняты — GitHub Actions → Азия/Иран часто 4–6 сек) ──
MAX_PING_MS = 5000          # жёсткий порог по TCP-пингу
TCP_TIMEOUT = 8             # таймаут TCP-подключения
TLS_TIMEOUT = 8             # таймаут TLS (только информационно)
PROBE_TIMEOUT = 6

_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_geo_lock = asyncio.Lock()


async def _get_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT + 3)
        )
    return _session


async def close_http_session() -> None:
    global _session
    if _session and not _session.closed:
        await _session.close()
        _session = None


async def _resolve_all(host: str) -> list[str]:
    """Все IP хоста, IPv4 в приоритете."""
    try:
        socket.inet_aton(host)
        return [host]
    except OSError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        pairs: list[tuple[int, str]] = []
        seen: set[str] = set()
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            pairs.append((fam, ip))
        # IPv4 вперёд
        pairs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        return [ip for _, ip in pairs]
    except Exception as e:  # noqa: BLE001
        log.debug("resolve %s failed: %s", host, e)
        return []


async def check_tcp(host: str, port: int) -> int | None:
    try:
        start = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        ping = int((time.perf_counter() - start) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return ping
    except Exception:  # noqa: BLE001
        return None


def _tls_handshake_sync(host: str, port: int, sni: str) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True
    except Exception:  # noqa: BLE001
        return False


async def check_tls(host: str, port: int, sni: str) -> bool:
    """Информационная проверка. НЕ используется для отбраковки."""
    if not sni:
        return False
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _tls_handshake_sync, host, port, sni),
            timeout=TLS_TIMEOUT + 2,
        )
    except Exception:  # noqa: BLE001
        return False


async def check_probe_resistant(sni: str) -> bool:
    if not sni:
        return False
    session = await _get_session()
    for scheme in ("https", "http"):
        url = f"{scheme}://{sni}/"
        try:
            async with session.get(
                url,
                ssl=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"},
            ) as resp:
                if resp.status < 500:
                    return True
        except Exception:  # noqa: BLE001
            continue
    return False


async def geolocate(ip: str) -> dict | None:
    """None — если не удалось. НЕ роняет прокси."""
    async with _geo_lock:
        cached = _geo_cache.get(ip)
        if cached is not None:
            return cached if cached else None

    session = await _get_session()
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
    data: dict | None = None
    for attempt in range(3):
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT)
            ) as resp:
                if resp.status == 429:
                    await asyncio.sleep(1 + attempt)
                    continue
                if resp.status == 200:
                    data = await resp.json()
                    break
        except Exception as e:  # noqa: BLE001
            log.debug("geo %s error: %s", ip, e)
            await asyncio.sleep(0.5)

    if not data or data.get("status") != "success":
        async with _geo_lock:
            _geo_cache[ip] = {}
        return None

    result = {
        "country": data.get("country") or "Unknown",
        "countryCode": (data.get("countryCode") or "").upper(),
        "city": data.get("city") or "",
        "provider": data.get("isp") or "",
    }
    async with _geo_lock:
        _geo_cache[ip] = result
    return result


def _flag_from_code(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in code)


def _stable_id(ip: str, port: int) -> int:
    h = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()[:16]
    return int(h, 16) % 10_000_000


def _enrich(
    proxy: dict,
    ip: str,
    ping: int,
    geo: dict,
    probe_ok: bool,
    tls_ok: bool,
) -> dict:
    out = dict(proxy)
    out["ip"] = ip
    out["country"] = geo.get("country", "Unknown")
    out["countryCode"] = geo.get("countryCode", "")
    out["city"] = geo.get("city", "")
    out["provider"] = geo.get("provider", "")
    out["flag"] = _flag_from_code(geo.get("countryCode", ""))
    out["ping"] = ping
    out["probe_resistant"] = probe_ok
    out["tls_ok"] = tls_ok
    out["id"] = _stable_id(ip, out["port"])
    out["score"] = compute_score(out)
    return out


def compute_score(proxy: dict) -> int:
    score = 10000
    if proxy.get("security") == "reality":
        score += 3000
    if proxy.get("flow") == "xtls-rprx-vision":
        score += 2000
    if proxy.get("probe_resistant"):
        score += 1000
    if proxy.get("tls_ok"):
        score += 500
    ping = proxy.get("ping", 5000)
    return score - min(int(ping), 5000)


async def process_vless(raw: dict) -> dict | None:
    host = raw.get("ip")
    port = raw.get("port")
    sni = raw.get("sni")
    if not host or not port:
        return None

    # 1. Резолв — все IP, IPv4 вперёд
    ips = await _resolve_all(host)
    if not ips:
        log.debug("DNS fail %s", host)
        return None

    # 2. TCP — жёсткий фильтр, пробуем до 3 IP
    ip = None
    ping: int | None = None
    for candidate in ips[:3]:
        p = await check_tcp(candidate, port)
        if p is not None and p <= MAX_PING_MS:
            ip = candidate
            ping = p
            break

    if ip is None:
        log.debug("TCP fail %s:%s", host, port)
        return None

    # 3. TLS — ТОЛЬКО информационно, не отбраковываем
    tls_ok = False
    if raw.get("security") in ("reality", "tls") and sni:
        tls_ok = await check_tls(ip, port, sni)

    # 4. Probe SNI-домена — тоже не отбраковывает
    probe_ok = False
    if sni:
        probe_ok = await check_probe_resistant(sni)

    # 5. Гео — опционально
    geo = await geolocate(ip) or {}

    return _enrich(raw, ip, ping, geo, probe_ok, tls_ok)
