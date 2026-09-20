"""Проверка VLESS-конфигов: TCP, TLS, probe, геолокация."""
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

MAX_PING_MS = 3000
TCP_TIMEOUT = 5
TLS_TIMEOUT = 5
PROBE_TIMEOUT = 5

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


async def _resolve(host: str) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except Exception as e:  # noqa: BLE001
        log.debug("resolve %s failed: %s", host, e)
    return None


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
    async with _geo_lock:
        cached = _geo_cache.get(ip)
        if cached is not None:
            return cached if cached else None

    session = await _get_session()
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
    data: dict | None = None
    for attempt in range(3):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT)) as resp:
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
    ping = proxy.get("ping", 5000)
    return score - min(int(ping), 5000)


async def process_vless(raw: dict) -> dict | None:
    host = raw.get("ip")
    port = raw.get("port")
    sni = raw.get("sni")
    if not host or not port:
        return None

    ip = await _resolve(host)
    if not ip:
        return None

    ping = await check_tcp(ip, port)
    if ping is None or ping > MAX_PING_MS:
        return None

    if raw.get("security") in ("reality", "tls") and sni:
        tls_ok = await check_tls(ip, port, sni)
        if not tls_ok:
            return None

    probe_ok = False
    if sni:
        probe_ok = await check_probe_resistant(sni)

    geo = await geolocate(ip)
    if not geo:
        return None

    return _enrich(raw, ip, ping, geo, probe_ok)
