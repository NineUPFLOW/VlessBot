"""
Проверка VLESS-конфигов.
TCP — жёсткий фильтр. TLS, probe, geo — параллельно.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import socket
import ssl
import time

import aiohttp

for name in ("telethon", "telethon.network", "telethon.client", "asyncio"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

MAX_PING_MS = 5000
MIN_PING_MS = 5
TCP_TIMEOUT = 6
TLS_TIMEOUT = 5
PROBE_TIMEOUT = 3
GEO_TIMEOUT = 5

_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_probe_cache: dict[str, bool] = {}
_geo_semaphore = asyncio.Semaphore(5)
PROBE_CACHE_LIMIT = 5000
GEO_CACHE_LIMIT = 2000

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
    return _http_session


async def close_http_session() -> None:
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
        _http_session = None


def compute_score(key: dict) -> int:
    score = 10000
    security = (key.get("security") or "").lower()
    if security == "reality":
        score += 3000
    if key.get("flow") == "xtls-rprx-vision":
        score += 2000
    if key.get("probe_resistant"):
        score += 1000
    if key.get("tls_ok"):
        score += 500
    ping = key.get("ping", 5000)
    return score - min(int(ping), 5000)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def _resolve_all(host: str) -> list[str]:
    if _is_ip(host):
        return [host]
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        pairs: list[tuple[int, str]] = []
        seen: set[str] = set()
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            pairs.append((fam, ip))
        pairs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)
        return [ip for _, ip in pairs]
    except Exception as e:
        logger.debug("resolve(%s) failed: %s", host, e)
        return []


def _stable_id(ip: str, port: int) -> int:
    digest = hashlib.md5(f"{ip}:{port}".encode()).hexdigest()
    return int(digest, 16) % 10_000_000


def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


async def geolocate(ip: str) -> dict:
    global _geo_cache
    if len(_geo_cache) > GEO_CACHE_LIMIT:
        _geo_cache.clear()
    if ip in _geo_cache:
        return _geo_cache[ip]
    async with _geo_semaphore:
        session = _get_http_session()
        for attempt in range(2):
            try:
                async with session.get(
                    f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,countryCode,city,isp,query",
                    timeout=aiohttp.ClientTimeout(total=GEO_TIMEOUT),
                ) as r:
                    if r.status == 429:
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    if r.status == 200:
                        data = await r.json()
                        if data.get("status") == "success":
                            _geo_cache[ip] = data
                            return data
                    return {}
            except Exception as e:
                logger.debug("geolocate(%s) #%s: %s", ip, attempt + 1, e)
                await asyncio.sleep(0.5)
    return {}


async def check_probe_resistant(domain: str) -> bool:
    if not domain:
        return False
    if domain in _probe_cache:
        return _probe_cache[domain]
    session = _get_http_session()
    try:
        async with session.get(
            f"https://{domain}/",
            timeout=aiohttp.ClientTimeout(total=PROBE_TIMEOUT),
            allow_redirects=False,
            ssl=False,
        ) as r:
            is_real = r.status < 500
    except Exception as e:
        logger.debug("probe %s failed: %s", domain, e)
        is_real = False
    if len(_probe_cache) >= PROBE_CACHE_LIMIT:
        _probe_cache.clear()
    _probe_cache[domain] = is_real
    return is_real


async def check_tcp(host: str, port: int) -> int | None:
    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        ping = int((time.perf_counter() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ping
    except Exception:
        return None


def _tls_handshake_sync(host: str, port: int, sni: str) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni):
                return True
    except Exception:
        return False


async def check_tls(host: str, port: int, sni: str) -> bool:
    if not sni:
        return False
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _tls_handshake_sync, host, port, sni),
            timeout=TLS_TIMEOUT + 2,
        )
    except Exception:
        return False


async def _safe(coro, default):
    try:
        return await coro
    except Exception:
        return default


async def _noop() -> bool:
    return False


def _enrich(
    key: dict, ip: str, ping: int, geo: dict, probe_ok: bool, tls_ok: bool
) -> dict:
    country_code = geo.get("countryCode", "")
    key.update(
        {
            "ip": ip,
            "ping": ping,
            "id": _stable_id(ip, key["port"]),
            "country": geo.get("country", "Unknown"),
            "countryCode": country_code,
            "city": geo.get("city", "Unknown"),
            "provider": geo.get("isp", "Unknown"),
            "flag": _country_flag(country_code),
            "probe_resistant": probe_ok,
            "tls_ok": tls_ok,
        }
    )
    key["score"] = compute_score(key)
    return key


async def process_vless(raw: dict) -> dict | None:
    """
    1. Резолв
    2. TCP (жёсткий фильтр, MIN_PING_MS <= ping <= MAX_PING_MS)
    3. TLS + probe + geo — ПАРАЛЛЕЛЬНО
    """
    host = raw.get("ip")
    port = raw.get("port")
    sni = raw.get("sni")
    security = (raw.get("security") or "").lower()

    if not host or not port:
        return None

    ips = await _resolve_all(host)
    if not ips:
        return None

    ip = None
    ping: int | None = None
    for candidate in ips[:3]:
        p = await check_tcp(candidate, port)
        if p is not None and MIN_PING_MS <= p <= MAX_PING_MS:
            ip = candidate
            ping = p
            break

    if ip is None:
        return None

    tls_coro = (
        check_tls(ip, port, sni)
        if security in ("reality", "tls") and sni
        else _safe(_noop(), False)
    )
    probe_coro = (
        check_probe_resistant(sni) if sni else _safe(_noop(), False)
    )

    tls_ok, probe_ok, geo = await asyncio.gather(
        _safe(tls_coro, False),
        _safe(probe_coro, False),
        _safe(geolocate(ip), {}),
    )

    if not geo:
        geo = {}

    return _enrich(raw, ip, ping, geo, probe_ok, tls_ok)
