"""
Проверка VLESS-конфигов.

VLESS — это НЕ прокси. Нельзя выполнить "handshake" как с MTProto.
Сервер не подтверждает валидность UUID.

Проверка VLESS = TCP + TLS-хендшейк к SNI-домену:
- TCP: сервер отвечает на порт (жёсткий фильтр)
- TLS: сервер завершает рукопожатие под SNI-домен (маскировка работает)
- Probe: SNI-домен реально существует и отвечает (белый IP, не палится при зондировании)
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

for name in (
    "telethon",
    "telethon.network",
    "telethon.client",
    "asyncio",
):
    logging.getLogger(name).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

# ─── Лимиты ────────────────────────────────────────────────────────────
MAX_PING_MS = 5000          # TCP-пинг. GitHub Actions → Азия/Иран часто 4000+
TCP_TIMEOUT = 8             # таймаут TCP-подключения
TLS_TIMEOUT = 8             # таймаут TLS-хендшейка
PROBE_TIMEOUT = 5

_http_session: aiohttp.ClientSession | None = None
_geo_cache: dict[str, dict] = {}
_probe_cache: dict[str, bool] = {}
_geo_semaphore = asyncio.Semaphore(5)
PROBE_CACHE_LIMIT = 5000

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(headers=HEADERS)
    return _http_session


async def close_http_session():
    global _http_session
    if _http_session is not None and not _http_session.closed:
        await _http_session.close()
        _http_session = None


# ─── Скоринг ───────────────────────────────────────────────────────────
def compute_score(key: dict) -> int:
    """VLESS-приоритеты: Reality > Vision > Probe > Ping."""
    score = 10000
    security = (key.get("security") or "").lower()
    if security == "reality":
        score += 3000           # Reality — приоритет, маскируется под реальный сайт
    if key.get("flow") == "xtls-rprx-vision":
        score += 2000           # XTLS-Vision — устойчив к DPI
    if key.get("probe_resistant"):
        score += 1000           # SNI-домен живой → не палится при зондировании
    ping = key.get("ping", 5000)
    return score - min(int(ping), 5000)


# ─── Утилиты ───────────────────────────────────────────────────────────
def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def _resolve_all(host: str) -> list[str]:
    """Все IP хоста, IPv4 в приоритете. Пробуем до 3 адресов."""
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
    if ip in _geo_cache:
        return _geo_cache[ip]
    async with _geo_semaphore:
        session = _get_http_session()
        for attempt in range(3):
            try:
                async with session.get(
                    f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,countryCode,city,isp,query",
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    if r.status == 429:
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    if r.status == 200:
                        data = await r.json()
                        if data.get("status") == "success":
                            _geo_cache[ip] = data
                            return data
                    return {}
            except Exception as e:
                logger.debug("geolocate(%s) #%s: %s", ip, attempt + 1, e)
                await asyncio.sleep(1)
    return {}


# ─── PROBE RESISTANCE TEST (для Reality/TLS) ──────────────────────────
async def check_probe_resistant(domain: str) -> bool:
    """Проверяет, что SNI-домен реально существует и отвечает.
    Если да — VLESS-сервер маскируется под живой сайт и не палится при зондировании."""
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


# ─── TCP CHECK (жёсткий фильтр) ───────────────────────────────────────
async def check_tcp(host: str, port: int) -> int | None:
    """Открывает TCP-соединение и меряет пинг.
    Это единственный жёсткий фильтр для VLESS — если порт не отвечает,
    ключ мёртв."""
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


# ─── TLS CHECK (Reality / TLS) ────────────────────────────────────────
def _tls_handshake_sync(host: str, port: int, sni: str) -> bool:
    """TLS-хендшейк к SNI-домену.
    Для Reality это подтверждает, что VLESS-сервер отвечает и маскируется.
    Для обычного TLS — что сертификат валиден."""
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


# ─── ENRICH ───────────────────────────────────────────────────────────
def _enrich(key: dict, ip: str, ping: int, geo: dict, probe_ok: bool,
            tls_ok: bool) -> dict:
    country_code = geo.get("countryCode", "")
    key.update({
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
    })
    key["score"] = compute_score(key)
    return key


# ─── MAIN PROCESS ─────────────────────────────────────────────────────
async def process_vless(raw: dict) -> dict | None:
    """
    1. Резолв (все IP, IPv4 вперёд)
    2. TCP (жёсткий фильтр, до 3 IP)
    3. TLS-хендшейк (информационно, не отбраковывает)
    4. Probe SNI-домена (информационно, для score)
    5. Гео (опционально, не отбраковывает)
    """
    host = raw.get("ip")
    port = raw.get("port")
    sni = raw.get("sni")
    security = (raw.get("security") or "").lower()

    if not host or not port:
        return None

    # 1. Резолв
    ips = await _resolve_all(host)
    if not ips:
        return None

    # 2. TCP — жёсткий фильтр
    ip = None
    ping: int | None = None
    for candidate in ips[:3]:
        p = await check_tcp(candidate, port)
        if p is not None and p <= MAX_PING_MS:
            ip = candidate
            ping = p
            break

    if ip is None:
        return None

    # 3. TLS-хендшейк — ТОЛЬКО для Reality/TLS, но НЕ отбраковывает
    tls_ok = False
    if security in ("reality", "tls") and sni:
        tls_ok = await check_tls(ip, port, sni)

    # 4. Probe SNI-домена — не отбраковывает
    probe_ok = False
    if sni:
        probe_ok = await check_probe_resistant(sni)

    # 5. Гео — опционально
    geo = await geolocate(ip) or {}

    return _enrich(raw, ip, ping, geo, probe_ok, tls_ok)
