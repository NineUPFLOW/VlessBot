# VLESS Bot

Telegram-бот, который автоматически собирает VLESS-ключи (Reality / TLS / XTLS-Vision) из публичных источников, проверяет их работоспособность и публикует лучшие в указанный чат.

## ✨ Возможности

- Сбор из GitHub-подписок (без Telethon) и Telegram-каналов (через userbot)
- Извлечение из текста, code/pre-блоков, inline-кнопок, подписей к медиа, тем (Topics)
- Фильтр: только `security in ("reality", "tls")`
- Проверка: TCP → TLS-хендшейк → probe SNI-домена → гео
- Приоритет: Reality + PROBE → Reality → XTLS-Vision → по пингу
- Публикация до 10 лучших ключей с готовой `<code>vless://…</code>`
- Дедупликация через SQLite (seen 2ч / published 6ч)
- Персистентность состояния через `actions/cache`
- Уведомления в чат, если публиковать нечего

## 🔐 Секреты (Settings → Secrets and variables → Actions)

| Секрет | Обязательно | Описание |
|---|---|---|
| `BOT_TOKEN` | ✅ | Токен бота от @BotFather |
| `CHAT_ID` | ✅ | ID канала/группы (отрицательный) |
| `TOPIC_ID` | — | ID темы в группе |
| `API_ID` | ✅ | С my.telegram.org |
| `API_HASH` | ✅ | С my.telegram.org |
| `TG_SESSION` | ✅ | StringSession Telethon |

## 🔧 Как получить TG_SESSION

```python
from telethon.sync import TelegramClient
from telethon.sessions import StringSession

with TelegramClient(StringSession(), API_ID, API_HASH) as c:
    print(c.session.save())
```

> ⚠️ Не запускайте один и тот же StringSession параллельно — Telegram инвалидирует сессию.

## 🚀 Запуск

1. Форкните репозиторий.
2. Добавьте секреты.
3. Actions → VLESS Bot → Run workflow.
4. Дальше — по cron каждые 10 минут.

## 🚀 Запуск через cron-job.org (без задержек GitHub)

GitHub Actions `schedule` часто срабатывает с задержкой 10–60 минут. Чтобы запускать бота точно каждые 10 минут:

1. Создайте GitHub Personal Access Token (fine-grained) с правами `Actions: Read and write`:
   https://github.com/settings/personal-access-tokens/new
2. На https://console.cron-job.org создайте задание:
   - **URL:** `https://api.github.com/repos/NineUPFLOW/VlessBot/actions/workflows/run.yml/dispatches`
   - **Method:** POST
   - **Headers:**
     - `Authorization: Bearer <TOKEN>`
     - `Accept: application/vnd.github+json`
     - `Content-Type: application/json`
   - **Body:** `{"ref":"main"}`
   - **Schedule:** `*/10 * * * *`
3. Отключите `schedule` в `run.yml`, чтобы не было двойных запусков.

## 📨 Что публикуется

```
🚀 #6894067 | 🇺🇸 United States

┌ 🔗 Тип: VLESS · Reality · XTLS-Vision
├ 🌐 Транспорт: TCP
├ 📡 Пинг: 60 ms (из 🇺🇸 US-раннера)
├ 🌍 Гео: New York · Inception Hosting Limited
├ 🔒 TLS-хендшейк: ✅ OK
└ 🎭 Reality → yahoo.com 🟢

🔑 VLESS-ключ:
vless://d65cc14c-f53f-4fe2-b262-97856601319c@169.40.42.95:443?...

⏱ Проверено: 14:42:53 МСК
```

## ⚠️ Ограничения

**Не проверяется:**
- Блокировка РКН в РФ
- Доступность в вашем регионе
- Скорость и стабильность под нагрузкой

**Что проверяется:**
- Сервер открывает TCP-порт
- SNI-домен отвечает (маскировка Reality)
- TLS-хендшейк

🟢 у маскировки — SNI-домен живой, 🔴 — SNI-домен не отвечает.

Пинг измеряется из 🇺🇸 US-раннера — из РФ будет выше на 50–150 мс.

## 📜 Лицензия

MIT
