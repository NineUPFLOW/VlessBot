
# VLESS Bot

Telegram-бот, который каждые 10 минут собирает VLESS-конфиги (Reality / XTLS-Vision) из публичных Telegram-каналов, проверяет их работоспособность (TCP + TLS + probe) и публикует лучшие в указанный чат (с поддержкой тем/Topics).

## ✨ Возможности

- Сбор `vless://` из ~22 Telegram-каналов через Telethon userbot
- Извлечение из текста, code/pre-блоков, inline-кнопок, подписей к медиа, тем
- Фильтр: только `security in ("reality", "tls")`
- Проверка: TCP-пинг → TLS-хендшейк к SNI → probe-тест SNI-домена → гео
- Приоритет: Reality + PROBE → Reality → XTLS-Vision → остальные (по пингу)
- Публикация до 10 лучших ключей с готовой `<code>vless://…</code>`
- Дедупликация через SQLite (seen 2ч / published 6ч)
- Персистентность состояния через `actions/cache`
- Уведомления в чат, если публиковать нечего

## 🔐 Секреты (Settings → Secrets and variables → Actions)

| Секрет | Обязательно | Описание |
|---|---|---|
| `BOT_TOKEN` | ✅ | Токен бота от @BotFather |
| `CHAT_ID` | ✅ | ID канала/группы (отрицательный) |
| `TOPIC_ID` | — | ID темы в группе (если нужно) |
| `API_ID` | ✅ | С my.telegram.org |
| `API_HASH` | ✅ | С my.telegram.org |
| `TG_SESSION` | ✅ | StringSession Telethon |

## 🔧 Как получить TG_SESSION

1. Зайдите на https://my.telegram.org → API development tools → получите `api_id` / `api_hash`.
2. Локально: `pip install telethon`, затем скрипт:

   ```python
   from telethon.sync import TelegramClient
   from telethon.sessions import StringSession

   with TelegramClient(StringSession(), API_ID, API_HASH) as c:
       print(c.session.save())
```

3. Скопируйте строку в секрет TG_SESSION.

⚠️ Не запускайте один и тот же StringSession параллельно — Telegram инвалидирует сессию.

🚀 Запуск

1. Форкните репозиторий.
2. Добавьте секреты.
3. Actions → VLESS Bot → Run workflow (первый запуск — вручную).
4. Дальше — по cron каждые 10 минут.

📨 Что публикуется

```
🚀 #1234567 | 🇩🇪 Germany ⬜ БЕЛЫЙ IP

┌ 🏷 Название: 🇩🇪 Germany | My Best Node
├ 🔗 Протокол: 🔹 VLESS · Reality · XTLS-Vision · 🛡 PROBE
├ 📡 Пинг: 42 ms
├ 🌍 Город: Frankfurt
└ 🏢 Провайдер: Hetzner

🔑 Ключ для подключения:
vless://uuid@1.2.3.4:443?...

⏱ Проверено: 12:34:56 | 
```

⚠️ Возможные проблемы

· FloodWait при чтении многих каналов — бот делает паузы и ждёт.
· TLS-хендшейк падает — Reality-прокси может отклонять рукопожатие без валидного pbk; такие ключи отсеиваются.
· ip-api.com 429 — есть retry и кэш.
· Кэш не восстанавливается — если ключи меняются, старые снапшоты всё равно подтягиваются через restore-keys.
· The same session was used in two places — не запускайте локально бота, использующего ту же TG_SESSION, что и Actions.

📜 Лицензия

MIT
