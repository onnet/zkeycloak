# zkeycloak — Keycloak SPI и аутентификация

Приложение `zkeycloak` (`applications/zkeycloak/`) обеспечивает интеграцию Kazoo с Keycloak через OIDC.

**Keycloak SPI** (`keycloak-brt-authenticator/`) — Java-расширение для Keycloak 23.0.3, реализующее единую точку входа.

## Маппинг идентификаторов (KIS owner_id ↔ Keycloak sub)

- При создании КИС-пользователя в Keycloak, его UUID = KIS `owner_id` (в формате с дефисами)
- `addUser(realm, toUuidFormat(ownerId), username, false, false)` — ownerId без дефисов конвертируется в UUID
- `sub` claim в OIDC-токене = owner_id в UUID-формате
- Callback: `zbrt_util:from_key(sub)` возвращает оригинальный KIS owner_id (убирает дефисы)
- Пользователь уже существует в КИС, повторное создание не требуется
- SPI автоматически назначает клиентскую роль `onbill_access` (на `onbill_client`)

## Authentication Flow `brt-unified`

1. Cookie (ALTERNATIVE) — восстановление сессии
2. Kerberos/SPNEGO (ALTERNATIVE) — прозрачная доменная авторизация
3. BRT Multi-Provider (ALTERNATIVE) — кастомная форма (username, password, account_name)
   - `account_name` пустое или `"rast"` → LDAP-авторизация (поиск по username/cn, fallback по email если содержит `@`) → OIDC flow
   - `account_name = "forwarder"` → TOS API → HTTP 302 redirect (без OIDC, без пользователя KC)
   - Любое другое значение → Kazoo API `/v2/user_auth` → OIDC flow

## Конфигурация аутентификатора (Keycloak Admin UI)

- `kazooApiUrl` — URL Kazoo API (`http://10.110.16.32:8000/v2`)
- `tosApiUrl` — URL TOS SSO API
- `tosApiKey` — API-ключ для TOS
- `httpTimeoutMs` — таймаут HTTP-вызовов

## Callback (`cb_zkeycloak_ext.erl`)

- `provide_keycloak_token/3` — обмен OIDC code → Kazoo auth token
- Проверяет наличие роли `onbill_access` в `resource_access.onbill_client.roles` (default `[]`)
- `OwnerId = zbrt_util:from_key(sub)` — извлекает KIS owner_id из Keycloak sub claim

## Деплой

`mvn clean package` → `scp brt-authenticator.jar` → `/opt/keycloak/providers/` → `kc.sh build` → `systemctl restart keycloak`

**Сервер:** `keycloak.brterminal.ru` (10.110.20.50), realm `BRT`, клиент `onbill_client`
