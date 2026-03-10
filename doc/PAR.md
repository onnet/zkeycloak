# PAR (Pushed Authorization Requests) и SPNEGO/Kerberos

## Проблема

Библиотека `oidcc` 3.6.0 автоматически использует PAR и Request Object JWT,
если Keycloak рекламирует соответствующие эндпоинты в `.well-known/openid-configuration`:

- `pushed_authorization_request_endpoint` → oidcc использует PAR
- `request_parameter_supported: true` → oidcc оборачивает параметры в подписанный JWT

### PAR + SPNEGO несовместимы

PAR-токены (`request_uri`) являются **одноразовыми** (single-use). SPNEGO/Kerberos
аутентификация в Keycloak использует HTTP 401 challenge-response:

1. Browser → `GET /auth?request_uri=urn:...` → Keycloak **потребляет** PAR,
   создаёт auth session, устанавливает cookies
2. Keycloak → `401 + WWW-Authenticate: Negotiate` (SPNEGO challenge)
3. Browser автоматически **повторяет** тот же запрос (с Kerberos-тикетом или без)
4. Keycloak получает повторный запрос с тем же `request_uri` →
   PAR уже потреблён → **"PAR not found. not issued or used multiple times."**

Браузер при автоматическом retry после 401 может не включать cookies
(`AUTH_SESSION_ID`, `KC_RESTART`) из ответа на шаг 1, поэтому Keycloak
не может найти auth session и пытается заново обработать `request_uri`.

### Request Object JWT + PAR

Отдельная проблема: когда `request_parameter_supported: true`, oidcc создаёт
подписанный JWT (Request Object) с параметрами авторизации и включает его
в PAR POST. Keycloak 23.0.3 некорректно обрабатывает комбинацию PAR + Request Object,
даже если PAR POST формально возвращает `request_uri`.

## Диагностика

### Ручной тест PAR (curl)

```bash
# 1. PAR POST с plain параметрами
curl -sk -X POST \
  'https://keycloak.brterminal.ru/realms/BRT/protocol/openid-connect/ext/par/request' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=onbill_client&client_secret=SECRET&response_type=code&redirect_uri=https%3A%2F%2Fbrterminal.ru%2Fext%2Flogin&scope=openid'
# Ожидаемый ответ: {"request_uri": "urn:ietf:params:oauth:request_uri:UUID", "expires_in": 60}

# 2. Проверка PAR-токена (выполнить сразу после п.1)
curl -sk -o /dev/null -w '%{http_code}' \
  'https://keycloak.brterminal.ru/realms/BRT/protocol/openid-connect/auth?request_uri=URN_FROM_STEP_1&client_id=onbill_client'
# 401 = PAR найден (SPNEGO challenge), 400 = PAR не найден
```

PAR работает корректно с одиночными запросами (curl). Проблема возникает
только при SPNEGO retry в браузере.

## Решение

Патч `deps/oidcc/src/oidcc_authorization.erl` — две модификации:

### 1. Request Object: только когда требуется

В `attempt_request_object`, первый clause теперь матчится только при
`require_signed_request_object = true` (было: `request_parameter_supported = true`).
Когда Request Object опционален, используются plain параметры.

### 2. PAR: только когда требуется

В `attempt_par`, рабочий clause теперь матчится только при
`require_pushed_authorization_requests = true`. Когда PAR опционален
(как в Keycloak 23.0.3 с `require_pushed_authorization_requests: false`),
используются plain query параметры в auth URL.

Plain параметры не одноразовые и корректно работают с SPNEGO 401 retry.

## Конфигурация

Keycloak `.well-known/openid-configuration`:

```
require_pushed_authorization_requests: false  → PAR не используется (plain params)
require_pushed_authorization_requests: true   → PAR используется
request_parameter_supported: true             → Request Object не создаётся (если не required)
require_signed_request_object: true           → Request Object создаётся и подписывается
```

## Включение PAR в будущем

Если Keycloak исправит взаимодействие PAR + SPNEGO (или SPNEGO будет отключён),
PAR можно включить через настройки клиента `onbill_client` в Keycloak Admin Console:
Client → Advanced → Pushed Authorization Request → Required.
