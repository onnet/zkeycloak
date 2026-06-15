# zkeycloak — интеграция Kazoo с Keycloak (OIDC SPI + auth-flow)

`zkeycloak` (`applications/zkeycloak/`, OTP-приложение, vsn 4.0.0) обеспечивает
OIDC-аутентификацию пользователей платформы через Keycloak. Поверх клиентской
библиотеки [`oidcc`](https://hex.pm/packages/oidcc) приложение реализует обмен
OIDC `code` → Kazoo `auth_token`, refresh, Kerberos/SPNEGO-вход и
RP-initiated logout (KC `end_session`). На входе для фронтендов выступает
Crossbar-модуль `cb_zkeycloak_ext`, монтируемый под `/v2/.../zkeycloak_ext`.

Приложение — общий слой логина для **zfront** (web) и **zfield** (mobile).
Web-клиент проходит authorize/callback без PKCE; mobile-клиент (zfield,
AppAuth) обязан использовать PKCE: на `/authorize` отправляет
`code_challenge` (S256), а на обмене `code` → token передаёт исходный
`code_verifier`. Mobile дополнительно работает по своему deep-link
`redirect_uri` (`ru.brt.zfield://oauth/callback`) и хранит KC refresh/id
токены в secure storage под биометрией. Поскольку Crossbar-точка входа — это
прод-нода API (crossbar :8000), `cb_zkeycloak_ext` живёт на **api-нодах**.

## Состав

```
src/
  zkeycloak.app.src            -- OTP application descriptor (vsn 4.0.0, dep oidcc)
  zkeycloak.hrl                -- макросы (?APP_NAME, ?CACHE_NAME)
  zkeycloak_app.erl            -- application callback (declare_exchanges + sup)
  zkeycloak_sup.erl            -- supervisor: cache + listener + oidcc-sup
  zkeycloak_oidcc_sup.erl      -- supervisor над oidcc_provider_configuration_worker
  zkeycloak_listener.erl       -- gen_listener (биндинги zbrt/self, RESPONDER tosdb)
  zkeycloak_handlers.erl       -- AMQP-хендлер tosdb_req/2
  kapi_zkeycloak.erl           -- kapi: resp/publish_resp (targeted)
  zkeycloak_util.erl           -- ядро OIDC: auth_url / retrieve_token / userinfo /
                                  refresh_token / create_user / logout_url / auth_method /
                                  jwt_claims / maybe_keycloak_token*
  crossbar/
    cb_zkeycloak_ext.erl       -- Crossbar-эндпоинты auth-flow
```

При старте `zkeycloak_app:start/2` объявляет AMQP-обмены (`kapi_self`) и
поднимает `zkeycloak_sup`: ETS-кэш `zkeycloak_cache`, `zkeycloak_listener`
(gen_listener) и `zkeycloak_oidcc_sup`, который держит
`oidcc_provider_configuration_worker` — он подтягивает метаданные KC по
`issuer` и регистрирует клиента под именем `client_id_atom()`.

## Конфигурация (`system_config/zkeycloak`)

Читается через `kapps_config` в `zkeycloak_util`:

| Ключ | Назначение |
|---|---|
| `issuer` | Issuer-URL realm KC (база для discovery и `end_session`) |
| `client_id` | OIDC client_id (он же registered name oidcc-воркера) |
| `client_secret` | Секрет confidential-клиента |
| `redirect_uri` | Дефолтный redirect_uri (web-flow zfront) |
| `preferred_auth_methods` | Методы client-auth (дефолт `client_secret_basic`, `client_secret_post`) |
| `kerberos_enabled` | Включает ветку `kerberos_login` (дефолт `false`) |
| `kerberos_idp_hint` | Значение `kc_idp_hint` для брокерного Kerberos-IdP (дефолт `kerberos`) |

## Crossbar API / Auth flow

Эндпоинты `cb_zkeycloak_ext` (методы из `allowed_methods/1`):

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/zkeycloak_ext/auth_link` | Вернуть `auth_url` — ссылку на KC `/authorize` (oidcc redirect URL) |
| GET | `/zkeycloak_ext/auth_callback` | Обмен `code` → Kazoo `auth_token` (см. ниже) |
| GET | `/zkeycloak_ext/kerberos_login` | `auth_url` с `kc_idp_hint` (только при `kerberos_enabled`); поддерживает `prompt=none` |
| GET | `/zkeycloak_ext/logout` | Вернуть `logout_url` (KC RP-initiated end_session) |
| POST | `/zkeycloak_ext/refresh` | Обмен `refresh_token` → новый Kazoo `auth_token` + новые KC-токены |
| GET/POST | `/zkeycloak_ext` | Заглушка (`zkeycloak_ext_post`) — возвращает пустой success |

Все эти ветки помечены `authenticate`/`authorize` как открытые
(`'true'`) — на эндпоинты логина токен ещё не выдан.

**Login (authorize → callback).**
1. Фронт получает `auth_url` из `auth_link` и редиректит пользователя в KC.
2. KC возвращает `code` на `auth_callback`. Из query string берутся:
   - `code` — обязателен;
   - `redirect_uri` — если клиент прислал свой (mobile deep-link), берётся он;
     иначе fallback на `redirect_uri` из конфига (web);
   - `code_verifier` — PKCE-verifier, опционален: mobile передаёт, web — нет.
3. `zkeycloak_util:retrieve_token/3` обменивает `code` на токены KC
   (`pkce_verifier` добавляется в запрос `/token` только если verifier задан),
   далее `retrieve_userinfo/1` берёт userinfo.
4. Проверяется роль: `resource_access.onbill_client.roles` должна содержать
   `onbill_access`; иначе — `insufficient_role`.
5. `provide_keycloak_token/6` выпускает Kazoo `auth_token`
   (`crossbar_auth:create_auth_token/2`). На login-пути user-doc в account-db
   гарантируется (создаётся при отсутствии через `zkeycloak_util:create_user/7`);
   при сбое создания auth не выдаётся (строгий provisioning).

**Refresh.** Тело `{"data":{"refresh_token":"..."}}`.
`zkeycloak_util:refresh_token/1` (try/catch вокруг `oidcc:refresh_token/5`,
с `expected_subject` из `sub` refresh-JWT и `preferred_auth_methods`) ротирует
токены KC, повторно проверяет роль `onbill_access` и наличие user-doc
(на refresh — только проверка существования, без создания), затем выдаёт новый
Kazoo `auth_token`. Любая ошибка KC (`invalid_grant`, отозванный/истёкший
refresh) → `invalid_credentials` (401), и mobile уходит в полный AppAuth-flow.

**Logout.** `logout` строит `logout_url` = `{issuer}/protocol/openid-connect/logout`
с `client_id` и `post_logout_redirect_uri`; если фронт передал в QS
`id_token_hint`, он добавляется — без него KC по OIDC-спеке показывает
confirmation page. Hint фронт берёт из `kc_id_token`, полученного при логине.

## Пробрасываемые / опускаемые JWT-claims

В Kazoo auth-doc (`issue_auth_token/7`, через `props:filter_undefined` —
`undefined`-поля выпадают) кладутся:

- `account_id` — из userinfo `account_id`;
- `owner_id` — `zbrt_util:from_key(sub)` (KC `sub` → KIS owner_id без дефисов);
- `keycloak_resource_access` — целиком `resource_access` из userinfo;
- `kc_full_name` — `given_name` + `family_name`; fallback на `name`, затем
  `preferred_username` (используется `zpaparazzi_authz` для ФИО-match с ЭПЛ);
- `auth_method` — `oidc` либо `kerberos` (определяется по `acr=kerberos` или
  маркерам `kerb`/`kerberos`/`spnego` в `amr`);
- `account_name` — из userinfo, если есть.

В resp_data (`enrich_resp_with_kc_tokens/3`) дополнительно подмешиваются
`kc_refresh_token` и `kc_id_token` — нужны mobile-клиенту (biometric-refresh
и end-session logout); web-клиент эти поля игнорирует. Остальные claims
из KC userinfo в auth-doc целенаправленно не переносятся.

## Валидация KC-токена (для downstream auth)

`zkeycloak_util` экспортирует хелперы для распознавания/проверки KC-токенов
вне callback'а: `maybe_keycloak_token/1` (сравнивает `iss` токена с `issuer`),
`maybe_keycloak_token_validate/2` (для KC-токена требует роль `onbill_access`),
`jwt_claims/1`/`jwt_iss/1`. `auth_method/1` различает OIDC и Kerberos по claims.

## AMQP

`zkeycloak_listener` — `gen_listener` с биндингами `zbrt`/`self` и
RESPONDER'ом на событие `zkeycloak.tosdb` (`zkeycloak_handlers:tosdb_req/2`).
`kapi_zkeycloak` публикует targeted-ответы (`publish_resp/2,3`).

## Замечание о Keycloak SPI (Java)

`CLAUDE.md`/`AGENTS.md` рядом описывают серверную часть — Java-расширение
Keycloak (`keycloak-brt-authenticator`, authentication flow `brt-unified`,
маппинг `sub` ↔ KIS `owner_id`, авто-роль `onbill_access`). Эта часть живёт и
деплоится на стороне сервера Keycloak (`/opt/keycloak/providers/`), а не в этом
Erlang-приложении; здесь — только клиент relying-party.

## Ссылки

- `CLAUDE.md` / `AGENTS.md` (этот каталог) — Keycloak SPI, flow `brt-unified`,
  маппинг идентификаторов и деплой Java-аутентификатора.
- Memory-заметки: `zkeycloak_mobile_pkce` (mobile обязан verifier, web без PKCE),
  `zfront_kc_logout_option_a` (logout всегда зовёт end_session с id_token_hint,
  `auth_method` дефолт `oidc`), `zkeycloak_jwt_claims_lost` (часть claims при
  пробросе отбрасывается).

Отдельного плана в `docs/superpowers/plans/` / `plans_implemented/` для
zkeycloak нет — изменения шли точечными коммитами (PKCE, refresh, logout,
строгий provisioning); см. `git log` каталога.
