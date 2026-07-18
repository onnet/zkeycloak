-module(zkeycloak_util).

-export([auth_url/0
        ,auth_url/1
        ,issuer/0
        ,client_id_atom/0
        ,client_id/0
        ,client_secret/0
        ,redirect_uri/0
        ,is_configured/0
        ,preferred_auth_methods/0
        ,retrieve_token/1
        ,retrieve_token/2
        ,retrieve_token/3
        ,retrieve_userinfo/1
        ,introspect_token/1
        ,refresh_token/1
        ,create_user/7
        ,jwt_claims/1
        ,jwt_iss/1
        ,maybe_keycloak_token/1
        ,maybe_keycloak_token_validate/2
        ,kerberos_enabled/0
        ,kerberos_idp_hint/0
        ,kerberos_auth_url/0
        ,kerberos_auth_url/1
        ,auth_method/1
        ,logout_url/0
        ,logout_url/1
        ,redact/1
        ,redact_headers/1
        ,redact_req_data/1
        ,claims_digest/1
        ,redact_provisioning_error/1
        ,redact_reason/1
        ,redact_token_result/1
        ]
       ).

-ifdef(TEST).
%% Внутренние санитайзеры лога, открытые для EUnit (`zkeycloak_util_tests').
%% В прод-API не выносим: наружу нужны только `redact*'/`claims_digest',
%% остальное — детали конкретных лог-строк этого модуля.
-export([redact_pii/1
        ,redact_validation_errors/1
        ,redact_crash/1
        ,redact_stack/1
        ,jwt_sub_unverified/1
        ]).
-endif.

%% @doc HTTP-заголовки, ЗНАЧЕНИЯ которых нельзя писать в лог сырыми: несут
%% живой Bearer-токен (`authorization'), Kazoo auth-token (`x-auth-token'),
%% session-cookie или proxy-креды. Имена сравниваем в нижнем регистре
%% (cowboy уже отдаёт lower-case, но нормализуем для устойчивости к
%% proplist-форме). См. `redact_headers/1' (issue 14 KC-auth ревью).
-define(SENSITIVE_HEADERS, [<<"authorization">>
                           ,<<"proxy-authorization">>
                           ,<<"cookie">>
                           ,<<"set-cookie">>
                           ,<<"x-auth-token">>
                           ]).

%% @doc Ключи ТЕЛА запроса, ЗНАЧЕНИЯ которых нельзя писать в лог сырыми.
%% Список ground'ится по именам, реально ходящим через этот app (grep по
%% коду), а не по догадкам:
%%   `refresh_token'  — тело `POST /zkeycloak_ext/refresh' — ЖИВОЙ токен на
%%                      ~30 дней (Offline Session Idle realm'а BRT);
%%   `kc_refresh_token'/`kc_id_token' — те же токены в нашей же resp_data
%%                      (`enrich_resp_with_kc_tokens/3'): клиент штатно
%%                      получает их от нас и может прислать обратно;
%%   `id_token_hint'  — сырой id_token (logout-флоу, `logout_url/1');
%%   `code'/`code_verifier' — обменный материал (одноразовый, но до обмена
%%                      валидный; тот же класс, что закрыл issue 01);
%%   `password'       — `create_user/7' Props + форма `brt-unified' flow;
%%   `client_secret'  — кред клиента `onbill_client' (config-ключ);
%%   `access_token'/`id_token'/`auth_token' — канонические имена ровно того
%%                      материала, которым оперирует модуль (`x-auth-token'
%%                      по той же причине уже в ?SENSITIVE_HEADERS).
%% `code_challenge' в списке НЕТ намеренно: он публичен по дизайну PKCE
%% (см. комментарий `kerberos_auth_url/1'). См. `redact_req_data/1' (issue 15).
-define(SENSITIVE_BODY_KEYS, [<<"refresh_token">>
                             ,<<"kc_refresh_token">>
                             ,<<"kc_id_token">>
                             ,<<"id_token_hint">>
                             ,<<"code">>
                             ,<<"code_verifier">>
                             ,<<"password">>
                             ,<<"client_secret">>
                             ,<<"access_token">>
                             ,<<"id_token">>
                             ,<<"auth_token">>
                             ]).

%% @doc Claim'ы KC (id_token / userinfo), значения которых МОЖНО писать в
%% лог: служебные поля OIDC-флоу и гейтов этого модуля, к ПДн не относящиеся.
%%
%% Подход — БЕЛЫЙ список, а не поимённый redact чувствительных ключей:
%% состав userinfo задаётся мапперами realm'а НА СТОРОНЕ KC, и новый
%% ПДн-claim (телефон, отдел, СНИЛС…) не должен утекать в лог по умолчанию
%% просто потому, что мы про него ещё не знали. Значения вне списка не
%% печатаются никогда; печатаются только ИМЕНА (`redacted_keys' в
%% `claims_digest/1') — имя claim'а это схема, а не данные, и по нему
%% оператор видит, что KC начал отдавать новое поле. Имя в `redacted_keys'
%% заодно работает presence-флагом («`family_name' пришёл?») — этого
%% достаточно для штатной диагностики, значение для неё не нужно.
%%
%% Почему именно эти:
%%   `sub'             — субъект = KIS owner_id, ключ корреляции всего флоу
%%                       (и так логируется как `owner_id' в cb_zkeycloak_ext);
%%   `iss'/`azp'/`aud' — realm/клиент: диагностика «токен не нашего issuer'а»;
%%   `session_state'/`sid' — корреляция с session-логами самого KC;
%%   `acr'/`amr'       — маркеры Kerberos vs password: `auth_method/1' читает
%%                       ровно их, и `auth_method' уходит в auth-doc;
%%   `exp'/`iat'/`auth_time'/`typ' — сроки жизни: диагностика `invalid_grant';
%%   `scope'           — запрошен ли `offline_access' (без него KC не даст
%%                       refresh — прямая причина поломки biometric-флоу);
%%   `resource_access'/`realm_access' — РОЛИ: гейт `onbill_access'
%%                       (`authorize_and_issue/6') читает их из userinfo, и
%%                       штатный отказ «выключен маппер Add to userinfo →
%%                       роли пусты → молча деним всех» (issue 13) без них
%%                       не диагностируется в принципе;
%%   `account_id'      — Kazoo-account из KazooAuth-claim'а (гейт issue 10).
%% ПДн (`email', `preferred_username' (= логин, часто почта), `given_name',
%% `family_name', `name', `phone_number', …) в список НЕ входят намеренно.
-define(LOG_SAFE_CLAIMS, [<<"sub">>
                         ,<<"iss">>
                         ,<<"azp">>
                         ,<<"aud">>
                         ,<<"session_state">>
                         ,<<"sid">>
                         ,<<"acr">>
                         ,<<"amr">>
                         ,<<"exp">>
                         ,<<"iat">>
                         ,<<"auth_time">>
                         ,<<"typ">>
                         ,<<"scope">>
                         ,<<"resource_access">>
                         ,<<"realm_access">>
                         ,<<"account_id">>
                         ]).

%% @doc Ключи внутри ошибок валидации (`kzd_users:validate/3'), под которыми
%% лежит ЭХО отвергнутого значения, т.е. ПДн из claim'ов KC. Живой путь:
%% `kzd_users:maybe_validate_username_is_unique/3' кладёт `{<<"cause">>,
%% Username}', а `create_user/7' подставляет в `username' именно `Email' —
%% т.е. коллизия username'а печатала email целиком. Схемные отказы
%% (`kz_json_schema:error_to_jobj/2') кладут отвергнутое значение в
%% `value'/`cause' — то же самое для `first_name'/`last_name'/`email'.
%% См. `redact_validation_errors/1' (issue 15).
-define(SENSITIVE_ERROR_KEYS, [<<"value">>
                              ,<<"cause">>
                              ]).

%% Префикс секрета в логе и минимальная длина, при которой его вообще есть
%% смысл печатать: 6 из >=24 байт — малая доля, 6 из 7 — весь секрет.
-define(REDACT_PREFIX_LEN, 6).
-define(REDACT_MIN_LEN_FOR_PREFIX, 24).

-define(MK_USER,
        {[{<<"enabled">>, 'true'}
         ,{<<"priv_level">>,<<"user">>}
         ,{<<"vm_to_email_enabled">>,true}
         ,{<<"fax_to_email_enabled">>,true}
         ,{<<"verified">>,false}
         ,{<<"timezone">>,<<"UTC">>}
         ,{<<"record_call">>,false}
         ,{<<"pvt_type">>, kzd_users:type()}
         ]}).

-define(ISSUER_UNSET, <<"issuer">>).

-spec issuer() -> kz_term:ne_binary().
issuer() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"issuer">>, ?ISSUER_UNSET).

-spec client_id_atom() -> atom().
client_id_atom() ->
    kapps_config:get_atom(<<"zkeycloak">>, <<"client_id">>, 'client_id').

-spec client_id() -> kz_term:ne_binary().
client_id() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"client_id">>, <<"client_id">>).

-spec client_secret() -> kz_term:ne_binary().
client_secret() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"client_secret">>, <<"client_secret">>).

-spec redirect_uri() -> kz_term:ne_binary().
redirect_uri() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"redirect_uri">>, <<"redirect_uri">>).

%% @doc Настроен ли KC на этой ноде: `issuer' задан (не дефолт-плейсхолдер)
%% и похож на http(s)-URL. Используется, чтобы (а) не поднимать oidcc
%% discovery-воркер вхолостую и (б) короткозамкнуть валидацию KC-токенов.
-spec is_configured() -> boolean().
is_configured() ->
    case issuer() of
        ?ISSUER_UNSET -> 'false';
        Issuer -> is_http_url(Issuer)
    end.

-spec is_http_url(kz_term:ne_binary()) -> boolean().
is_http_url(<<"http://", _/binary>>) -> 'true';
is_http_url(<<"https://", _/binary>>) -> 'true';
is_http_url(_) -> 'false'.

-spec preferred_auth_methods() -> kz_term:ne_binary().
preferred_auth_methods() ->
    case kapps_config:get(<<"zkeycloak">>, <<"preferred_auth_methods">>, [client_secret_basic, client_secret_post]) of
        L when is_list(L) ->
            [kz_term:to_atom(V, 'true') || V <- L];
        _ -> []
    end.

-spec auth_url() -> kz_term:ne_binary().
auth_url() ->
    auth_url('undefined').

%% @doc Auth URL с опциональным PKCE `code_challenge' (S256) для web-flow
%% (issue 04 KC-auth ревью — authorization-code-injection). Web-клиент
%% (zfront) генерирует `code_verifier'+`code_challenge' на своей стороне,
%% кладёт verifier в sessionStorage и присылает СЮДА только challenge. Мы
%% прокидываем `code_challenge'+`code_challenge_method=S256' в /authorize
%% через `url_extension' — тем же механизмом, что `kerberos_auth_url/1'
%% добавляет `kc_idp_hint'. oidcc сам PKCE не считает (для этого ему нужен
%% verifier, которого у бэкенда нет), поэтому raw-параметры через
%% url_extension — единственный корректный путь. Verifier участвует уже в
%% /token обмене (`retrieve_token/3'), который PKCE-плумбинг уже умеет.
%% `CodeChallenge='undefined'' → web-без-PKCE (обратная совместимость).
-spec auth_url(kz_term:api_ne_binary()) -> kz_term:ne_binary().
auth_url(CodeChallenge) ->
    lager:info("zkeycloak auth_url: issuer=~s client_id=~s redirect_uri=~s pkce=~s",
               [issuer(), client_id(), redirect_uri(),
                case CodeChallenge of 'undefined' -> <<"no">>; _ -> <<"yes">> end]),
    Result =
        oidcc:create_redirect_url(
          client_id_atom()
         ,client_id()
         ,client_secret()
         ,auth_url_opts(CodeChallenge)
         ),
    lager:info("zkeycloak auth_url oidcc result: ~p", [Result]),
    {ok, RedirectUri} = Result,
    Url = kz_binary:join(RedirectUri, <<"">>),
    lager:info("zkeycloak auth_url final: ~s", [Url]),
    Url.

%% @doc Opts для `oidcc:create_redirect_url' — с PKCE-challenge (S256) или без.
-spec auth_url_opts(kz_term:api_ne_binary()) -> map().
auth_url_opts('undefined') ->
    #{'redirect_uri' => redirect_uri()
     ,'preferred_auth_methods' => preferred_auth_methods()
     };
auth_url_opts(CodeChallenge) ->
    #{'redirect_uri' => redirect_uri()
     ,'preferred_auth_methods' => preferred_auth_methods()
     ,'url_extension' => [{<<"code_challenge">>, CodeChallenge}
                         ,{<<"code_challenge_method">>, <<"S256">>}
                         ]
     }.

-spec kerberos_enabled() -> boolean().
kerberos_enabled() ->
    kapps_config:get_is_true(<<"zkeycloak">>, <<"kerberos_enabled">>, 'false').

-spec kerberos_idp_hint() -> kz_term:ne_binary().
kerberos_idp_hint() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"kerberos_idp_hint">>, <<"kerberos">>).

-spec kerberos_auth_url() -> kz_term:ne_binary().
kerberos_auth_url() ->
    kerberos_auth_url(#{}).

-spec kerberos_auth_url(map()) -> kz_term:ne_binary().
kerberos_auth_url(ExtraOpts) ->
    BaseExtension = [{<<"kc_idp_hint">>, kerberos_idp_hint()}],
    PromptExtension = case maps:get('prompt', ExtraOpts, 'undefined') of
        'undefined' -> [];
        Prompt -> [{<<"prompt">>, Prompt}]
    end,
    %% PKCE и для Kerberos-flow (Fable-review issue 04): callback-обмен у
    %% web-клиента прикладывает verifier из sessionStorage к любому code —
    %% code, выданный /authorize БЕЗ challenge, KC отверг бы (invalid_grant).
    %% Заодно Kerberos-code получает ту же защиту от code-injection.
    %% 'undefined' → без PKCE (обратная совместимость со старым фронтом).
    PkceExtension = case maps:get('code_challenge', ExtraOpts, 'undefined') of
        'undefined' -> [];
        CodeChallenge -> [{<<"code_challenge">>, CodeChallenge}
                         ,{<<"code_challenge_method">>, <<"S256">>}
                         ]
    end,
    lager:info("zkeycloak kerberos_auth_url: issuer=~s client_id=~s redirect_uri=~s pkce=~s",
               [issuer(), client_id(), redirect_uri(),
                case PkceExtension of [] -> <<"no">>; _ -> <<"yes">> end]),
    Result =
        oidcc:create_redirect_url(
          client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{'redirect_uri' => redirect_uri()
           ,'preferred_auth_methods' => preferred_auth_methods()
           ,'url_extension' => BaseExtension ++ PromptExtension ++ PkceExtension
           }
         ),
    lager:info("zkeycloak kerberos_auth_url oidcc result: ~p", [Result]),
    {ok, RedirectUri} = Result,
    Url = kz_binary:join(RedirectUri, <<"">>),
    lager:info("zkeycloak kerberos_auth_url final: ~s", [Url]),
    Url.

-spec retrieve_token(kz_term:ne_binary()) ->
          {'ok', tuple()} | {'error', any()}.
retrieve_token(AuthCode) ->
    retrieve_token(AuthCode, redirect_uri()).

%% @doc Token exchange c явным redirect_uri (от клиента).
%% Нужно для mobile-клиентов (zfield) — они проходят /authorize через
%% свой deep-link (`ru.brt.zfield://oauth/callback`), а KC требует
%% совпадения redirect_uri в /authorize и /token. Web (zfront) шлёт
%% свой redirect_uri в QS либо вызывает retrieve_token/1 (default
%% config) — обратная совместимость сохранена.
-spec retrieve_token(kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', tuple()} | {'error', any()}.
retrieve_token(AuthCode, RedirectUri) ->
    retrieve_token(AuthCode, RedirectUri, 'undefined').

%% @doc Token exchange c явным redirect_uri и опциональным PKCE verifier'ом.
%% Mobile-клиенты (zfield) проходят /authorize через AppAuth, который
%% автоматически генерирует `code_verifier` + `code_challenge=S256`.
%% KC привязывает code к challenge'у — в /token нужен исходный verifier,
%% иначе KC отвечает 'invalid_grant: PKCE code verifier not specified'.
%% Web-flow без PKCE передаёт PkceVerifier='undefined' — opts без
%% pkce_verifier, oidcc не добавит его в /token request.
-spec retrieve_token(kz_term:ne_binary(), kz_term:ne_binary(), kz_term:api_ne_binary()) ->
          {'ok', tuple()} | {'error', any()}.
retrieve_token(AuthCode, RedirectUri, PkceVerifier) ->
    lager:info("zkeycloak retrieve_token redirect_uri: ~s pkce: ~s",
               [RedirectUri, case PkceVerifier of 'undefined' -> <<"no">>; _ -> <<"yes">> end]),
    BaseOpts = #{'redirect_uri' => RedirectUri
                ,'preferred_auth_methods' => preferred_auth_methods()
                },
    Opts = case PkceVerifier of
               'undefined' -> BaseOpts;
               _ -> BaseOpts#{'pkce_verifier' => PkceVerifier}
           end,
    %% `oidcc:retrieve_token/5' по спеке отдаёт `{ok, oidcc_token:t()}' на
    %% успехе, но на ошибке KC (invalid_grant: битый/просроченный/уже-
    %% использованный `code', PKCE-mismatch, KC недоступен) ЛИБО возвращает
    %% `{error,_}', ЛИБО выбрасывает исключение (парсинг JWT / http / JWKS —
    %% ровно как в `refresh_token/1'). Заворачиваем в try-catch и нормализуем
    %% к единому `{ok,_} | {error,_}' контракту — иначе жёсткий матч
    %% `{ok,Token} = ...' давал badmatch, и callback
    %% `cb_zkeycloak_ext:validate(?AUTH_CALLBACK)' отвечал Crossbar-500 вместо
    %% чистого 401 `invalid_credentials' (issue 05 кросс-слойного KC-auth ревью).
    normalize_oidcc(<<"retrieve_token">>,
                    fun() ->
                            oidcc:retrieve_token(
                              AuthCode
                             ,client_id_atom()
                             ,client_id()
                             ,client_secret()
                             ,Opts
                             )
                    end).

-spec retrieve_userinfo(tuple() | kz_term:ne_binary()) ->
          {'ok', map()} | {'error', any()}.
retrieve_userinfo(Token) ->
    %% Та же нормализация, что и `retrieve_token/3' (issue 05): userinfo
    %% зовётся уже после успешного обмена, но всё равно может дать `{error,_}'
    %% / исключение (сетевой сбой к KC) — не роняем Crossbar в 500.
    normalize_oidcc(<<"retrieve_userinfo">>,
                    fun() ->
                            oidcc:retrieve_userinfo(
                              Token
                             ,client_id_atom()
                             ,client_id()
                             ,client_secret()
                             ,#{}
                             )
                    end).

-spec introspect_token(tuple() | kz_term:ne_binary()) ->
          {'ok', tuple()} | {'error', any()}.
introspect_token(Token) ->
    %% Нормализация под общий контракт (issue 05). Вызывающих сейчас нет, но
    %% держим арность в едином fail-safe виде с остальными oidcc-обёртками.
    normalize_oidcc(<<"introspect_token">>,
                    fun() ->
                            oidcc:introspect_token(
                              Token
                             ,client_id_atom()
                             ,client_id()
                             ,client_secret()
                             ,#{}
                             )
                    end).

%% @doc Общий нормализатор результата oidcc-вызова к `{ok,_} | {error,_}'.
%% oidcc 3.x на сбое ЛИБО возвращает `{error,_}', ЛИБО бросает исключение
%% (зависит от этапа: парсинг JWT / http-ответ KC / JWKS-валидация). Ловим
%% оба и сводим к единому контракту, чтобы Crossbar-callback'и не падали в
%% badmatch-500 (issue 05). `Tag' — имя вызова для лога. Сам `~p'-результат
%% НЕ логируем на успехе: там живые bearer-токены (issue 01).
-spec normalize_oidcc(kz_term:ne_binary(), fun(() -> any())) ->
          {'ok', any()} | {'error', any()}.
normalize_oidcc(Tag, Fun) ->
    try Fun() of
        {'ok', _} = Ok -> Ok;
        {'error', _} = Err ->
            %% P3 (кросс-ревью 18.07): `Reason' oidcc-ошибки печатался сырым —
            %% редактируем встроенное в него значение (redact_reason/1 —
            %% no-op для протокольных ошибок, но чистит `{badmatch,V}' и пр.).
            lager:info("zkeycloak ~s oidcc error: ~p", [Tag, redact_reason(Err)]),
            Err;
        Other ->
            %% P3 (кросс-ревью 18.07): неузнанная форма oidcc-результата
            %% печаталась сырой — fail-open дрейф формы токена (если это
            %% `{ok,<token>}' с ЖИВЫМИ токенами, `~p' их бы слил; для
            %% refresh_token тот же класс уже закрыт через redact_token_result).
            %% Логируем и ПРОБРАСЫВАЕМ санитизированную форму, чтобы она не
            %% доехала сырой до `cb_zkeycloak_ext' (`~p' от Reason там).
            RedactedOther = redact_token_result(Other),
            lager:warning("zkeycloak ~s unexpected oidcc result: ~s", [Tag, RedactedOther]),
            {'error', {'unexpected_oidcc_result', RedactedOther}}
    catch
        Class:Reason:Stack ->
            %% issue 15 (review-loop): `Stack' печатался сырым, а обёрнутые
            %% тут вызовы — `oidcc:retrieve_token(AuthCode, _, ClientId,
            %% ClientSecret, _)' и пр., т.е. фрейм с аргументами несёт и
            %% `code', и `client_secret()'. Печатаем M:F/A без args.
            %% P3 (кросс-ревью 18.07): `Reason' тоже печатался сырым, а
            %% `error:{badmatch,V}'/`{case_clause,V}'/`{badmap,M}' встраивают
            %% значение (декодированные claim-байты из `jwt_sub_unverified/1'
            %% и т.п.). Чистим `Reason' И в логе, И в проброшенном наверх
            %% `{Class, Reason}' (тот доезжает до лога `cb_zkeycloak_ext').
            RedactedReason = redact_reason(Reason),
            lager:warning("zkeycloak ~s exception ~p:~p stack=~p",
                          [Tag, Class, RedactedReason, redact_stack(Stack)]),
            {'error', {Class, RedactedReason}}
    end.

%% @doc Обмен refresh_token → новый набор токенов (access + refresh + id_token).
%% Зfield (mobile) хранит refresh_token в secure_storage под BiometricPrompt и
%% дёргает эту функцию через `POST /zkeycloak_ext/refresh' — взамен полного
%% AppAuth-flow на КЛ-форме. Для нашей конфигурации realm (Offline Session
%% Idle = 30 дней, Max = unlimited, scope `offline_access' запрашивается явно
%% клиентом) KC возвращает новый refresh_token при каждом успешном вызове;
%% старый остаётся валидным (`Revoke Refresh Token' = Disabled) — это
%% упрощает retry-пайплайн на стороне Flutter (race-condition безопасен).
%%
%% oidcc 3.x при невалидном refresh может ЛИБО вернуть `{error, _}', ЛИБО
%% выбросить exception (зависит от того, на каком этапе сломалось — парсинг
%% JWT, http-ответ от KC, JWKS-валидация). Заворачиваем в try-catch и
%% нормализуем к единому `{ok, _} | {error, _}' контракту — без этого
%% `cb_zkeycloak_ext:handle_refresh' получал crash и Crossbar отвечал 500.
-spec refresh_token(kz_term:ne_binary()) ->
          {'ok', tuple()} | {'error', any()}.
refresh_token(RefreshToken) ->
    lager:info("zkeycloak refresh_token: client_id=~s", [client_id()]),
    try
        %% oidcc 3.x требует `expected_subject' в opts — защита от
        %% substitute-атаки (KC не должен подменить user'а при refresh).
        %% Берём sub из payload refresh JWT — он совпадает с sub нового
        %% id_token (это и есть инвариант, который oidcc проверяет).
        %% Без этой опции `oidcc_token:refresh/3' падает на line 544
        %% `map_get(expected_subject, Opts) -> badkey'.
        %%
        %% Парсим refresh БЕЗ верификации подписи: KC подписывает refresh
        %% HS256 (client-secret), а `kz_auth_jwt' умеет только asymmetric
        %% (RS256/ES256). Это OK — мы не проверяем подлинность здесь,
        %% криптографическую верификацию делает сам KC при /token/refresh.
        %% Если refresh битый — oidcc вернёт invalid_grant.
        ExpectedSub = jwt_sub_unverified(RefreshToken),
        lager:info("zkeycloak refresh_token expected_subject=~s", [ExpectedSub]),
        %% `preferred_auth_methods' нужен, иначе oidcc выбирает дефолтный
        %% client-auth метод, который KC отвергает для confidential client
        %% `onbill_client': получаем "unauthorized_client / Invalid client
        %% credentials". В `retrieve_token' это уже передаётся (line 151),
        %% забывать в refresh нельзя.
        Opts = #{'expected_subject' => ExpectedSub
                ,'preferred_auth_methods' => preferred_auth_methods()
                },
        Result =
            oidcc:refresh_token(
              RefreshToken
             ,client_id_atom()
             ,client_id()
             ,client_secret()
             ,Opts
             ),
        %% Result содержит новый набор живых токенов (access/refresh/id) —
        %% сырой `~p' = 30-дневный replay при утечке логов (issue 01 KC-auth).
        %% Логируем санитизированную структуру: префикс+длина вместо токенов.
        lager:info("zkeycloak refresh_token oidcc result: ~s", [redact_token_result(Result)]),
        case Result of
            {'ok', _} -> Result;
            {'error', _} -> Result;
            %% P3 (кросс-ревью 18.07): пробрасываем санитизированную форму —
            %% дрейфнувший `{ok,<token>}' не должен доехать сырым до
            %% `cb_zkeycloak_ext:handle_refresh' (там `~p' от Other). Result
            %% в лог уже ушёл выше через redact_token_result.
            Other -> {'error', {'unexpected_oidcc_result', redact_token_result(Other)}}
        end
    catch
        Class:Reason:Stack ->
            %% issue 15 (review-loop): тот же класс — во фрейме `oidcc:
            %% refresh_token(RefreshToken, …, ClientSecret, …)' лежат живой
            %% refresh и client_secret; `base64:decode/2' (BIF-badarg в
            %% `jwt_sub_unverified/1') кладёт во фрейм payload-сегмент JWT.
            %% P3 (кросс-ревью 18.07): `Reason' тоже — `error:{badmatch,V}' и
            %% пр. встраивают несовпавшее значение (payload/claim-байты).
            %% Чистим `Reason' в логе И в проброшенном `{Class, Reason}'.
            RedactedReason = redact_reason(Reason),
            lager:warning("zkeycloak refresh_token exception ~p:~p stack=~p",
                          [Class, RedactedReason, redact_stack(Stack)]),
            {'error', {Class, RedactedReason}}
    end.

%% @doc Маскирование bearer-кред (access/refresh/id token, code_verifier,
%% authorization code) для лога. Печатаем только короткий префикс + длину —
%% этого достаточно для корреляции лог-строк, но НЕ для реплея валидной
%% сессии. Сырой токен в логах = 30-дневный replay при утечке лог-архива
%% (issue 01 кросс-слойного KC-auth ревью). `lager'-вызов сохраняем —
%% редактируем только ЗНАЧЕНИЕ (правило проекта: не вырезать lager).
%%
%% Домен — `any()', а не `api_binary()': фактический (спека врала — issue 15).
%% `redact_header_kv/2' кормит сюда `term()' (значение заголовка), а
%% `redact_req_data_kv/2' — произвольный `kz_json:json_term()' из ТЕЛА
%% запроса, форму которого диктует КЛИЕНТ и до аутентификации
%% (`authorize/1' отрабатывает раньше неё).
%%
%% Отсюда же тотальность: `kz_term:to_binary/1' ЧАСТИЧЕН — на JSON-массиве
%% из объектов/чисел >255 (`iolist_to_binary' → badarg) и на map он падает.
%% Без `try' тело вида `{"refresh_token":[{"x":1}]}' роняло бы `authorize/1'
%% в Crossbar-500 (тот же класс, что чинили issue 05/07/10: чистый ответ
%% вместо badmatch-500), причём неаутентифицированным запросом. Секрет при
%% этом всё равно не печатаем — на любой непечатаемой форме отдаём сентинел.
%%
%% Префикс печатается ТОЛЬКО у значений от ?REDACT_MIN_LEN_FOR_PREFIX байт:
%% у короткого секрета `min(6, Len)' выдавал его целиком (`redact(<<"hunter2">>)'
%% → `<<"hunter..(len=7)">>'). Для issue 01 это не стреляло — там только
%% JWT/hex-креды в сотни байт, — но issue 15 завёл в ?SENSITIVE_BODY_KEYS
%% `password', который короткий по природе. Ниже порога печатаем только длину.
-spec redact(any()) -> kz_term:ne_binary().
redact('undefined') -> <<"undefined">>;
redact(<<>>) -> <<"empty">>;
redact(Value) when is_binary(Value), byte_size(Value) < ?REDACT_MIN_LEN_FOR_PREFIX ->
    <<"redacted(len=", (integer_to_binary(byte_size(Value)))/binary, ")">>;
redact(Value) when is_binary(Value) ->
    Len = byte_size(Value),
    Prefix = binary:part(Value, 0, ?REDACT_PREFIX_LEN),
    <<Prefix/binary, "..(len=", (integer_to_binary(Len))/binary, ")">>;
redact(Value) ->
    try redact(kz_term:to_binary(Value))
    catch
        _Class:_Reason -> <<"redacted(unprintable)">>
    end.

%% @doc Маскирование ПДн-значения (email/ФИО, эхнутые KC или валидатором).
%% В отличие от `redact/1' префикс НЕ печатаем совсем, по двум причинам:
%% (а) 6 байт email'а/ФИО — это всё ещё ПДн, корреляция по ним не нужна
%% (для неё есть `owner_id'/`account_id'); (б) ФИО в UTF-8 (кириллица —
%% 2 байта на символ), и побайтовый префикс режет символ пополам → в лог
%% уходит битый UTF-8. Печатаем только факт и длину (issue 15).
-spec redact_pii(any()) -> kz_term:ne_binary().
redact_pii('undefined') -> <<"undefined">>;
redact_pii(<<>>) -> <<"empty">>;
redact_pii(Value) when is_binary(Value) ->
    <<"redacted(len=", (integer_to_binary(byte_size(Value)))/binary, ")">>;
redact_pii(Value) ->
    try redact_pii(kz_term:to_binary(Value))
    catch
        _Class:_Reason -> <<"redacted(unprintable)">>
    end.

%% @doc Санитизация HTTP-заголовков перед логированием: значения
%% credential-заголовков (`authorization', `cookie', `x-auth-token' и пр.,
%% см. `?SENSITIVE_HEADERS') несут живой Bearer-токен / Kazoo auth-token /
%% session-cookie — сырой `~p'-дамп `cb_context:req_headers/1' в лог = утечка
%% (issue 14 кросс-слойного KC-auth ревью; тот же класс, что issue 01 про
%% токены). Маскируем ТОЛЬКО значения sensitive-заголовков через `redact/1'
%% (префикс+длина), имена и прочие заголовки оставляем как есть — лог
%% сохраняет диагностическую ценность. `lager'-вызовы НЕ удаляем: правило
%% проекта — редактировать данные, не вырезать логи. Работает и с map
%% (`cowboy:http_headers()' в этой версии Kazoo), и с proplist (историческая
%% форма); неожиданную форму отдаём без изменений (fail-safe, лог не роняем).
-spec redact_headers(map() | kz_term:proplist() | any()) ->
          map() | kz_term:proplist() | any().
redact_headers(Headers) when is_map(Headers) ->
    maps:map(fun redact_header_kv/2, Headers);
redact_headers(Headers) when is_list(Headers) ->
    [{K, redact_header_kv(K, V)} || {K, V} <- Headers];
redact_headers(Other) ->
    Other.

-spec redact_header_kv(term(), term()) -> term().
redact_header_kv(Key, Value) ->
    case is_sensitive_key(Key, ?SENSITIVE_HEADERS) of
        'true' -> redact(Value);
        'false' -> Value
    end.

%% @doc Санитизация ТЕЛА запроса перед логированием: маскируем ЗНАЧЕНИЯ
%% credential-ключей (?SENSITIVE_BODY_KEYS), структуру и остальные поля
%% сохраняем — лог остаётся диагностически полезным. Тот же класс утечки,
%% что закрыл `redact_headers/1' (issue 14), но через тело: сырой `~p' от
%% `cb_context:req_data/1' в `authorize/1,2' клал в лог 30-дневный
%% `refresh_token' целиком на каждом `POST /zkeycloak_ext/refresh'
%% (issue 15). `lager'-вызовы НЕ удаляем — редактируем данные.
%%
%% Рекурсивно, и это обязательно: `zkeycloak_ext_post/1' логирует
%% `cb_context:req_json/1' — тело ВМЕСТЕ с crossbar-конвертом
%% (`{"data":{"refresh_token":…}}'), т.е. секрет лежит вторым уровнем.
%% Внутрь JSON-массивов заходим по той же причине (объект в массиве).
%%
%% Не-объект (скаляр — напр. `{"data":"…"}' → req_data = binary) отдаём как
%% есть: маскировать по ключу там нечего, а глушить любой скаляр убило бы
%% лог целиком. Ни один из известных клиентов этого app'а скалярных тел с
%% кредами не шлёт (все креды — именованные поля JSON-объекта).
-spec redact_req_data(kz_json:object() | kz_json:json_term()) ->
          kz_json:object() | kz_json:json_term().
redact_req_data(Value) ->
    redact_json(Value, ?SENSITIVE_BODY_KEYS, fun redact/1).

%% @doc Рекурсивный key-wise редактор JSON-терма: значения ключей из `Keys'
%% пропускаются через `Redactor', структура и остальные поля сохраняются.
%% Параметризован, потому что мест применения два с РАЗНЫМИ доменами:
%% тело запроса (креды → `redact/1', префикс+длина) и ошибки валидации
%% (ПДн → `redact_pii/1', без префикса). См. `redact_req_data/1' и
%% `redact_validation_errors/1' (issue 15).
-spec redact_json(kz_json:json_term()
                 ,[kz_term:ne_binary()]
                 ,fun((any()) -> kz_term:ne_binary())
                 ) -> kz_json:json_term().
redact_json(Value, Keys, Redactor) ->
    case kz_json:is_json_object(Value) of
        'true' ->
            kz_json:map(fun(K, V) -> redact_json_kv(K, V, Keys, Redactor) end, Value);
        'false' ->
            redact_json_term(Value, Keys, Redactor)
    end.

-spec redact_json_kv(kz_json:key()
                    ,kz_json:json_term()
                    ,[kz_term:ne_binary()]
                    ,fun((any()) -> kz_term:ne_binary())
                    ) -> {kz_json:key(), kz_json:json_term()}.
redact_json_kv(Key, Value, Keys, Redactor) ->
    case is_sensitive_key(Key, Keys) of
        'true' -> {Key, Redactor(Value)};
        'false' -> {Key, redact_json(Value, Keys, Redactor)}
    end.

%% @doc Не-объектный JSON-терм: массив обходим поэлементно (в нём могут
%% лежать объекты с кредами), скаляр возвращаем как есть. kz_json-объект
%% сюда не попадает — он tuple (`?JSON_WRAPPER'), его снял `is_json_object/1'.
-spec redact_json_term(kz_json:json_term()
                      ,[kz_term:ne_binary()]
                      ,fun((any()) -> kz_term:ne_binary())
                      ) -> kz_json:json_term().
redact_json_term(Values, Keys, Redactor) when is_list(Values) ->
    [redact_json(V, Keys, Redactor) || V <- Values];
redact_json_term(Value, _Keys, _Redactor) ->
    Value.

%% @doc Log-safe выжимка claim'ов KC (`ClaimsMap' id_token'а, `UserInfoMap'
%% userinfo-ответа): значения ТОЛЬКО служебных полей (?LOG_SAFE_CLAIMS),
%% от остальных — одни имена в `redacted_keys'. Сырой `~p' этих мап клал в
%% plaintext-лог ПДн пользователя (email, ФИО, атрибуты realm'а) на каждом
%% логине (issue 15). Обоснование состава и выбора «whitelist, а не
%% denylist» — в комментарии к ?LOG_SAFE_CLAIMS.
%%
%% `redacted_keys' — атом-ключ намеренно: все claim'ы KC приходят с
%% binary-ключами, так что наше синтетическое поле с ними не столкнётся.
%%
%% Неожиданная форма (не map) — fail-CLOSED: печатаем только факт, не
%% содержимое. Это сознательно строже, чем fail-open в `redact_headers/1':
%% там имена полей известны и конечны, здесь состав задаёт realm KC, и
%% неизвестная форма может целиком состоять из ПДн.
-spec claims_digest(any()) -> map().
claims_digest(Claims) when is_map(Claims) ->
    Safe = maps:with(?LOG_SAFE_CLAIMS, Claims),
    Redacted = maps:keys(maps:without(?LOG_SAFE_CLAIMS, Claims)),
    Safe#{'redacted_keys' => lists:sort(Redacted)};
claims_digest(_Other) ->
    #{'unexpected_claims_shape' => 'true'}.

%% @doc Совпало ли `Key' с одним из чувствительных имён `Names'. `Key' —
%% имя заголовка или ключ JSON-тела (binary у cowboy/kz_json, возможно
%% atom/string в исторической proplist-форме). Сравниваем в нижнем
%% регистре: имена ASCII, поэтому `kz_term:to_lower_binary/1' их не портит
%% (кириллицы в HTTP-именах и OIDC-ключах нет), и результат используется
%% ТОЛЬКО для membership-проверки — оригинальный ключ в выводе сохраняется
%% как есть, даже если бы to_lower его исказил.
-spec is_sensitive_key(term(), [kz_term:ne_binary()]) -> boolean().
is_sensitive_key(Key, Names) when is_binary(Key);
                                  is_atom(Key);
                                  is_list(Key) ->
    lists:member(kz_term:to_lower_binary(Key), Names);
is_sensitive_key(_Key, _Names) ->
    'false'.

%% @doc Санитайзер oidcc-результата refresh для лога: сохраняем структуру
%% (ok/error + наличие полей), но маскируем сами токены.
%%
%% `{ok,_}' неузнанной формы — fail-CLOSED (issue 15): ok-клоуз матчит жёсткую
%% 5-tuple `oidcc_token', и любое расхождение (бамп oidcc, смена record'а)
%% уводило успешный результат — а это ЖИВЫЕ access+refresh+id — в общий
%% `~p'-catch-all, т.е. ровно в ту утечку, которую этот хелпер и закрывает,
%% но молча и без теста. Печатаем сентинел: на такой строке в логе видно, что
%% форма разъехалась, а токены не утекают. `{error,_}'/прочее печатаем как
%% есть — там причина отказа KC, не креды.
%%
%% Экспортируется в прод-API (P3 кросс-ревью 18.07): помимо `refresh_token/1'
%% и `normalize_oidcc/2' его теперь зовёт `cb_zkeycloak_ext' на своих
%% `Other'-клозах (`validate(?AUTH_CALLBACK)'/`handle_refresh'), где `Other' —
%% это `{ok,<нестандартная форма>}', т.е. тот же fail-open дрейф с живыми токенами.
-spec redact_token_result(any()) -> kz_term:ne_binary().
redact_token_result({'ok', {'oidcc_token'
                           ,{'oidcc_token_id', Id, _Claims}
                           ,{'oidcc_token_access', Access, _Timeout, _Type}
                           ,{'oidcc_token_refresh', Refresh}
                           ,_Scope
                           }}) ->
    <<"{ok,oidcc_token id=", (redact(Id))/binary
     ," access=", (redact(Access))/binary
     ," refresh=", (redact(Refresh))/binary, "}">>;
redact_token_result({'ok', _Unrecognized}) ->
    <<"{ok,<unrecognized oidcc_token shape — redacted>}">>;
redact_token_result({'error', Reason}) ->
    %% P1 (кросс-ревью 18.07 волна 2): `refresh_token/1' логирует ВЕСЬ Result
    %% через этот хелпер (line 497) ДО case-разбора, а на refresh-пути oidcc
    %% ШТАТНО отдаёт `{error, {http_error, 400, <тело ответа KC>}}' (ежедневный
    %% invalid_grant у mobile) и `{error, {missing_claim, _, <claims-map>}}' —
    %% оба уезжали в общий `~p'-catch-all этой функции СЫРЫМИ (тело HTTP-ответа
    %% KC / ПДн из claims). Тот же класс утечки, что закрыт `redact_reason/1'
    %% на других call-site'ах (996399b/8d052e8): чистим встроенное в `Reason'
    %% значение, тег/код ошибки оставляем диагностикой.
    kz_term:to_binary(io_lib:format("~p", [{'error', redact_reason(Reason)}]));
redact_token_result(Other) ->
    kz_term:to_binary(io_lib:format("~p", [Other])).

%% @doc Санитайзер причины отказа в провижининге user-doc'а для лога.
%% `create_user/7' редактирует СВОЮ лог-строку, но наверх отдаёт `Reason'
%% сырым (клиенту нужен полный per-field error) — и вызывающий
%% `cb_zkeycloak_ext:provide_keycloak_token/9' печатал его вторым `~p' на
%% том же самом запросе, обнуляя редакт (`reason=~p'). Диспетчер сводит обе
%% формы к их редакторам; всё прочее (`'datastore_unreachable'',
%% `{'missing_user_doc_on_refresh',_}') — атомы/теги без ПДн, отдаём как есть.
%% Экспортируется в прод-API (в отличие от самих редакторов) именно ради
%% этого внешнего call-site'а (issue 15, review-loop).
-spec redact_provisioning_error(any()) -> any().
redact_provisioning_error({'validation_errors', _} = Err) ->
    redact_validation_errors(Err);
redact_provisioning_error({'EXIT', _} = Crash) ->
    redact_crash(Crash);
redact_provisioning_error(Other) ->
    Other.

%% @doc Санитайзер ошибок валидации user-doc'а для лога. Форма
%% `kazoo_documents:doc_validation_errors()' — список триплетов
%% `{Path, Code, Msg}' (напр. `{[<<"username">>], <<"unique">>, Msg}');
%% диагностика живёт в `Path'+`Code' («какое поле и чем не угодило»), а ПДн —
%% в `Msg' под `value'/`cause'. Поэтому триплет сохраняем целиком и
%% редактируем ТОЛЬКО значения ?SENSITIVE_ERROR_KEYS внутри `Msg' — в отличие
%% от дропа третьего элемента, который убил бы и `message' («Username must be
%% unique»), т.е. смысл лога.
%%
%% ВАЖНО: это ЛОГ-копия. Наверх (`{'error', Err}' → `reject_user_provisioning/3'
%% → `add_doc_validation_errors/2') по-прежнему уходит СЫРОЙ `Err' — клиенту
%% нужен полный per-field error, поведение не меняется (issue 15).
-spec redact_validation_errors(any()) -> any().
redact_validation_errors({'validation_errors', Errors}) when is_list(Errors) ->
    {'validation_errors', [redact_validation_error(E) || E <- Errors]};
redact_validation_errors(Other) ->
    Other.

-spec redact_validation_error(any()) -> any().
redact_validation_error({Path, Code, Msg}) ->
    {Path, Code, redact_json(Msg, ?SENSITIVE_ERROR_KEYS, fun redact_pii/1)};
redact_validation_error(Other) ->
    Other.

%% @doc Санитайзер `catch'-результата для лога: `{'EXIT', {Reason, Stack}}'.
%% На `function_clause'/BIF-`badarg' Erlang кладёт в фрейм стектрейса РЕАЛЬНЫЕ
%% аргументы вызова, а сюда приезжает `kzd_users:validate(_, _, UDoc)' — т.е.
%% ФИО, email и сгенерированный пароль целиком (issue 15). Заменяем список
%% аргументов на арность: `M:F/A' + location для диагностики краша достаточно.
%% `Reason' оставляем как есть — обычно это атом (`function_clause') либо
%% тег с внутренним значением, ПДн там не по умолчанию.
-spec redact_crash(any()) -> any().
redact_crash({'EXIT', {Reason, Stack}}) when is_list(Stack) ->
    {'EXIT', {Reason, redact_stack(Stack)}};
redact_crash(Other) ->
    Other.

%% @doc Стектрейс без аргументов фреймов — см. `redact_crash/1'. Отдельно от
%% него, потому что `try/catch'-сайты (`normalize_oidcc/2', `refresh_token/1')
%% получают `Stack' напрямую, без обёртки `{'EXIT',_}'.
-spec redact_stack(any()) -> any().
redact_stack(Stack) when is_list(Stack) ->
    [redact_stack_frame(F) || F <- Stack];
redact_stack(Other) ->
    Other.

-spec redact_stack_frame(any()) -> any().
redact_stack_frame({M, F, Args, Loc}) when is_list(Args) ->
    {M, F, length(Args), Loc};
redact_stack_frame(Frame) ->
    Frame.

%% @doc Санитайзер `Reason' ошибки/исключения перед тем, как он попадёт в
%% лог-строку ИЛИ в проброшенный наверх `{Class, Reason}' (а оттуда — в лог
%% `cb_zkeycloak_ext'). `redact_stack/1' уже чистит АРГУМЕНТЫ фреймов, но сам
%% `Reason' печатался сырым — асимметрия защиты (P1/P3-находки кросс-ревью 18.07).
%% Два класса встраивания значения в `Reason':
%%
%%   1) BEAM-краши: `error:{badmatch,V}'/`{case_clause,V}'/`{try_clause,V}'/
%%      `{badmap,M}' ВСТРАИВАЮТ несовпавшее значение прямо в `Reason'. В этом
%%      модуле таким значением бывают декодированные байты claim'ов
%%      (`jwt_sub_unverified/1': `base64:decode' → `kz_json:decode' payload'а
%%      JWT) или token-материал.
%%   2) ШТАТНЫЙ error-протокол oidcc (ДОМИНИРУЮЩАЯ реальная форма, P1):
%%      `{missing_claim, Claim, Claims}' — 3-й элемент это ПОЛНАЯ декодированная
%%      claims-map (рутинные nonce/aud/exp-провалы; `oidcc_token'/`oidcc_jwt_util'/
%%      `oidcc_userinfo'); `{none_alg_used, TokenRecord|Claims}' и
%%      `{none_alg_used, Jwt, Jws}' — token-record / claims / сырой JWT;
%%      `{http_error, Code, ErrBody}' — `ErrBody' (`binary()|map()') это
%%      сырое/распарсенное тело HTTP-ответа KC (server-controlled, без схемы).
%%
%% Сохраняем ТЕГ краша и полезную диагностику (имя клейма `Claim' — публичная
%% схема, не ПДн), но вычищаем встроенное значение: binary → `redact/1'
%% (префикс+длина, тот же класс секрета, что токены), любую другую форму
%% (claims-map, token-record, JSON-объект, список) → непрозрачный сентинел
%% `'$redacted''. Атомы без встроенного значения (`function_clause' — его
%% аргументы живут ТОЛЬКО в стеке, а он редактируется отдельно; `badarg',
%% `token_expired', …) и прочие теги пропускаем как есть — диагностика выживает.
%% `{Class, Reason}'-пары (`error'/`exit'/`throw') разворачиваем рекурсивно:
%% так чистится и проброшенный catch-контракт `normalize_oidcc/2'/`refresh_token/1',
%% доехавший до вызывающего кода.
-spec redact_reason(any()) -> any().
redact_reason({'badmatch', Value}) ->
    {'badmatch', redact_reason_value(Value)};
redact_reason({'case_clause', Value}) ->
    {'case_clause', redact_reason_value(Value)};
redact_reason({'try_clause', Value}) ->
    {'try_clause', redact_reason_value(Value)};
redact_reason({'badmap', Value}) ->
    {'badmap', redact_reason_value(Value)};
redact_reason({'missing_claim', Claim, _Claims}) ->
    %% P1: 3-й элемент — полная claims-map (ПДн); имя клейма оставляем.
    {'missing_claim', Claim, '$redacted'};
redact_reason({'none_alg_used', Value}) ->
    %% token-record либо claims-map — обе не-binary, но зовём общий редактор.
    {'none_alg_used', redact_reason_value(Value)};
redact_reason({'none_alg_used', Jwt, Jws}) ->
    %% сырой JWT + JWS во фрейме валидации alg=none.
    {'none_alg_used', redact_reason_value(Jwt), redact_reason_value(Jws)};
redact_reason({'http_error', Code, _ErrBody}) ->
    %% P2: `ErrBody' (`binary()|map()', `oidcc_http_util') — сырое/распарсенное
    %% тело HTTP-ответа KC (token/userinfo/jwks; всплывает на рутинных
    %% invalid_grant), server-controlled и без схемы: реконфиг realm / апгрейд
    %% KC / прокси-страница могут поменять содержимое без правок с нашей
    %% стороны. Редакт по форме, не по доказанному содержимому; `Code' —
    %% диагностика, оставляем.
    {'http_error', Code, '$redacted'};
redact_reason({'invalid_property', {Field, GivenValue}}) ->
    %% P2 (кросс-ревью 18.07 волна 2): штатный `error()'-протокол oidcc —
    %% `oidcc_token' отдаёт `{invalid_property, {Field, GivenValue}}'
    %% (`oidcc_token.erl:249-251'), и для `Field' ∈ {access_token,
    %% refresh_token, id_token} `GivenValue' это СЫРОЙ токен-материал
    %% server-controlled формы (`:797/:809/:834'). `Field'
    %% (id_token/refresh_token/access_token/expires_in/scopes) — публичная
    %% схема, оставляем; `GivenValue' режем по форме (binary → префикс+длина,
    %% иначе сентинел) тем же редактором, что badmatch/none_alg_used.
    {'invalid_property', {Field, redact_reason_value(GivenValue)}};
redact_reason({Class, Reason}) when Class =:= 'error';
                                    Class =:= 'exit';
                                    Class =:= 'throw' ->
    {Class, redact_reason(Reason)};
redact_reason(Other) ->
    Other.

%% @doc Значение, встроенное в `Reason' краша: binary редактируем как секрет
%% (в него могли попасть token/claim-байты), любую другую форму заменяем
%% непрозрачным сентинелом — точной диагностики из значения не извлечь, а
%% утечка недопустима.
-spec redact_reason_value(any()) -> any().
redact_reason_value(Value) when is_binary(Value) ->
    redact(Value);
redact_reason_value(_Value) ->
    '$redacted'.

%% @doc Присутствует ли поле — для presence-логов вместо значений-ПДн
%% (`create_user/7', issue 15). `undefined'/пусто = отсутствует.
-spec is_present(any()) -> boolean().
is_present('undefined') -> 'false';
is_present(<<>>) -> 'false';
is_present(_Value) -> 'true'.

%% @doc Санитайзер результата сохранения user-doc'а для лога: `{ok, Doc}'
%% схлопываем до факта + `_id' (сам Doc — ПДн + pvt-хеши, issue 15);
%% `{error, _}' отдаём как есть — там причина датастора, не ПДн. Catch-all
%% делает хелпер fail-safe на неожиданной форме, как `redact_token_result/1'.
-spec redact_user_doc_result(any()) -> kz_term:ne_binary().
redact_user_doc_result({'ok', Doc}) ->
    Id = case kz_json:is_json_object(Doc) of
             'true' -> kz_json:get_ne_binary_value(<<"_id">>, Doc);
             'false' -> 'undefined'
         end,
    <<"{ok,doc_id=", (kz_term:to_binary(Id))/binary, "}">>;
redact_user_doc_result(Other) ->
    kz_term:to_binary(io_lib:format("~p", [Other])).

-spec create_user(kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ,kz_term:api_ne_binary()
                 ,kz_term:api_ne_binary()
                 ,kz_term:api_ne_binary()
                 ,kz_term:api_binary()
                 ,kz_term:ne_binary()
                 ) -> {'ok', kz_json:object()}
                    | {'error', {'validation_errors', kazoo_documents:doc_validation_errors()}
                              | {'system_error', atom()}
                              | term()}
                    | kz_datamgr:data_error().
create_user(AccountId, UserDocId, Firstname, Surname, Email, Phonenumber, UserPassword) ->
    %% issue 15: `Email'/`Firstname'/`Surname'/`Phonenumber' — ПДн, приехавшие
    %% из userinfo KC (`cb_zkeycloak_ext:ensure_user_doc/4' достаёт их из
    %% claim'ов), и сырой `~p' клал их в plaintext-лог на первом логине
    %% КАЖДОГО пользователя. Логируем НАЛИЧИЕ полей вместо значений —
    %% диагностическая ценность сохраняется полностью: штатный сбой здесь это
    %% ровно «у LDAP-юзера пустой `sn' → нет `last_name' → validation_errors»,
    %% и `has_surname=false' говорит об этом прямее, чем сам ФИО. `AccountId'/
    %% `UserDocId' — внутренние id, не ПДн: оставляем как есть (по ним всё и
    %% коррелируется). Сами `lager:info' сохранены — правило проекта.
    lager:info("create_user AccountId: ~p, UserDocId: ~p, has_email: ~p"
              ,[AccountId, UserDocId, is_present(Email)]),
    lager:info("create_user has_firstname: ~p",[is_present(Firstname)]),
    lager:info("create_user has_surname: ~p",[is_present(Surname)]),
    lager:info("create_user has_phonenumber: ~p",[is_present(Phonenumber)]),
    Props = props:filter_empty([{<<"username">>, Email}
                               ,{<<"first_name">>, Firstname}
                               ,{<<"last_name">>, Surname}
                               ,{<<"email">>, Email}
                               ,{<<"contact_phonenumber">>, Phonenumber}
                               ,{<<"password">>, UserPassword}
                               ,{<<"priv_level">>, <<"admin">>}
                               ]),
    DbName = kzs_util:format_account_db(AccountId),
    Ctx0 = cb_context:set_account_id(cb_context:new(), AccountId),
    Ctx1 = cb_context:set_db_name(Ctx0, DbName),
    UDoc = kz_json:set_values(Props, ?MK_USER),
    %% Канонический шейп `kzd_users:validate/3' — три клозы:
    %% `{true,_} | {validation_errors,_} | {system_error,_}'. `catch'
    %% дополнительно ловит исключения (`{'EXIT',_}' / throw / error) —
    %% не теряем их в немое `Err' как раньше.
    case catch kzd_users:validate(AccountId, UserDocId, UDoc) of
        {'true', UDoc1} ->
            UDoc2 = crossbar_doc:update_pvt_parameters(UDoc1, Ctx1),
            UDoc3 = kz_json:set_value(<<"pvt_type">>,<<"user">>,UDoc2),
            Creates = kz_json:to_proplist(UDoc3),
            UpdateOptions = [{'create', Creates}
                            ,{'update', Creates}
                            ,{'ensure_saved', 'true'}
                            ],
            Result = kz_datamgr:update_doc(DbName, UserDocId, UpdateOptions),
            %% issue 15: на успехе `Result' = `{ok, <сохранённый user-doc>}', а
            %% он несёт и ПДн (`first_name'/`last_name'/`email'/`username' из
            %% claim'ов), и pvt-хеши пароля — сырой `~p' = та же утечка, что
            %% claims. Печатаем факт + id документа.
            lager:info("create_user Result: ~s", [redact_user_doc_result(Result)]),
            Result;
        {'validation_errors', _} = Err ->
            %% issue 15: ошибки валидации ЭХАЮТ отвергнутое значение
            %% (`cause'/`value'), а `username' здесь = `Email' — коллизия
            %% username'а печатала email целиком. Редактируем ЛОГ-копию;
            %% наверх уходит сырой `Err' (клиенту нужен полный per-field error).
            lager:info("create_user Err: ~p", [redact_validation_errors(Err)]),
            {'error', Err};
        {'system_error', _} = Err ->
            lager:warning("create_user system_error: ~p", [Err]),
            {'error', Err};
        Crash ->
            %% issue 15: `catch' отдаёт `{'EXIT',{Reason,Stack}}', а фрейм
            %% стектрейса на function_clause/badarg несёт АРГУМЕНТЫ вызова —
            %% т.е. весь `UDoc' (ФИО, email, пароль). Логируем M:F/A без args.
            lager:error("create_user crashed: ~p", [redact_crash(Crash)]),
            {'error', Crash}
    end.

-spec jwt_claims(kz_term:ne_binary()) -> kz_term:proplist().
jwt_claims(Token) ->
    %% Верифицированные claims; на истёкшем/невалидном токене — пустой список.
    case decode_safe(Token, 'true') of
        {'ok', _Header, Claims} -> Claims;
        {'error', _Reason} -> []
    end.

%% @doc Обёртка над `kz_auth_jwt:decode/2': помимо `{error,_}' ловит и
%% исключения от парсинга произвольного auth-токена (не-JWT, битый base64).
%% `Verify' = `false' — только распарсить payload (routing-решение), без
%% криптопроверки; её делает downstream `kz_auth:validate_token/2'.
-spec decode_safe(kz_term:ne_binary(), boolean()) ->
          {'ok', kz_term:proplist(), kz_term:proplist()} | {'error', any()}.
decode_safe(Token, Verify) ->
    try kz_auth_jwt:decode(Token, Verify)
    catch
        _E:_R -> {'error', 'invalid_jwt'}
    end.

%% @doc Извлечь `sub' claim из JWT без верификации подписи. Нужно для
%% refresh-токенов KC: они подписаны HS256 (client-secret), а
%% `kz_auth_jwt:decode' принимает только asymmetric (RS256/ES256) и
%% возвращает `verify_failed'. Криптографическую проверку всё равно
%% делает KC при /token/refresh — здесь нам нужен только субъект, чтобы
%% передать его в `oidcc:refresh_token/5' opts (`expected_subject').
-spec jwt_sub_unverified(kz_term:ne_binary()) -> kz_term:ne_binary().
jwt_sub_unverified(Token) ->
    %% issue 15 (review-loop): жёсткий матч `[_H, Payload, _S] = split(...)'
    %% на не-3-частном токене давал `{badmatch, <части ТОКЕНА>}' — и `Reason'
    %% с живым refresh уезжал в лог через `~p' в catch-блоке `refresh_token/1'.
    %% Сейчас это в основном малформный токен клиента (не секрет), но стоит
    %% realm'у начать выдавать JWE-refresh (5 частей) — и в лог ляжет ЖИВОЙ
    %% 30-дневный токен целиком. Отказываем атомом, без данных: поведение то
    %% же (исключение → catch → `{error,_}' → `invalid_credentials'/401).
    Payload = case binary:split(Token, <<".">>, ['global']) of
                  [_Header, P, _Sig] -> P;
                  _Parts -> error('malformed_jwt')
              end,
    Padded = case byte_size(Payload) rem 4 of
                 0 -> Payload;
                 2 -> <<Payload/binary, "==">>;
                 3 -> <<Payload/binary, "=">>
             end,
    Bin = base64:decode(Padded, #{'mode' => 'urlsafe'}),
    Claims = kz_json:decode(Bin),
    kz_json:get_ne_binary_value(<<"sub">>, Claims).

-spec jwt_iss(kz_term:ne_binary()) -> kz_term:api_ne_binary().
jwt_iss(Token) ->
    %% routing-решение «KC-токен?»: криптопроверка не нужна.
    case decode_safe(Token, 'false') of
        {'ok', _Header, Claims} -> props:get_ne_binary_value(<<"iss">>, Claims);
        {'error', _Reason} -> 'undefined'
    end.

%% @doc Токен выпущен НАШИМ KC: JWT-shaped и `iss' совпал со
%% сконфигурированным issuer. Намеренно НЕ короткозамыкается по
%% `is_configured()': классификация «чей токен» не должна зависеть от
%% готовности интеграции — иначе полунастроенная нода трактовала бы
%% KC-токен как «не-KC» и пропускала его в общий `kz_auth' мимо
%% роль-гейта `onbill_access' (fail-open; Fable-review issue 12).
%% Дефолт-сентинел `?ISSUER_UNSET' с реальным `iss' (URL) не совпадёт.
-spec maybe_keycloak_token(kz_term:ne_binary()) -> boolean().
maybe_keycloak_token(Token) ->
    is_jwt_shaped(Token)
        andalso jwt_iss(Token) == issuer().

%% @doc Дешёвый предчек: JWT = `header.payload.sig' (минимум две точки).
%% Opaque Kazoo db-токены (UUID) точек не содержат → пропускаем дорогой
%% base64-decode для не-JWT и защищаемся от случайного совпадения с
%% дефолт-`issuer'.
-spec is_jwt_shaped(any()) -> boolean().
is_jwt_shaped(Token) when is_binary(Token) ->
    case binary:matches(Token, <<".">>) of
        [_, _ | _] -> 'true';
        _ -> 'false'
    end;
is_jwt_shaped(_) ->
    %% не-binary токен (напр. map db-токена) — точно не KC-JWT; без краша
    'false'.

-spec maybe_keycloak_token_validate(kz_term:ne_binary(), kz_term:proplist()) ->
          {'ok', 'not_keycloack_token' | 'onbill_access_provided'} |
          {'error', any()}.
maybe_keycloak_token_validate(Token, _Options) ->
    case maybe_keycloak_token(Token) of
        'false' ->
            {'ok', 'not_keycloack_token'};
        'true' ->
            case is_configured() of
                'true' -> validate_onbill_access(Token);
                'false' ->
                    %% fail-closed: токен нашего issuer'а, но интеграция не
                    %% считается сконфигурированной — отвергаем, а не
                    %% пропускаем в kz_auth (там KC-issuer может быть
                    %% доверенным провайдером auth-DB, и роль-гейт
                    %% `onbill_access' обходился бы). Fable-review issue 12.
                    lager:warning("keycloak-issued token while zkeycloak is not configured, rejecting"),
                    {'error', 'keycloak_not_configured'}
            end
    end.

-spec validate_onbill_access(kz_term:ne_binary()) ->
          {'ok', 'onbill_access_provided'} | {'error', any()}.
validate_onbill_access(Token) ->
    case decode_safe(Token, 'true') of
        {'ok', _Header, Claims} ->
            ResourceAccess = props:get_value(<<"resource_access">>, Claims, #{}),
            ClientRoles = kz_maps:get([<<"onbill_client">>, <<"roles">>], ResourceAccess, []),
            case lists:member(<<"onbill_access">>, ClientRoles) of
                'true' -> {'ok', 'onbill_access_provided'};
                'false' -> {'error', 'onbill_access_absent'}
            end;
        {'error', Reason} ->
            lager:debug("keycloak token rejected: ~p", [Reason]),
            {'error', Reason}
    end.

%% @doc Определяет, как именно KC аутентифицировал пользователя.
%% Маркеры Kerberos: `acr=kerberos' (broker IdP flow) или присутствие
%% `kerb'/`kerberos'/`spnego' в массиве `amr' (in-flow SPNEGO-authenticator).
%% Всё остальное в callback'е `cb_zkeycloak_ext' — OIDC по определению
%% (password form через `brt-unified' flow либо иной не-Kerberos путь).
%% Возврат `'unknown'' убран намеренно: он ломал logout-ветку во фронте
%% (фронт скипал end_session, если auth_method не входит в whitelist).
-spec auth_method(kz_term:ne_binary()) -> 'oidc' | 'kerberos'.
auth_method(Token) ->
    Claims = jwt_claims(Token),
    Acr = props:get_ne_binary_value(<<"acr">>, Claims, <<>>),
    Amr = props:get_value(<<"amr">>, Claims, []),
    KerberosInAmr = is_list(Amr)
        andalso (lists:member(<<"kerb">>, Amr)
                 orelse lists:member(<<"kerberos">>, Amr)
                 orelse lists:member(<<"spnego">>, Amr)),
    case {Acr, KerberosInAmr} of
        {<<"kerberos">>, _} -> 'kerberos';
        {_, 'true'} -> 'kerberos';
        _ -> 'oidc'
    end.

-spec logout_url() -> kz_term:ne_binary().
logout_url() ->
    logout_url('undefined').

%% @doc RP-initiated logout URL для KC.
%% `IdTokenHint' (из callback'а fronto'ом) обязателен по OIDC-спеке для
%% silent end_session — без него KC показывает confirmation page.
-spec logout_url(kz_term:api_ne_binary()) -> kz_term:ne_binary().
logout_url(IdTokenHint) ->
    Issuer = issuer(),
    ClientId = client_id(),
    RedirectUri = redirect_uri(),
    EndSession = <<Issuer/binary, "/protocol/openid-connect/logout">>,
    BaseParams = [{<<"client_id">>, ClientId}
                 ,{<<"post_logout_redirect_uri">>, RedirectUri}
                 ],
    Params = case IdTokenHint of
                 'undefined' -> BaseParams;
                 <<>> -> BaseParams;
                 Hint -> [{<<"id_token_hint">>, Hint} | BaseParams]
             end,
    QS = uri_string:compose_query(Params),
    <<EndSession/binary, "?", QS/binary>>.

