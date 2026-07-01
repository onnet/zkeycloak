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
        ]
       ).

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
            lager:info("zkeycloak ~s oidcc error: ~p", [Tag, Err]),
            Err;
        Other ->
            lager:warning("zkeycloak ~s unexpected oidcc result: ~p", [Tag, Other]),
            {'error', {'unexpected_oidcc_result', Other}}
    catch
        Class:Reason:Stack ->
            lager:warning("zkeycloak ~s exception ~p:~p stack=~p",
                          [Tag, Class, Reason, Stack]),
            {'error', {Class, Reason}}
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
            Other -> {'error', {'unexpected_oidcc_result', Other}}
        end
    catch
        Class:Reason:Stack ->
            lager:warning("zkeycloak refresh_token exception ~p:~p stack=~p",
                          [Class, Reason, Stack]),
            {'error', {Class, Reason}}
    end.

%% @doc Маскирование bearer-кред (access/refresh/id token, code_verifier,
%% authorization code) для лога. Печатаем только короткий префикс + длину —
%% этого достаточно для корреляции лог-строк, но НЕ для реплея валидной
%% сессии. Сырой токен в логах = 30-дневный replay при утечке лог-архива
%% (issue 01 кросс-слойного KC-auth ревью). `lager'-вызов сохраняем —
%% редактируем только ЗНАЧЕНИЕ (правило проекта: не вырезать lager).
-spec redact(kz_term:api_binary()) -> kz_term:ne_binary().
redact('undefined') -> <<"undefined">>;
redact(<<>>) -> <<"empty">>;
redact(Value) when is_binary(Value) ->
    Len = byte_size(Value),
    Prefix = binary:part(Value, 0, min(6, Len)),
    <<Prefix/binary, "..(len=", (integer_to_binary(Len))/binary, ")">>;
redact(Value) ->
    redact(kz_term:to_binary(Value)).

%% @doc Санитайзер oidcc-результата refresh для лога: сохраняем структуру
%% (ok/error + наличие полей), но маскируем сами токены. Catch-all делает
%% хелпер fail-safe — на неожиданной форме просто печатает её как есть.
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
redact_token_result(Other) ->
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
    lager:info("create_user AccountId: ~p, UserDocId: ~p, Email: ~p",[AccountId,UserDocId,Email]),
    lager:info("create_user Firstname: ~p",[Firstname]),
    lager:info("create_user Surname: ~p",[Surname]),
    lager:info("create_user Phonenumber: ~p",[Phonenumber]),
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
            lager:info("create_user Result: ~p", [Result]),
            Result;
        {'validation_errors', _} = Err ->
            lager:info("create_user Err: ~p", [Err]),
            {'error', Err};
        {'system_error', _} = Err ->
            lager:warning("create_user system_error: ~p", [Err]),
            {'error', Err};
        Crash ->
            lager:error("create_user crashed: ~p", [Crash]),
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
    [_Header, Payload, _Sig] = binary:split(Token, <<".">>, ['global']),
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

