-module(zkeycloak_util).

-export([auth_url/0
        ,issuer/0
        ,client_id_atom/0
        ,client_id/0
        ,client_secret/0
        ,redirect_uri/0
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

-spec issuer() -> kz_term:ne_binary().
issuer() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"issuer">>, <<"issuer">>).

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

-spec preferred_auth_methods() -> kz_term:ne_binary().
preferred_auth_methods() ->
    case kapps_config:get(<<"zkeycloak">>, <<"preferred_auth_methods">>, [client_secret_basic, client_secret_post]) of
        L when is_list(L) ->
            [kz_term:to_atom(V, 'true') || V <- L];
        _ -> []
    end.

-spec auth_url() -> kz_term:ne_binary().
auth_url() ->
    lager:info("zkeycloak auth_url: issuer=~s client_id=~s redirect_uri=~s",
               [issuer(), client_id(), redirect_uri()]),
    Result =
        oidcc:create_redirect_url(
          client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{'redirect_uri' => redirect_uri()
           ,'preferred_auth_methods' => preferred_auth_methods()
           }
         ),
    lager:info("zkeycloak auth_url oidcc result: ~p", [Result]),
    {ok, RedirectUri} = Result,
    Url = kz_binary:join(RedirectUri, <<"">>),
    lager:info("zkeycloak auth_url final: ~s", [Url]),
    Url.

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
    lager:info("zkeycloak kerberos_auth_url: issuer=~s client_id=~s redirect_uri=~s",
               [issuer(), client_id(), redirect_uri()]),
    Result =
        oidcc:create_redirect_url(
          client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{'redirect_uri' => redirect_uri()
           ,'preferred_auth_methods' => preferred_auth_methods()
           ,'url_extension' => BaseExtension ++ PromptExtension
           }
         ),
    lager:info("zkeycloak kerberos_auth_url oidcc result: ~p", [Result]),
    {ok, RedirectUri} = Result,
    Url = kz_binary:join(RedirectUri, <<"">>),
    lager:info("zkeycloak kerberos_auth_url final: ~s", [Url]),
    Url.

-spec retrieve_token(kz_term:ne_binary()) -> any().
retrieve_token(AuthCode) ->
    retrieve_token(AuthCode, redirect_uri()).

%% @doc Token exchange c явным redirect_uri (от клиента).
%% Нужно для mobile-клиентов (zfield) — они проходят /authorize через
%% свой deep-link (`ru.brt.zfield://oauth/callback`), а KC требует
%% совпадения redirect_uri в /authorize и /token. Web (zfront) шлёт
%% свой redirect_uri в QS либо вызывает retrieve_token/1 (default
%% config) — обратная совместимость сохранена.
-spec retrieve_token(kz_term:ne_binary(), kz_term:ne_binary()) -> any().
retrieve_token(AuthCode, RedirectUri) ->
    retrieve_token(AuthCode, RedirectUri, 'undefined').

%% @doc Token exchange c явным redirect_uri и опциональным PKCE verifier'ом.
%% Mobile-клиенты (zfield) проходят /authorize через AppAuth, который
%% автоматически генерирует `code_verifier` + `code_challenge=S256`.
%% KC привязывает code к challenge'у — в /token нужен исходный verifier,
%% иначе KC отвечает 'invalid_grant: PKCE code verifier not specified'.
%% Web-flow без PKCE передаёт PkceVerifier='undefined' — opts без
%% pkce_verifier, oidcc не добавит его в /token request.
-spec retrieve_token(kz_term:ne_binary(), kz_term:ne_binary(), kz_term:api_ne_binary()) -> any().
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
    {ok, Token} =
        oidcc:retrieve_token(
          AuthCode
         ,client_id_atom()
         ,client_id()
         ,client_secret()
         ,Opts
         ),
    Token.

-spec retrieve_userinfo(kz_term:ne_binary()) -> any().
retrieve_userinfo(Token) ->
    {ok, Claims} =
        oidcc:retrieve_userinfo(
          Token
         ,client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{}
         ),
    Claims.

-spec introspect_token(kz_term:ne_binary()) -> any().
introspect_token(Token) ->
    {ok, Introspection} =
        oidcc:introspect_token(
          Token
         ,client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{}
         ),
    Introspection.

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
        lager:info("zkeycloak refresh_token oidcc result: ~p", [Result]),
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

-spec maybe_keycloak_token(kz_term:ne_binary()) -> boolean().
maybe_keycloak_token(Token) ->
    jwt_iss(Token) == issuer().

-spec maybe_keycloak_token_validate(kz_term:ne_binary(), kz_term:proplist()) ->
          {'ok', 'not_keycloack_token' | 'onbill_access_provided'} |
          {'error', any()}.
maybe_keycloak_token_validate(Token, _Options) ->
    case maybe_keycloak_token(Token) of
        'false' ->
            {'ok', 'not_keycloack_token'};
        'true' ->
            validate_onbill_access(Token)
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

