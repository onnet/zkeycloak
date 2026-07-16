-module(cb_zkeycloak_ext).

-export([init/0
        ,allowed_methods/0, allowed_methods/1
        ,resource_exists/0, resource_exists/1
        ,authorize/1, authorize/2
        ,authenticate/1, authenticate/2
        ,validate/1,validate/2
        ]).

-export([zkeycloak_ext_post/1
        ]).

-include("/opt/kazoo/applications/crossbar/src/crossbar.hrl").

%%-include("zbrt_defs.hrl").
%%-define(HEADERS, [{"content-type", "application/x-www-form-urlencoded"}]).
-define(HEADERS, [{"content-type", "application/json"}]).

-define(AUTH_LINK, <<"auth_link">>).
-define(AUTH_CALLBACK, <<"auth_callback">>).
-define(KERBEROS_LOGIN, <<"kerberos_login">>).
-define(LOGOUT, <<"logout">>).
-define(REFRESH, <<"refresh">>).
-define(ZKEYCLOAK, <<"zkeycloak_ext">>).

-spec init() -> ok.
init() ->
    _ = crossbar_bindings:bind(<<"*.authenticate.zkeycloak_ext">>, ?MODULE, 'authenticate'),
    _ = crossbar_bindings:bind(<<"*.authorize.zkeycloak_ext">>, ?MODULE, 'authorize'),
    _ = crossbar_bindings:bind(<<"*.allowed_methods.zkeycloak_ext">>, ?MODULE, 'allowed_methods'),
    _ = crossbar_bindings:bind(<<"*.resource_exists.zkeycloak_ext">>, ?MODULE, 'resource_exists'),
    _ = crossbar_bindings:bind(<<"*.validate.zkeycloak_ext">>, ?MODULE, 'validate'),
    %%    _ = crossbar_bindings:bind(<<"*.execute.put.ext">>, ?MODULE, 'put'),
    ok.

-spec allowed_methods() -> http_methods().
allowed_methods() -> [?HTTP_POST, ?HTTP_GET].
-spec allowed_methods(path_token()) -> http_methods().
allowed_methods(?AUTH_LINK) -> [?HTTP_GET];
allowed_methods(?AUTH_CALLBACK) -> [?HTTP_GET];
allowed_methods(?KERBEROS_LOGIN) -> [?HTTP_GET];
allowed_methods(?LOGOUT) -> [?HTTP_GET];
allowed_methods(?REFRESH) -> [?HTTP_POST];
allowed_methods(?ZKEYCLOAK) -> [?HTTP_POST, ?HTTP_GET].

-spec resource_exists() -> boolean().
resource_exists() -> 'true'.
-spec resource_exists(path_tokens()) -> boolean().
resource_exists(?AUTH_LINK) -> 'true';
resource_exists(?AUTH_CALLBACK) -> 'true';
resource_exists(?KERBEROS_LOGIN) -> 'true';
resource_exists(?LOGOUT) -> 'true';
resource_exists(?REFRESH) -> 'true';
resource_exists(?ZKEYCLOAK) -> 'true'.

-spec authorize(cb_context:context()) -> boolean() | {'stop', cb_context:context()}.
authorize(Context) ->
    lager:info("authorisze/1  req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("authorisze/1  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/1  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("authorisze/1  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/1  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/1  req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).

-spec authorize(cb_context:context(), kz_term:ne_binary()) -> boolean().
authorize(Context, Token1) ->
    lager:info("authorisze/2 Token1: ~p",[Token1]),
    lager:info("authorisze/2 req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("authorisze/2 req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/2 req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("authorisze/2 req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/2 req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/2 req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).

authorize_nouns(_Context, [{<<"zkeycloak_ext">>, []}], Method) when Method =:= ?HTTP_POST ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing zkeycloak_ext"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_link">>]}], Method) when Method =:= ?HTTP_GET ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing zkeycloak_ext"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_callback">>]}], Method) when Method =:= ?HTTP_GET ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing zkeycloak_ext"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"kerberos_login">>]}], Method) when Method =:= ?HTTP_GET ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing kerberos_login"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"logout">>]}], Method) when Method =:= ?HTTP_GET ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing logout"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"refresh">>]}], Method) when Method =:= ?HTTP_POST ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing refresh"),
    'true';
authorize_nouns(_, _Nouns, _) ->
    lager:info("authorize_nouns_zkeycloak_ext undefined _Nouns: ~p", [_Nouns]),
    'false'.
%%'true'.

-spec authenticate(cb_context:context()) -> boolean().
authenticate(Context) ->
    lager:info("authenticate/1  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    authenticate_nouns(Context, cb_context:req_nouns(Context)).

-spec authenticate(cb_context:context(), kz_term:ne_binary()) -> boolean().
authenticate(Context, Token1) ->
    lager:info("authenticate/2  Token1: ~p",[Token1]),
    lager:info("authenticate/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    authenticate_nouns(Context, cb_context:req_nouns(Context)).

authenticate_nouns(Context, [{<<"zkeycloak_ext">>, []}]) ->
    lager:info("authenticate_nouns/2  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_link">>]}]) ->
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_callback">>]}]) ->
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"kerberos_login">>]}]) ->
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"logout">>]}]) ->
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"refresh">>]}]) ->
    'true';
authenticate_nouns(_Context, _Nouns) ->
    lager:info("authenticate_nouns/1 _Nouns: ~p",[_Nouns]),
    'false'.

-spec validate(cb_context:context()) -> cb_context:context().
validate(Context) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).

-spec validate(cb_context:context(), path_token()) -> cb_context:context().
validate(Context, ?AUTH_LINK) ->
    lager:info("validate_ext/2  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    %% PKCE code_challenge (S256) — опционален (issue 04). Web-flow zfront
    %% генерирует пару на своей стороне и присылает СЮДА только challenge;
    %% verifier он придержит в sessionStorage до /token обмена
    %% (auth_callback). Mobile (AppAuth) свой challenge шлёт в /authorize
    %% сам, эту ручку не зовёт. 'undefined' → web-без-PKCE (совместимость).
    QS = cb_context:query_string(Context),
    CodeChallenge = kz_json:get_ne_binary_value(<<"code_challenge">>, QS),
    lager:info("validate_ext/2  auth_link: has_code_challenge=~p", [CodeChallenge =/= 'undefined']),
    AuthUrl = zkeycloak_util:auth_url(CodeChallenge),
    JObj = kz_json:set_value(<<"auth_url">>, AuthUrl, kz_json:new()),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, JObj), 'success');
validate(Context, ?AUTH_CALLBACK) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    QS = cb_context:query_string(Context),
    Code = kz_json:get_ne_binary_value(<<"code">>, QS),
    %% Если клиент прислал свой redirect_uri (mobile-flow с deep-link'ом)
    %% — берём его, иначе fallback на config (web-flow zfront). KC требует
    %% совпадения redirect_uri в /authorize и /token, mobile проходит
    %% /authorize через AppAuth с собственным `ru.brt.zfield://oauth/callback`.
    RedirectUri = kz_json:get_ne_binary_value(<<"redirect_uri">>, QS,
                                              zkeycloak_util:redirect_uri()),
    %% PKCE code_verifier — опционален. Mobile-клиенты (zfield/AppAuth)
    %% всегда инициируют /authorize c `code_challenge` (S256), и KC
    %% требует исходный verifier в /token. Web-flow zfront пока без
    %% PKCE — передаёт 'undefined', oidcc не добавит pkce_verifier в /token.
    PkceVerifier = kz_json:get_ne_binary_value(<<"code_verifier">>, QS),
    %% issue 01: сырой QS = authorization `code' + PKCE `code_verifier' в логах
    %% (одноразовый, но чувствительный матерьял). Логируем только ФАКТ callback'а
    %% и НАЛИЧИЕ полей (boolean), без значений. redirect_uri не секрет.
    lager:info("validate_ext/2  auth_callback: has_code=~p has_code_verifier=~p redirect_uri=~s"
              ,[Code =/= 'undefined', PkceVerifier =/= 'undefined', RedirectUri]),
    case zkeycloak_util:retrieve_token(Code, RedirectUri, PkceVerifier) of
        {'ok', {oidcc_token
               ,{oidcc_token_id, TokenId, ClaimsMap}
               ,{oidcc_token_access, TokenAccess, _Timeout, _Type}
               ,{oidcc_token_refresh, TokenRefresh}
               ,_Scope
               } = TokenTuple} ->

            %% issue 01: id/access/refresh — живые bearer-креды (refresh ~30 дней).
            %% Маскируем значения (префикс+длина); сам lager:info сохранён.
            lager:info("validate_ext/2  TokenId: ~s",[zkeycloak_util:redact(TokenId)]),
            lager:info("validate_ext/2  TokenAccess: ~s",[zkeycloak_util:redact(TokenAccess)]),
            lager:info("validate_ext/2  TokenRefresh: ~s",[zkeycloak_util:redact(TokenRefresh)]),
            lager:info("validate_ext/2  ClaimsMap: ~p",[ClaimsMap]),
            lager:info("validate_ext/2  _Scope: ~p",[_Scope]),
            authorize_and_issue(Context, TokenTuple, TokenAccess, TokenId, TokenRefresh, 'login');
        %% issue 05: `retrieve_token/3' нормализован к {ok,_}|{error,_}. Битый/
        %% просроченный/уже-использованный `code' (invalid_grant, в т.ч. от гонки
        %% cancel→retry на MIUI — issue 06) или KC-недоступность → чистый 401
        %% `invalid_credentials' вместо прежнего badmatch-500.
        {'error', Reason} ->
            lager:info("validate_ext/2  auth_callback: token exchange failed ~p", [Reason]),
            cb_context:add_system_error('invalid_credentials', Context);
        Other ->
            lager:info("validate_ext/2  auth_callback: unexpected token result ~p", [Other]),
            cb_context:add_system_error('invalid_credentials', Context)
    end;
validate(Context, ?KERBEROS_LOGIN) ->
    lager:info("validate_ext/2 kerberos_login req_nouns: ~p",[cb_context:req_nouns(Context)]),
    case zkeycloak_util:kerberos_enabled() of
        'true' ->
            QS = cb_context:query_string(Context),
            Prompt = kz_json:get_ne_binary_value(<<"prompt">>, QS),
            PromptOpts = case Prompt of
                <<"none">> -> #{'prompt' => <<"none">>};
                _ -> #{}
            end,
            %% PKCE code_challenge (S256) — опционален, симметрично
            %% ?AUTH_LINK (Fable-review issue 04): web-фронт теперь шлёт
            %% challenge и для Kerberos-flow (verifier придержит в
            %% sessionStorage до auth_callback). challenge публичен по
            %% дизайну PKCE. 'undefined' → старый фронт без PKCE.
            CodeChallenge = kz_json:get_ne_binary_value(<<"code_challenge">>, QS),
            lager:info("validate_ext/2 kerberos_login: has_code_challenge=~p",
                       [CodeChallenge =/= 'undefined']),
            ExtraOpts = case CodeChallenge of
                'undefined' -> PromptOpts;
                _ -> PromptOpts#{'code_challenge' => CodeChallenge}
            end,
            AuthUrl = zkeycloak_util:kerberos_auth_url(ExtraOpts),
            JObj = kz_json:set_value(<<"auth_url">>, AuthUrl, kz_json:new()),
            cb_context:set_resp_status(cb_context:set_resp_data(Context, JObj), 'success');
        'false' ->
            cb_context:add_system_error('forbidden', Context)
    end;
validate(Context, ?LOGOUT) ->
    %% `id_token_hint' приходит из QS — фронт берёт его из своего state
    %% (`kc_id_token', enrich_resp_with_kc_tokens/3 положил его в auth-response).
    %% Без hint'а KC показывает confirmation page по OIDC-спеке.
    QS = cb_context:query_string(Context),
    IdTokenHint = kz_json:get_ne_binary_value(<<"id_token_hint">>, QS),
    LogoutUrl = zkeycloak_util:logout_url(IdTokenHint),
    %% issue 01: LogoutUrl несёт `id_token_hint=<сырой id_token>' в query —
    %% полный URL в лог писать нельзя. Логируем redacted-hint (он же сигналит
    %% наличие/отсутствие hint'а: `undefined' = no); endpoint восстановим из
    %% конфига. Сам lager:info сохранён.
    lager:info("zkeycloak logout_url: id_token_hint=~s"
              ,[zkeycloak_util:redact(IdTokenHint)]),
    JObj = kz_json:set_value(<<"logout_url">>, LogoutUrl, kz_json:new()),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, JObj), 'success');
%% @doc Обмен refresh_token → новый Kazoo auth_token + новый KC refresh/id.
%% Mobile-клиенты (zfield) хранят `kc_refresh_token' в secure_storage под
%% BiometricPrompt и дёргают эту ручку при cold-start (после биометрии) и
%% при 401 от Kazoo. Тело запроса: `{"data":{"refresh_token":"..."}}'
%% (стандартный Crossbar-конверт). Ответ — расширение auth_callback'а:
%% Kazoo auth_token + `kc_refresh_token' (новый, ротированный KC) +
%% `kc_id_token' (для последующего end-session). Ошибки KC (`invalid_grant',
%% истёкший/отозванный refresh) → `invalid_credentials' → клиент идёт в
%% полный AppAuth-flow.
validate(Context, ?REFRESH) ->
    ReqData = cb_context:req_data(Context),
    RefreshToken = kz_json:get_ne_binary_value(<<"refresh_token">>, ReqData),
    case RefreshToken of
        'undefined' ->
            lager:info("validate_ext/2 refresh: missing refresh_token in body"),
            cb_context:add_system_error('invalid_credentials', Context);
        _ ->
            handle_refresh(Context, RefreshToken)
    end;
validate(Context, ?ZKEYCLOAK) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec zkeycloak_ext_post(cb_context:context()) -> cb_context:context().
zkeycloak_ext_post(Context) ->
    ReqJSON = cb_context:req_json(Context),
    lager:info("zkeycloak_ext_post/1 req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("zkeycloak_ext_post/1 req_json: ~p",[ReqJSON]),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, kz_json:new()), 'success').

%% @doc Обмен refresh_token на KC и формирование Kazoo-сессии.
%% Структура oidcc-tuple строится в zkeycloak_util:retrieve_token; здесь
%% подхватываем её один-в-один (`oidcc_token_*' records определены в
%% `oidcc/include/oidcc_token.hrl').
-spec handle_refresh(cb_context:context(), kz_term:ne_binary()) ->
          cb_context:context().
handle_refresh(Context, RefreshToken) ->
    case zkeycloak_util:refresh_token(RefreshToken) of
        {'ok', {oidcc_token
               ,{oidcc_token_id, NewTokenId, _ClaimsMap}
               ,{oidcc_token_access, NewTokenAccess, _Timeout, _Type}
               ,{oidcc_token_refresh, NewTokenRefresh}
               ,_Scope
               } = TokenTuple} ->
            %% issue 01: маскируем новые токены (ротированный refresh валиден ~30 дней).
            lager:info("handle_refresh: ok, new_access=~s new_refresh=~s",
                       [zkeycloak_util:redact(NewTokenAccess), zkeycloak_util:redact(NewTokenRefresh)]),
            authorize_and_issue(Context, TokenTuple, NewTokenAccess, NewTokenId,
                                NewTokenRefresh, 'refresh');
        {'error', Reason} ->
            lager:info("handle_refresh: KC error ~p — invalid_grant flow", [Reason]),
            cb_context:add_system_error('invalid_credentials', Context);
        Other ->
            lager:info("handle_refresh: unexpected oidcc result ~p", [Other]),
            cb_context:add_system_error('invalid_credentials', Context)
    end.

%% @doc Общий хвост login- и refresh-путей после успешного получения набора
%% KC-токенов: тянем userinfo, гейтим по клиентской роли `onbill_access',
%% выдаём Kazoo-токен либо мапим отказ. `retrieve_userinfo/1' нормализован
%% (issue 05) к {ok,_}|{error,_} — сбой userinfo (сетевой к KC) даёт чистый
%% 401 `invalid_credentials' вместо badmatch-500. Ранее эта ветка (userinfo +
%% role-gate) дублировалась дословно в auth_callback'е и handle_refresh.
-spec authorize_and_issue(cb_context:context()
                         ,tuple()
                         ,kz_term:ne_binary()
                         ,kz_term:ne_binary()
                         ,kz_term:ne_binary()
                         ,'login' | 'refresh'
                         ) -> cb_context:context().
authorize_and_issue(Context, TokenTuple, TokenAccess, TokenId, TokenRefresh, Mode) ->
    case zkeycloak_util:retrieve_userinfo(TokenTuple) of
        {'ok', UserInfoMap} ->
            lager:info("authorize_and_issue[~p]  UserInfoMap: ~p", [Mode, UserInfoMap]),
            %% KC-auth ревью (issue 13, backend): роль-гейт читает
            %% `resource_access.onbill_client.roles' из USERINFO, а не из
            %% access-токена. KC отдаёт `resource_access' в userinfo ТОЛЬКО
            %% при включённом флаге маппера «Add to userinfo» на клиенте
            %% `onbill_client'. Если флаг выключен — `UserInfoRoles = []' и
            %% гейт деним ВСЕХ (fail-closed: безопасно, но хрупкая привязка к
            %% realm-конфигу — «молчаливый» отказ всех логинов вместо явной
            %% ошибки). Инвариант держится realm-настройкой, кодом не
            %% гарантируется → проверять флаг на стенде при любом
            %% реконфиге realm (в частности — в окно апгрейда KC 23→26.6.3).
            %% NB: гейт токен-пути (`zkeycloak_util:validate_onbill_access/1',
            %% для внешних KC-issued токенов) читает те же роли из КЛЕЙМОВ
            %% access-токена и от флага userinfo НЕ зависит — здесь оставляем
            %% userinfo-источник как есть (смена источника = поведенческое
            %% изменение, требует стенд-приёмки; вне scope low-sev бэклога).
            UserInfoRoles = kz_maps:get([<<"resource_access">>
                                        ,<<"onbill_client">>
                                        ,<<"roles">>], UserInfoMap, []),
            case lists:member(<<"onbill_access">>, UserInfoRoles) of
                'true' ->
                    provide_keycloak_token(Context, TokenAccess, TokenId,
                                           TokenRefresh, UserInfoMap, Mode);
                'false' ->
                    lager:info("authorize_and_issue[~p]  insufficient UserInfoRoles: ~p",
                               [Mode, UserInfoRoles]),
                    cb_context:add_system_error('insufficient_role', Context)
            end;
        {'error', Reason} ->
            lager:info("authorize_and_issue[~p]  retrieve_userinfo failed ~p", [Mode, Reason]),
            cb_context:add_system_error('invalid_credentials', Context)
    end.

-spec provide_keycloak_token(cb_context:context()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,map()
                            ,'login' | 'refresh'
                            ) -> cb_context:context().
provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap, Mode) ->
    %% issue 07: `sub' обязан быть KIS-производным UUID (SPI `toUuidFormat');
    %% LDAP/service-account/federated субъекты несут иной формат — их KIS
    %% owner_id не существует, отказываем чисто вместо function_clause-500.
    case zcore_util:from_key(kz_maps:get(<<"sub">>, UserInfoMap), 'undefined') of
        'undefined' ->
            lager:info("provide_keycloak_token[~p]: sub is not a KIS-derived uuid"
                       " (LDAP/service-account/federated subject?) — rejecting", [Mode]),
            cb_context:add_system_error('invalid_credentials', Context);
        OwnerId ->
            provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh,
                                   UserInfoMap, Mode, OwnerId)
    end.

-spec provide_keycloak_token(cb_context:context()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,map()
                            ,'login' | 'refresh'
                            ,kz_term:ne_binary()
                            ) -> cb_context:context().
provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap, Mode, OwnerId) ->
    %% issue 10: claim `account_id' ставит только SPI-путь handleKazooAuth;
    %% userinfo без него (LDAP/federated) раньше уезжал undefined'ом в
    %% format_account_id/open_doc/create_user — грязный сбой вместо 401.
    case kz_maps:get(<<"account_id">>, UserInfoMap) of
        'undefined' ->
            lager:info("provide_keycloak_token[~p]: userinfo has no account_id claim"
                       " owner_id=~s (non-KazooAuth subject?) — rejecting", [Mode, OwnerId]),
            cb_context:add_system_error('invalid_credentials', Context);
        AccountId ->
            DbName = kzs_util:format_account_id(AccountId, 'encoded'),
            provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh,
                                   UserInfoMap, Mode, OwnerId, AccountId, DbName)
    end.

-spec provide_keycloak_token(cb_context:context()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,map()
                            ,'login' | 'refresh'
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ) -> cb_context:context().
provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap,
                       Mode, OwnerId, AccountId, DbName) ->
    case check_user_doc(Mode, DbName, AccountId, OwnerId, UserInfoMap) of
        'ok' ->
            issue_auth_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap,
                             AccountId, OwnerId);
        {'error', Reason} ->
            lager:warning("provide_keycloak_token[~p]: user doc check failed"
                          " owner_id=~p account_id=~p reason=~p",
                          [Mode, OwnerId, AccountId, Reason]),
            reject_user_provisioning(Context, Mode, Reason)
    end.

%% @doc Login-путь — гарантируем существование user-doc'а (создаём при
%% необходимости). Refresh-путь — только проверяем существование; на
%% miss возвращаем тегированную ошибку, чтобы вызывающий смапил её в
%% `invalid_credentials' и mobile (zfield) пошёл в полный AppAuth-flow
%% (см. контракт в комментариях handle_refresh выше).
-spec check_user_doc('login' | 'refresh'
                    ,kz_term:ne_binary()
                    ,kz_term:ne_binary()
                    ,kz_term:ne_binary()
                    ,map()
                    ) -> 'ok' | {'error', term()}.
check_user_doc('login', DbName, AccountId, OwnerId, UserInfoMap) ->
    ensure_user_doc(DbName, AccountId, OwnerId, UserInfoMap);
check_user_doc('refresh', DbName, _AccountId, OwnerId, _UserInfoMap) ->
    case kz_datamgr:open_doc(DbName, OwnerId) of
        {'ok', _} -> 'ok';
        Err -> {'error', {'missing_user_doc_on_refresh', Err}}
    end.

%% @doc Гарантировать, что у `OwnerId' есть user-doc в account-db. Если
%% не существует — создать; на любой ошибке создания (в т.ч. missing
%% `last_name' у LDAP-юзера без `sn') — поднять наверх, чтобы вызывающий
%% отказал в выдаче auth-токена. Инвариант: `auth_token ⇒ есть user-doc'.
-spec ensure_user_doc(kz_term:ne_binary()
                     ,kz_term:ne_binary()
                     ,kz_term:ne_binary()
                     ,map()
                     ) -> 'ok' | {'error', term()}.
ensure_user_doc(DbName, AccountId, OwnerId, UserInfoMap) ->
    case kz_datamgr:open_doc(DbName, OwnerId) of
        {'ok', _} -> 'ok';
        {'error', 'not_found'} ->
            Firstname = kz_maps:get(<<"given_name">>, UserInfoMap, 'undefined'),
            Surname = kz_maps:get(<<"family_name">>, UserInfoMap, 'undefined'),
            Email = kz_maps:get(<<"email">>, UserInfoMap, 'undefined'),
            UserPassword = kz_binary:rand_hex(12),
            case zkeycloak_util:create_user(AccountId, OwnerId, Firstname, Surname,
                                            Email, 'undefined', UserPassword) of
                {'ok', _} -> 'ok';
                {'error', _} = Err -> Err
            end;
        {'error', _} = OpenErr ->
            %% Datastore error (timeout/unreachable/…) — НЕ пытаемся re-create:
            %% создавать на каждом transient-fail'е чревато гонкой и dup-doc'ами.
            lager:warning("ensure_user_doc: open_doc failed owner_id=~p err=~p",
                          [OwnerId, OpenErr]),
            {'error', 'datastore_unreachable'}
    end.

%% @doc Маппинг внутренней причины отказа в crossbar-ответ.
%%
%% Refresh-режим: любая проблема → `invalid_credentials' (401), чтобы
%% mobile-клиент свалился в полный AppAuth-flow (контракт handle_refresh).
%%
%% Login-режим:
%%   `{validation_errors,_}'  — канонический Kazoo per-field error через
%%                              `add_doc_validation_errors/2' (структурный
%%                              ответ; фронту понятно, какой именно атрибут
%%                              отсутствует — обычно `last_name' у юзера с
%%                              пустым `sn' в AD).
%%   `{system_error,Error}'   — `add_system_error(Error,_)' (как в cb_users).
%%   `'datastore_unreachable'' — 503, чтобы клиент ретраил.
%%   Иное (catch-all, `EXIT')  — `unspecified_fault' (500), чтобы оператор не
%%                              путал инфра-проблему с проблемой AD-профиля.
-spec reject_user_provisioning(cb_context:context()
                              ,'login' | 'refresh'
                              ,term()
                              ) -> cb_context:context().
reject_user_provisioning(Context, 'refresh', _Reason) ->
    cb_context:add_system_error('invalid_credentials', Context);
reject_user_provisioning(Context, 'login', {'validation_errors', Errors}) ->
    cb_context:add_doc_validation_errors(Context, Errors);
reject_user_provisioning(Context, 'login', {'system_error', Error}) ->
    cb_context:add_system_error(Error, Context);
reject_user_provisioning(Context, 'login', 'datastore_unreachable') ->
    cb_context:add_system_error('datastore_unreachable', Context);
reject_user_provisioning(Context, 'login', _Reason) ->
    cb_context:add_system_error('unspecified_fault', Context).

%% @doc Выпуск Kazoo auth-token'а + обогащение KC-токенами.
-spec issue_auth_token(cb_context:context()
                      ,kz_term:ne_binary()
                      ,kz_term:ne_binary()
                      ,kz_term:ne_binary()
                      ,map()
                      ,kz_term:ne_binary()
                      ,kz_term:ne_binary()
                      ) -> cb_context:context().
issue_auth_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap,
                 AccountId, OwnerId) ->
    UserInfoJObj = kz_json:from_map(UserInfoMap),
    lager:info("provide_keycloak_token/5  UserInfoJObj: ~p",[UserInfoJObj]),
    AuthMethod = kz_term:to_binary(zkeycloak_util:auth_method(TokenAccess)),
    AccountName = kz_maps:get(<<"account_name">>, UserInfoMap, 'undefined'),
    JObj = kz_json:from_list(
             props:filter_undefined(
               [{<<"account_id">>, AccountId}
               ,{<<"owner_id">>, OwnerId}
               ,{<<"keycloak_resource_access">>, kz_json:get_value(<<"resource_access">>, UserInfoJObj)}
               ,{<<"kc_full_name">>, build_full_name(UserInfoJObj)}
               ,{<<"auth_method">>, AuthMethod}
               ,{<<"account_name">>, AccountName}
               ])),
    Ctx1 = crossbar_auth:create_auth_token(cb_context:set_doc(Context, JObj),
                                           'cb_zkeycloak_ext'),
    %% После create_auth_token resp_data содержит kazoo-конверт с auth_token.
    %% Подмешиваем `kc_refresh_token' и `kc_id_token' — нужны mobile-клиенту
    %% (zfield) для biometric-flow: refresh хранится в secure_storage под
    %% BiometricPrompt, id_token используется для KC end-session при logout.
    %% Web-клиент (zfront) поля игнорирует — обратная совместимость сохранена.
    enrich_resp_with_kc_tokens(Ctx1, TokenId, TokenRefresh).

%% @doc Добавить kc_refresh_token + kc_id_token в resp_data.
-spec enrich_resp_with_kc_tokens(cb_context:context()
                                ,kz_term:ne_binary()
                                ,kz_term:ne_binary()
                                ) -> cb_context:context().
enrich_resp_with_kc_tokens(Context, TokenId, TokenRefresh) ->
    case cb_context:resp_status(Context) of
        'success' ->
            RespData0 = case cb_context:resp_data(Context) of
                            'undefined' -> kz_json:new();
                            Existing -> Existing
                        end,
            RespData1 = kz_json:set_values(
                          props:filter_undefined(
                            [{<<"kc_refresh_token">>, TokenRefresh}
                            ,{<<"kc_id_token">>, TokenId}
                            ]), RespData0),
            cb_context:set_resp_data(Context, RespData1);
        _ ->
            Context
    end.

%%------------------------------------------------------------------------------
%% @doc Собрать полное ФИО для auth-doc'а: `given_name' + ` ' + `family_name'.
%% Используется `zpaparazzi_authz:can_*_epl/3' для сопоставления с
%% `driver_fio' из EPL-doc'а через `zcore_util_fio_match:matches/2'.
%% Fallback: `name' (если Keycloak не отдаёт given/family), затем
%% `preferred_username'. Возвращает `'undefined'' если ничего нет —
%% `props:filter_undefined' убирает ключ из auth-doc'а.
%% @end
%%------------------------------------------------------------------------------
-spec build_full_name(kz_json:object()) -> kz_term:api_ne_binary().
build_full_name(UserInfoJObj) ->
    Given  = kz_json:get_ne_binary_value(<<"given_name">>, UserInfoJObj),
    Family = kz_json:get_ne_binary_value(<<"family_name">>, UserInfoJObj),
    case {Given, Family} of
        {'undefined', 'undefined'} ->
            case kz_json:get_ne_binary_value(<<"name">>, UserInfoJObj) of
                'undefined' -> kz_json:get_ne_binary_value(<<"preferred_username">>, UserInfoJObj);
                Name -> Name
            end;
        {'undefined', F} -> F;
        {G, 'undefined'} -> G;
        {G, F} -> <<G/binary, " ", F/binary>>
    end.

