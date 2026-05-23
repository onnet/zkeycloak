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
    lager:info("authorisze/1  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("authorisze/1  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/1  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/1  req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).

-spec authorize(cb_context:context(), kz_term:ne_binary()) -> boolean().
authorize(Context, Token1) ->
    lager:info("authorisze/2 Token1: ~p",[Token1]),
    lager:info("authorisze/2 req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("authorisze/2 req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/2 req_headers: ~p",[cb_context:req_headers(Context)]),
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
    lager:info("authenticate_nouns/2  req_headers: ~p",[cb_context:req_headers(Context)]),
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
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).

-spec validate(cb_context:context(), path_token()) -> cb_context:context().
validate(Context, ?AUTH_LINK) ->
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    AuthUrl = zkeycloak_util:auth_url(),
    JObj = kz_json:set_value(<<"auth_url">>, AuthUrl, kz_json:new()),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, JObj), 'success');
validate(Context, ?AUTH_CALLBACK) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    lager:info("validate_ext/2  cb_context:query_string: ~p",[cb_context:query_string(Context)]),
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
    case zkeycloak_util:retrieve_token(Code, RedirectUri, PkceVerifier) of
        {oidcc_token
        ,{oidcc_token_id, TokenId, ClaimsMap}
        ,{oidcc_token_access, TokenAccess, _Timeout, _Type}
        ,{oidcc_token_refresh, TokenRefresh}
        ,_Scope
        } = TokenTuple ->

            lager:info("validate_ext/2  TokenId: ~p",[TokenId]),
            lager:info("validate_ext/2  TokenAccess: ~p",[TokenAccess]),
            lager:info("validate_ext/2  TokenRefresh: ~p",[TokenRefresh]),
            lager:info("validate_ext/2  ClaimsMap: ~p",[ClaimsMap]),
            lager:info("validate_ext/2  _Scope: ~p",[_Scope]),

            UserInfoMap = zkeycloak_util:retrieve_userinfo(TokenTuple),
            lager:info("validate_ext/2  UserInfoMap: ~p",[UserInfoMap]),
            UserInfoRoles = kz_maps:get([<<"resource_access">>,<<"onbill_client">>,<<"roles">>], UserInfoMap, []),
            case lists:member(<<"onbill_access">>, UserInfoRoles) of
                'true' ->
                    provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap);
                'false' ->
                    lager:info("validate_ext/2  insufficient UserInfoRoles: ~p",[UserInfoRoles]),
                    cb_context:add_system_error('insufficient_role', Context)
            end;
        _ ->
            cb_context:add_system_error('invalid_credentials', Context)
    end;
validate(Context, ?KERBEROS_LOGIN) ->
    lager:info("validate_ext/2 kerberos_login req_nouns: ~p",[cb_context:req_nouns(Context)]),
    case zkeycloak_util:kerberos_enabled() of
        'true' ->
            QS = cb_context:query_string(Context),
            Prompt = kz_json:get_ne_binary_value(<<"prompt">>, QS),
            ExtraOpts = case Prompt of
                <<"none">> -> #{'prompt' => <<"none">>};
                _ -> #{}
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
    lager:info("zkeycloak logout_url (id_token_hint=~s): ~s"
              ,[case IdTokenHint of 'undefined' -> <<"no">>; _ -> <<"yes">> end
               ,LogoutUrl
               ]),
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
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
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
            lager:info("handle_refresh: ok, new_access=~s new_refresh=~s",
                       [NewTokenAccess, NewTokenRefresh]),
            UserInfoMap = zkeycloak_util:retrieve_userinfo(TokenTuple),
            UserInfoRoles = kz_maps:get([<<"resource_access">>
                                        ,<<"onbill_client">>
                                        ,<<"roles">>], UserInfoMap, []),
            case lists:member(<<"onbill_access">>, UserInfoRoles) of
                'true' ->
                    provide_keycloak_token(Context, NewTokenAccess, NewTokenId,
                                           NewTokenRefresh, UserInfoMap);
                'false' ->
                    lager:info("handle_refresh: insufficient roles ~p", [UserInfoRoles]),
                    cb_context:add_system_error('insufficient_role', Context)
            end;
        {'error', Reason} ->
            lager:info("handle_refresh: KC error ~p — invalid_grant flow", [Reason]),
            cb_context:add_system_error('invalid_credentials', Context);
        Other ->
            lager:info("handle_refresh: unexpected oidcc result ~p", [Other]),
            cb_context:add_system_error('invalid_credentials', Context)
    end.

provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap) ->
    AccountId = kz_maps:get(<<"account_id">>, UserInfoMap),
    OwnerId = zbrt_util:from_key(kz_maps:get(<<"sub">>, UserInfoMap)),
    DbName = kzs_util:format_account_id(AccountId, 'encoded'),

    case kz_datamgr:open_doc(DbName, OwnerId) of
        {'ok', _} -> 'ok';
        _ ->
            Firstname = kz_maps:get(<<"given_name">>, UserInfoMap),
            Surname = kz_maps:get(<<"family_name">>, UserInfoMap),
            Email = kz_maps:get(<<"email">>, UserInfoMap),
            Phonenumber = <<"">>,
            UserPassword = kz_binary:rand_hex(12),
            zkeycloak_util:create_user(AccountId, OwnerId, Firstname, Surname, Email, Phonenumber, UserPassword)
    end,
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

