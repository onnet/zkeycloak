-module(cb_zkeycloak_ext).

-export([init/0
        ,request_data/1, request_data/2, request_data/3
        ,allowed_methods/0, allowed_methods/1, allowed_methods/2
        ,resource_exists/0, resource_exists/1, resource_exists/2
        ,authorize/1, authorize/2, authorize/3
        ,authenticate/1, authenticate/2, authenticate/3
        ,validate/1, validate/2, validate/3
        ,post/1, post/2, post/3
        ]).

-include("/opt/kazoo/applications/crossbar/src/crossbar.hrl").

-ifdef(TEST).
%% Внутренние auth-гейты, открытые для EUnit (`cb_zkeycloak_ext_tests').
-export([provide_keycloak_token/6
        ,provide_keycloak_token/7
        ,logout_id_token_hint/1
        ,check_user_doc/5
        ]).
-endif.

%%-include("zbrt_defs.hrl").
%%-define(HEADERS, [{"content-type", "application/x-www-form-urlencoded"}]).
-define(HEADERS, [{"content-type", "application/json"}]).

-define(AUTH_LINK, <<"auth_link">>).
-define(AUTH_CALLBACK, <<"auth_callback">>).
-define(KERBEROS_LOGIN, <<"kerberos_login">>).
-define(LOGOUT, <<"logout">>).
-define(ACK, <<"ack">>).
-define(BACKCHANNEL, <<"backchannel">>).
-define(REFRESH, <<"refresh">>).
-define(ZKEYCLOAK, <<"zkeycloak_ext">>).

%% Claim'ы Kazoo-аккаунта: основной — user session note от `handleKazooAuth',
%% фолбэк — константа hardcoded-маппера скоупа `onbill_scope' для субъектов без
%% нот (LDAP/Kerberos). Обоснование и порядок раскатки — в `account_id_claim/1'.
-define(ACCOUNT_ID_CLAIM, <<"account_id">>).
-define(DEFAULT_ACCOUNT_ID_CLAIM, <<"default_account_id">>).

%% @doc Отдельный системный отказ для «OIDC-провайдер недоступен» — НЕ 401 и
%% НЕ 500 (инцидент 29.07). 401 `invalid_credentials' на этом классе прямо
%% вреден: он говорит клиенту «креды плохие», и портал начинал авторизацию
%% заново, переиспользуя тот же одноразовый `code' (в логах KC —
%% `Code '<uuid>' already used', 14 повторов). 503 — «инфраструктура, повтори
%% позже»; отдельный `error'-тег (а не переиспользованный
%% `datastore_unreachable', который тоже 503) нужен, чтобы клиент отличал
%% недоступный Keycloak от недоступного CouchDB.
-define(PROVIDER_UNAVAILABLE_CODE, 503).
-define(PROVIDER_UNAVAILABLE_ERROR, 'oidc_provider_unavailable').
-define(PROVIDER_UNAVAILABLE_MSG, <<"identity provider is not available, retry later">>).

%% Ключ хэнд-овера validate -> post (execute-фаза, issue 22). Значения тегированы
%% путём: refresh переносит authoritative binding до необратимой KC rotation;
%% logout переносит только проверенные входы до begin/revoke/ack. Старое имя
%% ключа сохраняется ради hotload-совместимости refresh. Отсутствие тега не
%% запускает эффект повторно.
-define(POST_HANDOVER, 'zkeycloak_ext_post_refresh').
-define(SESSION_CONTEXT, 'zkeycloak_session_context').

-define(LOGOUT_TRANSACTION_TTL_S, 300).

%% @doc Стоимость старта logout в token-bucket'е клиента (находка 01-P3-4
%% кросс-ревью 22.08.2026).
%%
%% `POST /zkeycloak_ext/logout' — НЕаутентифицированная ручка
%% (`authenticate_nouns'/`authorize_nouns' отдают `true'), и она СОЗДАЁТ
%% документ: `begin_logout/4' пишет transaction-док со случайным `state', то
%% есть каждый вызов — новый док в `token_auth' (TTL 300 с). Требование
%% валидной подписи `id_token' сужает круг до инсайдеров и утёкших токенов,
%% но НЕ ограничивает частоту: один валидный (в т.ч. ИСТЁКШИЙ —
%% `verify_logout_id_token/1' срок не смотрит намеренно) `id_token' даёт
%% неограниченную запись в прод-базу. Общий rate-limit `cb_token_auth' этот
%% путь не покрывает: он висит на `x-auth-token'/`bearer', которых здесь нет.
%%
%% Механика — та же, что у соседней неаутентифицированной ручки, создающей
%% состояние (`cb_user_auth:validate/1'): счёт по бакету клиента
%% (IP + account_id), цена из конфига, отказ = 429. Дефолт равен
%% `user_auth_tokens' — логин и выход одного пользователя это события одного
%% порядка частоты; занижать нельзя (клиент трёхшагового logout зовёт ручку
%% штатно).
-define(DEFAULT_LOGOUT_START_TOKENS, 35).
-define(LOGOUT_START_TOKENS,
        kapps_config:get_integer(?CONFIG_CAT, <<"zkeycloak_logout_tokens">>
                                ,?DEFAULT_LOGOUT_START_TOKENS)).
-spec init() -> ok.
init() ->
    _ = crossbar_bindings:bind(<<"*.authenticate.zkeycloak_ext">>, ?MODULE, 'authenticate'),
    _ = crossbar_bindings:bind(<<"*.authorize.zkeycloak_ext">>, ?MODULE, 'authorize'),
    _ = crossbar_bindings:bind(<<"*.allowed_methods.zkeycloak_ext">>, ?MODULE, 'allowed_methods'),
    _ = crossbar_bindings:bind(<<"*.resource_exists.zkeycloak_ext">>, ?MODULE, 'resource_exists'),
    _ = crossbar_bindings:bind(<<"*.request_data.post.zkeycloak_ext">>, ?MODULE, 'request_data'),
    _ = crossbar_bindings:bind(<<"*.validate.zkeycloak_ext">>, ?MODULE, 'validate'),
    _ = crossbar_bindings:bind(<<"*.execute.post.zkeycloak_ext">>, ?MODULE, 'post'),
    ok.

%% Keycloak Back-Channel Logout 1.0 sends a top-level form field rather than
%% the Crossbar JSON envelope. Consume it before the generic form parser: that
%% parser both rejects the top-level shape and logs the parsed object.
-spec request_data(api_util:request_data_args()) -> 'false'.
request_data({_Req, _Context, _ContentType, _QueryString}) ->
    'false'.

-spec request_data(api_util:request_data_args(), path_token()) -> 'false'.
request_data({_Req, _Context, _ContentType, _QueryString}, _Token) ->
    'false'.

-spec request_data(api_util:request_data_args(), path_token(), path_token()) ->
          'false' |
          {'ok', cb_context:context(), cowboy_req:req()} |
          {'error', 'invalid_credentials'}.
request_data({Req0, Context, <<"application/x-www-form-urlencoded">>, QueryString},
             ?LOGOUT, ?BACKCHANNEL) ->
    case api_util:get_request_body(Req0) of
        {'ok', Body, Req1} ->
            case parse_backchannel_body(Body) of
                {'ok', LogoutToken} ->
                    lager:debug("accepted keycloak backchannel form body (~b bytes), token=~s",
                                [byte_size(Body), zkeycloak_util:redact(LogoutToken)]),
                    ReqData = kz_json:from_list([{<<"logout_token">>, LogoutToken}]),
                    Ctx = cb_context:setters(
                            Context,
                            [{fun cb_context:set_req_data/2, ReqData}
                            ,{fun cb_context:set_req_json/2, ReqData}
                            ,{fun cb_context:set_query_string/2, QueryString}
                            ]),
                    {'ok', Ctx, Req1};
                'error' ->
                    lager:warning("rejected malformed keycloak backchannel form body (~b bytes)",
                                  [byte_size(Body)]),
                    {'error', 'invalid_credentials'}
            end;
        {'error', 'max_size', _Req1} ->
            lager:warning("rejected oversized keycloak backchannel form body"),
            {'error', 'invalid_credentials'}
    end;
request_data({_Req, _Context, _ContentType, _QueryString}, ?LOGOUT, ?BACKCHANNEL) ->
    {'error', 'invalid_credentials'};
request_data({_Req, _Context, _ContentType, _QueryString}, _Token1, _Token2) ->
    'false'.

-spec parse_backchannel_body(binary()) -> {'ok', kz_term:ne_binary()} | 'error'.
parse_backchannel_body(Body) ->
    try cow_qs:parse_qs(Body) of
        [{<<"logout_token">>, Token}] when is_binary(Token), Token =/= <<>> -> {'ok', Token};
        _ -> 'error'
    catch
        _:_ -> 'error'
    end.

-spec allowed_methods() -> http_methods().
allowed_methods() -> [?HTTP_POST, ?HTTP_GET].
-spec allowed_methods(path_token()) -> http_methods().
allowed_methods(?AUTH_LINK) -> [?HTTP_GET];
allowed_methods(?AUTH_CALLBACK) -> [?HTTP_GET];
allowed_methods(?KERBEROS_LOGIN) -> [?HTTP_GET];
allowed_methods(?LOGOUT) -> [?HTTP_POST];
allowed_methods(?REFRESH) -> [?HTTP_POST];
allowed_methods(?ZKEYCLOAK) -> [?HTTP_POST, ?HTTP_GET].

-spec allowed_methods(path_token(), path_token()) -> http_methods().
allowed_methods(?LOGOUT, ?ACK) -> [?HTTP_POST];
allowed_methods(?LOGOUT, ?BACKCHANNEL) -> [?HTTP_POST];
allowed_methods(_Token1, _Token2) -> [].

-spec resource_exists() -> boolean().
resource_exists() -> 'true'.
-spec resource_exists(path_tokens()) -> boolean().
resource_exists(?AUTH_LINK) -> 'true';
resource_exists(?AUTH_CALLBACK) -> 'true';
resource_exists(?KERBEROS_LOGIN) -> 'true';
resource_exists(?LOGOUT) -> 'true';
resource_exists(?REFRESH) -> 'true';
resource_exists(?ZKEYCLOAK) -> 'true'.

-spec resource_exists(path_token(), path_token()) -> boolean().
resource_exists(?LOGOUT, ?ACK) -> 'true';
resource_exists(?LOGOUT, ?BACKCHANNEL) -> 'true';
resource_exists(_Token1, _Token2) -> 'false'.

-spec authorize(cb_context:context()) -> boolean() | {'stop', cb_context:context()}.
authorize(Context) ->
    %% issue 15: `authorize/1' зовётся и на `POST /zkeycloak_ext/refresh' —
    %% сырой `~p' тела клал в лог 30-дневный `refresh_token' целиком. Тот же
    %% класс, что закрытый issue 14 (заголовки), но через тело: маскируем
    %% ЗНАЧЕНИЯ credential-ключей, сам lager:info сохранён.
    lager:info("authorisze/1  req_data: ~p",[zkeycloak_util:redact_req_data(cb_context:req_data(Context))]),
    lager:info("authorisze/1  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/1  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("authorisze/1  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/1  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/1  req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).

-spec authorize(cb_context:context(), kz_term:ne_binary()) -> boolean().
authorize(Context, Token1) ->
    lager:info("authorisze/2 Token1: ~p",[Token1]),
    %% issue 15: см. `authorize/1' — то же тело, тот же refresh_token.
    lager:info("authorisze/2 req_data: ~p",[zkeycloak_util:redact_req_data(cb_context:req_data(Context))]),
    lager:info("authorisze/2 req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/2 req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("authorisze/2 req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/2 req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/2 req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).


-spec authorize(cb_context:context(), path_token(), path_token()) -> boolean().
authorize(_Context, ?LOGOUT, ?ACK) -> 'true';
authorize(_Context, ?LOGOUT, ?BACKCHANNEL) -> 'true';
authorize(_Context, _Token1, _Token2) -> 'false'.
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
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"logout">>]}], Method)
  when Method =:= ?HTTP_POST ->
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

-spec authenticate(cb_context:context(), path_token(), path_token()) -> boolean().
authenticate(_Context, ?LOGOUT, ?ACK) -> 'true';
authenticate(_Context, ?LOGOUT, ?BACKCHANNEL) -> 'true';
authenticate(_Context, _Token1, _Token2) -> 'false'.

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
    %% `auth_url/1' нормализован к {ok,_}|{error,_} (инцидент 29.07): раньше не
    %% готовый discovery-воркер давал badmatch и Crossbar-500 на ручке логина.
    respond_with_auth_url(Context, <<"auth_link">>, zkeycloak_util:auth_url(CodeChallenge));
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
            %% Оставляем только короткий SHA-256 fingerprint; lager:info сохранён.
            lager:info("validate_ext/2  TokenId: ~s",[zkeycloak_util:redact(TokenId)]),
            lager:info("validate_ext/2  TokenAccess: ~s",[zkeycloak_util:redact(TokenAccess)]),
            lager:info("validate_ext/2  TokenRefresh: ~s",[zkeycloak_util:redact(TokenRefresh)]),
            %% issue 15: claim'ы id_token'а несут ПДн (email, ФИО, атрибуты
            %% realm'а) — сырой `~p' клал их в plaintext-лог. Логируем
            %% whitelist служебных полей + ИМЕНА остальных (`redacted_keys').
            lager:info("validate_ext/2  ClaimsMap: ~p",[zkeycloak_util:claims_digest(ClaimsMap)]),
            lager:info("validate_ext/2  _Scope: ~p",[_Scope]),
            SessionContext = keycloak_session_context(
                               'login', ClaimsMap, TokenAccess, TokenRefresh),
            authorize_and_issue(cb_context:store(Context, ?SESSION_CONTEXT, SessionContext),
                                TokenTuple, TokenAccess, TokenId, TokenRefresh, 'login');
        %% issue 05: `retrieve_token/3' нормализован к {ok,_}|{error,_}. Битый/
        %% просроченный/уже-использованный `code' (invalid_grant, в т.ч. от гонки
        %% cancel→retry на MIUI — issue 06) или KC-недоступность → чистый 401
        %% `invalid_credentials' вместо прежнего badmatch-500.
        {'error', Reason} ->
            %% P3 (кросс-ревью 18.07): `Reason' из retrieve_token/3 может нести
            %% встроенное в `{badmatch,V}'/… значение (claim-байты) — чистим.
            lager:info("validate_ext/2  auth_callback: token exchange failed ~p"
                      ,[zkeycloak_util:redact_reason(Reason)]),
            %% Инцидент 29.07: «дискавери-провайдер не готов» — это НЕ «клиент
            %% прислал плохие креды». Под 401 портал начинал авторизацию заново
            %% с тем же одноразовым `code' (KC: `Code '<uuid>' already used',
            %% 14 повторов) и залипал намертво. Отдаём 503 — «повтори позже».
            provider_error(Context, <<"auth_callback">>, Reason, 'invalid_credentials');
        Other ->
            %% P3 (кросс-ревью 18.07): `Other' здесь — `{ok,<нестандартная
            %% форма>}' (retrieve_token нормализован к {ok,_}|{error,_}), т.е.
            %% дрейф формы токена с потенциально ЖИВЫМИ токенами внутри.
            lager:info("validate_ext/2  auth_callback: unexpected token result ~s"
                      ,[zkeycloak_util:redact_token_result(Other)]),
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
            respond_with_auth_url(Context, <<"kerberos_login">>
                                 ,zkeycloak_util:kerberos_auth_url(ExtraOpts));
        'false' ->
            cb_context:add_system_error('forbidden', Context)
    end;
validate(Context, ?LOGOUT) ->
    validate_logout_start(Context);
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
        _ -> validate_refresh_binding(Context, RefreshToken)
    end;
validate(Context, ?ZKEYCLOAK) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[zkeycloak_util:redact_headers(cb_context:req_headers(Context))]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).
-spec validate(cb_context:context(), path_token(), path_token()) ->
          cb_context:context().
validate(Context, ?LOGOUT, ?BACKCHANNEL) ->
    LogoutToken = kz_json:get_ne_binary_value(
                    <<"logout_token">>, cb_context:req_data(Context)),
    case LogoutToken of
        'undefined' -> cb_context:add_system_error('invalid_credentials', Context);
        _ ->
            case zkeycloak_util:verify_backchannel_logout_token(LogoutToken) of
                {'ok', Event} ->
                    store_logout_handover(Context, {'backchannel', Event});
                {'error', Reason} -> logout_validation_error(Context, Reason)
            end
    end;
validate(Context, ?LOGOUT, ?ACK) ->
    ReqData = cb_context:req_data(Context),
    State = kz_json:get_ne_binary_value(<<"state">>, ReqData),
    Verifier = kz_json:get_ne_binary_value(<<"verifier">>, ReqData),
    case {State, Verifier} of
        {'undefined', _} -> cb_context:add_system_error('invalid_credentials', Context);
        {_, 'undefined'} -> cb_context:add_system_error('invalid_credentials', Context);
        _ -> store_logout_handover(Context, {'ack', State, Verifier})
    end;
validate(Context, _Token1, _Token2) ->
    cb_context:add_system_error('not_found', Context).


%%------------------------------------------------------------------------------
%% @doc execute-фаза (issue 22). Все необратимые refresh/logout эффекты
%% выполняются после успешной validate-фазы и определяются тегом пути.
%%
%% `?REFRESH' — эффект: обмен refresh-токена в Keycloak НЕОБРАТИМ (KC ротирует
%% токен, повторный обмен тем же значением даёт `invalid_grant') и завершается
%% выпуском Kazoo-auth-токена, то есть записью auth-дока. Раньше вся цепочка
%% шла из validate: без execute-подписчиков вендорный пресет fatal/500 отвечал
%% бы 500 клиенту, у которого refresh-токен УЖЕ потрачен, а новый он не увидел —
%% mobile-клиент уходил бы в полный AppAuth-flow на ровном месте.
%%
%% `/' и `?ZKEYCLOAK' мутаций не выполняют; POST logout применяет эффект только
%% в execute.
%% @end
%%------------------------------------------------------------------------------
-spec post(cb_context:context()) -> cb_context:context().
post(Context) ->
    post_reply(Context).

-spec post(cb_context:context(), path_token()) -> cb_context:context().
post(Context, ?REFRESH) ->
    execute_refresh(Context, cb_context:fetch(Context, ?POST_HANDOVER));
post(Context, ?LOGOUT) ->
    execute_logout_start(Context, cb_context:fetch(Context, ?POST_HANDOVER));
post(Context, ?ZKEYCLOAK) ->
    post_reply(Context);
post(Context, _Path) ->
    %% сюда не доводит allowed_methods (остальные пути GET-only), но коллбэк
    %% обязан быть тотальным: function_clause в фолде = 500 с обнулённым
    %% resp_data вместо честного ответа
    lager:info("execute post for non-mutating path ~s, nothing to apply", [_Path]),
    Context.

-spec post(cb_context:context(), path_token(), path_token()) -> cb_context:context().
post(Context, ?LOGOUT, ?BACKCHANNEL) ->
    execute_backchannel(Context, cb_context:fetch(Context, ?POST_HANDOVER));
post(Context, ?LOGOUT, ?ACK) ->
    execute_logout_ack(Context, cb_context:fetch(Context, ?POST_HANDOVER));
post(Context, _Token1, _Token2) ->
    Context.

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

%% @doc Validate the signed ID-token hint and bind it to the server-side SID
%% record before creating a logout transaction. No persistent effect occurs in
%% validate; Crossbar execute owns all mutations.
-spec validate_logout_start(cb_context:context()) -> cb_context:context().
validate_logout_start(Context) ->
    %% Крышка ПЕРЕД проверкой подписи: иначе счётчик тратился бы только на
    %% валидные токены, а поток невалидных гонял бы криптопроверку без
    %% ограничителя. См. ?LOGOUT_START_TOKENS.
    case logout_start_rate_limit(Context) of
        {'false', Context1} ->
            lager:warning("rate limiting keycloak logout start for ~s",
                          [cb_context:client_ip(Context1)]),
            cb_context:add_system_error('too_many_requests', Context1);
        {'true', Context1} -> validate_logout_start_verified(Context1)
    end.

%%------------------------------------------------------------------------------
%% @doc Крышка частоты на старте logout — FAIL-OPEN по построению.
%%
%% Ограничитель ДОБАВЛЕН поверх работавшего пути, и его собственный отказ
%% (нет `kz_buckets', недоступен `kapps_config') не имеет права запирать
%% выход: гейт в рабочем пути, падающий закрыто, превращает деградацию
%% инфраструктуры в отказ функции. Отказ ограничителя счётен по
%% `lager:warning' — то есть виден, а не молчалив.
%% @end
%%------------------------------------------------------------------------------
-spec logout_start_rate_limit(cb_context:context()) ->
          {boolean(), cb_context:context()}.
logout_start_rate_limit(Context) ->
    try cb_modules_util:consume_tokens_until(Context, logout_start_cost(Context))
    catch
        _E:_R ->
            lager:warning("keycloak logout rate limiter unavailable (~p:~p): passing through",
                          [_E, _R]),
            {'true', Context}
    end.

%% Цена читается ОТДЕЛЬНО и тоже тотально: недоступный `kapps_config' обязан
%% давать код-дефолт, а не снимать крышку целиком (иначе отказ конфига
%% выключал бы ограничитель, а не только его настройку).
-spec logout_start_cost(cb_context:context()) -> non_neg_integer().
logout_start_cost(Context) ->
    try cb_modules_util:token_cost(Context, ?LOGOUT_START_TOKENS)
    catch _E:_R -> ?DEFAULT_LOGOUT_START_TOKENS
    end.

-spec validate_logout_start_verified(cb_context:context()) -> cb_context:context().
validate_logout_start_verified(Context) ->
    IdTokenHint = logout_id_token_hint(Context),
    case IdTokenHint of
        'undefined' -> cb_context:add_system_error('invalid_credentials', Context);
        _ ->
            case zkeycloak_util:verify_logout_id_token(IdTokenHint) of
                {'ok', #{'sid' := Sid, 'sub' := Sub,
                         'account_id' := AccountId}} ->
                    case zcore_util:from_key(Sub, 'undefined') of
                        'undefined' ->
                            cb_context:add_system_error('invalid_credentials', Context);
                        OwnerId ->
                            store_logout_handover(
                              Context,
                              {'logout_start', IdTokenHint, AccountId, OwnerId, Sid})
                    end;
                {'error', Reason} -> logout_validation_error(Context, Reason)
            end
    end.

-spec store_logout_handover(cb_context:context(), tuple()) -> cb_context:context().
store_logout_handover(Context, Handover) ->
    cb_context:set_resp_status(
      cb_context:store(Context, ?POST_HANDOVER, Handover), 'success').

-spec logout_validation_error(cb_context:context(), any()) -> cb_context:context().
logout_validation_error(Context, Reason) ->
    lager:warning("keycloak logout token validation failed: ~p",
                  [zkeycloak_util:redact_reason(Reason)]),
    cb_context:add_system_error('invalid_credentials', Context).

-spec execute_logout_start(cb_context:context(), any()) -> cb_context:context().
execute_logout_start(Context,
                     {'logout_start', IdTokenHint, AccountId, OwnerId, Sid}) ->
    TtlS = ?LOGOUT_TRANSACTION_TTL_S,
    case kz_auth_session_family:begin_logout(AccountId, OwnerId, Sid, TtlS) of
        {'ok', #{'state' := State, 'verifier' := Verifier}} ->
            LogoutUrl = zkeycloak_util:logout_url(IdTokenHint, State),
            Resp = kz_json:from_list([{<<"logout_url">>, LogoutUrl}
                                     ,{<<"state">>, State}
                                     ,{<<"verifier">>, Verifier}
                                     ,{<<"kazoo_status">>, <<"pending">>}
                                     ,{<<"keycloak_status">>, <<"pending">>}]),
            cb_context:set_resp_status(
              cb_context:set_resp_data(Context, Resp), 'success');
        {'error', Reason} -> logout_backend_error(Context, Reason)
    end;
execute_logout_start(Context, _NoHandover) -> Context.

-spec execute_backchannel(cb_context:context(), any()) -> cb_context:context().
execute_backchannel(Context,
                    {'backchannel', #{'sid' := Sid, 'jti' := Jti,
                                      'expires_at' := ExpiresAt}}) ->
    case kz_auth_session_family:revoke_kc_sid(Sid, Jti, ExpiresAt) of
        {'ok', Result} when Result =:= 'op_revoked'; Result =:= 'replayed' ->
            cb_context:set_resp_status(
              cb_context:set_resp_data(Context, kz_json:new()), 'success');
        {'error', Reason} -> logout_backend_error(Context, Reason)
    end;
execute_backchannel(Context, _NoHandover) -> Context.

-spec execute_logout_ack(cb_context:context(), any()) -> cb_context:context().
execute_logout_ack(Context, {'ack', State, Verifier}) ->
    case kz_auth_session_family:ack_logout(State, Verifier) of
        {'ok', _Transaction} ->
            Resp = kz_json:from_list([{<<"kazoo_status">>, <<"revoked">>}
                                     ,{<<"keycloak_status">>, <<"confirmed">>}]),
            cb_context:set_resp_status(
              cb_context:set_resp_data(Context, Resp), 'success');
        {'error', Reason} -> logout_backend_error(Context, Reason)
    end;
execute_logout_ack(Context, _NoHandover) -> Context.

-spec logout_backend_error(cb_context:context(), any()) -> cb_context:context().
logout_backend_error(Context, Reason) ->
    lager:warning("keycloak logout state transition failed: ~p",
                  [zkeycloak_util:redact_reason(Reason)]),
    case Reason of
        'invalid_logout_verifier' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'invalid_logout_transaction' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'not_found' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'binding_identity_mismatch' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'invalid_binding_state' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'invalid_session_binding' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'logout_event_expired' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'logout_event_replay_mismatch' ->
            cb_context:add_system_error('invalid_credentials', Context);
        'logout_transaction_expired' ->
            cb_context:add_system_error(
              409, 'logout_transaction_expired',
              <<"logout transaction expired, start logout again">>, Context);
        'keycloak_logout_unconfirmed' ->
            cb_context:add_system_error(
              409, 'keycloak_logout_unconfirmed',
              <<"identity provider logout is not confirmed yet">>, Context);
        _ -> auth_store_error(Context)
    end.

%% Восстановить validate-конверт поверх fatal/500-пресета Crossbar-фолда.
-spec post_reply(cb_context:context()) -> cb_context:context().
post_reply(Context) ->
    cb_context:set_resp_status(Context, 'success').


%% Разрыв хэнд-овера (окно hotload-скью: validate прошёл на СТАРОМ биме и обмен
%% там уже сделал) — второго обмена НЕ делаем: refresh-токен запроса к этому
%% моменту уже ротирован KC, и повторный вызов вернул бы `invalid_grant',
%% выбросив клиента в полный AppAuth-flow. Клиент получает fatal/500-пресет и
%% ретраит после раскатки.
-spec execute_refresh(cb_context:context(), any()) -> cb_context:context().
execute_refresh(Context, {?REFRESH, RefreshToken, BindingMode}) ->
    handle_refresh(Context, RefreshToken, BindingMode);
execute_refresh(Context, _NoHandover) ->
    lager:info("execute post refresh without validate handover, refusing to exchange token"),
    Context.

%%------------------------------------------------------------------------------
%% @doc Ответ ручек, отдающих /authorize-URL (`auth_link', `kerberos_login').
%% `zkeycloak_util:auth_url/1'/`kerberos_auth_url/1' нормализованы к
%% `{ok,_} | {error,_}'; до инцидента 29.07 они матчились жёстко, и не готовый
%% discovery-воркер ронял ручку логина в Crossbar-500.
%%
%% Fallback здесь `unspecified_fault' (500), а НЕ `invalid_credentials': на этих
%% ручках клиент никаких кредов не предъявляет, и «401» был бы враньём — сбой
%% построения URL это наша серверная проблема (дрейф формы oidcc, кривой конфиг
%% клиента), а не проблема пользователя.
%% @end
%%------------------------------------------------------------------------------
-spec respond_with_auth_url(cb_context:context()
                           ,kz_term:ne_binary()
                           ,{'ok', kz_term:ne_binary()} | {'error', any()}
                           ) -> cb_context:context().
respond_with_auth_url(Context, _Tag, {'ok', AuthUrl}) ->
    JObj = kz_json:set_value(<<"auth_url">>, AuthUrl, kz_json:new()),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, JObj), 'success');
respond_with_auth_url(Context, Tag, {'error', Reason}) ->
    lager:warning("validate_ext/2 ~s: auth url build failed ~p"
                 ,[Tag, zkeycloak_util:redact_reason(Reason)]),
    provider_error(Context, Tag, Reason, 'unspecified_fault').

%%------------------------------------------------------------------------------
%% @doc Разложить отказ oidcc на «провайдер недоступен» (503, ждать) и всё
%% остальное (`Fallback' — как было до инцидента 29.07). Классификатор живёт в
%% `zkeycloak_util:is_provider_unavailable/1' — там же его EUnit и там же
%% перечислены все три наблюдаемые формы отказа.
%% @end
%%------------------------------------------------------------------------------
-spec provider_error(cb_context:context()
                    ,kz_term:ne_binary()
                    ,any()
                    ,atom()
                    ) -> cb_context:context().
provider_error(Context, Tag, Reason, Fallback) ->
    case zkeycloak_util:is_provider_unavailable(Reason) of
        'true' ->
            lager:warning("zkeycloak ~s: oidc provider unavailable (~p) — replying ~p"
                         ,[Tag, zkeycloak_util:redact_reason(Reason), ?PROVIDER_UNAVAILABLE_CODE]),
            cb_context:add_system_error(?PROVIDER_UNAVAILABLE_CODE
                                       ,?PROVIDER_UNAVAILABLE_ERROR
                                       ,?PROVIDER_UNAVAILABLE_MSG
                                       ,Context
                                       );
        'false' ->
            cb_context:add_system_error(Fallback, Context)
    end.

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec zkeycloak_ext_post(cb_context:context()) -> cb_context:context().
zkeycloak_ext_post(Context) ->
    ReqJSON = cb_context:req_json(Context),
    %% issue 15: обе точки — сырое тело. `req_json' вдобавок печатает его
    %% ВМЕСТЕ с crossbar-конвертом (`{"data":{…}}'), т.е. креды лежат вторым
    %% уровнем — `redact_req_data/1' поэтому рекурсивна.
    lager:info("zkeycloak_ext_post/1 req_data: ~p",[zkeycloak_util:redact_req_data(cb_context:req_data(Context))]),
    lager:info("zkeycloak_ext_post/1 req_json: ~p",[zkeycloak_util:redact_req_data(ReqJSON)]),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, kz_json:new()), 'success').

%% @doc Достать `id_token_hint' для logout только из POST-тела. `req_data/1' читает
%% inner-объект `data'-конверта тела (crossbar-конвенция `{"data":{…}}',
%% симметрично `validate(?REFRESH)'). JWT в query-string не поддерживается.
-spec logout_id_token_hint(cb_context:context()) -> kz_term:api_ne_binary().
logout_id_token_hint(Context) ->
    case cb_context:req_verb(Context) of
        ?HTTP_POST -> kz_json:get_ne_binary_value(<<"id_token_hint">>, cb_context:req_data(Context));
        _ -> 'undefined'
    end.

%% @doc Обмен refresh_token на KC и формирование Kazoo-сессии.
%% Структура oidcc-tuple строится в zkeycloak_util:retrieve_token; здесь
%% подхватываем её один-в-один (`oidcc_token_*' records определены в
%% `oidcc/include/oidcc_token.hrl').
-spec handle_refresh(cb_context:context(), kz_term:ne_binary(), any()) ->
          cb_context:context().
handle_refresh(Context, RefreshToken, BindingMode) ->
    case zkeycloak_util:refresh_token(RefreshToken) of
        {'ok', {oidcc_token
               ,{oidcc_token_id, NewTokenId, ClaimsMap}
               ,{oidcc_token_access, NewTokenAccess, _Timeout, _Type}
               ,{oidcc_token_refresh, NewTokenRefresh}
               ,_Scope
               } = TokenTuple} ->
            %% issue 01: маскируем новые токены (ротированный refresh валиден ~30 дней).
            lager:info("handle_refresh: ok, new_access=~s new_refresh=~s",
                       [zkeycloak_util:redact(NewTokenAccess), zkeycloak_util:redact(NewTokenRefresh)]),
            SessionContext = keycloak_session_context(
                               {'refresh', BindingMode}, ClaimsMap,
                               NewTokenAccess, NewTokenRefresh),
            authorize_and_issue(cb_context:store(Context, ?SESSION_CONTEXT, SessionContext),
                                TokenTuple, NewTokenAccess, NewTokenId,
                                NewTokenRefresh, 'refresh');
        {'error', Reason} ->
            %% P3 (кросс-ревью 18.07): тот же класс, что auth_callback —
            %% `Reason' из refresh_token/1 чистим (встроенное значение краша).
            lager:info("handle_refresh: KC error ~p — invalid_grant flow"
                      ,[zkeycloak_util:redact_reason(Reason)]),
            %% Инцидент 29.07: и здесь «провайдер недоступен» отделяем от
            %% «refresh протух». Под 401 mobile-клиент выбрасывал ВАЛИДНЫЙ
            %% 30-дневный refresh и уходил в полный AppAuth-flow, который при
            %% мёртвом провайдере тоже не проходит; 503 честнее и позволяет
            %% просто повторить позже.
            provider_error(Context, <<"refresh">>, Reason, 'invalid_credentials');
        Other ->
            %% P3 (кросс-ревью 18.07): `Other' — `{ok,<нестандартная форма>}'
            %% (refresh_token нормализован), дрейф формы с живыми токенами.
            lager:info("handle_refresh: unexpected oidcc result ~s"
                      ,[zkeycloak_util:redact_token_result(Other)]),
            cb_context:add_system_error('invalid_credentials', Context)
    end.

%% @doc Общий хвост login- и refresh-путей после успешного получения набора
%% KC-токенов: тянем userinfo, гейтим по клиентской роли `onbill_access',
%% выдаём Kazoo-токен либо мапим отказ. `retrieve_userinfo/1' нормализован
%% (issue 05) к {ok,_}|{error,_} — сбой userinfo (сетевой к KC) даёт чистый
%% 401 `invalid_credentials' вместо badmatch-500. Ранее эта ветка (userinfo +

%% @doc Resolve the authoritative refresh binding before the irreversible
%% Keycloak exchange. Unknown legacy credentials cross only the rollout gate;
%% uncertain storage is retryable and never becomes a provider call.
-spec validate_refresh_binding(cb_context:context(), kz_term:ne_binary()) ->
          cb_context:context().
validate_refresh_binding(Context, RefreshToken) ->
    case kz_auth_session_family:lookup_refresh(RefreshToken) of
        {'ok', Binding} ->
            store_refresh_handover(Context, RefreshToken, Binding);
        {'error', 'not_found'} ->
            case kz_auth_session_family:legacy_refresh_allowed() of
                'true' -> store_refresh_handover(Context, RefreshToken, 'legacy');
                'false' -> cb_context:add_system_error('invalid_credentials', Context)
            end;
        {'error', 'session_revoked'} ->
            cb_context:add_system_error('invalid_credentials', Context);
        {'error', 'invalid_session_binding'} ->
            cb_context:add_system_error('invalid_credentials', Context);
        {'error', Reason} ->
            lager:warning("refresh binding lookup failed: ~p",
                          [zkeycloak_util:redact_reason(Reason)]),
            auth_store_error(Context)
    end.

-spec store_refresh_handover(cb_context:context(), kz_term:ne_binary(), any()) ->
          cb_context:context().
store_refresh_handover(Context, RefreshToken, BindingMode) ->
    cb_context:set_resp_status(
      cb_context:store(
        Context, ?POST_HANDOVER, {?REFRESH, RefreshToken, BindingMode}),
      'success').

-spec auth_store_error(cb_context:context()) -> cb_context:context().
auth_store_error(Context) ->
    cb_context:add_system_error(
      503, 'auth_store_unavailable',
      <<"session state storage is unavailable, retry later">>, Context).
%% role-gate) дублировалась дословно в auth_callback'е и handle_refresh.
-spec keycloak_session_context('login' | {'refresh', any()}, map(),
                               kz_term:ne_binary(), kz_term:ne_binary()) -> any().
keycloak_session_context(Mode, ClaimsMap, TokenAccess, RefreshToken) ->
    AccessClaims = zkeycloak_util:jwt_claims(TokenAccess),
    Sid = claim_value([<<"sid">>, <<"session_state">>], ClaimsMap, AccessClaims),
    TokenExpiresAt = claim_value([<<"exp">>], ClaimsMap, AccessClaims),
    ExpiresAt = zkeycloak_util:refresh_expires_at(RefreshToken, TokenExpiresAt),
    case {Sid, ExpiresAt} of
        {'undefined', _} -> {'error', 'keycloak_sid_missing'};
        {_, Expiry} when is_integer(Expiry), Expiry > 0 ->
            case Mode of
                'login' -> {'login', Sid, Expiry};
                {'refresh', Binding} -> {'refresh', Binding, Sid, Expiry}
            end;
        _ -> {'error', 'keycloak_session_expiry_missing'}
    end.
-spec claim_value([kz_term:ne_binary(), ...], map(), kz_term:proplist()) -> any().
claim_value(Keys, ClaimsMap, AccessClaims) ->
    case map_claim(Keys, ClaimsMap) of
        'undefined' -> props:get_first_defined(Keys, AccessClaims);
        Value -> Value
    end.

-spec map_claim([kz_term:ne_binary()], map()) -> any().
map_claim([Key | Rest], ClaimsMap) ->
    case kz_maps:get(Key, ClaimsMap, 'undefined') of
        'undefined' -> map_claim(Rest, ClaimsMap);
        'null' -> map_claim(Rest, ClaimsMap);
        Value -> Value
    end;
map_claim([], _ClaimsMap) -> 'undefined'.

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
            %% issue 15: userinfo — основной носитель ПДн во всём флоу.
            %% `claims_digest/1' сохраняет `resource_access' (роли), т.е.
            %% диагностика role-гейта ниже и «молчаливого» отказа issue 13
            %% по логу остаётся возможной.
            lager:info("authorize_and_issue[~p]  UserInfoMap: ~p"
                      ,[Mode, zkeycloak_util:claims_digest(UserInfoMap)]),
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
            %% P1 (кросс-ревью 18.07): userinfo — основной носитель ПДн во всём
            %% флоу, а `retrieve_userinfo/1' в штатном error-протоколе oidcc
            %% отдаёт `{missing_claim, _, UserinfoClaims}' с ПОЛНОЙ claims-map.
            %% Сырой `~p' лил её в лог — чистим через redact_reason/1.
            lager:info("authorize_and_issue[~p]  retrieve_userinfo failed ~p"
                      ,[Mode, zkeycloak_util:redact_reason(Reason)]),
            %% Инцидент 29.07: userinfo идёт через тот же discovery-воркер, и
            %% его неготовность даёт здесь ровно тот же `provider_not_ready'.
            %% 401 на этом месте так же вводил бы клиента в заблуждение.
            provider_error(Context, <<"retrieve_userinfo">>, Reason, 'invalid_credentials')
    end.

-spec provide_keycloak_token(cb_context:context()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,map()
                            ,'login' | 'refresh'
                            ) -> cb_context:context().
provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh, UserInfoMap, Mode) ->
    %% issue 07 + P3-1 (кросс-ревью 16.07): гейт проверяет СТРУКТУРУ `sub' —
    %% `zcore_util:from_key/2' матчит только дефисный UUID (MDM-key) и
    %% возвращает KIS owner_id, иначе `'undefined''. Структурно-невалидный
    %% `sub' (federated `f:<idp>:<user>', client-id сервис-аккаунта) →
    %% чистый 401 вместо function_clause-500.
    %% NB: комментарий НАМЕРЕННО не утверждает «sub обязан быть KIS-derived» —
    %% LDAP/Kerberos-субъекты тоже несут дефисный UUID и СТРУКТУРНО проходят
    %% этот гейт (это и требуется — `ensure_user_doc' рассчитан на LDAP-юзеров);
    %% их отсекает следующий гейт (`account_id'), если KazooAuth-claim'а нет.
    %% «Фикс» до буквы старого комментария сломал бы LDAP/Kerberos-логин.
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
    %% issue 10 + P3 (кросс-ревью 16.07): claim `account_id' ставит только
    %% SPI-путь `handleKazooAuth' (какой claim выигрывает и почему их два —
    %% в `account_id_claim/1', дефект R1) и всегда в raw-форме (32 hex). Отсутствие
    %% claim'а закрыл `a1eae36'; но пустой (`<<>>') либо малформный (не-32-
    %% байтный) `account_id' проходил `undefined'-гейт и падал badmatch'ем в
    %% `kzs_util:format_account_id/2' (`?MATCH_ACCOUNT_RAW = raw_account_id(_)'
    %% на catch-all не матчится: `<<>>'/`<<"not-32-hex">>' → `error:{badmatch,_}')
    %% → грязный Crossbar-500 вместо 401. Гейтим строго на raw-account-id
    %% формат — единственную форму, которую `format_account_id/2` не роняет и
    %% которую реально шлёт SPI. Всё прочее (`undefined'/`<<>>'/малформ) →
    %% чистый 401 `invalid_credentials' (образец `a1eae36').
    {RawAccountId, Claim} = account_id_claim(UserInfoMap),
    case is_raw_account_id(RawAccountId) of
        'true' ->
            %% Дефект R1: ИЗ КАКОГО claim'а взят аккаунт — ключевая улика при
            %% разборе «пользователь попал не в свой аккаунт». Само значение уже
            %% печатает `claims_digest/1' выше, здесь логируем только источник.
            lager:info("provide_keycloak_token[~p]: account_id from claim ~s",
                       [Mode, Claim]),
            DbName = kzs_util:format_account_id(RawAccountId, 'encoded'),
            provide_keycloak_token(Context, TokenAccess, TokenId, TokenRefresh,
                                   UserInfoMap, Mode, OwnerId, RawAccountId, DbName);
        'false' ->
            %% P3 (кросс-ревью 18.07 волна 2): единый reject-путь.
            %% (1) `RawAccountId' печатался сырым `~p' — при misconfig маппера
            %%     KC (email/ФИО в claim'е account_id) в лог уходили ПДн;
            %%     логируем факт+длину через `zkeycloak_util:redact/1'.
            %% (2) `?MATCH_ACCOUNT_RAW' раньше матчил ЛЮБЫЕ 32 байта — 32-
            %%     байтный не-hex проходил гейт, а `format_account_id/2' давал
            %%     корректный по форме, но несуществующий db-путь → downstream
            %%     503 вместо чистого 401. Реальный account_id из SPI-claim'а
            %%     всегда 32 hex; `is_raw_account_id/1' добавляет проверку
            %%     алфавита → не-hex отвергается здесь же, до БД.
            %% `source' — из какого claim'а взято значение ПОСЛЕ фолбэка;
            %% `source=default_account_id' значит в том числе, что ноты
            %% `account_id' в userinfo не было вовсе.
            lager:info("provide_keycloak_token[~p]: userinfo account_id absent or"
                       " malformed (source=~s value=~s) owner_id=~s"
                       " (non-KazooAuth subject?) — rejecting",
                       [Mode, Claim, zkeycloak_util:redact(RawAccountId), OwnerId]),
            cb_context:add_system_error('invalid_credentials', Context)
    end.

%% @doc Значение Kazoo-`account_id' и ИМЯ claim'а, из которого оно взято.
%%
%% Дефект R1 (разбор 30.07, план `docs/superpowers/plans/2026-07-02-keycloak-26-upgrade.md'):
%% в realm'е на ОДИН claim `account_id' претендовали ДВА маппера — hardcoded
%% скоупа `onbill_scope' (константа; единственный источник для LDAP/Kerberos-
%% субъектов, которым `handleKazooAuth' нот не пишет) и session-note клиента
%% `onbill_client' (реальный аккаунт пользователя портала). В Keycloak порядок
%% мапперов задаёт `ProtocolMapper.getPriority()', у обоих он 0 и меняется
%% только КОДОМ провайдера, поэтому исход решает порядок обхода `HashSet' по
%% `id.hashCode()' мапперов — он переворачивается молча при любой правке набора,
%% а запись клейма идёт через `Map.put', т.е. побеждает последний. Фикс —
%% развести claim'ы (hardcoded отдаёт `default_account_id') и задать приоритет
%% ЗДЕСЬ, кодом: нота сильнее константы.
%%
%% Фолбэк срабатывает ТОЛЬКО когда ноты нет вовсе (`undefined' или JSON `null').
%% Если нота есть, но малформна — фолбэка НЕТ: молча увести пользователя с битой
%% нотой в ОБЩИЙ дефолтный аккаунт хуже, чем отдать чистый 401.
%%
%% NB: до правки realm'а (шаг 3.3 плана) `default_account_id' в токене не
%% появляется вовсе, и функция ведёт себя ровно как прежний однострочный
%% `kz_maps:get' — именно поэтому раскатывать её МОЖНО и НУЖНО до KC.
-spec account_id_claim(map()) -> {any(), kz_term:ne_binary()}.
account_id_claim(UserInfoMap) ->
    case kz_maps:get(?ACCOUNT_ID_CLAIM, UserInfoMap) of
        Absent when Absent =:= 'undefined';
                    Absent =:= 'null' ->
            {kz_maps:get(?DEFAULT_ACCOUNT_ID_CLAIM, UserInfoMap)
            ,?DEFAULT_ACCOUNT_ID_CLAIM
            };
        AccountId ->
            {AccountId, ?ACCOUNT_ID_CLAIM}
    end.

%% @doc raw-account-id это ровно 32 hex-байта (проверка длины И алфавита;
%% обоснование — у `zkeycloak_util:is_raw_account_id/1', куда хелпер
%% перенесён в G-3 Ф1: он нужен и на пути валидации сырого KC-токена).
%% Не-binary / не-32-байтные формы (`undefined'/`<<>>'/малформ) → `false'
%% → чистый 401 (сохраняет поведение issue 10 / P3-2).
-spec is_raw_account_id(any()) -> boolean().
is_raw_account_id(AccountId) ->
    zkeycloak_util:is_raw_account_id(AccountId).

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
    %% Токен разбираем РОВНО ОДИН раз на запрос: `auth_method/1' верифицирует
    %% подпись access-токена, и оба потребителя ниже — user-doc при
    %% автосоздании и claim'ы Kazoo-JWT — получают уже посчитанные значения.
    %% До этой правки декодирование было одно (в `issue_auth_token'); столько
    %% же осталось и после.
    AuthMethod = zkeycloak_util:auth_method(TokenAccess),
    AuthSource = zkeycloak_util:auth_source(UserInfoMap, AuthMethod),
    case check_user_doc(Mode, DbName, AccountId, OwnerId, UserInfoMap, AuthSource) of
        'ok' ->
            issue_auth_token(Context, TokenId, TokenRefresh, UserInfoMap,
                             AccountId, OwnerId, AuthMethod, AuthSource);
        {'error', Reason} ->
            %% issue 15 (review-loop): `Reason' приезжает из `create_user/8'
            %% СЫРЫМ — там редактируется только собственная лог-строка, а
            %% наверх терм уходит как есть (его ждёт `reject_user_provisioning/3'
            %% → `add_doc_validation_errors/2', клиенту нужен полный per-field
            %% error). Без редакта здесь тот же email/UDoc печатался вторым
            %% `~p' на том же запросе, обнуляя фикс в `create_user/8'.
            %% Редактируем ЛОГ-копию; в `reject_user_provisioning/3' по-прежнему
            %% уходит сырой `Reason' — поведение не меняется.
            lager:warning("provide_keycloak_token[~p]: user doc check failed"
                          " owner_id=~p account_id=~p reason=~p",
                          [Mode, OwnerId, AccountId
                          ,zkeycloak_util:redact_provisioning_error(Reason)]),
            reject_user_provisioning(Context, Mode, Reason)
    end.

%% @doc Login-путь — гарантируем существование user-doc'а (создаём при
%% необходимости). Refresh-путь — только проверяем существование; на
%% miss возвращаем тегированную ошибку, чтобы вызывающий смапил её в
%% `invalid_credentials' и mobile (zfield) пошёл в полный AppAuth-flow
%% (см. контракт в комментариях handle_refresh выше).
%%
%% G-1 (gap-анализ «центр периметра», решение Р1): обе ветки гейтят по
%% `enabled' user-doc'а — деактивированный через MDM/cb_users пользователь
%% (`enabled=false') не получает Kazoo-токен, пока жива его учётка в
%% KC/LDAP. Классический путь (`cb_user_auth') блокирует так же. Без
%% whitelist: сервисные учётки локальные, через Keycloak не ходят.
%% На login-ветке гейт ПОСЛЕ `ensure_user_doc' — JIT-созданный док
%% enabled по умолчанию, поведение первого входа не меняется.
-ifdef(TEST).
%% Входная точка EUnit (`cb_zkeycloak_ext_tests') — у теста access-токена нет,
%% и источник ему не интересен: он меряет enabled-гейт. Под `-ifdef(TEST)'
%% клауза стоит не для красоты: в прод-сборке её никто не зовёт, и `-Werror'
%% на `+warn_unused_vars' валит сборку на «function check_user_doc/5 is
%% unused». `'unknown'' здесь — не «поле не писать», а честное «источник не
%% определён»: в док оно так и попадёт.
-spec check_user_doc('login' | 'refresh'
                    ,kz_term:ne_binary()
                    ,kz_term:ne_binary()
                    ,kz_term:ne_binary()
                    ,map()
                    ) -> 'ok' | {'error', term()}.
check_user_doc(Mode, DbName, AccountId, OwnerId, UserInfoMap) ->
    check_user_doc(Mode, DbName, AccountId, OwnerId, UserInfoMap, 'unknown').
-endif.

-spec check_user_doc('login' | 'refresh'
                    ,kz_term:ne_binary()
                    ,kz_term:ne_binary()
                    ,kz_term:ne_binary()
                    ,map()
                    ,zkeycloak_util:auth_source()
                    ) -> 'ok' | {'error', term()}.
check_user_doc('login', DbName, AccountId, OwnerId, UserInfoMap, AuthSource) ->
    case ensure_user_doc(DbName, AccountId, OwnerId, UserInfoMap, AuthSource) of
        'ok' -> check_user_enabled(DbName, OwnerId);
        {'error', _} = Err -> Err
    end;
check_user_doc('refresh', DbName, _AccountId, OwnerId, _UserInfoMap, _AuthSource) ->
    %% Refresh-путь доков не создаёт: `auth_origin' проставляется один раз,
    %% при автосоздании, и переписывать его на каждом refresh нельзя —
    %% это стёрло бы источник ПЕРВИЧНОГО входа.
    case kz_datamgr:open_doc(DbName, OwnerId) of
        {'ok', UserDoc} -> user_enabled_gate(UserDoc);
        Err -> {'error', {'missing_user_doc_on_refresh', Err}}
    end.

%% @doc Перечитать user-doc после `ensure_user_doc' и прогнать enabled-гейт.
%% Сбой чтения здесь — только что открытый/созданный док не читается —
%% это datastore-проблема, а не «юзера нет»: отвечаем 503, не 401.
-spec check_user_enabled(kz_term:ne_binary(), kz_term:ne_binary()) ->
          'ok' | {'error', term()}.
check_user_enabled(DbName, OwnerId) ->
    case kz_datamgr:open_doc(DbName, OwnerId) of
        {'ok', UserDoc} -> user_enabled_gate(UserDoc);
        {'error', _} = Err ->
            lager:warning("check_user_enabled: re-open failed owner_id=~p err=~p",
                          [OwnerId, Err]),
            {'error', 'datastore_unreachable'}
    end.

%% @doc Гейт по полю `enabled' user-doc'а. Аксессор — `kzd_users:enabled/1'
%% (дефолт `true': док без поля = активный, каноническая семантика Kazoo,
%% та же, что в `cb_user_auth'). NB: `kzd_users:is_enabled/1' в кодбейзе
%% не существует — issue-01 ссылался на него по памяти.
-spec user_enabled_gate(kz_json:object()) -> 'ok' | {'error', 'user_disabled'}.
user_enabled_gate(UserDoc) ->
    case kzd_users:enabled(UserDoc) of
        'true' -> 'ok';
        'false' -> {'error', 'user_disabled'}
    end.

%% @doc Гарантировать, что у `OwnerId' есть user-doc в account-db. Если
%% не существует — создать; на любой ошибке создания (в т.ч. missing
%% `last_name' у LDAP-юзера без `sn') — поднять наверх, чтобы вызывающий
%% отказал в выдаче auth-токена. Инвариант: `auth_token ⇒ есть user-doc'.
-spec ensure_user_doc(kz_term:ne_binary()
                     ,kz_term:ne_binary()
                     ,kz_term:ne_binary()
                     ,map()
                     ,zkeycloak_util:auth_source()
                     ) -> 'ok' | {'error', term()}.
ensure_user_doc(DbName, AccountId, OwnerId, UserInfoMap, AuthSource) ->
    case kz_datamgr:open_doc(DbName, OwnerId) of
        {'ok', _} -> 'ok';
        {'error', 'not_found'} ->
            Firstname = kz_maps:get(<<"given_name">>, UserInfoMap, 'undefined'),
            Surname = kz_maps:get(<<"family_name">>, UserInfoMap, 'undefined'),
            Email = kz_maps:get(<<"email">>, UserInfoMap, 'undefined'),
            UserPassword = kz_binary:rand_hex(12),
            %% `auth_origin' фиксируется только здесь — на JIT-создании дока.
            %% Существующий док (ветка `{ok,_}') не трогаем: поле описывает
            %% ПЕРВЫЙ вход, а не последний.
            case zkeycloak_util:create_user(AccountId, OwnerId, Firstname, Surname,
                                            Email, 'undefined', UserPassword,
                                            kz_term:to_binary(AuthSource)) of
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
%%   `'user_disabled''         — 401 `invalid_credentials' (G-1): наружу НЕ
%%                              отличаем «деактивирован» от «кредов нет» —
%%                              не подсказываем перебором, что учётка
%%                              существует; причина видна оператору в
%%                              warning-логе `provide_keycloak_token'.
%%   `'datastore_unreachable'' — 503, чтобы клиент ретраил.
%%   Иное (catch-all, `EXIT')  — `unspecified_fault' (500), чтобы оператор не
%%                              путал инфра-проблему с проблемой AD-профиля.
-spec reject_user_provisioning(cb_context:context()
                              ,'login' | 'refresh'
                              ,term()
                              ) -> cb_context:context().
reject_user_provisioning(Context, 'refresh', _Reason) ->
    cb_context:add_system_error('invalid_credentials', Context);
reject_user_provisioning(Context, 'login', 'user_disabled') ->
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
-spec prepare_keycloak_session(cb_context:context(), kz_term:ne_binary(),
                               kz_term:ne_binary(), kz_term:ne_binary()) ->
          {'ok', cb_context:context()} | {'error', any()}.
prepare_keycloak_session(Context, AccountId, OwnerId, TokenRefresh) ->
    case cb_context:fetch(Context, ?SESSION_CONTEXT) of
        'undefined' -> {'ok', Context};
        {'error', Reason} -> {'error', Reason};
        {'login', Sid, ExpiresAt} ->
            bind_session_result(Context, Sid,
              kz_auth_session_family:create_keycloak_session(
                AccountId, OwnerId, Sid, TokenRefresh, ExpiresAt));
        {'refresh', 'legacy', Sid, ExpiresAt} ->
            bind_session_result(Context, Sid,
              kz_auth_session_family:create_keycloak_session(
                AccountId, OwnerId, Sid, TokenRefresh, ExpiresAt));
        {'refresh', Binding, Sid, ExpiresAt} ->
            bind_session_result(Context, Sid,
              kz_auth_session_family:rotate_keycloak_session(
                Binding, TokenRefresh, Sid, AccountId, OwnerId, ExpiresAt))
    end.

-spec bind_session_result(cb_context:context(), kz_term:ne_binary(), any()) ->
          {'ok', cb_context:context()} | {'error', any()}.
bind_session_result(Context, Sid, {'ok', Family}) ->
    {'ok', cb_context:store(Context, 'auth_session_family_mode',
                            {'inherit_keycloak', Family, Sid})};
bind_session_result(_Context, _Sid, {'error', _}=Error) -> Error.
%% `TokenAccess' в аргументах больше НЕТ: он был нужен только ради

-spec keycloak_session_error(cb_context:context(), any()) -> cb_context:context().
keycloak_session_error(Context, Reason) ->
    lager:warning("keycloak session binding failed: ~p",
                  [zkeycloak_util:redact_reason(Reason)]),
    case Reason of
        'session_revoked' -> cb_context:add_system_error('invalid_credentials', Context);
        'binding_identity_mismatch' -> cb_context:add_system_error('invalid_credentials', Context);
        'refresh_replay' -> cb_context:add_system_error('invalid_credentials', Context);
        'invalid_session_binding' -> cb_context:add_system_error('invalid_credentials', Context);
        _ -> auth_store_error(Context)
    end.
%% `auth_method/1', а тот теперь считается один раз в `provide_keycloak_token/9'
%% и приезжает сюда готовым. Значение в auth-doc'е от этого не меняется —
%% тот же атом, та же `kz_term:to_binary/1'.
-spec issue_auth_token(cb_context:context()
                      ,kz_term:ne_binary()
                      ,kz_term:ne_binary()
                      ,map()
                      ,kz_term:ne_binary()
                      ,kz_term:ne_binary()
                      ,'oidc' | 'kerberos'
                      ,zkeycloak_util:auth_source()
                      ) -> cb_context:context().
issue_auth_token(Context, TokenId, TokenRefresh, UserInfoMap,
                 AccountId, OwnerId, AuthMethodAtom, AuthSource) ->
    case prepare_keycloak_session(Context, AccountId, OwnerId, TokenRefresh) of
        {'ok', BoundContext} ->
            issue_bound_auth_token(BoundContext, TokenId, TokenRefresh, UserInfoMap,
                                   AccountId, OwnerId, AuthMethodAtom, AuthSource);
        {'error', Reason} ->
            keycloak_session_error(Context, Reason)
    end.

-spec issue_bound_auth_token(cb_context:context()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,map()
                            ,kz_term:ne_binary()
                            ,kz_term:ne_binary()
                            ,'oidc' | 'kerberos'
                            ,zkeycloak_util:auth_source()
                            ) -> cb_context:context().
issue_bound_auth_token(Context, TokenId, TokenRefresh, UserInfoMap,
                       AccountId, OwnerId, AuthMethodAtom, AuthSource) ->
    UserInfoJObj = kz_json:from_map(UserInfoMap),
    %% issue 15: `UserInfoJObj' — те же claim'ы, что и выше, только в
    %% JObj-форме; сырой `~p' дублировал утечку ПДн. Логируем выжимку из
    %% исходной мапы (она здесь в области видимости) — сам lager:info
    %% сохранён, хотя содержательно эта строка дублирует `authorize_and_issue'.
    lager:info("provide_keycloak_token/5  UserInfoJObj: ~p"
              ,[zkeycloak_util:claims_digest(UserInfoMap)]),
    AuthMethod = kz_term:to_binary(AuthMethodAtom),
    AccountName = kz_maps:get(<<"account_name">>, UserInfoMap, 'undefined'),
    JObj = kz_json:from_list(
             props:filter_undefined(
               [{<<"account_id">>, AccountId}
               ,{<<"owner_id">>, OwnerId}
               ,{<<"keycloak_resource_access">>, kz_json:get_value(<<"resource_access">>, UserInfoJObj)}
               ,{<<"kc_full_name">>, build_full_name(UserInfoJObj)}
               ,{<<"auth_method">>, AuthMethod}
               ,{<<"account_name">>, AccountName}
                %% `auth_source' ДОПОЛНЯЕТ `auth_method', а не заменяет его:
                %% `auth_method' остаётся прежним двузначным (`oidc'/`kerberos')
                %% — фронт гейтит по нему logout-ветку, и его словарь трогать
                %% нельзя. Consumer'ы, не знающие поля, ведут себя как раньше;
                %% токены, выпущенные до этой правки, поля не имеют вовсе —
                %% для них `auth_source' = `undefined', фолбэк на `auth_method'.
               ,{<<"auth_source">>, kz_term:to_binary(AuthSource)}
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

