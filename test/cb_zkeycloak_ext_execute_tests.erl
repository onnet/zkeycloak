%%%-----------------------------------------------------------------------------
%%% @doc EUnit для execute-контракта `cb_zkeycloak_ext' (issue 22, Ф4 подход №6).
%%%
%%% ПРОД-контур аутентификации. Модуль числился мигрированным по
%%% ЗАКОММЕНТИРОВАННОЙ копипастной строке биндинга `%% *.execute.put.ext'
%%% (FN-1 редакции 1 гейта) — при снятии our_patch из `api_util' POST
%%% `/zkeycloak_ext/refresh' отвечал бы 500 клиенту, у которого refresh-токен
%%% УЖЕ потрачен: KC ротирует токен при обмене, повторный обмен тем же
%%% значением даёт `invalid_grant'.
%%%
%%% Сюита пинит ровно эту границу:
%%%   - validate(?REFRESH) не ходит в KC вовсе (ни обмена, ни выпуска токена);
%%%   - отсутствие `refresh_token' в теле — 401 ДО обращения к провайдеру;
%%%   - execute без хэнд-овера НЕ делает обмен (окно hotload-скью);
%%%   - не-мутирующие пути (`/', `?LOGOUT') сохраняют свой конверт бит-в-бит.
%%% @end
%%%-----------------------------------------------------------------------------
-module(cb_zkeycloak_ext_execute_tests).

-compile([nowarn_missing_spec]).

-include_lib("eunit/include/eunit.hrl").

-define(SUB_UUID, <<"01234567-89ab-cdef-0123-456789abcdef">>).
-define(OWNER_ID, <<"0123456789abcdef0123456789abcdef">>).
-define(ACCOUNT_ID, <<"fedcba9876543210fedcba9876543210">>).

-define(REFRESH, <<"refresh">>).
-define(LOGOUT, <<"logout">>).
-define(ZKEYCLOAK, <<"zkeycloak_ext">>).
-define(AUTH_LINK, <<"auth_link">>).
-define(HANDOVER_KEY, 'zkeycloak_ext_post_refresh').

-define(OLD_REFRESH, <<"old-refresh-token-30d">>).
-define(NEW_ACCESS, <<"new-access-token">>).
-define(NEW_ID, <<"new-id-token">>).
-define(NEW_REFRESH, <<"new-refresh-token-30d">>).
-define(LOGOUT_URL, <<"https://keycloak.example/realms/BRT/protocol/openid-connect/logout">>).

-define(MOCKED, ['zkeycloak_util', 'kz_datamgr', 'crossbar_auth']).

execute_contract_test_() ->
    {'foreach'
    ,fun setup/0
    ,fun cleanup/1
    ,[fun validate_refresh_stores_token_without_calling_kc_/1
     ,fun validate_refresh_without_token_is_401_before_kc_/1
     ,fun execute_refresh_exchanges_and_issues_token_/1
     ,fun execute_refresh_without_handover_refuses_exchange_/1
     ,fun execute_refresh_invalid_grant_maps_to_401_/1
     ,fun execute_logout_keeps_url_envelope_/1
     ,fun execute_root_path_keeps_envelope_/1
     ,fun execute_non_mutating_unknown_path_applies_nothing_/1
     ]
    }.

setup() ->
    _ = [catch meck:unload(M) || M <- ?MOCKED],
    _ = [meck:new(M, ['unstick', 'passthrough']) || M <- ?MOCKED],
    %% Дефолтные expect на ГРАНИЦЕ с KC обязательны: под passthrough
    %% незапланированный вызов ушёл бы в НАСТОЯЩИЙ oidcc-воркер, и «эффект в
    %% validate» проявился бы таймаутом фикстуры вместо fail'а ассерта.
    meck:expect('zkeycloak_util', 'refresh_token', fun(_Token) -> {'error', 'no_expect_in_test'} end),
    meck:expect('zkeycloak_util', 'retrieve_userinfo', fun(_Tuple) -> {'ok', userinfo()} end),
    meck:expect('zkeycloak_util', 'auth_method', fun(_Access) -> 'oidc' end),
    meck:expect('zkeycloak_util', 'auth_source', fun(_UserInfo, _Method) -> 'keycloak' end),
    meck:expect('zkeycloak_util', 'logout_url', fun(_Hint) -> ?LOGOUT_URL end),
    meck:expect('kz_datamgr', 'open_doc', fun(_Db, _Id) -> {'ok', kz_json:new()} end),
    meck:expect('crossbar_auth', 'create_auth_token'
               ,fun(Ctx, _Mod) ->
                        cb_context:set_resp_status(
                          cb_context:set_resp_data(Ctx, kz_json:from_list([{<<"auth_token">>, <<"kazoo-token">>}]))
                         ,'success')
                end),
    'ok'.

cleanup(_) ->
    _ = [catch meck:unload(M) || M <- ?MOCKED],
    'ok'.

%%%=============================================================================
%%% validate: без обращения к провайдеру
%%%=============================================================================

validate_refresh_stores_token_without_calling_kc_(_) ->
    %% Валидация: токен из тела сложен в Context под тегом пути, success — и
    %% НИ ОДНОГО обращения к KC. До миграции здесь же шёл необратимый обмен.
    Result = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    [?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual({?REFRESH, ?OLD_REFRESH}, cb_context:fetch(Result, ?HANDOVER_KEY))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'retrieve_userinfo', '_'))
    ,?_assertEqual(0, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ].

validate_refresh_without_token_is_401_before_kc_(_) ->
    %% Тела нет / поля нет — 401 ДО провайдера, хэнд-овер не выставлен,
    %% execute не запустится вовсе (крossbar зовёт execute только после
    %% успешной валидации).
    Result = cb_zkeycloak_ext:validate(refresh_ctx('undefined'), ?REFRESH),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(401, cb_context:resp_error_code(Result))
    ,?_assertEqual('undefined', cb_context:fetch(Result, ?HANDOVER_KEY))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ].

%%%=============================================================================
%%% execute: обмен и выпуск токена
%%%=============================================================================

execute_refresh_exchanges_and_issues_token_(_) ->
    %% Execute-фаза: обмен РОВНО тем токеном, что сложил validate, и ровно один
    %% раз; ответ — Kazoo-токен плюс ротированные KC-токены (конверт бит-в-бит
    %% с до-миграционным) ПОВЕРХ fatal/500-пресета фолда.
    meck:expect('zkeycloak_util', 'refresh_token', fun(_Token) -> {'ok', token_tuple()} end),
    Validated = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?REFRESH),
    RespData = cb_context:resp_data(Result),
    [?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(1, meck:num_calls('zkeycloak_util', 'refresh_token', [?OLD_REFRESH]))
    ,?_assertEqual(1, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ,?_assertEqual(<<"kazoo-token">>, kz_json:get_value(<<"auth_token">>, RespData))
    ,?_assertEqual(?NEW_REFRESH, kz_json:get_value(<<"kc_refresh_token">>, RespData))
    ,?_assertEqual(?NEW_ID, kz_json:get_value(<<"kc_id_token">>, RespData))
    ].

execute_refresh_without_handover_refuses_exchange_(_) ->
    %% Разрыв хэнд-овера — САМЫЙ дорогой случай этого модуля: validate прошёл
    %% на СТАРОМ биме и обмен там уже сделал, KC токен ротировал. Повторный
    %% обмен вернул бы `invalid_grant' и выбросил клиента в полный AppAuth-flow,
    %% поэтому execute не делает НИЧЕГО и отдаёт fatal/500-пресет.
    Result = cb_zkeycloak_ext:post(preset_fatal(refresh_ctx(?OLD_REFRESH)), ?REFRESH),
    [?_assertEqual('fatal', cb_context:resp_status(Result))
    ,?_assertEqual(500, cb_context:resp_error_code(Result))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ,?_assertEqual(0, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ].

execute_refresh_invalid_grant_maps_to_401_(_) ->
    %% Протухший refresh: 401 `invalid_credentials' (контракт handle_refresh —
    %% mobile уходит в полный AppAuth-flow), Kazoo-токен НЕ выпускается.
    meck:expect('zkeycloak_util', 'refresh_token', fun(_Token) -> {'error', 'invalid_grant'} end),
    Validated = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?REFRESH),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(401, cb_context:resp_error_code(Result))
    ,?_assertEqual(1, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ,?_assertEqual(0, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ].

%%%=============================================================================
%%% execute: не-мутирующие пути сохраняют конверт
%%%=============================================================================

execute_logout_keeps_url_envelope_(_) ->
    %% `?LOGOUT' ничего не мутирует: url разлогина собирает validate (иначе
    %% legacy-GET, у которого execute-фазы нет вовсе, остался бы без ответа), а
    %% коллбэк только снимает fatal/500-пресет. resp_data обязан доехать целым.
    Validated = cb_zkeycloak_ext:validate(logout_ctx(), ?LOGOUT),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?LOGOUT),
    [?_assertEqual('success', cb_context:resp_status(Validated))
    ,?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(?LOGOUT_URL, kz_json:get_value(<<"logout_url">>, cb_context:resp_data(Result)))
    ,?_assertEqual(cb_context:resp_data(Validated), cb_context:resp_data(Result))
    ].

execute_root_path_keeps_envelope_(_) ->
    %% Корневой POST только логирует; конверт — success + пустой resp_data.
    Validated = cb_zkeycloak_ext:validate(root_ctx()),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated)),
    ZkResult = cb_zkeycloak_ext:post(preset_fatal(Validated), ?ZKEYCLOAK),
    [?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(kz_json:new(), cb_context:resp_data(Result))
    ,?_assertEqual('success', cb_context:resp_status(ZkResult))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ].

execute_non_mutating_unknown_path_applies_nothing_(_) ->
    %% GET-only путь: до execute его не доводит allowed_methods, но коллбэк
    %% тотален — function_clause в фолде дал бы 500 с обнулённым resp_data.
    Result = cb_zkeycloak_ext:post(preset_fatal(root_ctx()), ?AUTH_LINK),
    [?_assertEqual('fatal', cb_context:resp_status(Result))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ,?_assertEqual(0, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ].

%%%=============================================================================
%%% Пин набора биндингов
%%%=============================================================================

init_pins_execute_bindings_test() ->
    _ = (catch meck:unload('crossbar_bindings')),
    meck:new('crossbar_bindings', ['unstick', 'passthrough']),
    meck:expect('crossbar_bindings', 'bind', fun(_K, _M, _F) -> 'ok' end),
    try
        'ok' = cb_zkeycloak_ext:init(),
        Bound = [{K, F}
                 || {_Pid, {'crossbar_bindings', 'bind', [K, 'cb_zkeycloak_ext', F]}, _Res}
                        <- meck:history('crossbar_bindings')],
        ?assertEqual(lists:sort([{<<"*.authenticate.zkeycloak_ext">>, 'authenticate'}
                                ,{<<"*.authorize.zkeycloak_ext">>, 'authorize'}
                                ,{<<"*.allowed_methods.zkeycloak_ext">>, 'allowed_methods'}
                                ,{<<"*.resource_exists.zkeycloak_ext">>, 'resource_exists'}
                                ,{<<"*.validate.zkeycloak_ext">>, 'validate'}
                                ,{<<"*.execute.post.zkeycloak_ext">>, 'post'}
                                ])
                    ,lists:sort(Bound)
                    ),
        ?assert(erlang:function_exported('cb_zkeycloak_ext', 'post', 1)),
        ?assert(erlang:function_exported('cb_zkeycloak_ext', 'post', 2))
    after
        meck:unload('crossbar_bindings')
    end.

%%%=============================================================================
%%% Helpers
%%%=============================================================================

-spec preset_fatal(cb_context:context()) -> cb_context:context().
preset_fatal(Context) ->
    %% контекст, каким его отдаёт api_util:execute_request/5 до фолда
    cb_context:setters(Context
                      ,[{fun cb_context:set_resp_status/2, 'fatal'}
                       ,{fun cb_context:set_resp_error_msg/2, <<"request execution failed">>}
                       ,{fun cb_context:set_resp_error_code/2, 500}
                       ]).

-spec base_ctx() -> cb_context:context().
base_ctx() ->
    cb_context:setters(cb_context:new()
                      ,[{fun cb_context:set_req_verb/2, <<"POST">>}
                       ,{fun cb_context:set_req_id/2, <<"kc0123456789">>}
                       ]).

-spec refresh_ctx(kz_term:api_ne_binary()) -> cb_context:context().
refresh_ctx('undefined') ->
    cb_context:set_req_data(base_ctx(), kz_json:new());
refresh_ctx(Token) ->
    cb_context:set_req_data(base_ctx(), kz_json:from_list([{<<"refresh_token">>, Token}])).

-spec logout_ctx() -> cb_context:context().
logout_ctx() ->
    cb_context:set_req_data(base_ctx()
                           ,kz_json:from_list([{<<"id_token_hint">>, <<"dummy-id-token-hint">>}])).

-spec root_ctx() -> cb_context:context().
root_ctx() ->
    Ctx = cb_context:set_req_data(base_ctx(), kz_json:new()),
    cb_context:set_req_json(Ctx, kz_json:from_list([{<<"data">>, kz_json:new()}])).

%% форма oidcc-tuple — как её строит zkeycloak_util:refresh_token/1
-spec token_tuple() -> tuple().
token_tuple() ->
    {'oidcc_token'
    ,{'oidcc_token_id', ?NEW_ID, #{<<"sub">> => ?SUB_UUID}}
    ,{'oidcc_token_access', ?NEW_ACCESS, 300, <<"Bearer">>}
    ,{'oidcc_token_refresh', ?NEW_REFRESH}
    ,<<"openid profile">>
    }.

-spec userinfo() -> map().
userinfo() ->
    #{<<"sub">> => ?SUB_UUID
     ,<<"account_id">> => ?ACCOUNT_ID
     ,<<"given_name">> => <<"Иван"/utf8>>
     ,<<"family_name">> => <<"Петров"/utf8>>
     ,<<"resource_access">> => #{<<"onbill_client">> => #{<<"roles">> => [<<"onbill_access">>]}}
     }.
