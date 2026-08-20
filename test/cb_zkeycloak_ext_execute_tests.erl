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
-define(SID, <<"keycloak-session-1">>).
-define(FAMILY, <<"family-1">>).
-define(EXPIRES_AT, 2000000000).

-define(REFRESH, <<"refresh">>).
-define(LOGOUT, <<"logout">>).
-define(ACK, <<"ack">>).
-define(BACKCHANNEL, <<"backchannel">>).
-define(ZKEYCLOAK, <<"zkeycloak_ext">>).
-define(AUTH_LINK, <<"auth_link">>).
-define(HANDOVER_KEY, 'zkeycloak_ext_post_refresh').

-define(OLD_REFRESH, <<"old-refresh-token-30d">>).
-define(NEW_ACCESS, <<"new-access-token">>).
-define(NEW_ID, <<"new-id-token">>).
-define(NEW_REFRESH, <<"new-refresh-token-30d">>).
-define(LOGOUT_URL, <<"https://keycloak.example/realms/BRT/protocol/openid-connect/logout">>).

-define(MOCKED, ['zkeycloak_util', 'kz_datamgr', 'crossbar_auth', 'api_util',
                 'kz_auth_session_family']).

execute_contract_test_() ->
    {'foreach'
    ,fun setup/0
    ,fun cleanup/1
    ,[fun validate_refresh_stores_token_without_calling_kc_/1
     ,fun validate_refresh_loads_authoritative_binding_/1
     ,fun validate_refresh_unbound_rejected_before_kc_/1
     ,fun validate_refresh_without_token_is_401_before_kc_/1
     ,fun execute_refresh_exchanges_and_issues_token_/1
     ,fun execute_refresh_rotates_binding_before_issuance_/1
     ,fun execute_refresh_binding_failure_blocks_issuance_/1
     ,fun execute_refresh_without_handover_refuses_exchange_/1
     ,fun execute_backchannel_revokes_sid_/1
     ,fun execute_backchannel_expired_race_maps_to_401_/1
     ,fun validate_backchannel_invalid_signature_has_no_effect_/1
     ,fun request_data_accepts_standard_backchannel_form_/1
     ,fun request_data_rejects_non_form_backchannel_/1
     ,fun execute_logout_ack_requires_receipt_/1
     ,fun execute_logout_ack_unconfirmed_is_409_/1
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
    meck:expect('zkeycloak_util', 'logout_url', fun(_Hint, _State) -> ?LOGOUT_URL end),
    meck:expect('zkeycloak_util', 'verify_logout_id_token',
                fun(_Token) ->
                        {'ok', #{'sid' => ?SID, 'sub' => ?SUB_UUID,
                                 'account_id' => ?ACCOUNT_ID}}
                end),
    meck:expect('zkeycloak_util', 'verify_backchannel_logout_token',
                fun(_Token) ->
                        {'ok', #{'sid' => ?SID, 'jti' => <<"event-1">>,
                                 'expires_at' => ?EXPIRES_AT}}
                end),
    meck:expect('zkeycloak_util', 'auth_source', fun(_UserInfo, _Method) -> 'keycloak' end),
    meck:expect('zkeycloak_util', 'logout_url', fun(_Hint) -> ?LOGOUT_URL end),
    meck:expect('kz_auth_session_family', 'lookup_refresh',
                fun(_Token) -> {'ok', refresh_binding()} end),
    meck:expect('kz_auth_session_family', 'legacy_refresh_allowed', fun() -> 'false' end),
    meck:expect('kz_auth_session_family', 'rotate_keycloak_session',
                fun(_Old, _New, _Sid, _Account, _Owner, _Expiry) ->
                        {'ok', ?FAMILY}
                end),
    meck:expect('kz_auth_session_family', 'create_keycloak_session',
                fun(_Account, _Owner, _Sid, _Refresh, _Expiry) -> {'ok', ?FAMILY} end),
    meck:expect('kz_auth_session_family', 'begin_logout',
                fun(_Account, _Owner, _Sid, _Ttl) ->
                        {'ok', #{'state' => <<"state-1">>, 'verifier' => <<"verifier-1">>}}
                end),
    meck:expect('kz_auth_session_family', 'revoke_kc_sid',
                fun(_Sid, _Jti, _Expiry) -> {'ok', 'op_revoked'} end),
    meck:expect('kz_auth_session_family', 'ack_logout',
                fun(_State, _Verifier) ->
                        {'ok', kz_json:from_list([{<<"state">>, <<"consumed">>}])}
                end),
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
    ,?_assertEqual({?REFRESH, ?OLD_REFRESH, refresh_binding()},
                   cb_context:fetch(Result, ?HANDOVER_KEY))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'retrieve_userinfo', '_'))
    ,?_assertEqual(0, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ].

validate_refresh_loads_authoritative_binding_(_) ->
    Result = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    [?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(1, meck:num_calls('kz_auth_session_family', 'lookup_refresh',
                                     [?OLD_REFRESH]))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
    ].

validate_refresh_unbound_rejected_before_kc_(_) ->
    meck:expect('kz_auth_session_family', 'lookup_refresh',
                fun(_Token) -> {'error', 'not_found'} end),
    Result = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(401, cb_context:resp_error_code(Result))
    ,?_assertEqual(0, meck:num_calls('zkeycloak_util', 'refresh_token', '_'))
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

execute_refresh_rotates_binding_before_issuance_(_) ->
    meck:expect('zkeycloak_util', 'refresh_token', fun(_Token) -> {'ok', token_tuple()} end),
    Validated = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?REFRESH),
    IssuedContexts = [Ctx
                      || {_Pid,
                          {'crossbar_auth', 'create_auth_token', [Ctx, 'cb_zkeycloak_ext']},
                          _Reply} <- meck:history('crossbar_auth')],
    [?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(1, meck:num_calls(
                         'kz_auth_session_family', 'rotate_keycloak_session',
                         [refresh_binding(), ?NEW_REFRESH, ?SID,
                          ?ACCOUNT_ID, ?OWNER_ID, ?EXPIRES_AT]))
    ,?_assertMatch([_], IssuedContexts)
    ,?_assertEqual({'inherit_keycloak', ?FAMILY, ?SID},
                   cb_context:fetch(hd(IssuedContexts),
                                    'auth_session_family_mode'))
    ].

execute_refresh_binding_failure_blocks_issuance_(_) ->
    meck:expect('zkeycloak_util', 'refresh_token', fun(_Token) -> {'ok', token_tuple()} end),
    meck:expect('kz_auth_session_family', 'rotate_keycloak_session',
                fun(_Old, _New, _Sid, _Account, _Owner, _Expiry) ->
                        {'error', 'db_unavailable'}
                end),
    Validated = cb_zkeycloak_ext:validate(refresh_ctx(?OLD_REFRESH), ?REFRESH),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?REFRESH),
    RespData = cb_context:resp_data(Result),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(503, cb_context:resp_error_code(Result))
    ,?_assertEqual(0, meck:num_calls('crossbar_auth', 'create_auth_token', '_'))
    ,?_assertEqual('undefined', kz_json:get_value(<<"kc_refresh_token">>, RespData))
    ,?_assertEqual('undefined', kz_json:get_value(<<"kc_id_token">>, RespData))
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
    Validated = cb_zkeycloak_ext:validate(logout_ctx(), ?LOGOUT),
    BeginCallsAfterValidate = meck:num_calls('kz_auth_session_family', 'begin_logout', '_'),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?LOGOUT),
    Resp = cb_context:resp_data(Result),
    [?_assertEqual('success', cb_context:resp_status(Validated))
    ,?_assertEqual(0, BeginCallsAfterValidate)
    ,?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(1, meck:num_calls(
                         'kz_auth_session_family', 'begin_logout',
                         [?ACCOUNT_ID, ?OWNER_ID, ?SID, 300]))
    ,?_assertEqual(?LOGOUT_URL, kz_json:get_value(<<"logout_url">>, Resp))
    ,?_assertEqual(<<"state-1">>, kz_json:get_value(<<"state">>, Resp))
    ,?_assertEqual(<<"verifier-1">>, kz_json:get_value(<<"verifier">>, Resp))
    ].

execute_backchannel_revokes_sid_(_) ->
    Validated = cb_zkeycloak_ext:validate(
                  backchannel_ctx(), ?LOGOUT, ?BACKCHANNEL),
    Result = cb_zkeycloak_ext:post(
               preset_fatal(Validated), ?LOGOUT, ?BACKCHANNEL),
    [?_assertEqual('success', cb_context:resp_status(Validated))
    ,?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(1, meck:num_calls(
                         'kz_auth_session_family', 'revoke_kc_sid',
                         [?SID, <<"event-1">>, ?EXPIRES_AT]))
    ].

execute_backchannel_expired_race_maps_to_401_(_) ->
    meck:expect('kz_auth_session_family', 'revoke_kc_sid', fun(_Sid, _Jti, _Expiry) -> {'error', 'logout_event_expired'} end),
    Validated = cb_zkeycloak_ext:validate(backchannel_ctx(), ?LOGOUT, ?BACKCHANNEL),
    Result = cb_zkeycloak_ext:post(preset_fatal(Validated), ?LOGOUT, ?BACKCHANNEL),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(401, cb_context:resp_error_code(Result))
    ,?_assertEqual(1, meck:num_calls('kz_auth_session_family', 'revoke_kc_sid', [?SID, <<"event-1">>, ?EXPIRES_AT]))].

validate_backchannel_invalid_signature_has_no_effect_(_) ->
    meck:expect('zkeycloak_util', 'verify_backchannel_logout_token',
                fun(_Token) -> {'error', 'invalid_signature'} end),
    Result = cb_zkeycloak_ext:validate(backchannel_ctx(), ?LOGOUT, ?BACKCHANNEL),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(401, cb_context:resp_error_code(Result))
    ,?_assertEqual(1, meck:num_calls('zkeycloak_util', 'verify_backchannel_logout_token', '_'))
    ,?_assertEqual(0, meck:num_calls('kz_auth_session_family', 'revoke_kc_sid', '_'))
    ].
request_data_accepts_standard_backchannel_form_(_) ->
    Req0 = #{'body_state' => 'unread'},
    Req1 = #{'body_state' => 'consumed'},
    Token = <<"header.payload.signature">>,
    meck:expect('api_util', 'get_request_body',
                fun(Req) when Req =:= Req0 ->
                        {'ok', <<"logout_token=header.payload.signature">>, Req1}
                end),
    {'ok', Parsed, Req1} =
        erlang:apply('cb_zkeycloak_ext', 'request_data',
                     [{Req0, base_ctx(), <<"application/x-www-form-urlencoded">>,
                       kz_json:new()}, ?LOGOUT, ?BACKCHANNEL]),
    [?_assertEqual(Token,
                   kz_json:get_ne_binary_value(
                     <<"logout_token">>, cb_context:req_data(Parsed)))
    ,?_assertEqual(1, meck:num_calls('api_util', 'get_request_body', [Req0]))
    ].

request_data_rejects_non_form_backchannel_(_) ->
    Result = erlang:apply(
               'cb_zkeycloak_ext', 'request_data',
               [{#{}, base_ctx(), <<"application/json">>, kz_json:new()},
                ?LOGOUT, ?BACKCHANNEL]),
    [?_assertEqual({'error', 'invalid_credentials'}, Result)
    ,?_assertEqual(0, meck:num_calls('api_util', 'get_request_body', '_'))
    ].


execute_logout_ack_requires_receipt_(_) ->
    Validated = cb_zkeycloak_ext:validate(ack_ctx(), ?LOGOUT, ?ACK),
    Result = cb_zkeycloak_ext:post(
               preset_fatal(Validated), ?LOGOUT, ?ACK),
    [?_assertEqual('success', cb_context:resp_status(Validated))
    ,?_assertEqual('success', cb_context:resp_status(Result))
    ,?_assertEqual(1, meck:num_calls(
                         'kz_auth_session_family', 'ack_logout',
                         [<<"state-1">>, <<"verifier-1">>]))
    ,?_assertEqual(<<"revoked">>,
                   kz_json:get_value(<<"kazoo_status">>,
                                     cb_context:resp_data(Result)))
    ,?_assertEqual(<<"confirmed">>,
                   kz_json:get_value(<<"keycloak_status">>,
                                     cb_context:resp_data(Result)))
    ].

execute_logout_ack_unconfirmed_is_409_(_) ->
    meck:expect('kz_auth_session_family', 'ack_logout',
                fun(_State, _Verifier) -> {'error', 'keycloak_logout_unconfirmed'} end),
    Validated = cb_zkeycloak_ext:validate(ack_ctx(), ?LOGOUT, ?ACK),
    Result = cb_zkeycloak_ext:post(
               preset_fatal(Validated), ?LOGOUT, ?ACK),
    [?_assertEqual('error', cb_context:resp_status(Result))
    ,?_assertEqual(409, cb_context:resp_error_code(Result))
    ,?_assertEqual(1, meck:num_calls(
                         'kz_auth_session_family', 'ack_logout',
                         [<<"state-1">>, <<"verifier-1">>]))
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
                                ,{<<"*.request_data.post.zkeycloak_ext">>, 'request_data'}
                                ,{<<"*.validate.zkeycloak_ext">>, 'validate'}
                                ,{<<"*.execute.post.zkeycloak_ext">>, 'post'}
                                ])
                    ,lists:sort(Bound)
                    ),
        ?assert(erlang:function_exported('cb_zkeycloak_ext', 'post', 1)),
        ?assert(erlang:function_exported('cb_zkeycloak_ext', 'post', 2)),
        ?assert(erlang:function_exported('cb_zkeycloak_ext', 'post', 3)),
        ?assert(erlang:function_exported('cb_zkeycloak_ext', 'request_data', 3))
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
-spec backchannel_ctx() -> cb_context:context().
backchannel_ctx() ->
    cb_context:set_req_data(
      base_ctx(), kz_json:from_list([{<<"logout_token">>, <<"signed-logout-token">>}])).

-spec ack_ctx() -> cb_context:context().
ack_ctx() ->
    cb_context:set_req_data(
      base_ctx(), kz_json:from_list([{<<"state">>, <<"state-1">>}
                                   ,{<<"verifier">>, <<"verifier-1">>}])).

-spec root_ctx() -> cb_context:context().
root_ctx() ->
    Ctx = cb_context:set_req_data(base_ctx(), kz_json:new()),
    cb_context:set_req_json(Ctx, kz_json:from_list([{<<"data">>, kz_json:new()}])).

%% форма oidcc-tuple — как её строит zkeycloak_util:refresh_token/1
-spec token_tuple() -> tuple().
token_tuple() ->
    {'oidcc_token'
    ,{'oidcc_token_id', ?NEW_ID, #{<<"sub">> => ?SUB_UUID
                                  ,<<"sid">> => ?SID
                                  ,<<"exp">> => ?EXPIRES_AT}}
    ,{'oidcc_token_access', ?NEW_ACCESS, 300, <<"Bearer">>}
    ,{'oidcc_token_refresh', ?NEW_REFRESH}
    ,<<"openid profile">>
    }.


-spec refresh_binding() -> kz_json:object().
refresh_binding() ->
    kz_json:from_list([{<<"_id">>, <<"auth-binding-kc_refresh-old">>}
                      ,{<<"family">>, <<"family-1">>}
                      ,{<<"account_id">>, ?ACCOUNT_ID}
                      ,{<<"owner_id">>, ?OWNER_ID}
                      ,{<<"state">>, <<"active">>}
                      ]).
-spec userinfo() -> map().
userinfo() ->
    #{<<"sub">> => ?SUB_UUID
     ,<<"account_id">> => ?ACCOUNT_ID
     ,<<"given_name">> => <<"Иван"/utf8>>
     ,<<"family_name">> => <<"Петров"/utf8>>
     ,<<"resource_access">> => #{<<"onbill_client">> => #{<<"roles">> => [<<"onbill_access">>]}}
     }.
