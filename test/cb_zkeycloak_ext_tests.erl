%%%-----------------------------------------------------------------------------
%%% @doc EUnit для auth-гейтов `cb_zkeycloak_ext'.
%%%
%%% Харднинг из P3 кросс-ревью 16.07 (`.scratch/zkeycloak-hardening-2026-07-16').
%%% Покрыты чистые гейты `provide_keycloak_token/6' (sub) и
%%% `provide_keycloak_token/7' (account_id) — они открыты для теста через
%%% `-ifdef(TEST). -export(...)' в модуле:
%%%
%%%   * не-UUID / отсутствующий `sub' → чистый 401 (issue 07);
%%%   * отсутствующий / пустой (`<<>>') / малформный `account_id' → чистый 401
%%%     (issue 10 + P3-2: раньше `<<>>'/малформ падал badmatch'ем в
%%%     `kzs_util:format_account_id/2' → 500);
%%%   * валидный login-флоу (валидный sub + raw account_id) → `success'
%%%     (границы `kz_datamgr'/`crossbar_auth' замоканы; наши модули —
%%%     `cb_zkeycloak_ext'/`zkeycloak_util' — НЕ мокаем, чтобы держать cover).
%%%
%%% Санитизация заголовков (`zkeycloak_util:redact_headers/1', issue 14) —
%%% в `zkeycloak_util_tests'.
%%% @end
%%%-----------------------------------------------------------------------------
-module(cb_zkeycloak_ext_tests).

-include_lib("eunit/include/eunit.hrl").

%% Дефисный UUID (MDM-key): `from_key/2' стрипнет дефисы → raw owner_id.
-define(SUB_UUID, <<"01234567-89ab-cdef-0123-456789abcdef">>).
-define(OWNER_ID, <<"0123456789abcdef0123456789abcdef">>).
%% raw-account-id: ровно 32 байта.
-define(ACCOUNT_ID, <<"fedcba9876543210fedcba9876543210">>).

-define(TA, <<"dummy-access-token">>).
-define(TID, <<"dummy-id-token">>).
-define(TR, <<"dummy-refresh-token">>).

%%%=============================================================================
%%% sub-гейт (`provide_keycloak_token/6')
%%%=============================================================================

sub_gate_rejects_non_uuid_test() ->
    %% federated sub `f:<idp>:<user>' — структурно не UUID → 401, не 500.
    UserInfo = #{<<"sub">> => <<"f:ldap-idp:jdoe">>},
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login'),
    assert_401(Ctx).

sub_gate_rejects_missing_sub_test() ->
    UserInfo = #{},
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'refresh'),
    assert_401(Ctx).

%%%=============================================================================
%%% account_id-гейт (`provide_keycloak_token/7')
%%%=============================================================================

account_gate_rejects_undefined_test() ->
    %% claim'а нет вовсе (LDAP/federated без KazooAuth) → 401 (закрыл a1eae36).
    UserInfo = #{<<"sub">> => ?SUB_UUID},
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login', ?OWNER_ID),
    assert_401(Ctx).

account_gate_rejects_empty_test() ->
    %% пустой `<<>>' — раньше badmatch → 500, теперь 401 (P3-2).
    UserInfo = #{<<"account_id">> => <<>>},
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login', ?OWNER_ID),
    assert_401(Ctx).

account_gate_rejects_malformed_test() ->
    %% не-32-байтный — раньше badmatch → 500, теперь 401 (P3-2).
    UserInfo = #{<<"account_id">> => <<"not-a-valid-account-id">>},
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'refresh', ?OWNER_ID),
    assert_401(Ctx).

%%%=============================================================================
%%% Валидный login-флоу через оба гейта (границы замоканы)
%%%=============================================================================

valid_login_flow_test_() ->
    {setup, fun setup_boundaries/0, fun cleanup_boundaries/1,
     fun(_) ->
             [{"валидный sub+account, login → success",
               fun() ->
                       UserInfo = #{<<"sub">> => ?SUB_UUID
                                   ,<<"account_id">> => ?ACCOUNT_ID
                                   ,<<"given_name">> => <<"Ivan">>
                                   ,<<"family_name">> => <<"Petrov">>
                                   ,<<"email">> => <<"ivan.petrov@example.com">>
                                   },
                       Ctx = cb_zkeycloak_ext:provide_keycloak_token(
                               cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login'),
                       ?assertEqual('success', cb_context:resp_status(Ctx))
               end}]
     end}.

setup_boundaries() ->
    %% Границы (не наши модули) — мокаем, чтобы гейт-хвост не ходил в БД/auth.
    meck:new('kz_datamgr', ['no_link']),
    meck:expect('kz_datamgr', 'open_doc', fun(_Db, _Id) -> {'ok', kz_json:new()} end),
    meck:new('crossbar_auth', ['no_link']),
    meck:expect('crossbar_auth', 'create_auth_token',
                fun(Ctx, _AuthModule) ->
                        cb_context:set_resp_status(
                          cb_context:set_resp_data(Ctx, kz_json:new()), 'success')
                end),
    'ok'.

cleanup_boundaries(_) ->
    _ = (catch meck:unload('kz_datamgr')),
    _ = (catch meck:unload('crossbar_auth')),
    'ok'.

%%%=============================================================================
%%% helpers
%%%=============================================================================

-spec assert_401(cb_context:context()) -> 'ok'.
assert_401(Ctx) ->
    ?assertEqual(401, cb_context:resp_error_code(Ctx)),
    ?assertEqual('error', cb_context:resp_status(Ctx)),
    ?assertEqual(<<"invalid_credentials">>, cb_context:resp_error_msg(Ctx)),
    'ok'.
