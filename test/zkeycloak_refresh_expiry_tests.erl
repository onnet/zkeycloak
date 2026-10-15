-module(zkeycloak_refresh_expiry_tests).

-include_lib("eunit/include/eunit.hrl").

offline_refresh_expiry_test_() ->
    {'setup', fun setup/0, fun cleanup/1,
     [fun offline_without_exp_outlives_short_access/0
     ,fun offline_zero_exp_outlives_short_access/0
     ,fun explicit_exp_is_preserved/0
     ,fun ordinary_missing_exp_keeps_fallback/0
     ,fun configured_retention_is_used/0
     ,fun invalid_config_uses_default/0
     ,fun config_failure_uses_default/0
     ]}.

setup() ->
    meck:new('kapps_config', ['non_strict']),
    meck:expect('kapps_config', 'get_integer',
                fun(<<"zkeycloak">>, <<"offline_refresh_retention_s">>, Default) -> Default end).

cleanup(_) -> meck:unload('kapps_config').

offline_without_exp_outlives_short_access() ->
    assert_offline_window([{<<"typ">>, <<"Offline">>}], 30 * 86400).

offline_zero_exp_outlives_short_access() ->
    assert_offline_window([{<<"typ">>, <<"Offline">>}, {<<"exp">>, 0}], 30 * 86400).

explicit_exp_is_preserved() ->
    Exp = kz_time:current_unix_tstamp() + 3600,
    ?assertEqual(Exp, zkeycloak_util:refresh_expires_at(
                       token([{<<"typ">>, <<"Offline">>}, {<<"exp">>, Exp}]), Exp - 300)).

ordinary_missing_exp_keeps_fallback() ->
    ?assertEqual(2000000000, zkeycloak_util:refresh_expires_at(
                              token([{<<"typ">>, <<"Refresh">>}]), 2000000000)).

configured_retention_is_used() ->
    meck:expect('kapps_config', 'get_integer', fun(_, _, _) -> 45 * 86400 end),
    assert_offline_window([{<<"typ">>, <<"Offline">>}], 45 * 86400).

invalid_config_uses_default() ->
    meck:expect('kapps_config', 'get_integer', fun(_, _, _) -> 0 end),
    assert_offline_window([{<<"typ">>, <<"Offline">>}], 30 * 86400).

config_failure_uses_default() ->
    meck:expect('kapps_config', 'get_integer', fun(_, _, _) -> error('unavailable') end),
    assert_offline_window([{<<"typ">>, <<"Offline">>}], 30 * 86400).

assert_offline_window(Claims, Ttl) ->
    Before = kz_time:current_unix_tstamp(),
    Expiry = zkeycloak_util:refresh_expires_at(token(Claims), Before + 300),
    After = kz_time:current_unix_tstamp(),
    ?assert(Expiry >= Before + Ttl),
    ?assert(Expiry =< After + Ttl).

token(Claims) ->
    Payload = base64:encode(kz_json:encode(kz_json:from_list(Claims)),
                            #{'mode' => 'urlsafe', 'padding' => 'false'}),
    <<"header.", Payload/binary, ".signature">>.
