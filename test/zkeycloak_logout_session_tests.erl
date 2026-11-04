-module(zkeycloak_logout_session_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SID, <<"verified-sid">>).
-define(SUB, <<"01234567-89ab-cdef-0123-456789abcdef">>).
-define(CLIENT, <<"onbill_client">>).

provider_closure_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(_) -> fun() ->
        Closed = kz_json:from_list([{<<"status">>, <<"closed">>},
                                   {<<"sid">>, ?SID}, {<<"sub">>, ?SUB},
                                   {<<"client_id">>, ?CLIENT}]),
        meck:expect(kz_http, post, fun(Url, _Headers, Body, Opts) ->
            ?assertEqual(<<"https://kc.example/realms/BRT/brt-session/logout">>, Url),
            ?assertEqual(false, props:get_value(autoredirect, Opts)),
            ?assertEqual(1000, props:get_value(timeout, Opts)),
            Ssl = props:get_value(ssl, Opts),
            ?assertEqual(verify_peer, props:get_value(verify, Ssl)),
            ?assertNotEqual(nomatch, binary:match(iolist_to_binary(Body), <<"client_secret=secret">>)),
            {ok, 200, [], kz_json:encode(Closed)}
        end),
        ?assertEqual(ok, zkeycloak_util:close_logout_session(?SID, ?SUB)),
        Invalid = [kz_json:set_value(K, <<"wrong">>, Closed)
                   || K <- [<<"status">>, <<"sid">>, <<"sub">>, <<"client_id">>]],
        Responses = [{ok, 200, [], kz_json:encode(J)} || J <- Invalid]
            ++ [{ok, 200, [], <<"not-json">>}, {ok, 200, [], <<"null">>},
                {ok, 401, [], <<>>}, {ok, 503, [], <<>>},
                {ok, 302, [], <<>>}, {error, timeout}],
        lists:foreach(fun(Response) ->
            assert_unconfirmed_response(Response)
        end, Responses),
        meck:reset(kz_http),
        meck:expect(kz_auth_issuer, keycloak, fun(_) -> <<"http://kc.example/realms/BRT">> end),
        ?assertEqual({error, keycloak_logout_unconfirmed},
                     zkeycloak_util:close_logout_session(?SID, ?SUB)),
        ?assertEqual(0, meck:num_calls(kz_http, post, '_'))
    end end}.

setup() ->
    meck:new(kz_http, [no_link]),
    meck:new(kz_auth_issuer, [no_link]),
    meck:new(kapps_config, [no_link]),
    meck:expect(kz_auth_issuer, keycloak, fun(_) -> <<"https://kc.example/realms/BRT">> end),
    meck:expect(kapps_config, get_ne_binary,
                fun(_, <<"client_id">>, _) -> ?CLIENT;
                   (_, <<"client_secret">>, _) -> <<"secret">>
                end),
    meck:expect(kapps_config, get_integer, fun(_, _, _) -> 1000 end),
    ok.

cleanup(_) ->
    [meck:unload(M) || M <- [kz_http, kz_auth_issuer, kapps_config]],
    ok.

assert_unconfirmed_response(Response) ->
    meck:expect(kz_http, post, fun(_, _, _, _) -> Response end),
    ?assertEqual({error, keycloak_logout_unconfirmed},
                 zkeycloak_util:close_logout_session(?SID, ?SUB)).
