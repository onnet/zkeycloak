%%%-----------------------------------------------------------------------------
%%% @doc EUnit для `zkeycloak_util' — санитизация логов.
%%%
%%% Покрыто (issue 14 KC-auth ревью + харднинг 16.07):
%%%   * `redact/1' — маскирование одиночного секрета (undefined/пусто/binary);
%%%   * `redact_headers/1' — маскирование ЗНАЧЕНИЙ credential-заголовков
%%%     (`authorization'/`cookie'/`x-auth-token' …) с сохранением имён и
%%%     не-sensitive значений; map- и proplist-формы; case-insensitive имена;
%%%     fail-safe на неожиданной форме.
%%%
%%% Наши модули НЕ мокаем (держим cover); границ здесь нет — функции чистые.
%%% @end
%%%-----------------------------------------------------------------------------
-module(zkeycloak_util_tests).

-include_lib("eunit/include/eunit.hrl").

%%%=============================================================================
%%% redact/1
%%%=============================================================================

redact_undefined_test() ->
    ?assertEqual(<<"undefined">>, zkeycloak_util:redact('undefined')).

redact_empty_test() ->
    ?assertEqual(<<"empty">>, zkeycloak_util:redact(<<>>)).

redact_binary_masks_tail_test() ->
    Secret = <<"Bearer eyJhbGciOiJ-secret-tail-9f8e7d">>,
    Masked = zkeycloak_util:redact(Secret),
    %% сохранён только короткий префикс + длина; хвост секрета отсутствует.
    ?assertMatch(<<"Bearer", _/binary>>, Masked),
    ?assertEqual('nomatch', binary:match(Masked, <<"secret-tail-9f8e7d">>)),
    ?assert(byte_size(Masked) < byte_size(Secret)).

%%%=============================================================================
%%% redact_headers/1 — map-форма (cowboy:http_headers())
%%%=============================================================================

redact_headers_masks_authorization_test() ->
    Hs = #{<<"authorization">> => <<"Bearer live-access-token-abcdef">>
          ,<<"content-type">> => <<"application/json">>
          },
    R = zkeycloak_util:redact_headers(Hs),
    ?assertEqual(<<"application/json">>, maps:get(<<"content-type">>, R)),
    Masked = maps:get(<<"authorization">>, R),
    ?assertNotEqual(<<"Bearer live-access-token-abcdef">>, Masked),
    ?assertEqual('nomatch', binary:match(Masked, <<"live-access-token-abcdef">>)).

redact_headers_masks_cookie_and_xauth_test() ->
    Hs = #{<<"cookie">> => <<"session=deadbeefcafe">>
          ,<<"x-auth-token">> => <<"kazoo-auth-token-1234567890">>
          ,<<"accept">> => <<"*/*">>
          },
    R = zkeycloak_util:redact_headers(Hs),
    ?assertEqual('nomatch', binary:match(maps:get(<<"cookie">>, R), <<"deadbeefcafe">>)),
    ?assertEqual('nomatch', binary:match(maps:get(<<"x-auth-token">>, R), <<"1234567890">>)),
    ?assertEqual(<<"*/*">>, maps:get(<<"accept">>, R)).

redact_headers_case_insensitive_name_test() ->
    %% имя в смешанном регистре (историческая proplist-форма) всё равно детектится.
    Hs = [{<<"Authorization">>, <<"Bearer UPPER-secret-xyz">>}
         ,{<<"Accept">>, <<"text/html">>}
         ],
    R = zkeycloak_util:redact_headers(Hs),
    {<<"Authorization">>, Masked} = lists:keyfind(<<"Authorization">>, 1, R),
    ?assertEqual('nomatch', binary:match(Masked, <<"UPPER-secret-xyz">>)),
    ?assertEqual({<<"Accept">>, <<"text/html">>}, lists:keyfind(<<"Accept">>, 1, R)).

redact_headers_undefined_value_no_crash_test() ->
    %% значение sensitive-заголовка = undefined → redact/1 не роняет.
    R = zkeycloak_util:redact_headers(#{<<"authorization">> => 'undefined'}),
    ?assertEqual(<<"undefined">>, maps:get(<<"authorization">>, R)).

redact_headers_preserves_all_keys_test() ->
    Hs = #{<<"authorization">> => <<"Bearer x">>
          ,<<"cookie">> => <<"c=1">>
          ,<<"host">> => <<"api.example.com">>
          },
    R = zkeycloak_util:redact_headers(Hs),
    ?assertEqual(lists:sort(maps:keys(Hs)), lists:sort(maps:keys(R))),
    ?assertEqual(<<"api.example.com">>, maps:get(<<"host">>, R)).

redact_headers_non_container_passthrough_test() ->
    ?assertEqual('undefined', zkeycloak_util:redact_headers('undefined')).
