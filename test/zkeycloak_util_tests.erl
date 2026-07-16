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
%%% Покрыто (issue 15 — тот же класс утечки через тело и claim'ы):
%%%   * `redact_req_data/1' — маскирование значений credential-ключей тела
%%%     (`refresh_token' и пр.), в т.ч. под crossbar-конвертом `{"data":{…}}'
%%%     и внутри массивов; PKCE-`code_challenge' (публичный) не трогаем;
%%%   * `claims_digest/1' — whitelist служебных claim'ов, ПДн наружу не идут
%%%     даже для НЕИЗВЕСТНЫХ ключей от KC; fail-closed на не-map форме.
%%%
%%% Проверяем свойство на уровне ЛОГ-СТРОКИ (`?FMT' = то, что реально уйдёт
%%% в lager через `~p'), а не только структуры: утечка — это подстрока
%%% секрета в логе, её и ищем.
%%%
%%% Наши модули НЕ мокаем (держим cover); границ здесь нет — функции чистые.
%%% @end
%%%-----------------------------------------------------------------------------
-module(zkeycloak_util_tests).

-include_lib("eunit/include/eunit.hrl").

%% Отформатированная лог-строка — ровно то, что `lager:info("~p", [Term])'
%% положит в лог-файл.
-define(FMT(Term), iolist_to_binary(io_lib:format("~p", [Term]))).

%% Живой 30-дневный refresh (issue 15) и ПДн — то, чего в логе быть не должно.
-define(REFRESH, <<"eyJhbGciOiJIUzI1NiJ9.refresh-secret-tail-30d">>).
-define(SECRET_TAIL, <<"refresh-secret-tail-30d">>).
-define(EMAIL, <<"ivan.petrov@brterminal.ru">>).

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

%%%=============================================================================
%%% redact_req_data/1 (issue 15) — тело запроса
%%%=============================================================================

redact_req_data_masks_refresh_token_test() ->
    %% Ядро issue 15: тело `POST /zkeycloak_ext/refresh' в `authorize/1'.
    Body = kz_json:from_list([{<<"refresh_token">>, ?REFRESH}]),
    R = zkeycloak_util:redact_req_data(Body),
    ?assertEqual('nomatch', binary:match(?FMT(R), ?SECRET_TAIL)),
    %% ключ на месте — видно, что клиент прислал refresh_token.
    ?assertNotEqual('undefined', kz_json:get_value(<<"refresh_token">>, R)).

redact_req_data_masks_under_crossbar_envelope_test() ->
    %% `zkeycloak_ext_post/1' логирует req_json — секрет ВТОРЫМ уровнем,
    %% под конвертом `{"data":{…}}'. Без рекурсии утечка осталась бы.
    ReqJSON = kz_json:from_list(
                [{<<"data">>, kz_json:from_list([{<<"refresh_token">>, ?REFRESH}])}
                ]),
    R = zkeycloak_util:redact_req_data(ReqJSON),
    ?assertEqual('nomatch', binary:match(?FMT(R), ?SECRET_TAIL)).

redact_req_data_masks_password_and_code_test() ->
    Body = kz_json:from_list([{<<"password">>, <<"hunter2-secret">>}
                             ,{<<"code">>, <<"oidc-code-abcdef">>}
                             ,{<<"code_verifier">>, <<"pkce-verifier-xyz">>}
                             ]),
    Fmt = ?FMT(zkeycloak_util:redact_req_data(Body)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"hunter2-secret">>)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"oidc-code-abcdef">>)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"pkce-verifier-xyz">>)).

redact_req_data_preserves_non_sensitive_test() ->
    %% Лог обязан остаться диагностически полезным.
    Body = kz_json:from_list([{<<"refresh_token">>, ?REFRESH}
                             ,{<<"account_name">>, <<"rast">>}
                             ,{<<"redirect_uri">>, <<"ru.brt.zfield://oauth/callback">>}
                             ]),
    R = zkeycloak_util:redact_req_data(Body),
    ?assertEqual(<<"rast">>, kz_json:get_value(<<"account_name">>, R)),
    ?assertEqual(<<"ru.brt.zfield://oauth/callback">>
                ,kz_json:get_value(<<"redirect_uri">>, R)).

redact_req_data_keeps_code_challenge_test() ->
    %% PKCE-challenge публичен по дизайну — маскировать его нечего,
    %% и он полезен в логе (диагностика invalid_grant).
    Body = kz_json:from_list([{<<"code_challenge">>, <<"S256-challenge-value">>}]),
    R = zkeycloak_util:redact_req_data(Body),
    ?assertEqual(<<"S256-challenge-value">>, kz_json:get_value(<<"code_challenge">>, R)).

redact_req_data_case_insensitive_key_test() ->
    Body = kz_json:from_list([{<<"Refresh_Token">>, ?REFRESH}]),
    R = zkeycloak_util:redact_req_data(Body),
    ?assertEqual('nomatch', binary:match(?FMT(R), ?SECRET_TAIL)).

redact_req_data_recurses_into_array_test() ->
    %% Объект с кредом внутри JSON-массива.
    Body = kz_json:from_list(
             [{<<"tokens">>, [kz_json:from_list([{<<"refresh_token">>, ?REFRESH}])]}
             ]),
    R = zkeycloak_util:redact_req_data(Body),
    ?assertEqual('nomatch', binary:match(?FMT(R), ?SECRET_TAIL)).

redact_req_data_scalar_passthrough_test() ->
    %% Не-объектное тело: маскировать по ключу нечего, лог не глушим.
    ?assertEqual('undefined', zkeycloak_util:redact_req_data('undefined')),
    ?assertEqual(<<"plain">>, zkeycloak_util:redact_req_data(<<"plain">>)).

%%%=============================================================================
%%% claims_digest/1 (issue 15) — claim'ы id_token / userinfo
%%%=============================================================================

%% Реалистичная userinfo от KC realm'а BRT: служебные поля + ПДн + роли.
userinfo() ->
    #{<<"sub">> => <<"01234567-89ab-cdef-0123-456789abcdef">>
     ,<<"iss">> => <<"https://keycloak.brterminal.ru/realms/BRT">>
     ,<<"azp">> => <<"onbill_client">>
     ,<<"acr">> => <<"kerberos">>
     ,<<"account_id">> => <<"fedcba9876543210fedcba9876543210">>
     ,<<"resource_access">> =>
          #{<<"onbill_client">> => #{<<"roles">> => [<<"onbill_access">>]}}
     ,<<"email">> => ?EMAIL
     ,<<"preferred_username">> => <<"ipetrov">>
     ,<<"given_name">> => <<"Иван"/utf8>>
     ,<<"family_name">> => <<"Петров"/utf8>>
     }.

claims_digest_keeps_service_claims_test() ->
    D = zkeycloak_util:claims_digest(userinfo()),
    ?assertEqual(<<"01234567-89ab-cdef-0123-456789abcdef">>, maps:get(<<"sub">>, D)),
    ?assertEqual(<<"onbill_client">>, maps:get(<<"azp">>, D)),
    ?assertEqual(<<"kerberos">>, maps:get(<<"acr">>, D)),
    ?assertEqual(<<"fedcba9876543210fedcba9876543210">>, maps:get(<<"account_id">>, D)).

claims_digest_keeps_resource_access_test() ->
    %% Роли обязаны остаться: без них «молчаливый» отказ role-гейта
    %% (выключен маппер Add to userinfo, issue 13) не диагностируется.
    D = zkeycloak_util:claims_digest(userinfo()),
    ?assertEqual([<<"onbill_access">>]
                ,kz_maps:get([<<"resource_access">>, <<"onbill_client">>, <<"roles">>], D)).

claims_digest_drops_pii_values_test() ->
    %% Главное свойство issue 15: ПДн нет в лог-строке.
    Fmt = ?FMT(zkeycloak_util:claims_digest(userinfo())),
    ?assertEqual('nomatch', binary:match(Fmt, ?EMAIL)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"ipetrov">>)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"Иван"/utf8>>)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"Петров"/utf8>>)).

claims_digest_reports_redacted_key_names_test() ->
    %% Имена (схема) остаются — по ним видно, что поле пришло; заодно это
    %% presence-флаг для диагностики «у LDAP-юзера нет sn».
    D = zkeycloak_util:claims_digest(userinfo()),
    Redacted = maps:get('redacted_keys', D),
    ?assert(lists:member(<<"email">>, Redacted)),
    ?assert(lists:member(<<"family_name">>, Redacted)),
    %% служебные в redacted_keys не дублируются
    ?assertNot(lists:member(<<"sub">>, Redacted)).

claims_digest_new_unknown_claim_not_leaked_test() ->
    %% Суть выбора whitelist'а: НОВЫЙ ПДн-claim от KC (маппер добавили на
    %% стороне realm'а, мы про него не знаем) не утекает по умолчанию —
    %% в лог идёт только его имя.
    Claims = maps:put(<<"phone_number">>, <<"+79001234567">>, userinfo()),
    D = zkeycloak_util:claims_digest(Claims),
    ?assertEqual('nomatch', binary:match(?FMT(D), <<"+79001234567">>)),
    ?assert(lists:member(<<"phone_number">>, maps:get('redacted_keys', D))).

claims_digest_unexpected_shape_fails_closed_test() ->
    %% Не-map (сменилась форма oidcc) — печатаем факт, не содержимое.
    D = zkeycloak_util:claims_digest([{<<"email">>, ?EMAIL}]),
    ?assertEqual('nomatch', binary:match(?FMT(D), ?EMAIL)),
    ?assertEqual(#{'unexpected_claims_shape' => 'true'}, D).

claims_digest_empty_claims_test() ->
    ?assertEqual(#{'redacted_keys' => []}, zkeycloak_util:claims_digest(#{})).
