%%%-----------------------------------------------------------------------------
%%% @doc EUnit для `zkeycloak_util' — санитизация логов.
%%%
%%% Покрыто (issue 14 KC-auth ревью + харднинг 16.07):
%%%   * `redact/1' — маскирование одиночного секрета (undefined/пусто/binary);
%%%   * `redact_headers/1' — маскирование ЗНАЧЕНИЙ credential-заголовков
%%%     (`authorization'/`cookie'/`x-auth-token' …) и креды-параметров в URL
%%%     прочих заголовков (`referer' с `code='), с сохранением имён и
%%%     остального; map- и proplist-формы; case-insensitive имена;
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
-define(SUB, <<"01234567-89ab-cdef-0123-456789abcdef">>).

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
    %% Сохранён только короткий SHA-256 fingerprint + длина.
    ?assertMatch(<<"sha256:", _/binary>>, Masked),
    ?assertEqual('nomatch', binary:match(Masked, <<"secret-tail-9f8e7d">>)),
    ?assert(byte_size(Masked) < byte_size(Secret)).

redact_total_on_client_shaped_terms_test() ->
    %% `redact/1' кормится значениями из ТЕЛА, форму которых задаёт клиент —
    %% и `authorize/1' зовётся ДО аутентификации. `kz_term:to_binary/1'
    %% частичен (badarg на списке объектов / числе >255 / map), поэтому
    %% redact обязан быть тотальным: иначе тело `{"refresh_token":[{"x":1}]}'
    %% роняет authorize в Crossbar-500 неаутентифицированным запросом.
    ?assertEqual(<<"redacted(unprintable)">>, zkeycloak_util:redact([{[{<<"x">>,1}]}])),
    ?assertEqual(<<"redacted(unprintable)">>, zkeycloak_util:redact([1000])),
    ?assertEqual(<<"redacted(unprintable)">>, zkeycloak_util:redact(#{'a' => 1})),
    %% печатаемые не-binary формы маскируются, а не глушатся
    ?assertMatch(<<"sha256:", _/binary>>, zkeycloak_util:redact({[{<<"a">>,1}]})),
    ?assertMatch(<<"sha256:", _/binary>>, zkeycloak_util:redact(12345)).

redact_short_secret_hides_prefix_test() ->
    %% `min(6, Len)' выдавал короткий секрет целиком; в ?SENSITIVE_BODY_KEYS
    %% есть `password', который короткий по природе.
    Short = zkeycloak_util:redact(<<"hunter7">>),
    ?assertMatch(<<"sha256:", _/binary>>, Short),
    ?assertEqual('nomatch', binary:match(Short, <<"hunter7">>)),
    %% На длинном значении также нет обратимого префикса.
    Long = <<"abcdefghijklmnopqrstuvwx">>, %% ровно 24
    ?assertEqual('nomatch', binary:match(zkeycloak_util:redact(Long), <<"abcdef">>)).

redact_pii_never_reveals_prefix_test() ->
    %% ПДн: префикс не печатаем совсем — 6 байт email'а это всё ещё ПДн,
    %% а на кириллице побайтовый префикс резал бы символ пополам.
    ?assertEqual(<<"redacted(len=25)">>, zkeycloak_util:redact_pii(?EMAIL)),
    ?assertEqual(<<"undefined">>, zkeycloak_util:redact_pii('undefined')),
    Fio = <<"Пётр"/utf8>>,
    R = zkeycloak_util:redact_pii(Fio),
    ?assertEqual('nomatch', binary:match(R, <<"Пёт"/utf8>>)),
    %% результат — валидный UTF-8 (битого префикса в логе не будет)
    ?assertNotEqual('error', unicode:characters_to_binary(R, 'utf8')).

redact_req_data_object_valued_secret_no_crash_test() ->
    %% Тот же вектор через публичную дверь: credential-ключ со значением-
    %% массивом объектов. Должно быть замаскировано и без краша.
    Body = kz_json:from_list([{<<"refresh_token">>, [kz_json:from_list([{<<"x">>,1}])]}]),
    ?assertEqual(<<"redacted(unprintable)">>
                ,kz_json:get_value(<<"refresh_token">>, zkeycloak_util:redact_req_data(Body))).

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

%%%=============================================================================
%%% redact_headers/1 — креды в URL несекретного заголовка (referer после KC)
%%%=============================================================================

%% Форма `referer' на `auth_callback' 30.09: KC редиректит на наш адрес с
%% `session_state', `iss' и `code' в query. Значения вымышленные.
-define(KC_CODE, <<"1f2e3d4c-aaaa-bbbb-cccc-0123456789ab.5e6f7a8b-dddd-eeee-ffff-0123456789ab.9c0d1e2f-1111-2222-3333-0123456789ab">>).

referer(Query) ->
    <<"https://portal.example.ru/ext/login/", Query/binary>>.

redacted_referer(Query) ->
    maps:get(<<"referer">>, zkeycloak_util:redact_headers(#{<<"referer">> => referer(Query)})).

referer_code_and_session_state_are_masked_test() ->
    Out = redacted_referer(<<"?session_state=SeSsIoNsTaTe0123456789ab&iss=https%3A%2F%2Fkc.example.ru%2Frealms%2Fbrt&code=", ?KC_CODE/binary>>),
    ?assertEqual('nomatch', binary:match(Out, ?KC_CODE)),
    ?assertEqual('nomatch', binary:match(Out, <<"SeSsIoNsTaTe0123456789ab">>)),
    ?assertNotEqual('nomatch', binary:match(Out, <<"&code=sha256:">>)),
    ?assertNotEqual('nomatch', binary:match(Out, <<"?session_state=sha256:">>)),
    ?assertNotEqual('nomatch', binary:match(Out, <<"&iss=https%3A%2F%2Fkc.example.ru%2Frealms%2Fbrt&">>)),
    ?assertNotEqual('nomatch', binary:match(Out, <<"https://portal.example.ru/ext/login/?">>)).

referer_fragment_tokens_are_masked_test() ->
    %% implicit/hybrid-флоу кладёт токены во fragment.
    Out = redacted_referer(<<"#access_token=eyJ.acc.sig&state=st4t3value&token_type=Bearer">>),
    ?assertEqual('nomatch', binary:match(Out, <<"eyJ.acc.sig">>)),
    ?assertEqual('nomatch', binary:match(Out, <<"st4t3value">>)),
    ?assertNotEqual('nomatch', binary:match(Out, <<"&token_type=Bearer">>)).

referer_value_with_equals_sign_is_masked_whole_test() ->
    %% base64-`state' с паддингом: значение режется по ПЕРВОМУ `='.
    Out = redacted_referer(<<"?state=c3RhdGUtdmFsdWU==&tab=1">>),
    ?assertEqual('nomatch', binary:match(Out, <<"c3RhdGUtdmFsdWU">>)),
    ?assertNotEqual('nomatch', binary:match(Out, <<"&tab=1">>)).

referer_param_name_is_case_insensitive_test() ->
    Out = redacted_referer(<<"?Code=", ?KC_CODE/binary>>),
    ?assertEqual('nomatch', binary:match(Out, ?KC_CODE)).

referer_password_gets_length_only_test() ->
    %% Низкоэнтропийный класс тот же, что в теле: отпечаток пароля обратим.
    Out = redacted_referer(<<"?password=hunter2">>),
    ?assertEqual('nomatch', binary:match(Out, <<"hunter2">>)),
    ?assertEqual('nomatch', binary:match(Out, <<"sha256:">>)).

referer_code_challenge_is_kept_test() ->
    %% Публичен по дизайну PKCE — см. ?SENSITIVE_BODY_KEYS.
    Q = <<"?code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256">>,
    ?assertEqual(referer(Q), redacted_referer(Q)).

referer_without_sensitive_params_is_unchanged_test() ->
    Q = <<"?tab=containers&page=2#top">>,
    ?assertEqual(referer(Q), redacted_referer(Q)).

header_without_query_is_unchanged_test() ->
    Hs = #{<<"referer">> => <<"https://portal.example.ru/ext/login/">>
          ,<<"user-agent">> => <<"Mozilla/5.0 (X11; Linux x86_64)">>
          },
    ?assertEqual(Hs, zkeycloak_util:redact_headers(Hs)).

non_binary_plain_header_is_unchanged_test() ->
    Hs = #{<<"referer">> => 'undefined'},
    ?assertEqual(Hs, zkeycloak_util:redact_headers(Hs)).

referer_in_proplist_form_is_masked_test() ->
    [{<<"Referer">>, Out}] = zkeycloak_util:redact_headers([{<<"Referer">>, referer(<<"?code=", ?KC_CODE/binary>>)}]),
    ?assertEqual('nomatch', binary:match(Out, ?KC_CODE)).

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

%%%-----------------------------------------------------------------------------
%%% Низкоэнтропийные секреты маскируются ДЛИНОЙ, а не отпечатком
%%% (находка 01-P2-2 кросс-ревью 22.08.2026)
%%%
%%% `redact/1' печатает 12 hex несолёного SHA-256 = 48 бит. Для токена это
%%% безопасно, для ПАРОЛЯ — нет: обладатель лог-архива считает
%%% `sha256(кандидат)' офлайн и сравнивает префикс, а `lager:info' виден на
%%% проде. Утверждение формулируется ИСПОЛНЯЕМО: по лог-строке пароль из
%%% словаря обязан быть НЕ восстановим тем самым вычислением, которым его
%%% восстанавливали.
%%%-----------------------------------------------------------------------------

redact_req_data_password_is_not_a_dictionary_oracle_test() ->
    Password = <<"hunter2">>,
    Body = kz_json:from_list([{<<"password">>, Password}]),
    Fmt = ?FMT(zkeycloak_util:redact_req_data(Body)),
    %% сам пароль в логе не лежит
    ?assertEqual('nomatch', binary:match(Fmt, Password)),
    %% и его отпечаток — тоже: иначе словарный перебор по логу тривиален
    ?assertEqual('nomatch', binary:match(Fmt, fingerprint(Password))),
    ?assertEqual('nomatch', binary:match(Fmt, <<"sha256:">>)).

redact_req_data_client_secret_is_length_only_test() ->
    Secret = <<"onbill-client-secret">>,
    Body = kz_json:from_list([{<<"client_secret">>, Secret}]),
    Fmt = ?FMT(zkeycloak_util:redact_req_data(Body)),
    ?assertEqual('nomatch', binary:match(Fmt, Secret)),
    ?assertEqual('nomatch', binary:match(Fmt, fingerprint(Secret))).

redact_req_data_high_entropy_keeps_its_fingerprint_test() ->
    %% Позитивный контроль: разделение по энтропии не имеет права выродиться
    %% в «всем длину» — корреляция «тот же токен?» по логу должна остаться.
    Body = kz_json:from_list([{<<"refresh_token">>, ?REFRESH}
                             ,{<<"password">>, <<"hunter2">>}
                             ]),
    R = zkeycloak_util:redact_req_data(Body),
    ?assertMatch(<<"sha256:", _/binary>>,
                 kz_json:get_value(<<"refresh_token">>, R)),
    ?assertMatch(<<"redacted(len=", _/binary>>,
                 kz_json:get_value(<<"password">>, R)).

redact_req_data_password_under_envelope_test() ->
    %% Тот же класс вторым уровнем — форма, которой ходит `brt-unified'.
    ReqJSON = kz_json:from_list(
                [{<<"data">>, kz_json:from_list([{<<"password">>, <<"hunter2">>}])}]),
    Fmt = ?FMT(zkeycloak_util:redact_req_data(ReqJSON)),
    ?assertEqual('nomatch', binary:match(Fmt, fingerprint(<<"hunter2">>))).

redact_low_entropy_is_total_test() ->
    %% Домен тот же, что у `redact/1': форму значения диктует КЛИЕНТ, и
    %% `authorize/1' отрабатывает до аутентификации. Частичный редактор ронял
    %% бы запрос в 500 — ровно тот класс, что закрывали issue 05/07/10.
    Body = kz_json:from_list([{<<"password">>, [kz_json:from_list([{<<"x">>,1}])]}]),
    ?assertEqual(<<"redacted(unprintable)">>
                ,kz_json:get_value(<<"password">>, zkeycloak_util:redact_req_data(Body))),
    Empty = kz_json:from_list([{<<"password">>, <<>>}]),
    ?assertEqual(<<"empty">>
                ,kz_json:get_value(<<"password">>, zkeycloak_util:redact_req_data(Empty))).

fingerprint(Value) ->
    binary:part(kz_binary:hexencode(crypto:hash('sha256', Value)), 0, 12).

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

%%%=============================================================================
%%% redact_validation_errors/1 (issue 15) — эхо ПДн в ошибках валидации
%%%=============================================================================

%% Форма `kzd_users:maybe_validate_username_is_unique/3': в `create_user/8'
%% `username' = Email, поэтому коллизия печатала email целиком.
username_unique_error() ->
    Msg = kz_json:from_list([{<<"message">>, <<"Username must be unique within account">>}
                            ,{<<"cause">>, ?EMAIL}
                            ]),
    {'validation_errors', [{[<<"username">>], <<"unique">>, Msg}]}.

redact_validation_errors_masks_echoed_email_test() ->
    R = zkeycloak_util:redact_validation_errors(username_unique_error()),
    ?assertEqual('nomatch', binary:match(?FMT(R), ?EMAIL)).

redact_validation_errors_keeps_diagnostics_test() ->
    %% Диагностика обязана выжить: какое поле, чем не угодило и человеческий
    %% message — иначе лог бесполезен («у LDAP-юзера пустой sn»).
    {'validation_errors', [{Path, Code, Msg}]} =
        zkeycloak_util:redact_validation_errors(username_unique_error()),
    ?assertEqual([<<"username">>], Path),
    ?assertEqual(<<"unique">>, Code),
    ?assertEqual(<<"Username must be unique within account">>
                ,kz_json:get_value(<<"message">>, Msg)).

redact_validation_errors_masks_schema_value_test() ->
    %% `kz_json_schema:error_to_jobj/2' кладёт отвергнутое значение в `value'.
    Msg = kz_json:from_list([{<<"message">>, <<"String must be at least 1 characters">>}
                            ,{<<"value">>, <<"Пётр"/utf8>>}
                            ]),
    Err = {'validation_errors', [{[<<"first_name">>], <<"minLength">>, Msg}]},
    ?assertEqual('nomatch', binary:match(?FMT(zkeycloak_util:redact_validation_errors(Err))
                                        ,<<"Пётр"/utf8>>)).

redact_validation_errors_unexpected_shape_passthrough_test() ->
    ?assertEqual({'system_error', 'datastore_fault'}
                ,zkeycloak_util:redact_validation_errors({'system_error', 'datastore_fault'})).

%%%=============================================================================
%%% redact_crash/1 (issue 15) — аргументы в стектрейсе
%%%=============================================================================

redact_crash_strips_stack_frame_args_test() ->
    %% `catch kzd_users:validate(_,_,UDoc)' на function_clause кладёт в фрейм
    %% РЕАЛЬНЫЕ аргументы — весь UDoc: ФИО, email, пароль.
    UDoc = kz_json:from_list([{<<"email">>, ?EMAIL}
                             ,{<<"password">>, <<"generated-secret">>}
                             ]),
    Crash = {'EXIT', {'function_clause'
                     ,[{'kzd_users', 'validate', [<<"acc">>, <<"usr">>, UDoc]
                       ,[{'file',"kzd_users.erl"},{'line',1027}]}
                      ]}},
    Fmt = ?FMT(zkeycloak_util:redact_crash(Crash)),
    ?assertEqual('nomatch', binary:match(Fmt, ?EMAIL)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"generated-secret">>)),
    %% M:F/A + location остаются — краш диагностируется
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"kzd_users">>)),
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"1027">>)).

redact_crash_non_exit_passthrough_test() ->
    ?assertEqual('some_atom', zkeycloak_util:redact_crash('some_atom')).

%%%=============================================================================
%%% redact_provisioning_error/1 — редакт на ВЫЗЫВАЮЩЕЙ стороне (review-loop)
%%%=============================================================================

redact_provisioning_error_masks_validation_errors_test() ->
    %% `create_user/8' отдаёт Reason наверх СЫРЫМ, и
    %% `cb_zkeycloak_ext:provide_keycloak_token/9' печатал его вторым `~p'
    %% на том же запросе — редакт в create_user без этого бесполезен.
    R = zkeycloak_util:redact_provisioning_error(username_unique_error()),
    ?assertEqual('nomatch', binary:match(?FMT(R), ?EMAIL)).

redact_provisioning_error_masks_crash_test() ->
    UDoc = kz_json:from_list([{<<"email">>, ?EMAIL}]),
    Crash = {'EXIT', {'function_clause'
                     ,[{'kzd_users', 'validate', [<<"acc">>, <<"usr">>, UDoc], []}]}},
    ?assertEqual('nomatch', binary:match(?FMT(zkeycloak_util:redact_provisioning_error(Crash))
                                        ,?EMAIL)).

redact_provisioning_error_passthrough_test() ->
    %% Прочие причины — атомы/теги без ПДн, диагностика должна выжить.
    ?assertEqual('datastore_unreachable'
                ,zkeycloak_util:redact_provisioning_error('datastore_unreachable')),
    ?assertEqual({'missing_user_doc_on_refresh', {'error', 'not_found'}}
                ,zkeycloak_util:redact_provisioning_error(
                   {'missing_user_doc_on_refresh', {'error', 'not_found'}})).

%%%=============================================================================
%%% redact_stack/1 — аргументы во фреймах try/catch-сайтов (review-loop)
%%%=============================================================================

redact_stack_masks_oidcc_client_secret_test() ->
    %% `normalize_oidcc/2` оборачивает `oidcc:retrieve_token(AuthCode, _,
    %% ClientId, ClientSecret, _)' — фрейм с args несёт code И client_secret.
    Stack = [{'oidcc', 'retrieve_token'
             ,[<<"auth-code-live">>, 'client_id', <<"onbill_client">>
              ,<<"super-secret-client-secret">>, #{}]
             ,[{'file',"oidcc.erl"},{'line',42}]}
            ],
    Fmt = ?FMT(zkeycloak_util:redact_stack(Stack)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"super-secret-client-secret">>)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"auth-code-live">>)),
    %% M:F/A + location остаются
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"retrieve_token">>)),
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"42">>)).

redact_stack_arity_frame_and_non_list_passthrough_test() ->
    %% фрейм уже с арностью — не трогаем; не-список — fail-safe.
    Frame = [{'m', 'f', 3, [{'line',7}]}],
    ?assertEqual(Frame, zkeycloak_util:redact_stack(Frame)),
    ?assertEqual('undefined', zkeycloak_util:redact_stack('undefined')).

%%%=============================================================================
%%% jwt_sub_unverified/1 — токен не должен попадать в Reason (review-loop)
%%%=============================================================================

jwt_sub_unverified_malformed_token_not_in_reason_test() ->
    %% Жёсткий матч давал `{badmatch, <части токена>}' → Reason с ЖИВЫМ
    %% refresh уезжал в лог catch-блока `refresh_token/1'. Например, если
    %% realm начнёт выдавать JWE-refresh (5 частей).
    Jwe = <<"hdr.enckey.iv.ciphertext.tag-LIVE-SECRET">>,
    Reason = try zkeycloak_util:jwt_sub_unverified(Jwe), 'no_error'
             catch _C:R -> R
             end,
    ?assertEqual('malformed_jwt', Reason),
    ?assertEqual('nomatch', binary:match(?FMT(Reason), <<"LIVE-SECRET">>)).

jwt_sub_unverified_happy_path_test() ->
    %% Поведение на валидном JWT не изменилось.
    Payload = base64:encode(kz_json:encode(kz_json:from_list([{<<"sub">>, ?SUB}]))
                           ,#{'mode' => 'urlsafe', 'padding' => 'false'}),
    Token = <<"hdr.", Payload/binary, ".sig">>,
    ?assertEqual(?SUB, zkeycloak_util:jwt_sub_unverified(Token)).


refresh_expires_at_uses_trusted_refresh_exp_test() ->
    RefreshExp = 2000003600,
    Payload = base64:encode(
                kz_json:encode(
                  kz_json:from_list([{<<"sub">>, ?SUB}, {<<"exp">>, RefreshExp}])),
                #{'mode' => 'urlsafe', 'padding' => 'false'}),
    Token = <<"hdr.", Payload/binary, ".sig">>,
    ?assertEqual(RefreshExp, zkeycloak_util:refresh_expires_at(Token, 2000000000)),
    ?assertEqual(RefreshExp + 1,
                 zkeycloak_util:refresh_expires_at(Token, RefreshExp + 1)),
    ?assertEqual(2000000000,
                 zkeycloak_util:refresh_expires_at(<<"opaque-refresh">>, 2000000000)).
%%%=============================================================================
%%% redact_token_result/1 — fail-closed на неузнанной ok-форме (issue 15)
%%%=============================================================================

redact_token_result_unrecognized_ok_fails_closed_test() ->
    %% Бамп oidcc / смена record'а не должны молча вывалить живые токены.
    Live = {'ok', {'oidcc_token_v9', <<"live-access-token-payload">>
                  ,<<"live-refresh-token-payload">>}},
    R = zkeycloak_util:redact_token_result(Live),
    ?assertEqual('nomatch', binary:match(R, <<"live-access-token-payload">>)),
    ?assertEqual('nomatch', binary:match(R, <<"live-refresh-token-payload">>)).

redact_token_result_error_reason_masked_test() ->
    %% P1 (волна 2): `refresh_token/1' логирует ВЕСЬ Result через этот хелпер
    %% ДО case; на refresh-пути oidcc штатно отдаёт `{error,{http_error,_,Body}}'
    %% (invalid_grant у mobile) и `{error,{missing_claim,_,Claims}}' — оба
    %% раньше уходили в `~p'-catch-all СЫРЫМИ. Теперь чистятся через redact_reason.
    HttpErr = {'error', {'http_error', 400
                        ,#{<<"error_description">> => <<"invalid_grant LIVE-SECRET">>}}},
    RH = zkeycloak_util:redact_token_result(HttpErr),
    ?assertEqual('nomatch', binary:match(RH, <<"LIVE-SECRET">>)),
    %% статус-код диагностики сохранён
    ?assertNotEqual('nomatch', binary:match(RH, <<"400">>)),
    %% missing_claim с полной claims-map — ПДн (email/ФИО) не утекают
    ClaimsMap = maps:put(<<"nonce">>, <<"expected-nonce">>, userinfo()),
    RC = zkeycloak_util:redact_token_result({'error', {'missing_claim', <<"nonce">>, ClaimsMap}}),
    ?assertEqual('nomatch', binary:match(RC, ?EMAIL)),
    ?assertEqual('nomatch', binary:match(RC, <<"Иван"/utf8>>)),
    %% имя клейма — публичная схема — остаётся диагностикой
    ?assertNotEqual('nomatch', binary:match(RC, <<"nonce">>)).

%%%=============================================================================
%%% redact_reason/1 (P3 кросс-ревью 18.07) — значение, встроенное в Reason
%%%=============================================================================

redact_reason_masks_binary_in_badmatch_test() ->
    %% Асимметрия защиты: stack чистился, а `Reason' — нет. `error:{badmatch,V}'
    %% на декодированных claim-байтах / token-материале уводил `V' в лог сырым
    %% через catch-блоки normalize_oidcc/2 и refresh_token/1.
    Reason = {'badmatch', <<"eyJhbGci-decoded-claim-bytes-LIVE-SECRET">>},
    Fmt = ?FMT(zkeycloak_util:redact_reason(Reason)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"LIVE-SECRET">>)),
    %% тег краша сохранён — сбой остаётся диагностируемым
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"badmatch">>)).

redact_reason_masks_case_try_clause_and_badmap_test() ->
    %% case_clause / try_clause / badmap — тот же класс: значение встроено
    %% прямо в Reason (подтверждено в erl). Не-binary форму (map claim'ов)
    %% заменяем непрозрачным сентинелом.
    Claims = #{<<"email">> => ?EMAIL, <<"sub">> => ?SUB},
    ?assertEqual({'case_clause', '$redacted'}
                ,zkeycloak_util:redact_reason({'case_clause', Claims})),
    ?assertEqual({'try_clause', '$redacted'}
                ,zkeycloak_util:redact_reason({'try_clause', Claims})),
    ?assertEqual({'badmap', '$redacted'}
                ,zkeycloak_util:redact_reason({'badmap', Claims})),
    ?assertEqual('nomatch'
                ,binary:match(?FMT(zkeycloak_util:redact_reason({'case_clause', Claims}))
                             ,?EMAIL)).

redact_reason_masks_oidcc_missing_claim_map_test() ->
    %% P1 — ДОМИНИРУЮЩАЯ реальная утечка: oidcc в ШТАТНОМ error-протоколе
    %% отдаёт `{error, {missing_claim, Claim, Claims}}' с ПОЛНОЙ декодированной
    %% claims-map (рутинные nonce/aud/exp-провалы). 3-кортеж НЕ матчился 2-
    %% кортежными клозами и проходил сырым и в normalize_oidcc-лог, и в
    %% redact_reason-вызовы cb_zkeycloak_ext (:399 retrieve_userinfo).
    ClaimsMap = maps:put(<<"nonce">>, <<"expected-nonce">>, userinfo()),
    Err = {'error', {'missing_claim', <<"nonce">>, ClaimsMap}},
    R = zkeycloak_util:redact_reason(Err),
    Fmt = ?FMT(R),
    %% ПДн из claims-map (email/ФИО) в лог-строку не попадают
    ?assertEqual('nomatch', binary:match(Fmt, ?EMAIL)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"Иван"/utf8>>)),
    %% имя клейма — публичная схема — остаётся диагностикой
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"nonce">>)),
    ?assertMatch({'error', {'missing_claim', <<"nonce">>, '$redacted'}}, R).

redact_reason_masks_oidcc_none_alg_used_test() ->
    %% oidcc: токен подписан alg=none — reason несёт token-record / claims-map
    %% (2-кортеж) либо сырой JWT + JWS (3-кортеж).
    Claims = #{<<"email">> => ?EMAIL, <<"sub">> => ?SUB},
    ?assertEqual({'none_alg_used', '$redacted'}
                ,zkeycloak_util:redact_reason({'none_alg_used', Claims})),
    ?assertEqual('nomatch'
                ,binary:match(?FMT(zkeycloak_util:redact_reason({'none_alg_used', Claims}))
                             ,?EMAIL)),
    R3 = zkeycloak_util:redact_reason(
           {'none_alg_used', <<"raw.jwt.LIVE-SECRET-payload">>, {'jose_jws', #{}}}),
    ?assertEqual('nomatch', binary:match(?FMT(R3), <<"LIVE-SECRET">>)).

redact_reason_masks_oidcc_http_error_body_test() ->
    %% P2: `{http_error, Code, ErrBody}' — `ErrBody' (binary|map) это тело
    %% HTTP-ответа KC (token/userinfo/jwks), server-controlled и без схемы:
    %% реконфиг realm / апгрейд KC / прокси-страница могут положить туда что
    %% угодно. Режем по форме; статус-код оставляем диагностикой.
    Err = {'error', {'http_error', 401
                    ,#{<<"error_description">> => <<"user secret LIVE-SECRET leaked">>}}},
    R = zkeycloak_util:redact_reason(Err),
    Fmt = ?FMT(R),
    ?assertEqual('nomatch', binary:match(Fmt, <<"LIVE-SECRET">>)),
    %% статус-код на месте — диагностика жива
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"401">>)),
    ?assertMatch({'error', {'http_error', 401, '$redacted'}}, R).

redact_reason_masks_badrecord_value_test() ->
    %% P3 (волна 2): `error:{badrecord, V}' встраивает значение как badmatch
    %% (подтверждено в erl). В этом модуле V — декодированные claim-байты /
    %% token-материал.
    Reason = {'badrecord', <<"decoded-claim-bytes-LIVE-SECRET">>},
    Fmt = ?FMT(zkeycloak_util:redact_reason(Reason)),
    ?assertEqual('nomatch', binary:match(Fmt, <<"LIVE-SECRET">>)),
    %% тег краша сохранён — сбой диагностируется
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"badrecord">>)),
    %% не-binary значение (map claim'ов) → непрозрачный сентинел
    ?assertEqual({'badrecord', '$redacted'}
                ,zkeycloak_util:redact_reason({'badrecord', #{<<"email">> => ?EMAIL}})).

redact_reason_masks_use_dpop_nonce_body_test() ->
    %% P3 (волна 2): 3-й элемент `{use_dpop_nonce, Nonce, HttpBodyResult}' —
    %% то же тело HTTP-ответа KC, что в http_error (oidcc_http_util.erl:28/165).
    Err = {'error', {'use_dpop_nonce', <<"srv-nonce">>
                    ,#{<<"error_description">> => <<"body LIVE-SECRET">>}}},
    R = zkeycloak_util:redact_reason(Err),
    Fmt = ?FMT(R),
    ?assertEqual('nomatch', binary:match(Fmt, <<"LIVE-SECRET">>)),
    %% Nonce (anti-replay) остаётся диагностикой, тело — сентинел
    ?assertMatch({'error', {'use_dpop_nonce', <<"srv-nonce">>, '$redacted'}}, R).

redact_reason_masks_oidcc_invalid_property_token_test() ->
    %% P2 (волна 2): oidcc `{invalid_property, {Field, GivenValue}}' — для
    %% access_token/refresh_token/id_token `GivenValue' = сырой токен-материал
    %% (oidcc_token.erl:797/809/834). Имя поля — схема, значение — секрет.
    Err = {'error', {'invalid_property', {'refresh_token', <<"raw-live-refresh-LIVE-SECRET">>}}},
    R = zkeycloak_util:redact_reason(Err),
    Fmt = ?FMT(R),
    ?assertEqual('nomatch', binary:match(Fmt, <<"LIVE-SECRET">>)),
    %% имя поля осталось диагностикой
    ?assertNotEqual('nomatch', binary:match(Fmt, <<"refresh_token">>)),
    ?assertMatch({'error', {'invalid_property', {'refresh_token', _}}}, R),
    %% не-binary GivenValue (напр. scopes-список) → непрозрачный сентинел
    ?assertEqual({'invalid_property', {'scopes', '$redacted'}}
                ,zkeycloak_util:redact_reason({'invalid_property', {'scopes', [<<"a">>, <<"b">>]}})).

redact_reason_passthrough_atoms_and_tags_test() ->
    %% Диагностика без встроенного значения выживает как есть. `function_clause'
    %% — голый атом (аргументы только в стеке, а он редактируется отдельно),
    %% поэтому проходит без изменений (мёртвый `{function_clause,_}'-клоз убран).
    ?assertEqual('function_clause', zkeycloak_util:redact_reason('function_clause')),
    ?assertEqual('badarg', zkeycloak_util:redact_reason('badarg')),
    ?assertEqual({'missing_user_doc_on_refresh', {'error', 'not_found'}}
                ,zkeycloak_util:redact_reason(
                   {'missing_user_doc_on_refresh', {'error', 'not_found'}})).

redact_reason_recurses_into_class_reason_pair_test() ->
    %% Проброшенный catch-контракт `{Class, Reason}' — встроенное значение
    %% чистится и внутри пары (эта форма доезжает до лога cb_zkeycloak_ext).
    Reason = {'error', {'badmatch', <<"token-bytes-LIVE-SECRET">>}},
    R = zkeycloak_util:redact_reason(Reason),
    ?assertEqual('nomatch', binary:match(?FMT(R), <<"LIVE-SECRET">>)),
    ?assertMatch({'error', {'badmatch', _}}, R).

%%%=============================================================================
%%% backoff_opts/4 — самовосстановление oidcc discovery-воркера
%%%
%%% Инцидент 29.07.2026: воркер умирал на первой же ошибке дискавери
%%% (`backoff_type = stop' — дефолт библиотеки), `econnrefused' приходит
%%% мгновенно ⇒ лимит рестартов супервизора выгорал за доли секунды и дерево
%%% `zkeycloak' оставалось мёртвым до ручного `restart_app'.
%%%
%%% Валидацию проверяем отдельно от `discovery_worker_opts/0' (тот читает
%%% `kapps_config'): цена ошибки здесь — `function_clause' ВНУТРИ
%%% `handle_continue' воркера, т.е. та же смерть, только уже без связи с
%%% доступностью KC. Гарды, которые обязаны быть соблюдены:
%%% `oidcc_backoff:handle_retry/4' — `Min > 0, Max > 0, Max >= Min';
%%% `priv_handle_retry/4' — закрытый набор типов.
%%%=============================================================================

backoff_opts_valid_values_pass_through_test() ->
    Opts = zkeycloak_util:backoff_opts('exponential', 500, 60000, 7000),
    ?assertEqual('exponential', maps:get('backoff_type', Opts)),
    ?assertEqual(500, maps:get('backoff_min', Opts)),
    ?assertEqual(60000, maps:get('backoff_max', Opts)),
    ?assertEqual(#{'request_opts' => #{'timeout' => 7000}}
                ,maps:get('provider_configuration_opts', Opts)).

backoff_opts_defaults_are_retrying_test() ->
    %% Главное свойство: при дефолтах воркер РЕТРАИТ, а не умирает.
    Opts = zkeycloak_util:backoff_opts('random_exponential', 1000, 30000, 10000),
    ?assertNotEqual('stop', maps:get('backoff_type', Opts)),
    ?assert(lists:member(maps:get('backoff_type', Opts)
                        ,['exponential', 'random', 'random_exponential'])).

backoff_opts_rejects_stop_type_test() ->
    %% `stop' — валидное для библиотеки значение и её дефолт, но это ровно
    %% инцидент 29.07 в чистом виде: конфигом его взвести нельзя.
    Opts = zkeycloak_util:backoff_opts('stop', 1000, 30000, 10000),
    ?assertNotEqual('stop', maps:get('backoff_type', Opts)),
    ?assertEqual('random_exponential', maps:get('backoff_type', Opts)).

backoff_opts_rejects_unknown_type_test() ->
    %% Неизвестный атом дал бы `function_clause' в `priv_handle_retry/4'.
    ?assertEqual('random_exponential'
                ,maps:get('backoff_type'
                         ,zkeycloak_util:backoff_opts('linear', 1000, 30000, 10000))),
    ?assertEqual('random_exponential'
                ,maps:get('backoff_type'
                         ,zkeycloak_util:backoff_opts('undefined', 1000, 30000, 10000))).

backoff_opts_rejects_inverted_bounds_test() ->
    %% Ключевой случай: каждое значение по отдельности валидно (положительное
    %% целое), но пара нарушает гард `Max >= Min' — раздельная проверка
    %% пропустила бы её прямиком в `function_clause'.
    Opts = zkeycloak_util:backoff_opts('random_exponential', 30000, 1000, 10000),
    ?assertEqual(1000, maps:get('backoff_min', Opts)),
    ?assertEqual(30000, maps:get('backoff_max', Opts)).

backoff_opts_rejects_non_positive_bounds_test() ->
    Zero = zkeycloak_util:backoff_opts('random_exponential', 0, 30000, 10000),
    ?assertEqual(1000, maps:get('backoff_min', Zero)),
    ?assertEqual(30000, maps:get('backoff_max', Zero)),
    Negative = zkeycloak_util:backoff_opts('random_exponential', 1000, -1, 10000),
    ?assertEqual(1000, maps:get('backoff_min', Negative)),
    ?assertEqual(30000, maps:get('backoff_max', Negative)).

backoff_opts_rejects_non_integer_bounds_test() ->
    %% `kapps_config:get_integer/3' отдаёт `undefined', если в документе лежит
    %% не-число (руками правленный конфиг) — гард обязан это пережить.
    Opts = zkeycloak_util:backoff_opts('random_exponential', 'undefined', 'undefined', 10000),
    ?assertEqual(1000, maps:get('backoff_min', Opts)),
    ?assertEqual(30000, maps:get('backoff_max', Opts)).

backoff_opts_rejects_bad_request_timeout_test() ->
    %% `0'/отрицательный httpc трактует как «уже истёк», `infinity' вернул бы
    %% блокировку gen_server'а на неопределённый срок — обе формы отвергаем.
    Expected = #{'request_opts' => #{'timeout' => 10000}},
    ?assertEqual(Expected
                ,maps:get('provider_configuration_opts'
                         ,zkeycloak_util:backoff_opts('random_exponential', 1000, 30000, 0))),
    ?assertEqual(Expected
                ,maps:get('provider_configuration_opts'
                         ,zkeycloak_util:backoff_opts('random_exponential', 1000, 30000, 'infinity'))),
    ?assertEqual(Expected
                ,maps:get('provider_configuration_opts'
                         ,zkeycloak_util:backoff_opts('random_exponential', 1000, 30000, 'undefined'))).

%%%=============================================================================
%%% is_provider_unavailable/1 — «провайдер недоступен» против «плохие креды»
%%%=============================================================================

is_provider_unavailable_true_forms_test() ->
    %% штатный ответ oidcc_client_context: воркер мёртв либо ещё не загрузился
    ?assert(zkeycloak_util:is_provider_unavailable('provider_not_ready')),
    %% воркер ЖИВ, но занят HTTP-попыткой; oidcc зовёт его gen_server:call с 5 s
    ?assert(zkeycloak_util:is_provider_unavailable(
              {'exit', {'timeout', {'gen_server', 'call'
                                   ,['onbill_client', 'get_provider_configuration']}}})),
    %% воркер умер между whereis и gen_server:call
    ?assert(zkeycloak_util:is_provider_unavailable(
              {'exit', {'noproc', {'gen_server', 'call'
                                  ,['onbill_client', 'get_jwks']}}})).

is_provider_unavailable_true_for_dead_keycloak_test() ->
    %% ВТОРАЯ группа форм, которую легко упустить: обмен кода идёт не только
    %% через discovery-воркер — `oidcc_token'/`oidcc_userinfo' ходят в KC САМИ,
    %% и `oidcc_http_util:request/4' НИКОГДА не бросает исключение: транспортный
    %% сбой возвращается обычным `{error, Reason}' (oidcc_http_util.erl:128).
    %% Т.е. эти формы приезжают по НЕ-catch ветке `normalize_oidcc/2', сырыми,
    %% и без клозов ниже мапились бы в 401 «неверные креды» при попросту
    %% лежащем Keycloak — ровно та ложь, которую план и устраняет.
    ?assert(zkeycloak_util:is_provider_unavailable('timeout')),
    ?assert(zkeycloak_util:is_provider_unavailable('socket_closed_remotely')),
    %% ровно та форма, что видели в инциденте 29.07
    ?assert(zkeycloak_util:is_provider_unavailable(
              {'failed_connect', [{'to_address', {"keycloak.brterminal.ru", 443}}
                                 ,{'inet', ['inet'], 'econnrefused'}
                                 ]})),
    %% KC жив по TCP, но не обслуживает (прокси в окно рестарта KC)
    ?assert(zkeycloak_util:is_provider_unavailable({'http_error', 502, <<"Bad Gateway">>})),
    ?assert(zkeycloak_util:is_provider_unavailable({'http_error', 503, <<>>})),
    ?assert(zkeycloak_util:is_provider_unavailable({'http_error', 504, <<>>})).

is_provider_unavailable_false_for_credential_errors_test() ->
    %% Ежедневный invalid_grant (протухший/использованный code) — это НЕ
    %% недоступность провайдера, ответ должен остаться 401.
    ?assertNot(zkeycloak_util:is_provider_unavailable({'http_error', 400, <<"invalid_grant">>})),
    %% Порог 5xx обязан быть строгим: 4xx — это отказ АУТЕНТИФИКАЦИИ, и утащить
    %% его в 503 значило бы замаскировать реальный invalid_grant под инфра-сбой
    %% (зеркальная ошибка той, что чиним).
    ?assertNot(zkeycloak_util:is_provider_unavailable({'http_error', 401, <<>>})),
    ?assertNot(zkeycloak_util:is_provider_unavailable({'http_error', 403, <<>>})),
    ?assertNot(zkeycloak_util:is_provider_unavailable({'http_error', 499, <<>>})),
    ?assertNot(zkeycloak_util:is_provider_unavailable({'missing_claim', <<"nonce">>, '$redacted'})),
    ?assertNot(zkeycloak_util:is_provider_unavailable('token_expired')),
    %% `error'-класс (не `exit') — это краш нашего кода, не недоступность KC
    ?assertNot(zkeycloak_util:is_provider_unavailable({'error', 'badarg'})),
    ?assertNot(zkeycloak_util:is_provider_unavailable({'badmatch', <<"whatever">>})).

%%%=============================================================================
%%% validate_subject_enabled/1 — enabled-гейт сырого KC-токена (G-3 Ф1,
%%% план 2026-07-31-activity-audit-track.md)
%%%
%%% До гейта сырой KC access-токен валидировался МИМО user-doc'а:
%%% деактивированный (`enabled=false') сохранял доступ ко всем ручкам
%%% crossbar/zmcp до конца жизни KC-токена, и G-2-отзыв на него не
%%% действует. Семантика — как G-1 на выдаче: док без поля `enabled' =
%%% активный; всё нерезолвящееся/нечитаемое — отказ (fail-closed).
%%%
%%% Границу `kz_datamgr' мокаем (не наш модуль, cover не страдает);
%%% путь от claims до неё — чистый.
%%%=============================================================================

-define(GATE_SUB, <<"fedcba98-7654-3210-fedc-ba9876543210">>).
-define(GATE_OWNER_ID, <<"fedcba9876543210fedcba9876543210">>).
-define(GATE_ACCOUNT_ID, <<"0123456789abcdef0123456789abcdef">>).
-define(GATE_ACCOUNT_DB, <<"account%2F01%2F23%2F456789abcdef0123456789abcdef">>).
-define(GATE_CLAIMS, [{<<"sub">>, ?GATE_SUB}
                     ,{<<"account_id">>, ?GATE_ACCOUNT_ID}
                     ]).
-define(GATE_ENABLED_DOC, kz_json:from_list([{<<"enabled">>, 'true'}])).
-define(GATE_DISABLED_DOC, kz_json:from_list([{<<"enabled">>, 'false'}])).

subject_enabled_gate_test_() ->
    {'setup', fun gate_setup/0, fun gate_cleanup/1,
     fun(_) ->
             [{"enabled=true → onbill_access_provided; читаем ИМЕННО"
               " encoded-db аккаунта из claim'а (open_cache_doc — путь горячий)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(Db, Id) ->
                                           ?assertEqual(?GATE_ACCOUNT_DB, Db),
                                           ?assertEqual(?GATE_OWNER_ID, Id),
                                           {'ok', ?GATE_ENABLED_DOC}
                                   end),
                       ?assertEqual({'ok', 'onbill_access_provided'},
                                    zkeycloak_util:validate_subject_enabled(?GATE_CLAIMS))
               end}
             ,{"поля enabled нет → активный (дефолт kzd_users:enabled/1, как G-1)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> {'ok', kz_json:new()} end),
                       ?assertEqual({'ok', 'onbill_access_provided'},
                                    zkeycloak_util:validate_subject_enabled(?GATE_CLAIMS))
               end}
             ,{"enabled=false → user_disabled: живой KC-токен деактивированного"
               " больше не проходит валидацию",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> {'ok', ?GATE_DISABLED_DOC} end),
                       ?assertEqual({'error', 'user_disabled'},
                                    zkeycloak_util:validate_subject_enabled(?GATE_CLAIMS))
               end}
             ,{"дока нет → kc_user_doc_missing (JIT-создания на валидации нет)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> {'error', 'not_found'} end),
                       ?assertEqual({'error', 'kc_user_doc_missing'},
                                    zkeycloak_util:validate_subject_enabled(?GATE_CLAIMS))
               end}
             ,{"datastore-сбой → datastore_unreachable, НЕ пропуск (fail-closed;"
               " транспортно это тоже 401 — cb_token_auth схлопывает error в decline)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> {'error', 'timeout'} end),
                       ?assertEqual({'error', 'datastore_unreachable'},
                                    zkeycloak_util:validate_subject_enabled(?GATE_CLAIMS))
               end}
             ,{"sub не KIS-derived uuid → kc_subject_not_kis, до datastore не доходим",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> erlang:error('unexpected_datamgr_call') end),
                       Claims = [{<<"sub">>, <<"service-account-robot">>}
                                ,{<<"account_id">>, ?GATE_ACCOUNT_ID}
                                ],
                       ?assertEqual({'error', 'kc_subject_not_kis'},
                                    zkeycloak_util:validate_subject_enabled(Claims))
               end}
             ,{"sub отсутствует → kc_subject_not_kis (from_key от undefined)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> erlang:error('unexpected_datamgr_call') end),
                       ?assertEqual({'error', 'kc_subject_not_kis'},
                                    zkeycloak_util:validate_subject_enabled(
                                      [{<<"account_id">>, ?GATE_ACCOUNT_ID}]))
               end}
             ,{"нет НИ account_id, НИ default_account_id → kc_account_claim_invalid,"
               " до datastore не доходим",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> erlang:error('unexpected_datamgr_call') end),
                       ?assertEqual({'error', 'kc_account_claim_invalid'},
                                    zkeycloak_util:validate_subject_enabled(
                                      [{<<"sub">>, ?GATE_SUB}]))
               end}
             ,{"ноты account_id нет → фолбэк default_account_id"
               " (LDAP/Kerberos-субъект, как в cb_zkeycloak_ext:account_id_claim/1)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(Db, _Id) ->
                                           ?assertEqual(?GATE_ACCOUNT_DB, Db),
                                           {'ok', ?GATE_ENABLED_DOC}
                                   end),
                       Claims = [{<<"sub">>, ?GATE_SUB}
                                ,{<<"default_account_id">>, ?GATE_ACCOUNT_ID}
                                ],
                       ?assertEqual({'ok', 'onbill_access_provided'},
                                    zkeycloak_util:validate_subject_enabled(Claims))
               end}
             ,{"нота account_id = null → тоже фолбэк на default_account_id",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> {'ok', ?GATE_ENABLED_DOC} end),
                       Claims = [{<<"sub">>, ?GATE_SUB}
                                ,{<<"account_id">>, 'null'}
                                ,{<<"default_account_id">>, ?GATE_ACCOUNT_ID}
                                ],
                       ?assertEqual({'ok', 'onbill_access_provided'},
                                    zkeycloak_util:validate_subject_enabled(Claims))
               end}
             ,{"МАЛФОРМНАЯ нота account_id → отказ БЕЗ фолбэка даже при валидном"
               " default_account_id (семантика cb_zkeycloak_ext сохранена)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> erlang:error('unexpected_datamgr_call') end),
                       Claims = [{<<"sub">>, ?GATE_SUB}
                                ,{<<"account_id">>, <<"junk">>}
                                ,{<<"default_account_id">>, ?GATE_ACCOUNT_ID}
                                ],
                       ?assertEqual({'error', 'kc_account_claim_invalid'},
                                    zkeycloak_util:validate_subject_enabled(Claims))
               end}
             ,{"account_id 32 байта, но не hex → kc_account_claim_invalid"
               " (is_raw_account_id проверяет и алфавит)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_cache_doc',
                                   fun(_Db, _Id) -> erlang:error('unexpected_datamgr_call') end),
                       Claims = [{<<"sub">>, ?GATE_SUB}
                                ,{<<"account_id">>, <<"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz">>}
                                ],
                       ?assertEqual({'error', 'kc_account_claim_invalid'},
                                    zkeycloak_util:validate_subject_enabled(Claims))
               end}
             ]
     end}.

gate_setup() ->
    meck:new('kz_datamgr', ['no_link']),
    'ok'.

gate_cleanup(_) ->
    _ = (catch meck:unload('kz_datamgr')),
    'ok'.

%%%=============================================================================
%%% `auth_source/2' — источник личности пользователя
%%%
%%% Четыре ветки и их ПОРЯДОК: `kerberos' → `ldap' → `kis' → `unknown'.
%%% Порядок и есть предмет теста: Kerberos-субъект федерирован из того же AD,
%%% и `ldap_uuid' у него тоже стоит; КИС-нота `account_name' появляется и у
%%% LDAP-входа через форму `brt-unified'. Проверка «по одному маркеру за раз»
%%% прошла бы и на неправильном порядке веток — поэтому в каждом тесте маркеры
%%% КОНФЛИКТУЮТ, и утверждение звучит как «X сильнее Y».
%%%
%% Функция ЧИСТАЯ: вторым аргументом идёт уже посчитанный `auth_method/1',
%% поэтому четыре ветки проверяются без мока крипто-границы. Связка
%% «`auth_method' → `auth_source'» — ровно та, что собирает
%% `cb_zkeycloak_ext:provide_keycloak_token/9' — покрыта отдельно
%% (`auth_source_composition_test_'), уже с моком `kz_auth_jwt'.
%%%=============================================================================

-define(AS_LDAP_UUID, #{<<"ldap_uuid">> => <<"s-1-5-21-0001">>}).
-define(AS_ACCOUNT_NAME, #{<<"account_name">> => <<"rast">>}).

auth_source_test_() ->
    [{"kerberos ПЕРВЫМ: сильнее ldap_uuid И account_name разом",
      ?_assertEqual('kerberos', zkeycloak_util:auth_source(both_markers(), 'kerberos'))}
    ,{"kerberos не смотрит на userinfo вовсе — даже на пустую мапу",
      ?_assertEqual('kerberos', zkeycloak_util:auth_source(#{}, 'kerberos'))}
    ,{"ldap: маркеров kerberos нет → ldap_uuid сильнее account_name",
      ?_assertEqual('ldap', zkeycloak_util:auth_source(both_markers(), 'oidc'))}
    ,{"ldap: пустой ldap_uuid — это всё равно федерированный субъект"
      " (проверяем ПРИСУТСТВИЕ ключа, не годность значения)",
      ?_assertEqual('ldap', zkeycloak_util:auth_source(#{<<"ldap_uuid">> => <<>>}, 'oidc'))}
    ,{"kis: только нота account_name",
      ?_assertEqual('kis', zkeycloak_util:auth_source(?AS_ACCOUNT_NAME, 'oidc'))}
    ,{"unknown: ни одного маркера",
      ?_assertEqual('unknown', zkeycloak_util:auth_source(#{<<"sub">> => <<"x">>}, 'oidc'))}
    ,{"unknown: пустая userinfo",
      ?_assertEqual('unknown', zkeycloak_util:auth_source(#{}, 'oidc'))}
    ].

%% Оба не-керберосных маркера сразу — так тест ловит именно ПОРЯДОК веток.
both_markers() ->
    maps:merge(?AS_LDAP_UUID, ?AS_ACCOUNT_NAME).

%%%=============================================================================
%%% Связка `auth_method/1' → `auth_source/2' — как её собирает
%%% `cb_zkeycloak_ext:provide_keycloak_token/9'
%%%
%%% Смысл: определение «керберос» в приложении ОДНО, и живёт оно в
%%% `auth_method/1' — вместе с маркером `amr' (in-flow SPNEGO), которого нет
%%% в `acr'. SPNEGO-субъект федерирован из того же AD, `ldap_uuid' у него
%%% стоит, и без этой связки он получил бы `auth_method=kerberos' и
%%% `auth_source=ldap' в ОДНОМ токене.
%%%
%%% `kz_auth_jwt' — граница (проверка подписи), её мокаем: собирать живой
%%% подписанный JWT ради двух claim'ов незачем.
%%%=============================================================================

-define(AS_TOKEN, <<"access-token-stub">>).

auth_source_composition_test_() ->
    {'setup', fun auth_source_setup/0, fun auth_source_cleanup/1,
     fun(_) ->
             [{"acr=kerberos + ldap_uuid → kerberos",
               fun() ->
                       mock_claims([{<<"acr">>, <<"kerberos">>}]),
                       ?assertEqual('kerberos', auth_source_of_token(both_markers()))
               end}
             ,{"amr=[spnego] БЕЗ acr=kerberos + ldap_uuid → тоже kerberos:"
               " маркер amr виден только через auth_method/1",
               fun() ->
                       mock_claims([{<<"acr">>, <<"1">>}
                                   ,{<<"amr">>, [<<"spnego">>]}
                                   ]),
                       ?assertEqual('kerberos', auth_source_of_token(both_markers()))
               end}
             ,{"обычный OIDC-вход (маркеров нет) + ldap_uuid → ldap",
               fun() ->
                       mock_claims([{<<"acr">>, <<"1">>}]),
                       ?assertEqual('ldap', auth_source_of_token(both_markers()))
               end}
             ,{"битый/непроверяемый access-токен не роняет связку: auth_method/1"
               " отдаёт oidc, решает состав userinfo",
               fun() ->
                       meck:expect('kz_auth_jwt', 'decode',
                                   fun(_T, _V) -> {'error', 'verify_failed'} end),
                       ?assertEqual('kis', auth_source_of_token(?AS_ACCOUNT_NAME)),
                       ?assertEqual('unknown', auth_source_of_token(#{}))
               end}
             ]
     end}.

%% Ровно та композиция, что стоит в `provide_keycloak_token/9'.
auth_source_of_token(UserInfoMap) ->
    zkeycloak_util:auth_source(UserInfoMap, zkeycloak_util:auth_method(?AS_TOKEN)).

mock_claims(Claims) ->
    meck:expect('kz_auth_jwt', 'decode', fun(_T, _V) -> {'ok', [], Claims} end).

auth_source_setup() ->
    meck:new('kz_auth_jwt', ['no_link']),
    'ok'.

auth_source_cleanup(_) ->
    _ = (catch meck:unload('kz_auth_jwt')),
    'ok'.

%%%=============================================================================
%%% `auth_origin' в user-doc'е при автосоздании (`create_user/8')
%%%
%%% Проверяем ровно точку записи: что уходит в `kzd_users:validate/3'.
%%% Дальше по коду — `crossbar_doc'/`kz_datamgr', их не трогаем: мок валидации
%%% отдаёт `validation_errors' и обрывает путь до датастора.
%%% `passthrough' нужен из-за `?MK_USER' — он зовёт `kzd_users:type/0'.
%%%=============================================================================

-define(CU_ACCOUNT_ID, <<"0123456789abcdef0123456789abcdef">>).
-define(CU_OWNER_ID, <<"fedcba9876543210fedcba9876543210">>).

create_user_auth_origin_test_() ->
    {'setup', fun create_user_setup/0, fun create_user_cleanup/1,
     fun(_) ->
             [{"create_user/8 кладёт auth_origin в user-doc",
               fun() ->
                       _ = create_user([<<"ldap">>]),
                       ?assertEqual(<<"ldap">>, captured(<<"auth_origin">>))
               end}
             ,{"unknown пишется значением, а не пропуском поля: отличает"
               " «новый код, источник не определён» от дока до этой правки",
               fun() ->
                       _ = create_user([<<"unknown">>]),
                       ?assertEqual(<<"unknown">>, captured(<<"auth_origin">>))
               end}
             ,{"create_user/7 (старая арность, прод-beam во время хотлоада)"
               " поля не добавляет — старые доки остаются валидными",
               fun() ->
                       _ = create_user([]),
                       ?assertEqual('undefined', captured(<<"auth_origin">>))
               end}
             ,{"остальные поля дока не поехали от новой арности",
               fun() ->
                       _ = create_user([<<"kis">>]),
                       ?assertEqual(<<"ivan@example.com">>, captured(<<"username">>)),
                       ?assertEqual(<<"Ivan">>, captured(<<"first_name">>)),
                       ?assertEqual(<<"Petrov">>, captured(<<"last_name">>)),
                       ?assertEqual(<<"user">>, captured(<<"priv_level">>))
               end}
             ,{"create-путь НЕ выдаёт priv_level=admin (В-32, issue 51):"
               " автосоздание дока на ПЕРВОМ логине через KC делало админом"
               " любого вошедшего, мимо гварда cb_users",
               fun() ->
                       _ = create_user([<<"kis">>]),
                       %% двусторонне: `admin' исчез И поле осталось на месте —
                       %% пропажа ключа дала бы «админа нет» пустым нулём
                       ?assertEqual(<<"user">>, captured(<<"priv_level">>)),
                       ?assertNotEqual('undefined', captured(<<"username">>))
               end}
             ]
     end}.

%% `Extra' — либо `[]' (вызов старой арности), либо `[AuthOrigin]'.
create_user(Extra) ->
    apply('zkeycloak_util', 'create_user'
         ,[?CU_ACCOUNT_ID, ?CU_OWNER_ID, <<"Ivan">>, <<"Petrov">>
          ,<<"ivan@example.com">>, 'undefined', <<"pwd-stub">>
          ] ++ Extra).

%% Последний `UDoc', доехавший до валидации. В истории есть и `type/0'
%% (его зовёт `?MK_USER'), поэтому отбираем именно клаузы `validate/3'.
captured(Key) ->
    UDocs = [UDoc
             || {_Pid, {'kzd_users', 'validate', [_AccountId, _Id, UDoc]}, _Res}
                    <- meck:history('kzd_users')
            ],
    kz_json:get_value(Key, lists:last(UDocs)).

create_user_setup() ->
    meck:new('kzd_users', ['no_link', 'passthrough']),
    meck:expect('kzd_users', 'validate', fun(_A, _I, _UDoc) -> {'validation_errors', []} end),
    'ok'.

create_user_cleanup(_) ->
    _ = (catch meck:unload('kzd_users')),
    'ok'.
%%%=============================================================================
%%% OIDC logout claim validation. Signature verification is covered by the
%%% production wrappers; this pure seam pins identity and event constraints.
%%%=============================================================================

-define(LOGOUT_ISSUER, <<"https://keycloak.example/realms/BRT">>).
-define(LOGOUT_CLIENT, <<"onbill_client">>).
-define(LOGOUT_SID, <<"kc-session-1">>).
-define(LOGOUT_SUB, <<"01234567-89ab-cdef-0123-456789abcdef">>).
-define(LOGOUT_ACCOUNT, <<"fedcba9876543210fedcba9876543210">>).
-define(LOGOUT_EVENT,
        <<"http://schemas.openid.net/event/backchannel-logout">>).

logout_claim_validation_test_() ->
    Now = 2000000000,
    IdClaims = #{<<"iss">> => ?LOGOUT_ISSUER
                ,<<"aud">> => ?LOGOUT_CLIENT
                ,<<"sub">> => ?LOGOUT_SUB
                ,<<"sid">> => ?LOGOUT_SID
                ,<<"account_id">> => ?LOGOUT_ACCOUNT
                },
    EventClaims = #{<<"iss">> => ?LOGOUT_ISSUER
                   ,<<"aud">> => [?LOGOUT_CLIENT]
                   ,<<"sid">> => ?LOGOUT_SID
                   ,<<"jti">> => <<"logout-event-1">>
                   ,<<"iat">> => Now - 1
                   ,<<"exp">> => Now + 60
                   ,<<"events">> => #{?LOGOUT_EVENT => #{}}
                   },
    [?_assertEqual(
        {'ok', #{'sid' => ?LOGOUT_SID
                ,'sub' => ?LOGOUT_SUB
                ,'account_id' => ?LOGOUT_ACCOUNT}},
        zkeycloak_util:validate_logout_id_claims(
          IdClaims, ?LOGOUT_ISSUER, ?LOGOUT_CLIENT))
    ,?_assertEqual(
        {'error', 'logout_token_bad_audience'},
        zkeycloak_util:validate_logout_id_claims(
          IdClaims#{<<"aud">> => <<"foreign-client">>},
          ?LOGOUT_ISSUER, ?LOGOUT_CLIENT))
    ,?_assertEqual(
        {'ok', #{'sid' => ?LOGOUT_SID
                ,'jti' => <<"logout-event-1">>
                ,'expires_at' => Now + 60}},
        zkeycloak_util:validate_backchannel_claims(
          EventClaims, ?LOGOUT_ISSUER, ?LOGOUT_CLIENT, Now))
    ,?_assertEqual(
        {'error', 'logout_event_missing'},
        zkeycloak_util:validate_backchannel_claims(
          EventClaims#{<<"events">> => #{}},
          ?LOGOUT_ISSUER, ?LOGOUT_CLIENT, Now))
    ,?_assertEqual(
        {'error', 'logout_event_nonce_forbidden'},
        zkeycloak_util:validate_backchannel_claims(
          EventClaims#{<<"nonce">> => <<"must-not-exist">>},
          ?LOGOUT_ISSUER, ?LOGOUT_CLIENT, Now))
    ,?_assertEqual(
        {'error', 'logout_event_expired'},
        zkeycloak_util:validate_backchannel_claims(
          EventClaims#{<<"exp">> => Now},
          ?LOGOUT_ISSUER, ?LOGOUT_CLIENT, Now))
    ,?_assertEqual(
        {'error', 'logout_token_bad_issuer'},
        zkeycloak_util:validate_backchannel_claims(
          EventClaims#{<<"iss">> => <<"https://foreign.example/realms/BRT">>},
          ?LOGOUT_ISSUER, ?LOGOUT_CLIENT, Now))
    ].

%%%=============================================================================
%%% F3A-P3-2 (кросс-ревью 22.08): issuer сверяется по КАНОНИЧЕСКОЙ форме
%%% (RFC 3986 §6.2.2–6.2.3), а не побайтово.
%%%
%%% Класс расхождений «та же сущность, другая запись» — хвостовой слэш, явный
%%% дефолтный порт, регистр схемы/хоста — клиентский гард zfield
%%% (`AuthRepositoryImpl._isOurIssuer', Uri-нормализация Dart) прощает, а
%%% бэкенд до фикса ломался ровно на нём: старт logout отдавал 401, а
%%% backchannel-токен отвергался с `logout_token_bad_issuer', из-за чего
%%% binding никогда не доходил до `op_revoked' и клиент получал вечный 409.
%%%
%%% Канонизация НЕ смеет сближать РАЗНЫЕ сущности: путь регистро-зависим
%%% (realm `BRT' =/= `brt'), недефолтный порт значим, схема значима — поэтому
%%% ниже к каждому «эквивалентному» написанию идёт «чужое» контрольное.
%%%=============================================================================

-define(KC_CANONICAL, <<"https://keycloak.brterminal.ru/realms/BRT">>).

%% Написания, обозначающие ТОТ ЖЕ issuer, что и ?KC_CANONICAL.
kc_issuer_equivalents() ->
    [<<"https://keycloak.brterminal.ru/realms/BRT/">>          %% хвостовой слэш
    ,<<"https://Keycloak.brterminal.ru/realms/BRT">>           %% регистр хоста
    ,<<"https://Keycloak.brterminal.ru/realms/BRT/">>          %% регистр + слэш
    ,<<"https://keycloak.brterminal.ru:443/realms/BRT">>       %% явный дефолтный порт
    ,<<"HTTPS://keycloak.brterminal.ru/realms/BRT">>           %% регистр схемы
    ,<<"https://keycloak.brterminal.ru/realms/BRT//">>         %% двойной хвостовой слэш
    ].

%% Написания ДРУГОГО issuer'а: гард `foreign_issuer' обязан их ловить и после
%% канонизации.
kc_issuer_foreigners() ->
    [<<"https://keycloak.brterminal.ru/realms/OTHER">>         %% другой realm
    ,<<"https://keycloak.brterminal.ru/realms/brt">>           %% путь регистро-ЗАВИСИМ
    ,<<"https://foreign.example/realms/BRT">>                  %% другой хост
    ,<<"https://keycloak.brterminal.ru:8443/realms/BRT">>      %% НЕдефолтный порт
    ,<<"http://keycloak.brterminal.ru/realms/BRT">>            %% другая схема
    ,<<"https://keycloak.brterminal.ru/realms/BRT/extra">>     %% лишний сегмент пути
    ].

logout_issuer_canonical_forms_test_() ->
    Now = 2000000000,
    IdClaims = #{<<"iss">> => ?KC_CANONICAL
                ,<<"aud">> => ?LOGOUT_CLIENT
                ,<<"sub">> => ?LOGOUT_SUB
                ,<<"sid">> => ?LOGOUT_SID
                ,<<"account_id">> => ?LOGOUT_ACCOUNT
                },
    EventClaims = #{<<"iss">> => ?KC_CANONICAL
                   ,<<"aud">> => [?LOGOUT_CLIENT]
                   ,<<"sid">> => ?LOGOUT_SID
                   ,<<"jti">> => <<"logout-event-canon">>
                   ,<<"iat">> => Now - 1
                   ,<<"exp">> => Now + 60
                   ,<<"events">> => #{?LOGOUT_EVENT => #{}}
                   },
    IdOk = {'ok', #{'sid' => ?LOGOUT_SID
                   ,'sub' => ?LOGOUT_SUB
                   ,'account_id' => ?LOGOUT_ACCOUNT}},
    EventOk = {'ok', #{'sid' => ?LOGOUT_SID
                      ,'jti' => <<"logout-event-canon">>
                      ,'expires_at' => Now + 60}},
    BadIssuer = {'error', 'logout_token_bad_issuer'},
    %% позитивный контроль: канонический конфиг работал и до фикса — он не
    %% должен перестать работать от канонизации.
    Positive =
        [{"канонический конфиг — старт logout",
          ?_assertEqual(IdOk, zkeycloak_util:validate_logout_id_claims(
                                IdClaims, ?KC_CANONICAL, ?LOGOUT_CLIENT))}
        ,{"канонический конфиг — backchannel",
          ?_assertEqual(EventOk, zkeycloak_util:validate_backchannel_claims(
                                   EventClaims, ?KC_CANONICAL, ?LOGOUT_CLIENT, Now))}
        ],
    %% фальсификатор: на до-фиксовом коде каждая строка красная
    %% (`logout_token_bad_issuer' вместо `ok').
    Equivalent =
        [[{"эквивалентный конфиг — старт logout: " ++ binary_to_list(Cfg),
           ?_assertEqual(IdOk, zkeycloak_util:validate_logout_id_claims(
                                 IdClaims, Cfg, ?LOGOUT_CLIENT))}
         ,{"эквивалентный конфиг — backchannel: " ++ binary_to_list(Cfg),
           ?_assertEqual(EventOk, zkeycloak_util:validate_backchannel_claims(
                                    EventClaims, Cfg, ?LOGOUT_CLIENT, Now))}
         ]
         || Cfg <- kc_issuer_equivalents()
        ],
    %% негативный контроль: гард foreign issuer жив.
    Foreign =
        [[{"чужой issuer отвергнут — старт logout: " ++ binary_to_list(Cfg),
           ?_assertEqual(BadIssuer, zkeycloak_util:validate_logout_id_claims(
                                      IdClaims, Cfg, ?LOGOUT_CLIENT))}
         ,{"чужой issuer отвергнут — backchannel: " ++ binary_to_list(Cfg),
           ?_assertEqual(BadIssuer, zkeycloak_util:validate_backchannel_claims(
                                      EventClaims, Cfg, ?LOGOUT_CLIENT, Now))}
         ]
         || Cfg <- kc_issuer_foreigners()
        ],
    %% отсутствующий `iss' — отказ, а не совпадение с `undefined'.
    Missing =
        [{"токен без iss отвергнут",
          ?_assertEqual(BadIssuer, zkeycloak_util:validate_logout_id_claims(
                                     maps:remove(<<"iss">>, IdClaims)
                                    ,?KC_CANONICAL, ?LOGOUT_CLIENT))}
        ],
    lists:flatten([Positive, Equivalent, Foreign, Missing]).

verify_backchannel_uses_unix_time_test_() ->
    {'setup',
     fun() ->
             _ = (catch meck:unload('kz_auth_jwt')),
             meck:new('kz_auth_jwt', ['no_link']),
             'ok'
     end,
     fun(_) -> _ = (catch meck:unload('kz_auth_jwt')), 'ok' end,
     fun(_) ->
             Now = erlang:system_time('seconds'),
             Issuer = kapps_config:get_ne_binary(
                        <<"zkeycloak">>, <<"issuer">>, <<"issuer">>),
             ClientId = kapps_config:get_ne_binary(
                          <<"zkeycloak">>, <<"client_id">>, <<"client_id">>),
             Claims = [{<<"iss">>, Issuer}
                      ,{<<"aud">>, ClientId}
                      ,{<<"sid">>, ?LOGOUT_SID}
                      ,{<<"jti">>, <<"logout-event-current-time">>}
                      ,{<<"iat">>, Now - 1}
                      ,{<<"exp">>, Now + 60}
                      ,{<<"events">>, #{?LOGOUT_EVENT => #{}}}
                      ],
             meck:expect('kz_auth_jwt', 'decode',
                         fun(_Token, 'true') -> {'ok', [], Claims} end),
             ?_assertMatch(
                {'ok', #{'sid' := ?LOGOUT_SID,
                         'jti' := <<"logout-event-current-time">>}},
                zkeycloak_util:verify_backchannel_logout_token(
                  <<"signed-logout-token">>))
     end}.

logout_sensitive_body_keys_test() ->
    Body = kz_json:from_list([{<<"logout_token">>, <<"signed-secret">>}
                            ,{<<"verifier">>, <<"private-secret">>}
                            ,{<<"state">>, <<"correlation">>}]),
    Redacted = zkeycloak_util:redact_req_data(Body),
    ?assertNotEqual(<<"signed-secret">>, kz_json:get_value(<<"logout_token">>, Redacted)),
    ?assertNotEqual(<<"private-secret">>, kz_json:get_value(<<"verifier">>, Redacted)).
