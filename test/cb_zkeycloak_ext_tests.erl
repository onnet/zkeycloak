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
%% Аккаунт из hardcoded-маппера скоупа (`default_account_id') — заведомо ДРУГОЙ,
%% иначе тест на приоритет ноты был бы вакуумным.
-define(DEFAULT_ACCOUNT_ID, <<"00112233445566778899aabbccddeeff">>).

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

account_gate_rejects_32byte_non_hex_test() ->
    %% P3 (волна 2): ровно 32 байта, но не hex. `?MATCH_ACCOUNT_RAW' матчит
    %% любые 32 байта → раньше проходил гейт, `format_account_id/2' давал путь
    %% к несуществующей БД → downstream 503 вместо чистого 401. hex-гейт
    %% отклоняет до БД.
    UserInfo = #{<<"account_id">> => binary:copy(<<"z">>, 32)},
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login', ?OWNER_ID),
    assert_401(Ctx).

account_gate_rejects_malformed_note_even_with_valid_default_test() ->
    %% Дефект R1, шаг 3.1: фолбэка на `default_account_id' при БИТОЙ ноте нет.
    %% Молча увести пользователя с малформной нотой в общий дефолтный аккаунт
    %% хуже, чем отдать чистый 401 — 401 виден, чужой аккаунт нет.
    UserInfo = #{<<"account_id">> => <<"not-a-valid-account-id">>
                ,<<"default_account_id">> => ?DEFAULT_ACCOUNT_ID
                },
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login', ?OWNER_ID),
    assert_401(Ctx).

%%%=============================================================================
%%% Приоритет claim'ов `account_id' vs `default_account_id' (дефект R1, шаг 3.1)
%%%
%%% В realm'е на claim `account_id' претендовали два маппера (hardcoded-константа
%%% скоупа и session-note клиента), а порядок их применения в Keycloak при равном
%%% приоритете — хеш-порядок UUID'ов мапперов, т.е. может перевернуться молча.
%%% Фикс разводит claim'ы, и приоритет задаётся здесь, кодом: нота сильнее
%%% константы. Эти тесты проверяют РЕЗУЛЬТАТ резолва — какой account_id уехал в
%%% auth-doc, — а не только код ответа.
%%%=============================================================================

account_claim_precedence_test_() ->
    {setup, fun setup_echo_doc/0, fun cleanup_boundaries/1,
     fun(_) ->
             [{"ноты нет → берём default_account_id (LDAP/Kerberos-субъект)",
               fun() ->
                       UserInfo = #{<<"default_account_id">> => ?DEFAULT_ACCOUNT_ID},
                       ?assertEqual(?DEFAULT_ACCOUNT_ID, resolved_account_id(UserInfo))
               end}
             ,{"нота сильнее константы (вход аккаунтом портала)",
               fun() ->
                       UserInfo = #{<<"account_id">> => ?ACCOUNT_ID
                                   ,<<"default_account_id">> => ?DEFAULT_ACCOUNT_ID
                                   },
                       ?assertEqual(?ACCOUNT_ID, resolved_account_id(UserInfo))
               end}
             ,{"JSON null в ноте = ноты нет → фолбэк",
               fun() ->
                       UserInfo = #{<<"account_id">> => 'null'
                                   ,<<"default_account_id">> => ?DEFAULT_ACCOUNT_ID
                                   },
                       ?assertEqual(?DEFAULT_ACCOUNT_ID, resolved_account_id(UserInfo))
               end}
             ,{"нота без константы работает как раньше (до правки realm'а)",
               fun() ->
                       UserInfo = #{<<"account_id">> => ?ACCOUNT_ID},
                       ?assertEqual(?ACCOUNT_ID, resolved_account_id(UserInfo))
               end}
             ]
     end}.

%% @doc Прогнать `provide_keycloak_token/7' и вернуть `account_id', который
%% уехал в auth-doc. Через resp_data — его эхом отдаёт мок `crossbar_auth'.
resolved_account_id(UserInfo) ->
    Ctx = cb_zkeycloak_ext:provide_keycloak_token(
            cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login', ?OWNER_ID),
    ?assertEqual('success', cb_context:resp_status(Ctx)),
    kz_json:get_value(<<"account_id">>, cb_context:resp_data(Ctx)).

setup_echo_doc() ->
    'ok' = setup_boundaries(),
    %% В отличие от `setup_boundaries/0' мок возвращает САМ auth-doc — иначе
    %% результат резолва claim'а из теста не виден вообще.
    meck:expect('crossbar_auth', 'create_auth_token',
                fun(Ctx, _AuthModule) ->
                        cb_context:set_resp_status(
                          cb_context:set_resp_data(Ctx, cb_context:doc(Ctx)), 'success')
                end),
    'ok'.

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
%%% enabled-гейт user-doc'а (G-1, решение Р1 гриллинга 30.07)
%%%
%%% Деактивированный пользователь (`enabled=false' — MDM-шов либо cb_users)
%%% не должен получать Kazoo-токен ни на login-, ни на refresh-ветке, пока
%%% его учётка жива в KC/LDAP. Док без поля `enabled' = активный (дефолт
%%% `kzd_users:enabled/1' — та же семантика, что у `cb_user_auth').
%%%=============================================================================

-define(DISABLED_DOC, kz_json:from_list([{<<"enabled">>, 'false'}])).
-define(ENABLED_DOC, kz_json:from_list([{<<"enabled">>, 'true'}])).

enabled_gate_test_() ->
    {'setup', fun setup_boundaries/0, fun cleanup_boundaries/1,
     fun(_) ->
             [{"login: enabled=false → 401 через полный гейт-хвост",
               fun() ->
                       meck:expect('kz_datamgr', 'open_doc',
                                   fun(_Db, _Id) -> {'ok', ?DISABLED_DOC} end),
                       UserInfo = #{<<"sub">> => ?SUB_UUID
                                   ,<<"account_id">> => ?ACCOUNT_ID
                                   },
                       Ctx = cb_zkeycloak_ext:provide_keycloak_token(
                               cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'login'),
                       assert_401(Ctx)
               end}
             ,{"refresh: enabled=false → 401 через полный гейт-хвост",
               fun() ->
                       meck:expect('kz_datamgr', 'open_doc',
                                   fun(_Db, _Id) -> {'ok', ?DISABLED_DOC} end),
                       UserInfo = #{<<"sub">> => ?SUB_UUID
                                   ,<<"account_id">> => ?ACCOUNT_ID
                                   },
                       Ctx = cb_zkeycloak_ext:provide_keycloak_token(
                               cb_context:new(), ?TA, ?TID, ?TR, UserInfo, 'refresh'),
                       assert_401(Ctx)
               end}
             ,{"check_user_doc: enabled=true → ok (обе ветки)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_doc',
                                   fun(_Db, _Id) -> {'ok', ?ENABLED_DOC} end),
                       ?assertEqual('ok', check_user_doc('login')),
                       ?assertEqual('ok', check_user_doc('refresh'))
               end}
             ,{"check_user_doc: поля enabled нет → ok (дефолт активный)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_doc',
                                   fun(_Db, _Id) -> {'ok', kz_json:new()} end),
                       ?assertEqual('ok', check_user_doc('login')),
                       ?assertEqual('ok', check_user_doc('refresh'))
               end}
             ,{"check_user_doc: enabled=false → тегированный user_disabled",
               fun() ->
                       meck:expect('kz_datamgr', 'open_doc',
                                   fun(_Db, _Id) -> {'ok', ?DISABLED_DOC} end),
                       ?assertEqual({'error', 'user_disabled'}, check_user_doc('login')),
                       ?assertEqual({'error', 'user_disabled'}, check_user_doc('refresh'))
               end}
             ,{"refresh: дока нет → missing_user_doc_on_refresh (контракт сохранён)",
               fun() ->
                       meck:expect('kz_datamgr', 'open_doc',
                                   fun(_Db, _Id) -> {'error', 'not_found'} end),
                       ?assertMatch({'error', {'missing_user_doc_on_refresh', _}},
                                    check_user_doc('refresh'))
               end}
             ]
     end}.

check_user_doc(Mode) ->
    cb_zkeycloak_ext:check_user_doc(Mode, <<"account%2Ffe%2Fdc%2Fba">>,
                                    ?ACCOUNT_ID, ?OWNER_ID, #{}).

%%%=============================================================================
%%% logout `id_token_hint' — транспорт POST-тело vs GET-query (issue 02 волна 2)
%%%
%%% GET клал сырой id_token (ПДн) в query-string → он оседал в access-логах
%%% nginx/бэкенда. POST переносит hint в JSON-тело. GET сохранён на переходный
%%% период. `logout_id_token_hint/1' — точка выбора источника (открыта для
%%% теста через `-ifdef(TEST). -export'); downstream (`logout_url/1' → KC
%%% end_session) для обеих веток идентичен и здесь не дублируется.
%%%=============================================================================

%% Зеркалят `kazoo_web.hrl' — чтобы не тащить include-цепочку crossbar в тест.
-define(HTTP_GET, <<"GET">>).
-define(HTTP_POST, <<"POST">>).
-define(HINT, <<"eyJhbGciOiJSUzI1NiJ9.dummy-id-token-hint.sig">>).

logout_hint_from_post_body_test() ->
    %% POST — целевой транспорт: hint из тела (`req_data', inner data-конверт).
    Ctx0 = cb_context:set_req_verb(cb_context:new(), ?HTTP_POST),
    Ctx = cb_context:set_req_data(Ctx0, kz_json:from_list([{<<"id_token_hint">>, ?HINT}])),
    ?assertEqual(?HINT, cb_zkeycloak_ext:logout_id_token_hint(Ctx)).

logout_hint_from_get_query_test() ->
    %% GET (legacy) — hint из query-string; поведение сохранено дословно.
    Ctx0 = cb_context:set_req_verb(cb_context:new(), ?HTTP_GET),
    Ctx = cb_context:set_query_string(Ctx0, kz_json:from_list([{<<"id_token_hint">>, ?HINT}])),
    ?assertEqual(?HINT, cb_zkeycloak_ext:logout_id_token_hint(Ctx)).

logout_post_ignores_query_hint_test() ->
    %% Подтверждение смены транспорта: POST-ветка НЕ читает QS, поэтому hint,
    %% просочившийся в query при POST, ею не подхватывается (тело пустое → undefined).
    Ctx0 = cb_context:set_req_verb(cb_context:new(), ?HTTP_POST),
    Ctx = cb_context:set_query_string(Ctx0, kz_json:from_list([{<<"id_token_hint">>, ?HINT}])),
    ?assertEqual('undefined', cb_zkeycloak_ext:logout_id_token_hint(Ctx)).

logout_missing_hint_undefined_test() ->
    %% Hint'а нет — обе ветки дают `undefined' (KC confirmation-page путь;
    %% канон Option A: end_session всё равно уходит, но без silent-logout).
    CtxPost = cb_context:set_req_verb(cb_context:new(), ?HTTP_POST),
    ?assertEqual('undefined', cb_zkeycloak_ext:logout_id_token_hint(CtxPost)),
    CtxGet = cb_context:set_req_verb(cb_context:new(), ?HTTP_GET),
    ?assertEqual('undefined', cb_zkeycloak_ext:logout_id_token_hint(CtxGet)).

%%%=============================================================================
%%% helpers
%%%=============================================================================

-spec assert_401(cb_context:context()) -> 'ok'.
assert_401(Ctx) ->
    ?assertEqual(401, cb_context:resp_error_code(Ctx)),
    ?assertEqual('error', cb_context:resp_status(Ctx)),
    ?assertEqual(<<"invalid_credentials">>, cb_context:resp_error_msg(Ctx)),
    'ok'.
