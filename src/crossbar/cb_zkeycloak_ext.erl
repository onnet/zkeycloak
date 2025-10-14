-module(cb_zkeycloak_ext).

-export([init/0
        ,allowed_methods/0, allowed_methods/1
        ,resource_exists/0, resource_exists/1
        ,authorize/1, authorize/2
        ,authenticate/1, authenticate/2
        ,validate/1,validate/2
        ]).

-export([zkeycloak_ext_post/1
        ]).

-include("/opt/kazoo/applications/crossbar/src/crossbar.hrl").

%%-include("zbrt_defs.hrl").
%%-define(HEADERS, [{"content-type", "application/x-www-form-urlencoded"}]).
-define(HEADERS, [{"content-type", "application/json"}]).

-define(AUTH_LINK, <<"auth_link">>).
-define(AUTH_CALLBACK, <<"auth_callback">>).
-define(ZKEYCLOAK, <<"zkeycloak_ext">>).

-spec init() -> ok.
init() ->
    _ = crossbar_bindings:bind(<<"*.authenticate.zkeycloak_ext">>, ?MODULE, 'authenticate'),
    _ = crossbar_bindings:bind(<<"*.authorize.zkeycloak_ext">>, ?MODULE, 'authorize'),
    _ = crossbar_bindings:bind(<<"*.allowed_methods.zkeycloak_ext">>, ?MODULE, 'allowed_methods'),
    _ = crossbar_bindings:bind(<<"*.resource_exists.zkeycloak_ext">>, ?MODULE, 'resource_exists'),
    _ = crossbar_bindings:bind(<<"*.validate.zkeycloak_ext">>, ?MODULE, 'validate'),
    %%    _ = crossbar_bindings:bind(<<"*.execute.put.ext">>, ?MODULE, 'put'),
    ok.

-spec allowed_methods() -> http_methods().
allowed_methods() -> [?HTTP_POST, ?HTTP_GET].
-spec allowed_methods(path_token()) -> http_methods().
allowed_methods(?AUTH_LINK) -> [?HTTP_GET];
allowed_methods(?AUTH_CALLBACK) -> [?HTTP_GET];
allowed_methods(?ZKEYCLOAK) -> [?HTTP_POST, ?HTTP_GET].

-spec resource_exists() -> boolean().
resource_exists() -> 'true'.
-spec resource_exists(path_tokens()) -> boolean().
resource_exists(?AUTH_LINK) -> 'true';
resource_exists(?AUTH_CALLBACK) -> 'true';
resource_exists(?ZKEYCLOAK) -> 'true'.

-spec authorize(cb_context:context()) -> boolean() | {'stop', cb_context:context()}.
authorize(Context) ->
    lager:info("authorisze/1  req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("authorisze/1  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/1  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("authorisze/1  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/1  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/1  req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).

-spec authorize(cb_context:context(), kz_term:ne_binary()) -> boolean().
authorize(Context, Token1) ->
    lager:info("authorisze/2 Token1: ~p",[Token1]),
    lager:info("authorisze/2 req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("authorisze/2 req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("authorisze/2 req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("authorisze/2 req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("authorisze/2 req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("authorisze/2 req_id: ~p",[cb_context:req_id(Context)]),
    authorize_nouns(Context, cb_context:req_nouns(Context), cb_context:req_verb(Context)).

authorize_nouns(_Context, [{<<"zkeycloak_ext">>, []}], Method) when Method =:= ?HTTP_POST ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing zkeycloak_ext"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_link">>]}], Method) when Method =:= ?HTTP_GET ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing zkeycloak_ext"),
    'true';
authorize_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_callback">>]}], Method) when Method =:= ?HTTP_GET ->
    lager:info("authorize_nouns_zkeycloak_ext authorizing zkeycloak_ext"),
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

authenticate_nouns(Context, [{<<"zkeycloak_ext">>, []}]) ->
    lager:info("authenticate_nouns/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_link">>]}]) ->
    'true';
authenticate_nouns(_Context, [{<<"zkeycloak_ext">>, [<<"auth_callback">>]}]) ->
    'true';
authenticate_nouns(_Context, _Nouns) ->
    lager:info("authenticate_nouns/1 _Nouns: ~p",[_Nouns]),
    'false'.

-spec validate(cb_context:context()) -> cb_context:context().
validate(Context) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).

-spec validate(cb_context:context(), path_token()) -> cb_context:context().
validate(Context, ?AUTH_LINK) ->
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    AuthUrl = zkeycloak_util:auth_url(),
    JObj = kz_json:set_value(<<"auth_url">>, AuthUrl, kz_json:new()),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, JObj), 'success');
validate(Context, ?AUTH_CALLBACK) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    lager:info("validate_ext/2  cb_context:query_string: ~p",[cb_context:query_string(Context)]),
    QS = cb_context:query_string(Context),
    Code = kz_json:get_ne_binary_value(<<"code">>, QS),
    case zkeycloak_util:retrieve_token(Code) of
        {oidcc_token
            ,{oidcc_token_id, TokenId, ClaimsMap}
            ,{oidcc_token_access, TokenAccess, _Timeout, _Type}
            ,{oidcc_token_refresh, TokenRefresh}
            ,_Scope
        } ->
            lager:info("validate_ext/2  TokenId: ~p",[TokenId]),
            lager:info("validate_ext/2  TokenAccess: ~p",[TokenAccess]),
            lager:info("validate_ext/2  TokenRefresh: ~p",[TokenRefresh]),
            ClaimsProps = kz_json:to_proplist(kz_json:from_map(ClaimsMap)),
            %%OwnerId = props:get_value(<<"owner_id">>, ClaimsProps),
            AccountId = props:get_value(<<"account_id">>, ClaimsProps),
            OwnerId = zbrt_util:from_key(props:get_value(<<"sub">>, ClaimsProps)),
            DbName = kzs_util:format_account_id(AccountId,'encoded'),
            case kz_datamgr:open_doc(DbName, OwnerId) of
                {'ok', _} -> 'ok';
                _ ->
                    Firstname = props:get_value(<<"given_name">>, ClaimsProps),
                    Surname = props:get_value(<<"family_name">>, ClaimsProps),
                    Email = props:get_value(<<"email">>, ClaimsProps),
                    Phonenumber = <<"">>,
                    UserPassword = kz_binary:rand_hex(12),
                    zkeycloak_util:create_user(AccountId, OwnerId, Firstname, Surname, Email, Phonenumber, UserPassword)
            end,
            lager:info("validate_ext/2  ClaimsProps: ~p",[ClaimsProps]),
            Setters = [{fun cb_context:set_auth_token/2, TokenAccess}
                      ,{fun cb_context:set_auth_doc/2, kz_json:from_list(ClaimsProps)}
                      ],
            Props = props:filter_undefined(
                      [{<<"account_id">>, AccountId}
                      ,{<<"owner_id">>, OwnerId}
                      ]),
            Resp = crossbar_util:response_auth(kz_json:from_list(Props), AccountId, OwnerId),
%
%
%            lager:debug("created new local auth token: ~s", [kz_json:encode(Resp)]),
%
%            log_success_auth(Method, <<"jwt_auth_token">>, <<"authentication resulted in token creation">>, Context, AccountId, AuthConfig),
%
%            lager:info("create_auth_token JObj: ~p", [JObj]),
%            lager:info("create_auth_token RespObj: ~p", [RespObj]),
%            lager:info("create_auth_token Claims: ~p", [Claims]),
%            lager:info("create_auth_token AuthConfig: ~p", [AuthConfig]),
%            lager:info("create_auth_token Method: ~p", [Method]),
            crossbar_util:response(Resp, cb_context:setters(Context, Setters));
        _ ->
            cb_context:add_system_error('invalid_credentials', Context)
    end;
validate(Context, ?ZKEYCLOAK) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).

%%%=============================================================================
%%% Internal functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% @end
%%------------------------------------------------------------------------------
-spec zkeycloak_ext_post(cb_context:context()) -> cb_context:context().
zkeycloak_ext_post(Context) ->
    ReqJSON = cb_context:req_json(Context),
    lager:info("zkeycloak_ext_post/1 req_data: ~p",[cb_context:req_data(Context)]),
    lager:info("zkeycloak_ext_post/1 req_json: ~p",[ReqJSON]),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, kz_json:new()), 'success').
