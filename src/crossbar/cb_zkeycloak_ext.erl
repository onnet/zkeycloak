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
allowed_methods(?ZKEYCLOAK) -> [?HTTP_POST, ?HTTP_GET].

-spec resource_exists() -> boolean().
resource_exists() -> 'true'.
-spec resource_exists(path_tokens()) -> boolean().
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
%%    WebHookSecretToken = kapps_config:get_ne_binary(<<"zkeycloak">>,
%%                                                    <<"tlg_secret_token">>,
%%                                                    <<"pls_install_value_in_db">>),
%%    case maps:get(<<"x-telegram-bot-api-secret-token">>, cb_context:req_headers(Context), <<>>) of
%%        WebHookSecretToken ->
%%            lager:info("authenticate_nouns/1: true"),
%%            true;
%%        _ -> lager:info("authenticate_nouns/1: false"),
%%             false
%%    end;
    'true';
authenticate_nouns(_Context, _Nouns) ->
    lager:info("authenticate_nouns/1 _Nouns: ~p",[_Nouns]),
    'false'.
%%'true'.

-spec validate(cb_context:context()) -> cb_context:context().
validate(Context) ->
    lager:info("validate_ext/2  req_files: ~p",[cb_context:req_files(Context)]),
    lager:info("validate_ext/2  req_headers: ~p",[cb_context:req_headers(Context)]),
    lager:info("validate_ext/2  req_nouns: ~p",[cb_context:req_nouns(Context)]),
    lager:info("validate_ext/2  req_verb: ~p",[cb_context:req_verb(Context)]),
    lager:info("validate_ext/2  req_id: ~p",[cb_context:req_id(Context)]),
    zkeycloak_ext_post(Context).

-spec validate(cb_context:context(), path_token()) -> cb_context:context().
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
    Result = zkeycloak_webhooks_handler:ext_post_handler(ReqJSON),
    lager:info("zkeycloak_webhooks_handler:ext_post_handler/1 Result: ~p",[Result]),
    cb_context:set_resp_status(cb_context:set_resp_data(Context, kz_json:new()), 'success').
