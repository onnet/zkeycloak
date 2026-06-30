%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2010-2020, 2600Hz
%%% @doc
%%% @end
%%%-----------------------------------------------------------------------------
-module(zkeycloak_app).

-behaviour(application).

-include_lib("kazoo_stdlib/include/kz_types.hrl").

-export([start/2, stop/1]).

%%------------------------------------------------------------------------------
%% @doc Implement the application start behaviour.
%% @end
%%------------------------------------------------------------------------------
-spec start(application:start_type(), any()) -> kz_types:startapp_ret().
start(_Type, _Args) ->
    _ = declare_exchanges(),
    _ = maybe_flush_crossbar_keycloak_gate(),
    zkeycloak_sup:start_link().

%%------------------------------------------------------------------------------
%% @doc Implement the application stop behaviour.
%% @end
%%------------------------------------------------------------------------------
-spec stop(any()) -> any().
stop(_State) ->
    'ok'.


-spec declare_exchanges() -> 'ok'.
declare_exchanges() ->
    kapi_self:declare_exchanges().

%% @doc `crossbar_auth' кеширует «доступен ли zkeycloak» в persistent_term.
%% При старте zkeycloak модуль становится доступен — сбрасываем кеш, чтобы
%% хук KC-валидации включился без рестарта crossbar. `function_exported'
%% (после `ensure_loaded') страхует от рассинхрона версий при rolling-деплое.
-spec maybe_flush_crossbar_keycloak_gate() -> 'ok'.
maybe_flush_crossbar_keycloak_gate() ->
    _ = code:ensure_loaded('crossbar_auth'),
    case erlang:function_exported('crossbar_auth', 'flush_keycloak_gate', 0) of
        'true' -> crossbar_auth:flush_keycloak_gate();
        'false' -> 'ok'
    end.
