-module(zkeycloak_oidcc_sup).
-behaviour(supervisor).

-export([start_link/0
        ,start_child/1, start_child/2
        ]).

-export([init/1]).

-include("zkeycloak.hrl").

-define(SERVER, ?MODULE).

-define(CHILDREN, [#{'id' => 'oidcc_provider_configuration_worker',
                     'start' =>
                         {'oidcc_provider_configuration_worker', 'start_link', [
                             #{
                                 'issuer' =>  zkeycloak_util:issuer(),
                                 'name' => {'local', zkeycloak_util:client_id_atom()}
                             }
                         ]},
                     'shutdown' => 'brutal_kill'
                   }]).

-spec start_link() -> kz_types:startlink_ret().
start_link() ->
    supervisor:start_link({'local', ?SERVER}, ?MODULE, []).

-spec start_child(module()) -> kz_types:sup_startchild_ret().
start_child(Mod) ->
    start_child(Mod, 'worker').

-spec start_child(module(), 'worker' | 'supervisor') -> kz_types:sup_startchild_ret().
start_child(Mod, 'worker') ->
    supervisor:start_child(?SERVER, ?WORKER(Mod));
start_child(Mod, 'supervisor') ->
    supervisor:start_child(?SERVER, ?SUPER(Mod)).

-spec init(any()) -> kz_types:sup_init_ret().
init([]) ->
    RestartStrategy = 'one_for_one',
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    {'ok', {SupFlags, ?CHILDREN}}.

