-module(zkeycloak_handlers).

-export([tosdb_req/2
        ]).

-include("zkeycloak.hrl").

-spec tosdb_req(kz_json:object(), kz_term:proplist()) -> any().
tosdb_req(JObj, Props) ->
    lager:info("zbrt tosdb_req JObj: ~p",[JObj]),
    lager:info("zbrt tosdb_req Props: ~p",[Props]).
