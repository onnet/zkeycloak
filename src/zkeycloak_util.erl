-module(zkeycloak_util).

-export([add_pool/0
%        ,sql_query/1
        ]
       ).

-spec add_pool() -> {ok, pid()} | {error, term()}.
add_pool() ->
    'ok'.
