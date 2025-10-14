-module(zkeycloak_util).

-export([auth_url/0
        ,issuer/0
        ,client_id_atom/0
        ,client_id/0
        ,client_secret/0
        ,redirect_uri/0
        ,preferred_auth_methods/0
        ,retrieve_token/1
        ]
       ).

-spec issuer() -> kz_term:ne_binary().
issuer() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"issuer">>, <<"issuer">>).

-spec client_id_atom() -> atom().
client_id_atom() ->
    kapps_config:get_atom(<<"zkeycloak">>, <<"client_id">>, 'client_id').

-spec client_id() -> kz_term:ne_binary().
client_id() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"client_id">>, <<"client_id">>).

-spec client_secret() -> kz_term:ne_binary().
client_secret() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"client_secret">>, <<"client_secret">>).

-spec redirect_uri() -> kz_term:ne_binary().
redirect_uri() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"redirect_uri">>, <<"redirect_uri">>).

-spec preferred_auth_methods() -> kz_term:ne_binary().
preferred_auth_methods() ->
    case kapps_config:get(<<"zkeycloak">>, <<"preferred_auth_methods">>, [client_secret_basic, client_secret_post]) of
        L when is_list(L) ->
            [kz_term:to_atom(V, 'true') || V <- L];
        _ -> []
    end.

-spec auth_url() -> kz_term:ne_binary().
auth_url() ->
    {ok, RedirectUri} =
        oidcc:create_redirect_url(
            client_id_atom()
            ,client_id()
            ,client_secret()
            ,#{'redirect_uri' => redirect_uri()
              ,'preferred_auth_methods' => preferred_auth_methods() 
              }
        ),
    kz_binary:join(RedirectUri, <<"">>).

-spec retrieve_token(kz_term:ne_binary()) -> kz_term:ne_binary().
retrieve_token(AuthCode) ->
    {ok, Token} =
        oidcc:retrieve_token(
            AuthCode
            ,client_id_atom()
            ,client_id()
            ,client_secret()
            ,#{'redirect_uri' => redirect_uri()
              ,'preferred_auth_methods' => preferred_auth_methods()
              }
        ),
    Token.
