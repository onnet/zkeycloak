-module(zkeycloak_util).

-export([auth_url/0
        ,issuer/0
        ,client_id_atom/0
        ,client_id/0
        ,client_secret/0
        ,redirect_uri/0
        ,preferred_auth_methods/0
        ,retrieve_token/1
        ,create_user/7
        ]
       ).

-define(MK_USER,
        {[{<<"enabled">>, 'true'}
         ,{<<"priv_level">>,<<"user">>}
         ,{<<"vm_to_email_enabled">>,true}
         ,{<<"fax_to_email_enabled">>,true}
         ,{<<"verified">>,false}
         ,{<<"timezone">>,<<"UTC">>}
         ,{<<"record_call">>,false}
         ,{<<"pvt_type">>, kzd_users:type()}
         ]}).

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

-spec create_user(kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ,kz_term:ne_binary()
                 ) -> {'ok', kz_json:object()} | kz_datamgr:data_error().
create_user(AccountId, UserDocId, Firstname, Surname, Email, Phonenumber, UserPassword) ->
    lager:info("create_user AccountId: ~p, UserDocId: ~p, Email: ~p",[AccountId,UserDocId,Email]),
    lager:info("create_user Firstname: ~p",[Firstname]),
    lager:info("create_user Surname: ~p",[Surname]),
    lager:info("create_user Phonenumber: ~p",[Phonenumber]),
    Props = props:filter_empty([{<<"username">>, Email}
                               ,{<<"first_name">>, Firstname}
                               ,{<<"last_name">>, Surname}
                               ,{<<"email">>, Email}
                               ,{<<"contact_phonenumber">>, Phonenumber}
                               ,{<<"password">>, UserPassword}
                               ,{<<"priv_level">>, <<"admin">>}
                               ]),
    DbName = kzs_util:format_account_db(AccountId),
    Ctx0 = cb_context:set_account_id(cb_context:new(), AccountId),
    Ctx1 = cb_context:set_db_name(Ctx0, DbName),
    UDoc = kz_json:set_values(Props, ?MK_USER),
    case catch kzd_users:validate(AccountId, UserDocId, UDoc) of
        {true, UDoc1} ->
            UDoc2 = crossbar_doc:update_pvt_parameters(UDoc1, Ctx1),
            UDoc3 = kz_json:set_value(<<"pvt_type">>,<<"user">>,UDoc2),
            Creates = kz_json:to_proplist(UDoc3),
            UpdateOptions = [{'create', Creates}
                            ,{'update', Creates}
                            ,{'ensure_saved', 'true'}
                            ],
            Result = kz_datamgr:update_doc(DbName, UserDocId, UpdateOptions),
            lager:info("create_user Result: ~p", [Result]);
        Err ->
            lager:info("create_user Err: ~p", [Err])
    end.

