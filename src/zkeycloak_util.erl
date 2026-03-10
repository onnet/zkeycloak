-module(zkeycloak_util).

-export([auth_url/0
        ,issuer/0
        ,client_id_atom/0
        ,client_id/0
        ,client_secret/0
        ,redirect_uri/0
        ,preferred_auth_methods/0
        ,retrieve_token/1
        ,retrieve_userinfo/1
        ,introspect_token/1
        ,refresh_token/1
        ,create_user/7
        ,jwt_claims/1
        ,jwt_iss/1
        ,maybe_keycloak_token/1
        ,maybe_keycloak_token_validate/2
        ,kerberos_enabled/0
        ,kerberos_idp_hint/0
        ,kerberos_auth_url/0
        ,kerberos_auth_url/1
        ,auth_method/1
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
    lager:info("zkeycloak auth_url: issuer=~s client_id=~s redirect_uri=~s",
               [issuer(), client_id(), redirect_uri()]),
    Result =
        oidcc:create_redirect_url(
          client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{'redirect_uri' => redirect_uri()
           ,'preferred_auth_methods' => preferred_auth_methods()
           }
         ),
    lager:info("zkeycloak auth_url oidcc result: ~p", [Result]),
    {ok, RedirectUri} = Result,
    Url = kz_binary:join(RedirectUri, <<"">>),
    lager:info("zkeycloak auth_url final: ~s", [Url]),
    Url.

-spec kerberos_enabled() -> boolean().
kerberos_enabled() ->
    kapps_config:get_is_true(<<"zkeycloak">>, <<"kerberos_enabled">>, 'false').

-spec kerberos_idp_hint() -> kz_term:ne_binary().
kerberos_idp_hint() ->
    kapps_config:get_ne_binary(<<"zkeycloak">>, <<"kerberos_idp_hint">>, <<"kerberos">>).

-spec kerberos_auth_url() -> kz_term:ne_binary().
kerberos_auth_url() ->
    kerberos_auth_url(#{}).

-spec kerberos_auth_url(map()) -> kz_term:ne_binary().
kerberos_auth_url(ExtraOpts) ->
    BaseExtension = [{<<"kc_idp_hint">>, kerberos_idp_hint()}],
    PromptExtension = case maps:get('prompt', ExtraOpts, 'undefined') of
        'undefined' -> [];
        Prompt -> [{<<"prompt">>, Prompt}]
    end,
    lager:info("zkeycloak kerberos_auth_url: issuer=~s client_id=~s redirect_uri=~s",
               [issuer(), client_id(), redirect_uri()]),
    Result =
        oidcc:create_redirect_url(
          client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{'redirect_uri' => redirect_uri()
           ,'preferred_auth_methods' => preferred_auth_methods()
           ,'url_extension' => BaseExtension ++ PromptExtension
           }
         ),
    lager:info("zkeycloak kerberos_auth_url oidcc result: ~p", [Result]),
    {ok, RedirectUri} = Result,
    Url = kz_binary:join(RedirectUri, <<"">>),
    lager:info("zkeycloak kerberos_auth_url final: ~s", [Url]),
    Url.

-spec retrieve_token(kz_term:ne_binary()) -> any().
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

-spec retrieve_userinfo(kz_term:ne_binary()) -> any().
retrieve_userinfo(Token) ->
    {ok, Claims} =
        oidcc:retrieve_userinfo(
          Token
         ,client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{}
         ),
    Claims.

-spec introspect_token(kz_term:ne_binary()) -> any().
introspect_token(Token) ->
    {ok, Introspection} =
        oidcc:introspect_token(
          Token
         ,client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{}
         ),
    Introspection.

-spec refresh_token(kz_term:ne_binary()) -> any().
refresh_token(Token) ->
    {ok, RefreshedToken} =
        oidcc:introspect_token(
          Token
         ,client_id_atom()
         ,client_id()
         ,client_secret()
         ,#{}
         ),
    RefreshedToken.

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

-spec jwt_claims(kz_term:ne_binary()) -> kz_term:proplist().
jwt_claims(Token) ->
    {ok, _Heder, Claims} = kz_auth_jwt:decode(Token),
    Claims.

-spec jwt_iss(kz_term:ne_binary()) -> kz_term:proplist().
jwt_iss(Token) ->
    Claims = jwt_claims(Token),
    props:get_ne_binary_value(<<"iss">>, Claims).

-spec maybe_keycloak_token(kz_term:ne_binary()) -> boolean().
maybe_keycloak_token(Token) ->
    jwt_iss(Token) == issuer().

-spec maybe_keycloak_token_validate(kz_term:ne_binary(), kz_term:proplist()) -> boolean().
maybe_keycloak_token_validate(Token, _Options) ->
    case maybe_keycloak_token(Token) of
        'false' ->
            {'ok', 'not_keycloack_token'};
        'true' ->
            Claims = jwt_claims(Token),
            ResourceAccessMap = props:get_value(<<"resource_access">>, Claims),
            ClientRoles = kz_maps:get([<<"onbill_client">>,<<"roles">>], ResourceAccessMap),
            case lists:member(<<"onbill_access">>, ClientRoles) of
                'true' ->
                    {'ok', 'onbill_access_provided'};
                'false' ->
                    {'error', 'onbill_access_absent'}
            end
    end.

-spec auth_method(kz_term:ne_binary()) -> 'oidc' | 'kerberos' | 'unknown'.
auth_method(Token) ->
    Claims = jwt_claims(Token),
    Acr = props:get_ne_binary_value(<<"acr">>, Claims, <<>>),
    case Acr of
        <<"kerberos">> -> 'kerberos';
        <<"1">> -> 'oidc';
        _ -> 'unknown'
    end.

