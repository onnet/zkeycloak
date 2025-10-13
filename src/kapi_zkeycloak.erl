-module(kapi_zkeycloak).

-export([resp/1, resp_v/1]).
-export([publish_resp/2, publish_resp/3]).

-include("zkeycloak.hrl").

%% AMQP fields for zkeycloak Response
-define(ZKEYCLOAK_RESP_HEADERS, []).
-define(OPTIONAL_ZKEYCLOAK_RESP_HEADERS, [<<"Msg-ID">>,<<"QueryResultStatus">>, <<"QueryResult">>, <<"ClassId">> ,<<"Data">> ,<<"data">> ,<<"action">> ,<<"syncdate">> ]).
-define(ZKEYCLOAK_RESP_VALUES, []).
-define(ZKEYCLOAK_RESP_TYPES, []).

-spec publish_resp(kz_term:ne_binary(), kz_term:api_terms()) -> 'ok'.
publish_resp(Queue, JObj) ->
    publish_resp(Queue, JObj, ?DEFAULT_CONTENT_TYPE).

-spec publish_resp(kz_term:ne_binary(), kz_term:api_terms(), kz_term:ne_binary()) -> 'ok'.
publish_resp(Queue, Resp, ContentType) ->
    {'ok', Payload} = kz_api:prepare_api_payload(Resp, ?ZKEYCLOAK_RESP_VALUES, fun resp/1),
    kz_amqp_util:targeted_publish(Queue, Payload, ContentType).

-spec resp(kz_term:api_terms()) ->
          {'ok', iolist()} |
          {'error', string()}.
resp(Prop) when is_list(Prop) ->
    lager:info("resp(Prop): ~p",[Prop]),
    case resp_v(Prop) of
        'true' -> kz_api:build_message(Prop, ?ZKEYCLOAK_RESP_HEADERS, ?OPTIONAL_ZKEYCLOAK_RESP_HEADERS);
        'false' -> {'error', "Proplist failed validation for zkeycloak_resp:resp_v"}
    end;
resp(JObj) ->
    resp(kz_json:to_proplist(JObj)).

-spec resp_v(kz_term:api_terms()) -> boolean().
resp_v(Prop) when is_list(Prop) ->
    kz_api:validate(Prop, ?ZKEYCLOAK_RESP_HEADERS, ?ZKEYCLOAK_RESP_VALUES, ?ZKEYCLOAK_RESP_TYPES);
resp_v(JObj) ->
    resp_v(kz_json:to_proplist(JObj)).

