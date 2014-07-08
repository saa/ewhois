-module(ewhois).

-export([query/1]).
-export([query/2]).
-export([is_available/1]).

-define(IANAHOST, "whois.iana.org").
-define(TIMEOUT, 15000).
-define(PORT, 43).
-define(OPTS, [{port, ?PORT}, {timeout, ?TIMEOUT}]).

query(Domain) ->
    query(Domain, ?OPTS).

query(Domain, Opts) when is_binary(Domain), is_list(Opts) ->
    Nic = proplists:get_value(nic, Opts, get_nic(Domain)),
    case send_query(Domain, Nic, Opts) of
        {ok, Reply} ->
            response(Reply, Opts);
        {error, Reason} ->
            {error, Reason}
    end.


is_available(Domain) ->
    RawData = query(Domain, [raw]),
    Patterns = free_patterns(),
    CheckFun = fun(Pattern) ->
                       case re:run(RawData, Pattern, [{capture, none}]) of
                           match ->
                               true;
                           nomatch ->
                               false
                       end
               end,
    Result = lists:map(CheckFun, Patterns),
    lists:member(true, Result).


response(RawData, [raw | _T]) ->
    RawData;
response(RawData, [bind | _T]) ->
    ewhois_parser:bind(RawData);
response(RawData, _Opts) ->
    ewhois_parser:parse_vals(RawData).


send_query(Domain, Nic, Opts) when is_list(Nic) ->
    Port = proplists:get_value(port, Opts, ?PORT),
    Timeout = proplists:get_value(timeout, Opts, ?TIMEOUT),
    case gen_tcp:connect(Nic, Port, [binary, {active, false}, {packet, 0}, {send_timeout, Timeout}], Timeout) of
        {ok, Sock} ->
            ok = gen_tcp:send(Sock, iolist_to_binary([Domain, <<"\r\n">>])),
            Reply = recv(Sock),
            ok = gen_tcp:close(Sock),
            {ok, Reply};
        {error, Reason} ->
            {error, Reason}
    end.

recv(Sock) ->
    recv(Sock, []).

recv(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, Data} ->
            recv(Sock, [Data | Acc]);
        {error, closed} ->
            iolist_to_binary(lists:reverse(Acc))
    end.


get_nic(Domain) ->
    case get_nic(Domain, defined_nics()) of
        undefined ->
            get_root_nics(Domain);
        {ok, Nic} ->
            Nic
    end.

get_nic(_Domain, []) ->
    undefined;
get_nic(Domain, [{Nic, Re} | Nics]) ->
    case re:run(Domain, Re) of
        {match, _} ->
            {ok, Nic};
        nomatch ->
            get_nic(Domain, Nics)
    end.


get_root_nics(Domain) ->
    case send_query(Domain, ?IANAHOST, ?OPTS) of
        {ok, Result} ->
            case re:run(Result, <<"refer:\s+(.*)\n">>, [{capture, [1], binary}]) of
                {match, [Refer]} ->
                    binary_to_list(Refer);
                nomatch ->
                    ?IANAHOST
            end;
        {error, Reason} ->
            {error, Reason}
    end.


defined_nics() ->
    [
     {"whois.nic.ru", <<"^(.*)+.(org|net|com|msk|spb|nov|sochi).ru$">>},
     {"whois.nic.fm", <<"^(.*)+fm">>},
     {"mn.whois-servers.net", <<"^(.*)+mn">>}
    ].


free_patterns() ->
    [
     "No entries found for the selected",
     "No match for",
     "NOT FOUND",
     "Not found:",
     "No match",
     "not found in database",
     "Nothing found for this query",
     "Status: AVAILABLE",
     "Status:\tAVAILABLE",
     "Status: Not Registered",
     "NOT FOUND"
    ].
