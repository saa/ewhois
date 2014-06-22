-module(ewhois_parser).

-export([bind/1]).
-export([parse_vals/1]).


bind(Data) ->
    bind(Data, bind_patterns(), []).

bind(_Data, [], Acc) ->
    Acc;
bind(Data, [{K, Patterns} | Tail], Acc) ->
    Acc2 = case match_value(Data, Patterns) of
               undefined ->
                   Acc;
               V ->
                   [{K, V} | Acc]
           end,
    bind(Data, Tail, Acc2).


match_value(_Data, []) ->
    undefined;
match_value(Data, [Pattern | Tail]) ->
    case re:run(Data, iolist_to_binary([Pattern, <<":(.*)">>]), [{capture, [1], binary}]) of
        {match, [Value]} ->
            trimre(Value);
        nomatch ->
            match_value(Data, Tail)
    end.


parse_vals(Data) ->
    Lines = binary:split(Data, <<"\n">>, [global]),
    Fun = fun(Line) ->
                  case re:run(Line, <<"(.*):\s+(.*)">>, [{capture, [1,2], binary}]) of
                      {match, [K, V]} ->
                          {trimre(K), trimre(V)};
                      nomatch ->
                          []
                  end
          end,
    lists:flatten(lists:map(Fun, Lines)).


trimre(Bin) ->
    re:replace(Bin, "^\\s+|\\s+$", "", [{return, binary}, global]).


bind_patterns() ->
    [
     {status, [<<"state">>, <<"Status">>]},
     {creation_date, [<<"created">>, <<"Creation Date">>, <<"Creation date">>, <<"Registration Date">>,
                      <<"created-date">>, <<"registered">>, <<"registration">>]},
     {expiration_date, [<<"paid-till">>, <<"Registry Expiry Date">>, <<"Registrar Registration Expiration Date">>,
                        <<"Expiration date">>, <<"Expiration Date">>, <<"reg-till">>]},
     {registrar, [<<"registrar">>, <<"Registrar">>, <<"Sponsoring Registrar Organization">>, <<"Sponsoring Registrar">>,
                  <<"Registered through">>, <<"Registrar Name[.]*">>, <<"Record maintained by">>,
                  <<"Registration Service Provided By">>, <<"Registar of Record">>, <<"Domain Registar">>]},
     {whois_server, [<<"Whois Server">>]},
     {nameservers, [<<"nserver">>, <<"Nameservers">>, <<"Name Server">>, <<"nameserver">>, <<"Hostname">>, <<"Nserver">>]}
    ].
