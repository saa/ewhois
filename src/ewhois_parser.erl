-module(ewhois_parser).

-export([bind/1]).
-export([parse_vals/1]).


bind(Data) ->
    BaseRe = <<":\s+(.*)\n">>,
    Fun = fun({Key, Patterns}, Acc) ->
                  lists:map(fun(Pattern) ->
                                    P = iolist_to_binary([Pattern, BaseRe]),
                                    ReOpts = [{capture, [1], binary}],
                                    case re:run(Data, P, ReOpts) of
                                        {match, [Value]} ->
                                            [{Key, Value}] ++ [Acc];
                                        nomatch ->
                                            Acc
                                    end
                            end, Patterns)
          end,
    lists:flatten(lists:foldl(Fun, [], bind_patterns())).


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
                      <<"created">>, <<"created-date">>, <<"registered">>, <<"registration">>]},
     {expiration_date, [<<"paid-till">>]},
     {registrar, [<<"registrar">>, <<"Registrar">>]},
     {whois_server, [<<"Whois Server">>]},
     {nameservers, [<<"nserver">>]}
    ].
