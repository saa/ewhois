#ewhois

`ewhois` erlang whois client library.

API
---

```erlang
ewhois:query(Domain)
```

```erlang
ewhois:query(Domain, Opts)
```

Domain :: binary()
Opts   :: options()

Types
_____

```erlang
-type options() :: [bind
                    | raw
                    | vals
                    | {nic, string()}
                    | {timeout, timeout()}
                    | {port, non_neg_integer()}
                   ].

-type bind() :: [{atom, binary()}].
-type vals() :: [{binary(), binary()}].
-type raw() :: binary().
-type result() :: bind() | vals() | raw().
```

TODO
----
1. Parse date to erlang terms
2. Collect many values in bind, example - nameservers.
3. Add support for ipv4/ipv6 whois query
4. Add tests
5. Fix parsing for EU

Examples
--------

Split key/value data:

```erlang
1>  ewhois:query(<<"google.com">>).
{ok,[{<<"Domain Name">>,<<"google.com">>},
     {<<"Registry Domain ID">>,<<"2138514_DOMAIN_COM-VRSN">>},
     {<<"Registrar WHOIS Server">>,<<"whois.markmonitor.com">>},
     {<<"Registrar URL">>,<<"http://www.markmonitor.com">>},
     {<<"Updated Date">>,<<"2014-10-28T12:38:28-0700">>},
     {<<"Creation Date">>,<<"1997-09-15T00:00:00-0700">>},
     {<<"Registrar Registration Expiration Date">>,
      <<"2020-09-13T21:00:00-0700">>},
     {<<"Registrar">>,<<"MarkMonitor, Inc.">>},
     {<<"Registrar IANA ID">>,<<"292">>},
     {<<"Registrar Abuse Contact Email">>,
      <<"abusecomplaints@markmonitor.com">>},
     {<<"Registrar Abuse Contact Phone">>,<<"+1.2083895740">>},
     {<<"Domain Status">>,
      <<"clientUpdateProhibited (https://www.icann.org/epp#cl"...>>},
     {<<"Domain Status">>,
      <<"clientTransferProhibited (https://www.icann.org/"...>>},
     {<<"Domain Status">>,
      <<"clientDeleteProhibited (https://www.icann.or"...>>},
     {<<"Registry Registrant ID">>,<<>>},
     {<<"Registrant Name">>,<<"Dns Admin">>},
     {<<"Registrant Organization">>,<<"Google Inc.">>},
     {<<"Registrant Street">>,
      <<"Please contact contact-admin"...>>},
     {<<"Registrant City">>,<<"Mountain View">>},
     {<<"Registrant State/Provinc"...>>,<<"CA">>},
     {<<"Registrant Postal Co"...>>,<<"94043">>},
     {<<"Registrant Count"...>>,<<"US">>},
     {<<"Registrant P"...>>,<<"+1.65025"...>>},
     {<<"Registra"...>>,<<>>},
     {<<"Regi"...>>,<<...>>},
     {<<...>>,...},
     {...}|...]}
```

Raw data:

```erlang
1> ewhois:query(<<"google.com">>, [raw]).
{ok,<<"\n\nDomain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmoni"...>>}
```

Bind

```erlang
1> ewhois:query(<<"google.com">>, [bind]).
{ok,[{nameservers,<<"ns4.google.com">>},
     {registrar,<<"MarkMonitor, Inc.">>},
     {expiration_date,<<"2020-09-13T21:00:00-0700">>},
     {creation_date,<<"1997-09-15T00:00:00-0700">>},
     {status,<<"clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)">>}]}
```

Set whois server:

```erlang
1> ewhois:query(<<"google.com">>, [{nic, "whois.r01.ru"}]).
{ok,[]}
```
