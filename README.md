#ewhois

`ewhois` erlang whois client library.

API
---

```erlang
ewhois:query(Domain)
```

Domain is binary. Example, <<"github.com">>.

```erlang
ewhois:query(Domain, Opts)
```

Opts = [Option]

Option = {nic, "whois.example.com"} | raw | vals | {timeout, 5000} | {port, 43}

TODO
----
1. Parse date to erlang terms
2. Collect many values in bind, example - nameservers.
3. Add support for ipv4/ipv6 whois query
4. Add tests
5. Fix parsing for EU

Examples
--------

Bind data:

```erlang
1> ewhois:query(<<"github.com">>).
[{nameservers,<<"NS1.P16.DYNECT.NET">>},
 {whois_server,<<"whois.markmonitor.com">>},
 {registrar,<<"MARKMONITOR INC.">>},
 {expiration_date,<<"09-oct-2020">>},
 {creation_date,<<"09-oct-2007">>},
 {status,<<"clientDeleteProhibited">>}]
```

Raw data:

```erlang
1> ewhois:query(<<"github.com">>, [raw]).
<<"\nWhois Server Version 2.0\n\nDomain names in the .com and .net domains can now be registered\nwith many different compe"...>>
```

Split key - values data:

```erlang
1> ewhois:query(<<"github.com">>, [vals]).
[{<<"Domain Name">>,<<"GITHUB.COM">>},
 {<<"Registrar">>,<<"MARKMONITOR INC.">>},
 {<<"Whois Server">>,<<"whois.markmonitor.com">>},
 {<<"Referral URL">>,<<"http://www.markmonitor.com">>},
 {<<"Name Server">>,<<"NS1.P16.DYNECT.NET">>},
 {<<"Name Server">>,<<"NS2.P16.DYNECT.NET">>},
 {<<"Name Server">>,<<"NS3.P16.DYNECT.NET">>},
 {<<"Name Server">>,<<"NS4.P16.DYNECT.NET">>},
 {<<"Status">>,<<"clientDeleteProhibited">>},
 {<<"Status">>,<<"clientTransferProhibited">>},
 {<<"Status">>,<<"clientUpdateProhibited">>},
 {<<"Updated Date">>,<<"14-jun-2013">>},
 {<<"Creation Date">>,<<"09-oct-2007">>},
 {<<"Expiration Date">>,<<"09-oct-2020">>},
 {<<">>> Last update of whois database">>,
  <<"Sun, 22 Jun 2014 08:58:19 UTC <<<">>},
 {<<"NOTICE">>,
  <<"The expiration date displayed in this record"...>>},
 {<<"TERMS OF USE">>,
 <<"You are not authorized to access or quer"...>>}]
```

Set whois server:

```erlang
1> ewhois:query(<<"google.ru">>, [{nic, "whois.r01.ru"}]).
[{nameservers,<<"ns1.google.com.">>},
 {registrar,<<"RU-CENTER-REG-RIPN">>},
 {expiration_date,<<"2015.03.05">>},
 {creation_date,<<"2004.03.04">>},
 {status,<<"REGISTERED, DELEGATED, VERIFIED">>}]
```
