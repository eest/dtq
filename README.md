# dtq: dnstap query

This tool allows you to filter [dnstap](https://dnstap.info) data using [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) expressions

This allows you to for example filter on a combination of question name and
specific DNS message ID like so:
```
$ dtq -file dnstap.file -filter '"/DNSMsg/Question/0/Name" == "www.domain.example." and "/DNSMsg/MsgHdr/Id" == 1337'
```
