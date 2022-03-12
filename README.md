# dtq: dnstap query

This tool allows you to filter [dnstap](https://dnstap.info) data using [JSON
Pointer](https://datatracker.ietf.org/doc/html/rfc6901) expressions and get the
matching data printed in a JSON format.

This allows you to for example filter on a combination of question name and
specific DNS message ID like so:
```
$ dtq -file dnstap.file -filter '"/DNSMsg/Question/0/Name" == "www.domain.example." and "/DNSMsg/MsgHdr/Id" == 1337'
{
  "Dnstap": {
    "type": 1,
    "message": {
      "type": 6,
      "socket_family": 2,
       [...]
    }
  },
  "DNSMsg": {
    "Id": 1337,
    "Response": true,
    "Opcode": 0,
    "Authoritative": false,
    "Truncated": false,
    "RecursionDesired": true,
    "RecursionAvailable": true,
    "Zero": false,
    "AuthenticatedData": false,
    "CheckingDisabled": false,
    "Rcode": 0,
    "Question": [
      {
        "Name": "www.domain.example.",
        "Qtype": 1,
        "Qclass": 1
      }
    ],
    [...]
  }
}
```
