# dtq: dnstap query

This tool allows you to make SQL-like SELECT statements against [dnstap](https://dnstap.info) files.

The only table is `dnstap` and you can use `WHERE` and `LIMIT` to filter on the available columns.

To list the columns available for filtering:
```
$ dtq -where-columns
Columns available for WHERE statement:
  dns_id (uint16)
  dns_question_class_name (string)
  dns_question_name (string)
  dns_question_type_name (string)
  dnstap_is_query (*bool)
  dnstap_type_name (string)
  message_type_name (string)
  query_address_string (string)
  query_port (uint32)
  query_time_string (string)
  response_address_string (string)
  response_port (uint32)
  response_time_string (string)
  socket_family_name (string)
  socket_protocol_name (string)
```

This allows you to filter on a specific DNS message ID like so:
```
$ dtq -query 'SELECT dns_question_name,dnstap_is_query,dns_id from dnstap WHERE dns_id = 31337' -file example.dnstap
{"dnstap_is_query":true,"dns_question_name":"www.example.com.","dns_id":31337}
{"dnstap_is_query":false,"dns_question_name":"www.example.com.","dns_id":31337}
```
