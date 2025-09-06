# dnsalert
A small pseudo DNS server that always returns NXDOMAIN or times out, but keeps
metrics for matching resolution attempts.

The purpose of the tool is to provide a way to detect name resolution attempts
and monitor or alert based on them. It can for example be used as a form of
honeypot or to trigger an action in situations where direct communication is
blocked, but DNS is available.

Resolution of any name below one of the allowed domains will result in a
negative (name error/NXDOMAIN) response that includes a SOA record for the
matching allowed domain. Anything else is rejected and will simply time out.

The tool is implemented in Python and has no dependencies.

# Usage
The SOA record needs to know the name of the nameserver it represents. This is
provided as the first argument to the tool. All following arguments are treated
as allowed domains to respond to:

```
dnsalert.py <nameServer> <allowedDomain> [<allowedDomain>...]
```

Example:

```
dnsalert.py ns1.example.org alerting.example.org
```

This will report the nameserver as "ns1.example.org" and responsible mailbox as
"hostmaster@ns1.example.org" in the SOA record and resolve anything under
"alerting.example.org" with NXDOMAIN. So "test.alerting.example.org" would
resolve while "other.example.org" would not.

# DNS Configuration
For the tool to work, it has to be reachable on UDP port 53 via a DNS name. For
example "ns1.example.org" would resolve to the address where the tool is
reachable. Then a subdomain can be delegated to it by creating a nameserver
record for that subdomain with a value of the nameserver DNS name:

```
ns1.example.org A 12.34.56.78
alerting.example.org NS ns1.example.org
```

With this "alerting.example.org" and any subdomain of it will be resolved by the
tool.

Note that the A record of the nameserver cannot reside under the delegated
subdomain, as it could then not be resolved. So in the example above it could
not be "ns1.alerting.example.org". The A record does not need to be on the same
domain as the delegated subdomain.

# Metrics
Metrics can be retrieved via HTTP in plain text Prometheus exposition format
at port 9855 under "/metrics", for example:

```
$ curl http://localhost:9855/metrics
# TYPE dns_accepted_count counter
dns_accepted_count 2
# TYPE dns_rejected_count counter
dns_rejected_count 6
# TYPE dns_malformed_count counter
dns_malformed_count 1
# TYPE dns_query_count counter
dns_query_count{name="test.alerting.example.org"} 2
```

# Logs
All resolution attempts are logged to stdout:

```
name: test.alerting.example.org; type: A; class: IN; remote: 172.25.0.1:37371; accept: True
name: test.alerting.example.net; type: A; class: IN; remote: 172.25.0.1:53900; accept: False
empty; remote: 172.25.0.1:55805
name: test.alerting.example.org; type: A; class: CH; remote: 172.25.0.1:50141; accept: False
non-query: IQUERY; remote: 172.25.0.1:40727
name: 1.0.0.127.in-addr.arpa; type: PTR; class: IN; remote: 172.25.0.1:35934; accept: False
name: test.alerting.example.org; type: A; class: IN; remote: 172.25.0.1:35011; accept: True
name: test.alerting.example.net; type: A; class: IN; remote: 172.25.0.1:53185; accept: False
exception: index out of range; remote: 172.25.0.1:45164
```
