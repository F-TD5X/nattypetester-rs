Test your network NAT type via cli

- RFC 3489/5780/8489 Support
- Test proxies' NAT Type by using socks option

See options via `nattypetester -h`

example:

```
$ nattypetester rfc3489 -6

Mode: Rfc3489
Effective Mode: Rfc3489
Transport: Udp
Server: stun.hot-chilli.net:3478
NAT Type: SymmetricUdpFirewall (no NAT mapping; symmetric UDP filtering/firewall)
Local Endpoint: [masked ipv6]:35145
Public Endpoint: [masked ipv6]:35145

Explaination: No NAT mapping observed, but inbound UDP is filtered unless traffic was initiated.
```

> As you known, most ipv6 network doesn't needs NAT, but you may sill needs IPv6 Pin Hole cause your or your ISP's firewall filtering the traffic to protect you.
> And at this time you may see the output as above.


```
$ nattypetester -4

Mode: Auto
Effective Mode: Rfc8489
Transport: Udp
Server: stun.hot-chilli.net:3478
Binding Test: Success
Mapping Behavior: EndpointIndependent
Filtering Behavior: EndpointIndependent
Local Endpoint: 192.168.1.1:54087
Public Endpoint: <masked ipv4>:43681
Other Endpoint: 49.12.125.24:3479

Explaination: binding succeeded; mapping is endpoint-independent; filtering is endpoint-independent.
```

