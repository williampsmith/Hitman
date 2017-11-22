# HITMAN

<p align="center">
  <img src="https://github.com/williampsmith/Hitman/blob/master/Assets/hitman.png" width=250>
  <br/>
</p>


## Hitman provides reliable TCP/IP communication and detection in the presence of
on-path connection reset censorship technologies and firewalls, such as the
Great Firewall of China.

## Usage

### Detection
Detection of an on-path connection reset censorship technology is obtained by
pinging the provided destination host IP with the suspected censored data.

`$ sudo python ping.py`

```
SIP IP 172.26.9.210, iface eth0, netmask 255.255.240.0, enet 06:ed:1d:58:b8:c2
Gateway 172.26.0.1
Ethernet destination 06:5d:b0:be:f6:0c
Sniffer started
Sniffer rule "src net 202.106.121.6 or icmp"
.
Sent 1 packets.
.
Sent 1 packets.
FIREWALL
```

### Analysis
In the analysis phase, we can infer information about the relative location of
the on-path packet injection, by number of hops from the originating host.
Data is of the form `<i>:  <IP | None>`, where `i` is the hop number and `IP` is
the IP is of the switch at hop `i`, or `None` if it cannot be determined, or the
packet never reaches hop `i`. An `*` is appended to all IP's for which a RST
packet was received.

`$ sudo python traceroute.py`

```
ICMP PACKET RECEIVED. IP: 219.158.112.45
NON-ICMP PACKET RECEIVED. ACK: 2002169909
RST PACKET RECEIVED
ICMP PACKET RECEIVED. IP: 219.158.112.45
.
.
.
  1:   None
  2:   None
  3:   None
  4:   None
  5:   None
  6:   None
  7:   100.65.11.161
  8:   54.239.48.176
  9:   52.93.12.130
 10:   52.93.12.127
 11:   None
 12:   52.95.52.124
 13:   52.95.52.189
 14:   12.246.35.13
 15:   52.95.52.53
 16:   12.122.1.78
 17:   12.122.85.210
 18:   12.122.129.241
 19:   12.122.28.121
 20:   12.122.129.241
 21:   219.158.103.29
 22:   219.158.96.29
 23: * 219.158.112.45
 24: * 202.96.12.82
 25: * 219.158.112.45
 ```

### Evasion
Evasion is obtained by passing in the hop count at which we suspect the censorship
device to be located on path, as found in the analysis step. Shown below, the
argument to `evade.py` is the hop count.

`$ sudo python evade.py 20`

```
SIP IP 172.26.9.210, iface eth0, netmask 255.255.240.0, enet 06:ed:1d:58:b8:c2
Gateway 172.26.0.1
Ethernet destination 06:5d:b0:be:f6:0c
Sniffer started
Sniffer rule "src net 202.106.121.6 or icmp"
.
Sent 1 packets.
.
Sent 1 packets.
.
Sent 1 packets.
.
.
.
Sent 1 packets.
HTTP/1.1 404 Not Found
Content-Type: text/html
Expires: 0
Cache-control: private
Content-Length: 300

Sorry, Page Not Found HTTP/1.1 404 Not Found
Date: Wed, 22 Nov 2017 07:21:33 GMT
Server: Apache
Content-Length: 208
Keep-Alive: timeout=5, max=91
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1
```

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /Falun+Gong was not found on this server.</p>
</body></html>
HTTP/1.1 404 Not Found
Date: Wed, 22 Nov 2017 07:21:33 GMT
Server: Apache
Content-Length: 208
Keep-Alive: timeout=5, max=91
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1
```
