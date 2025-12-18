## Netdiscover

For wireless networks without dhcp server, it also works on hub/switched networks.



```
$ sudo netdiscover
Currently scanning: 172.16.129.0/16 | Screen View: Unique Hosts
13 Captured ARP Req/Rep packets, from 4 hosts. Total size: 780
------------------------------------------------------------------------------
IP At MAC Address Count Len MAC Vendor / Hostname
------------------------------------------------------------------------------
192.168.195.2 00:50:56:f0:23:20 6 360 VMware, Inc.
192.168.195.130 00:0c:29:74:7c:5d 4 240 VMware, Inc.
192.168.195.132 00:0c:29:85:40:c0 2 120 VMware, Inc.
192.168.195.254 00:50:56:ed:c0:7c 1 60 VMware, Inc.
```

## Ping Sweep

_It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built_

```
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

```
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

### cmd

```
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

### powershell

```
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

## Nmap


```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

10.129.2.4
10.129.2.10
10.129.2.11
10.129.2.18
10.129.2.19
10.129.2.20
10.129.2.28
```