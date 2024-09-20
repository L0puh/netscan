# network utilities.

## current features:
- ping a host 
- traceroute 
- concurrent open port scanning (using threads)
- list IP addresses of a host 
- packet sniffer 
- list information about an ip address (parsed from ipinfo.io)
- visualization of in-coming traffic 

## dependencies: 
- curl
- cJSON
- glut 

## usage:
```text
-p [hostname]                          - ping hostname
-o [hostname] [start] [end] [threads]  - scan open ports
-l [hostname]                          - list available IPs
-s [v6/v4] [udp/tcp] [verbose (-v)]    - packet sniffer
-i [ip address]                        - print information about ip (from ipinfo.io)
-v [v4/v6]                             - visualize traffic
-t [hostname] [max ttl (default 30)]   - traceroute
```

## screenshots:
- packet sniffer:
![](https://github.com/L0puh/netscan/blob/master/media/1.png)
- list IPs and information of IP
![](https://github.com/L0puh/netscan/blob/master/media/2.png)
- ping host and list open ports
![](https://github.com/L0puh/netscan/blob/master/media/3.png)
- visualize incoming traffic 
![](https://github.com/L0puh/netscan/blob/master/media/4.png)

## example: 
```sh
./netscan -o google.com 75 90 10
./netscan -s v4 all -v
```
