To test first login to ec2 instance or vm, then open two terminals and n each run:
telnet www.nsae.miit.gov.cn 80

en0 or eth0 depending on what ifconfig says is the interface
sudo tcpdump -vv -i en0 host www.nsae.miit.gov.cn
sudo tcpdump -vv -i eth0 host www.nsae.miit.gov.cn

Get requests to try:
GET /search?q=Falun%20Gong HTTP/1.1
host: www.google.com

GET / HTTP/1.1
connection: keep-alive
host: www.miit.gov.cn

GET / HTTP/1.1
host: www.miit.gov.cn

GET / HTTP/1.1
connection: keep-alive
host: www.nsae.miit.gov.cn

GET / HTTP/1.1
connection: keep-alive
host: www.facebook.com

More information:
To send DSN request for facebook.com to 202.106.121.6 enter into terminal:
dig www.facebook.com @202.106.121.6

To make TCP handshake and send request:

telnet {server} 80
telnet www.nsae.miit.gov.cn 80
It will ask for request, paste and press entire two times to submit it:
GET /search?q=falun+gong HTTP/1.1
host: www.google.com

gives you a TCP connection to the web server in question on port 80.  You can run this in your VM or on your own computer outside the VM.

To sniff packets: TCPdump
You can also then capture packets with TCPdump  {man TCPDump for details}
TCPdump you run at the same time as telnet, since the goal is to capture the packets you send.
RST packets have the R flag set.

Syntax:

tcpdump -v -i {interface} host {server}
sudo tcpdump -w dump.pcap -vv -i enp0s3 host www.miit.gov.cn
sudo tcpdump -w dump.pcap -vv -i enp0s3 host www.nsae.miit.gov.cn

tcpdump -vv -n -r {filename}
# tcpdump -w /path/to/file
 Then to read the file, you need to interpret the binary with tcpdump -r (read). The other flags are optional (-v or -vv for verbose and -n for no translating hostnames & ports) 

-s is the snaplen (so the amount of data in each frame to be recorded). Look through the posts to find an example to use.

Example:
$ tcpdump -vv -n -r question1.pcap 
reading from file question1.pcap, link-type EN10MB (Ethernet)
20:49:32.938268 IP (tos 0x0, ttl 64, id 15258, offset 0, flags [DF], proto TCP (6), length 60)
    192.168.1.10.35418 > 202.106.121.6.80: Flags [S], cksum 0x0552 (incorrect -> 0x2dad), seq 1414384840, win 29200, options [mss 1460,sackOK,TS val 849746 ecr 0,nop,wscale 7], length 0
20:49:33.192979 IP (tos 0x20, ttl 239, id 32513, offset 0, flags [DF], proto TCP (6), length 44)
    202.106.121.6.80 > 192.168.1.10.35418: Flags [S.], cksum 0x64d5 (correct), seq 361965657, ack 1414384841, win 17520, options [mss 1460], length 0

......
[more TCP packets]


