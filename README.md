# LocationSniffer

Program captures all IP packets and print all locations of captured IP addresses.

Program uses http://ip-api.com for receiving IP locations. 
There are some limits: request amount and time which means the program starts sleeping(~60 seconds) as the amount has ended.

In progress:
*     Process RARP, ARP, IPv6 protocols
*     Print timer on sleeping
*     Add options for filtering output

Used libraries:
* libpcap-dev >= 1.10.0-2
* libcurlpp-dev >= 0.8.1-3

Type `make` to compile and launch code.
