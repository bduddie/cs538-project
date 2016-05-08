# Private addressing using OpenFlow

This project contains a proof-of-concept for a system whereby access can be
restricted to certain hosts, created as part of a final project for CS538
Advanced Networks at UIUC. In the envisioned system, clients can access these
protected/hidden services nearly transparently via this scheme:

1. Client is configured via DHCP to handle DNS requests locally

1. Client has a DNS proxy server running locally. It has two main paths for
   handling requests:

   1. If the domain name is identified as a protected address on the local
      network, e.g. via matching a domain name suffix like *.sec.mycompany.com,
      then the request is forwarded to a secure DNS (SDNS) server that
      specifically manages access to private addresses. This request may
      require additional authentication with the user's two-factor token.

   1. Otherwise, the DNS request is proxied to the traditional DNS server.

1. The SDNS server identifies the private IP address associated with the
   client's request, and generates a pair of virtual IPs valid for use only by
   the requesting client and target server. The virtual IP is returned in the
   DNS response (with a short TTL), and a request is sent to the OpenFlow
   controller to install rules to handle the virtual/private address mapping.

1. The OpenFlow controller identifies the edge switches connected to the end
   hosts associated with each private IP address, and installs a rules to
   handle mapping between virtual and private addresses, and vice versa. Also,
   the edge switches are configured to respond to ARP requests for the virtual
   IPs with a virtual MAC address that is also replaced by the switch in
   packets transiting the network.

1. The client and server communicate with each other, only knowing the virtual
   address of each other. Access to the protected system can be revoked at any
   time by removing the mapping rules from the edge switches.

The simulation requires these dependencies:

* Mininet VM (tested version: 2.2.1)
* POX (tested version: eel @ 0cc9de5 - Apr. 6, 2016)

To install/run, log in to your Mininet VM as the "mininet" user, then execute
these commands in the shell:

```
$ git clone https://github.com/bduddie/cs538-project
$ cd pox
$ git fetch && git checkout eel && git reset --hard 0cc9de5d2bc95ebc1cf232b21d788ba931faa6d0
$ cd ~/cs538-project
$ cp pox/misc/sdns-mapper.py ~/pox/pox/misc/
$ ./run.sh
```
