TRAASv2
=======

Install: `go get github.com/willscott/traas2/server`

Traas provides "traceroute as a service". A webserver that provides information
on the path that client packets take in reaching it. Information is provided
on the reverse path (the path from the server to the client). The TraceRoute
conducted is *parasitic*, meaning that it will be conducted over the same
TCP connection that the client has opened in connecting to the server. This
means that the information can sometimes provide information on the network
structure near the client. For example, consider the following diagram:

Server ---- NAT --- Client

There are many cases where the client cannot learn about its own local network
conditions. Perhaps an HTTP proxy is involved. Perhaps an internal NAT prevents
the client from gaining information about anything beyond an immediate LAN.
A direct traceroute from a remote server won't help either, as it will only
be able to see the network up until the first NAT. TCP traceorutes provide an
opportunity to potentially learn information about the active IP addresses
and path within carrier grade NATs that would not otherwise be easily visible.

------

Installation
------------

```bash
apt-get install libpcapdev
cd server
go get
go build
sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip server
```

Configuration
-------------

By default, a configuration file is expected in `./.config/traas.json`.
An explicit file can be specified using the `--config=` command line flag.
A new configuration file can be generated using the `--init` command line flag.

The following configuration parameters are used by Traas:

* ServePort - Which port the HTTP server is bound to. Default: 8080
* ListenPort - Incoming packets on this port are listened to by the pcap listener. Default: 8080. this value can differ from the ServePort when Traas is protected by a forward proxy, like Nginx or equivalent. In those cases, the forward proxy would relay requests to Traas, but the listener continues to rely on watching the actual packets from the client.
* Path - Traas can be prefixed to allow multiple applications to be served on the server. For example, "/traas" would limit its scope. Default: ""
* Device - Which ethernet device to bind to. Default: eth0, or the first device on your system.
* DstMac - The ethernet address of the default gateway. This can be found in the output of
    ```bash
    netstat -rn
    ```
* originHeader - If there is a local forwarding web server, request to the http server will be from localhost, and the origin clientIP should be passed in an additional HTTP header. That header can be specified here. Default: ""
