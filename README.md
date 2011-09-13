udptap
======

A tool to passively "tap" UDP sessions and send the traffic to another
host.

USAGE
-----

Options:	

    -i <interface>      Interface to tap
    -u <port>           UDP port to tap
    -d <host>           Destination host
    -p <port>           Destination port

EXAMPLE
-------

The following example will sniff syslog packets off eth0 and resend
them to port 514 on somehost where a syslog server may be listening.

    ./udptap -i eth0 -u 514 -d somehost:514
