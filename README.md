# divert\_rbl

This is an OpenBSD program that listens on a divert socket and performs real
time blacklist (RBL) checks for the source IP address on any packets that
arrive. Based on the result, the IP is added to a `rbl-spammers` or `rbl-clean`
table in pf. When combined with pass or block rules using those tables, this
enables RBL protection for a mail server. 

The daemon uses privilege separation to separate the DNS lookup function from
the pf table editing function. Improvements would be to pledge() both processes,
and to re-exec one of the processes after fork() in order to re-randomize memory
layout. It would also be useful to take parameters on the command line instead
of compiling them into the binary. These enhancements may arrive in a later
version. 

## deamon startup

Install the included divert\_rbl.rc script as `/etc/rc.d/divert_rbl`. Enable it
as usual in `/etc/rc.conf.local`, then start the deamon. It listens on port 2525
by default. 

## pf rules

Assuming that your mail server is behind NAT, the following pf rules on your
gateway will pass packets destined for port 25 to the divert\_rbl daemon, which
will add the source IP to the `rbl-spammers` or `rbl-clean` pf tables, depending
on what your RBL said. Subsequent packets from that host will be dropped or
passed. Note that `$ext_if` and `$host_mail` is your internet facing network
interface and the internal IP address of your mail server. 

    table <rbl-spammers> persist
    table <rbl-clean> persist
    block in log quick on $ext_if proto tcp from <rbl-spammers> to ($ext_if) port {25}
    pass  in on $ext_if proto tcp from any to ($ext_if) port 25 divert-packet port 2525 no state
    pass  in log on $ext_if proto tcp from <rbl-clean> to ($ext_if) port {25} rdr-to $host_mail

Note that the first packet from a new host will always be dropped. There is code
in here to rewrite the destination IP address and forward it out to the mail
host if it passed the RBL, but this gets a bit tricky because the state entries
in pf won't be set up right and the reply traffic gets dropped. This is not a
big deal in practice, because the sender will retransmit the initial SYN packet
anyway, which will go through if the sender is on the rbl-clean list. The
practical consequence of this is a short delay (~3s) setting up the initial TCP
connection the first time a particular host tries to contact your server. 

## cron

You will need to periodically expire old entries in `rbl-spammers` and
`rbl-clean`. You can do this with the following commands:

    # expire clean entries after a day
    pfctl -t rbl-clean    -T expire 86400
    # expire spammers after a week
    pfctl -t rbl-spammers -T expire 604800

### Disclaimer

This code comes with no warranty, may not work for you, or may not do what you
want. If you find this code useful I'd love to hear about it. If you make
modifications that you think would be useful I am happy to take pull requests. 

