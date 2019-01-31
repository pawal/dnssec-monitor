# dnssec-monitor

This repository contains a number of DNSSEC related tools for monitoring of DNSSEC signed zones. Most of the tools are written in Perl.

The tools that are named nagios* are suitable from running as automated tests for monitoring such as Nagios.

## List of the tools

**dnssec_monitor.pl**

Checks a DNSSEC signed domain for the signature validity. Shows warnings if the signature validity is too short, or errors if it is wrongly signed.

```
Usage:
    dnssec_monitor [options] [nameservers]

    Options:

     --help           brief help message
     --zone ZONE      zone to check
     --kskcritical N  check for KSK expire within DAYS days
     --kskwarning  N  check for KSK expire within DAYS days
     --zskcritical N  check for ZSK expire within DAYS days
     --zskwarning  N  check for ZSK expire within DAYS days
     --wildcard       disable the nxdomain check to allow for wildcards
     --nsec3          require NSEC3
     --debug          turn on debugging
     --quiet          be really quiet
     --version        display version and exit

     If no nameservers are specified, all nameservers for ZONE are checked.
```

**nagios_dnssec.pl**

This is the same type of tool as dnssec_monitor, suitable for running as a monitoring plugin for Nagios.

```
Usage:
    nagios_dnssec.pl --zone zonename nameserver

            --zone zonename     The zone to test (required argument)
            --kskcritical=i     KSK critical (days) (7 is default)
            --kskwarning=i      KSK warning  (days) (14 is default)
            --zskcritical=i     ZSK critical (days) (1 is default)
            --zskwarning=i      ZSK warning  (days) (3 is default)
            --debug             Debug mode
            --dstport=i         Destination port on name server (53 is default)
            --wildcard          Disable the NXDOMAIN check to allow for wildcards
            --nsec3             Require NSEC3
```

**nagios_noaxfr.pl**

Monitoring tool to look for open AXFR. Example output:

```
$ nagios_noaxfr.pl --zone example.com --server b.iana-servers.net.
OK: zone transfer refused
```

```
Usage:
    nagios_noaxfr.pl --zone zonename --server nameserver

            --zone zone         The zone to test (required argument)
            --server server     Name server
            --debug             Debug mode
            --timeout=i         Timeout
```

**nagios_zonecheck.pl**

Currently broken with newer Net::DNS versions.

This tool checks a complete zonefile from AXFR for the validity of DNSSEC signatures.

**ns-timestamp.pl**

This timestamp check uses a DNS trick that checks the time on the name servers. The result of the check is a devation from local time per name server:

```
$ ns-timestamp.pl example.com
a.iana-servers.net (199.43.135.53)                                     0
b.iana-servers.net (199.43.133.53)                                     0
```

**test_noaxfr.sh**

Test a domain for open AXFRs. Returns a list of name servers and the status of an AXFR test, like this:

 > $ test_noaxfr.sh example.com
> example.com b.iana-servers.net. 199.43.133.53
> OK: zone transfer refused
> example.com a.iana-servers.net. 199.43.135.53
> WARNING: server not authoritative for example.com

This is a shell script that uses nagios_noaxfr.pl for each name server.
