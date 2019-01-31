#!/usr/bin/perl
#
# Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
#                    All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
######################################################################

require 5.8.0;
use warnings;
use strict;

use Pod::Usage;
use Getopt::Long;
use Net::DNS;

######################################################################

sub main {
    my $help    = 0;
    my $debug   = 0;
    my $timeout = 10;

    my $zone;
    my $server;

    GetOptions(
        'help|?'    => \$help,
        'zone=s'    => \$zone,
        'server=s'  => \$server,
        'timeout=i' => \$timeout,
        'debug+'    => \$debug
    ) or die;

    pod2usage(2) if ($help);
    die "need zone and server" unless ($zone && $server);

    my $res = Net::DNS::Resolver->new;

    $res->debug(1) if ($debug > 1);
    $res->recurse(0);
    $res->tcp_timeout($timeout);
    $res->nameservers($server);

    my $i = $res->axfr($zone);
    if (! defined $i) {
        my $error = $res->errorstring;

        if ($error =~ /NOTAUTH/) {
            printf("WARNING: server not authoritative for $zone\n");
            exit(1);
        }

        if ($error =~ /REFUSED/) {
            printf("OK: zone transfer refused\n");
            exit(0);
        }

        printf("WARNING: %s\n", $res->errorstring);
        return 1;
    }

    if ($i->()) {
        printf("CRITICAL: zone transfer possible\n");
        exit(2);
    }

    exit(1);
}

main;

=head1 NAME

nagios_noaxfr.pl - Nagios NOAXFR Plugin

=head1 SYNOPSIS

nagios_noaxfr.pl --zone zonename --server nameserver

        --zone zone         The zone to test (required argument)
        --server server     Name server
        --debug             Debug mode
        --timeout=i         Timeout

=head1 AUTHOR

.SE

=head1 LICENCE AND COPYRIGHT

Copyright (c) .SE, The Internet Infrastructure Foundation (2010) <hostmaster@iis.se>

BSD License.

=cut
