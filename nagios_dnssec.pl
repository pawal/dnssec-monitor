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

use Crypt::OpenSSL::Random qw(random_bytes);
use Digest::SHA1 qw(sha1);
use Digest::BubbleBabble qw(bubblebabble);

use Pod::Usage;
use Getopt::Long;

use dnssec_monitor;

######################################################################

sub main {
    my $debug = 0;
    my $help = 0;

    my $zone;
    my $ksk_expire_critical = 7;
    my $ksk_expire_warning  = 14;
    my $zsk_expire_critical = 1;
    my $zsk_expire_warning  = 3;
    my $dstport             = 53;
    my $enable_wildcard     = 0;
    my $enable_nsec3        = 0;

    GetOptions(
	'help|?'     => \$help,
        'zone=s'        => \$zone,
        'kskcritical=i' => \$ksk_expire_critical,
        'kskwarning=i'  => \$ksk_expire_warning,
        'zskcritical=i' => \$zsk_expire_critical,
        'zskwarning=i'  => \$zsk_expire_warning,
        'debug+'        => \$debug,
        'dstport=i'     => \$dstport,
        'wildcard'      => \$enable_wildcard,
        'nsec3'         => \$enable_nsec3,
    ) or die;

    pod2usage(2) if ($help);
    die "no zone"       unless ($zone);
    die "no nameserver" unless ($#ARGV == 0);

    my %args = (
        quiet               => 1,
        debug               => $debug,
        ksk_expire_critical => $ksk_expire_critical,
        ksk_expire_warning  => $ksk_expire_warning,
        zsk_expire_critical => $zsk_expire_critical,
        zsk_expire_warning  => $zsk_expire_warning,
        dstport             => $dstport,
    );

    my $ns = shift @ARGV;
    my $c = new dnssec_monitor($zone, $ns, %args);

    # create nonexisting domain name
    my @tmp = split(/-/, bubblebabble(Digest => sha1(random_bytes(64))));
    my $nonexisting = sprintf("%s.%s", join("", @tmp[1 .. 6]), $zone);

    #### NAGIOS CHECKS ####

    unless ($c->check_apex_rrsig()) {
        nagios($c->{error});
    }

    unless ($c->check_exist($zone, "SOA")) {
        nagios($c->{error});
    }

    unless ($c->check_exist($zone, "NS")) {
        nagios($c->{error});
    }

    unless ($c->check_nxdomain($nonexisting, "NS", $enable_wildcard, $enable_nsec3)) {
        nagios($c->{error});
    }

    nagios("OK: Looking good");
}

sub nagios {
    $_ = shift;

    if (/^WARNING: (.*)/) {
        print "DNSSEC WARNING: $1\n";
        exit(1);
    }

    if (/^CRITICAL: (.*)/) {
        print "DNSSEC CRITICAL: $1\n";
        exit(2);
    }

    if (/^UNKNOWN: (.*)/) {
        print "DNSSEC UNKNOWN: $1\n";
        exit(0);
    }

    if (/^OK: (.*)/) {
        print "DNSSEC OK: $1\n";
        exit(0);
    }

    if (/^(.*)/) {
        print "DNSSEC CRITICAL: $1\n";
        exit(2);
    }

    exit(-1);
}

main;

=head1 NAME

nagios_dnssec.pl - Nagios DNSSEC Plugin

=head1 SYNOPSIS

nagios_dssec.pl --zone zonename nameserver

        --zone zone         The zone to test (required argument)
        --kskcritical=i     KSK critical (days)
        --kskwarning=i      KSK warning (days)
        --zskcritical=i     ZSK critical (days)
        --zskwarning=i      ZSK warning (days)
        --debug             Debug mode
        --dstport=i         Destination port on name server (53 is default)

=head1 AUTHOR

.SE

=head1 LICENCE AND COPYRIGHT

Copyright (c) .SE, The Internet Infrastructure Foundation (2010) <hostmaster@iis.se>

BSD License.

=cut
