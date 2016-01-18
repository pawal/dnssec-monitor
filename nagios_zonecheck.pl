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

use Getopt::Long;

use Net::DNS 0.49;
use Net::DNS::SEC 0.12;
use Date::Parse;

######################################################################

sub main {
    my $debug = 0;
    my $help = 0;

    my $zone;
    my $expire_critical;
    my $expire_warning;
    my $tsig;
    my $count;

    GetOptions(
	'help|?'     => \$help,
        'zone=s'     => \$zone,
        'critical=i' => \$expire_critical,
        'warning=i'  => \$expire_warning,
        'count=i'    => \$count,
        'tsig=s'     => \$tsig,
        'debug+'     => \$debug
    ) or die;

    pod2usage(2) if ($help);
    die "no zone"   unless ($zone);
    die "no master" unless ($#ARGV == 0);

    my $master = shift @ARGV;

    my $res = Net::DNS::Resolver->new;

    if ($tsig) {
        my ($name, $key) = split(/:/, $tsig);
        $res->tsig($name, $key);
    }

    $res->debug(1) if ($debug > 1);

    $res->recurse(0);
    $res->nameservers($master);
    $res->axfr_start($zone);

    my $rr;
    my $now = time();

    my $expire_min;
    my $nsigs    = 0;
    my $warnings = 0;

  AXFR:
    while ($rr = $res->axfr_next) {
        next unless ($rr->type eq "RRSIG");

        $nsigs++;

        my ($inception, $expiration) = rrsig2time($rr);
        my $days = int(($expiration - $now) / (60 * 60 * 24));

        printf STDERR (
            "RRSIG(%s/IN/%s) expires in %.1f days\n",
            $rr->name, $rr->typecovered, $days
        ) if ($debug);

        $expire_min = $days if (!defined($expire_min) || $expire_min > $days);

        if ($days < 0) {
            printf("CRITICAL: signatures has expired\n");
            exit(2);
        }

        if ($expire_critical && $days <= $expire_critical) {
            printf("CRITICAL: some signatures will expire in %d days\n",
                $expire_min);
            exit(2);
        }

        if ($expire_warning && $days <= $expire_warning) {
            $warnings++;
        }

        last AXFR if ($count && $nsigs >= $count);
    }

    if ($warnings) {
        printf("WARNING: some signatures will expire in %d days\n",
            $expire_min);
        exit(1);
    }

    unless ($nsigs > 0) {
        printf("CRITICAL: no signatures found\n");
        exit(2);
    }

    printf("OK: minimum signature expire in %d days\n", $expire_min);
    exit(0);
}

sub rrsig2time {
    my $rrsig = shift;

    my $i = $rrsig->siginception;
    my $e = $rrsig->sigexpiration;

    $i =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:$6/;
    $e =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:$6/;

    return (str2time($i, "UTC"), str2time($e, "UTC"));
}

main;

=head1 NAME

nagios_zonecheck.pl - Nagios Zonecheck Plugin

=head1 SYNOPSIS

nagios_zonecheck.pl --zone zonename nameserver

        --zone zone         The zone to test (required argument)
        --critical=i        Number of days until Critical 
        --warning=i         Number of days until Warning
        --count=i           Max number of signatures to check
        --tsig=s            TSIG for AXFR
        --debug             Debug mode

=head1 AUTHOR

.SE

=head1 LICENCE AND COPYRIGHT

Copyright (c) .SE, The Internet Infrastructure Foundation (2010) <hostmaster@iis.se>

BSD License.

=cut
