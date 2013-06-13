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
use Pod::Usage;

use Net::DNS 0.49;
use Net::DNS::SEC 0.12;

use Crypt::OpenSSL::Random qw(random_bytes);
use Digest::SHA1 qw(sha1);
use Digest::BubbleBabble qw(bubblebabble);

use dnssec_monitor;

use constant PROGNAME => "dnssec_monitor";
use constant VERSION  => $dnssec_monitor::VERSION;

######################################################################

sub main {
    my $help    = 0;
    my $version = 0;
    my $debug   = 0;
    my $quiet   = 0;

    my $zone;
    my $ksk_expire_critical = 7;
    my $ksk_expire_warning  = 14;
    my $zsk_expire_critical = 1;
    my $zsk_expire_warning  = 3;
    my $enable_wildcard     = 0;
    my $enable_nsec3        = 0;

    GetOptions(
        'help|?'        => \$help,
        'version|v'     => \$version,
        'zone=s'        => \$zone,
        'kskcritical=i' => \$ksk_expire_critical,
        'kskwarning=i'  => \$ksk_expire_warning,
        'zskcritical=i' => \$zsk_expire_critical,
        'zskwarning=i'  => \$zsk_expire_warning,
        'wildcard'      => \$enable_wildcard,
        'nsec3'         => \$enable_nsec3,
        'debug+'        => \$debug,
        'quiet|q'       => \$quiet
    ) or pod2usage(2);
    pod2usage(1) if ($help);

    if ($version) {
        printf("%s %s\n", PROGNAME, VERSION);
        exit(-1);
    }

    pod2usage(1) unless ($zone);

    # initialize NS list for zone
    my @nameservers;
    if ($#ARGV >= 0) {
        @nameservers = @ARGV;
    } else {
        @nameservers = get_ns($zone);
    }

    # create nonexisting domain name
    my @tmp = split(/-/, bubblebabble(Digest => sha1(random_bytes(64))));
    my $nonexisting = sprintf("%s.%s", join("", @tmp[1 .. 6]), $zone);

    my %args = (
        quiet               => $quiet,
        debug               => $debug,
        ksk_expire_critical => $ksk_expire_critical,
        ksk_expire_warning  => $ksk_expire_warning,
        zsk_expire_critical => $zsk_expire_critical,
        zsk_expire_warning  => $zsk_expire_warning,
    );

    my $errors = 0;

    for my $ns (@nameservers) {
        print "Checking $ns ...\n" unless ($quiet);

        my $c = new dnssec_monitor($zone, $ns, %args);

        $errors++ unless ($c->report($c->check_apex_rrsig()));
        $errors++ unless ($c->report($c->check_exist($zone, "SOA")));
        $errors++ unless ($c->report($c->check_exist($zone, "NS")));
        $errors++
          unless (
            $c->report(
                $c->check_nxdomain(
                    $nonexisting, "NS", $enable_wildcard, $enable_nsec3
                )
            )
          );
    }

    exit($errors);
}

sub get_ns {
    my $zone = shift;

    my $res = Net::DNS::Resolver->new;

    my @n = ();
    my @a = ();

    my $packet = $res->send($zone, "NS");
    return () unless $packet;
    foreach my $rr ($packet->answer) {
        push @n, $rr->nsdname if ($rr->type eq "NS");
    }

    foreach my $ns (@n) {
        $packet = $res->query($ns, "A");
        next unless $packet;
        foreach my $rr ($packet->answer) {
            push @a, $rr->address if ($rr->type eq "A"
                or $rr->type eq "AAAA");
        }
    }

    return @a;
}

sub uniq {
    my %u;

    foreach my $x (@_) {
        $u{$x} = "";
    }

    return keys %u;
}

main;

__END__

=head1 NAME

dnssec_monitor - simple DNSSEC monitor

=head1 SYNOPSIS

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


=head1 ABSTRACT

dnssec-monitor will check integrity of the zone DNSKEYs, SOA and NS.
It will also generate a random domain name and verify that a NSEC
record is generated for negative answers. NSEC3 is not supported.
