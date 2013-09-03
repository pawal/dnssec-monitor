#!/usr/bin/perl
#
# Copyright (c) 2011-2012 Jakob Schlyter, Kirei AB. All rights reserved.
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

use strict;
use Net::DNS;
use Date::Format;
use Pod::Usage;
use Getopt::Long;
use Data::Dumper;

my $debug    = 0;
my %hostname = ();

my $do_help;
my $do_nagios      = 0;
my $do_absolute    = 0;
my $delta_warning  = 60;
my $delta_critical = 120;

sub main {
    GetOptions(
        'help|?'     => \$do_help,
        'debug'      => \$debug,
        'nagios'     => \$do_nagios,
        'absolute'   => \$do_absolute,
        'warning=i'  => \$delta_warning,
        'critical=i' => \$delta_critical,
    ) or pod2usage(2);
    pod2usage(1) if ($do_help);
    pod2usage(2) unless ($#ARGV >= 0);

    my $domain = shift @ARGV;

    # append mising trailing dot
    $domain = $domain . "." if ($domain !~ /\.$/);

    # name server addresses
    my @addr = nameservers($domain);

    # find timestamp deltas
    exit(timestamp($domain, @addr));
}

sub nameservers {
    my $qname = shift;

    my @res      = ();
    my $resolver = Net::DNS::Resolver->new;

    my $query = $resolver->query($qname, "NS");

    if ($query) {
        foreach my $rr (grep { $_->type eq 'NS' } $query->answer) {
            printf STDERR ("%s IN NS %s.\n", $qname, $rr->nsdname) if $debug;
            push @res, addresses($rr->nsdname);
        }
    } else {
        printf STDERR ("No nameservers found for %s\n", $qname) if $debug;
        exit(-1);
    }

    return @res;
}

sub addresses {
    my $qname = shift;

    my @res      = ();
    my $resolver = Net::DNS::Resolver->new;

    my $query = $resolver->query($qname, "A");
    if ($query) {
        foreach my $rr (grep { $_->type eq 'A' } $query->answer) {
            printf STDERR ("%s IN A %s\n", $qname, $rr->address) if $debug;
            push @res, $rr->address;
            $hostname{ $rr->address } = $qname;
        }
    }

    my $query = $resolver->query($qname, "AAAA");
    if ($query) {
        foreach my $rr (grep { $_->type eq 'AAAA' } $query->answer) {
            printf STDERR ("%s IN AAAA %s\n", $qname, $rr->address) if $debug;
            push @res, $rr->address;
            $hostname{ $rr->address } = $qname;
        }
    }

    return @res;
}

sub timestamp {
    my $domain = shift;
    my @nsaddr = @_;

    my $resolver = Net::DNS::Resolver->new;

  NAMESERVER:
    foreach my $ns (@nsaddr) {
        $resolver->nameservers($ns);
        $resolver->recurse(0);

        # create SOA query for domain and sign with dummy TSIG
        my $query = Net::DNS::Packet->new($domain, "SOA", "IN");
        $query->sign_tsig("name", "secret");
	@{[$query->additional]}[0]->algorithm; # temporary fix for Net::DNS
        my $now = time();

        my $response = $resolver->send($query);

        unless ($response) {
            printf STDERR ("No response from %s\n", $ns) if $debug;
            next;
        }

        foreach my $rr ($response->additional) {

            if ($rr->type eq "TSIG") {
                my $diff = $rr->time_signed - $now;

                if ($do_nagios) {
                    return 2 if ($diff > $delta_critical);
                    return 1 if ($diff > $delta_warning);
                    return 0;
                } else {
                    my $diff_s = "";
                    $diff_s = $diff    if ($diff < 0);
                    $diff_s = "+$diff" if ($diff > 0);

                    if ($do_absolute) {
                        my $ts = time2str("%Y:%m:%d %H:%M:%S", $rr->time_signed,
                            "UTC");
                        printf("%-50s  %s %s\n",
                            sprintf("%s (%s)", $hostname{$ns}, $ns),
                            $ts, $diff_s);
                    } else {
                        printf("%-60s  %10d\n",
                            sprintf("%s (%s)", $hostname{$ns}, $ns), $diff);

                    }
                    next NAMESERVER;
                }
            }
        }

        printf STDERR ("No TSIG reply from %s\n", $ns) if $debug;
    }
}

main();

__END__

=head1 NAME

ns-timestamp.pl - Name Server Timestamp

=head1 SYNOPSIS

ns-timestamp.pl [options] domain

Options:

 --help           brief help message
 --nagios         exit with Nagios return codes (OK, CRITICAL, WARNING)
 --warning=N      warning if time diff is > N seconds
 --critical=N     critical if time diff is > N seconds
 --absolute       output absolut time
