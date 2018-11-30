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

package dnssec_monitor;

require 5.8.0;

use warnings;
use strict;

use Net::DNS 0.49;
use Net::DNS::SEC 0.12;
use Date::Parse;
use POSIX qw(strftime);

######################################################################

our $VERSION = "1.0";

my %default = (
    debug               => 0,
    quiet               => 0,
    bufsize             => 4096,
    ksk_expire_critical => 7,
    ksk_expire_warning  => 14,
    zsk_expire_critical => 1,
    zsk_expire_warning  => 3,
    dstport             => 53,
);

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};

    my $zone   = shift;
    my $ns     = shift;
    my %config = @_;

    foreach my $k (keys %default) {
        if (defined $config{$k}) {
            $self->{$k} = $config{$k};
        } else {
            $self->{$k} = $default{$k};
        }
    }

    $self->{zone} = $zone;
    $self->{ns}   = $ns;

    $self->{resolver} = Net::DNS::Resolver->new;

    $self->{resolver}->recurse(0);
    $self->{resolver}->dnssec(1);
    $self->{resolver}->defnames(0);
    $self->{resolver}->udp_timeout(3);
    $self->{resolver}->tcp_timeout(3);
    $self->{resolver}->nameservers($self->{ns});
    $self->{resolver}->udppacketsize($self->{bufsize});
    $self->{resolver}->port($self->{dstport});

    if ($self->{debug} >= 1) {
        $self->{quiet} = 0;
    }

    if ($self->{debug} >= 2) {
        $self->{resolver}->{debug} = 1;
    }

    $self->{message} = undef;
    $self->{error}   = undef;

    bless $self, $class;
    return $self;
}

sub _init {
    my $self = shift;

    $self->_reset();
    $self->initialize_keyset() unless ($self->{ksk} && $self->{zsk});
}

sub _reset {
    my $self = shift;

    $self->{message} = undef;
    $self->{error}   = undef;
}

sub report {
    my $self   = shift;
    my $result = shift;

    if ($self->{error}) {
        print $self->{error}, "\n" unless ($self->{quiet});
    }

    if ($self->{message}) {
        print $self->{message}, "\n" unless ($self->{quiet});
    }

    return $result;
}

sub trusted_key ($) {
    my $self = shift;
    my $keys = shift;

    if ($keys) {
        $self->{ksk} = @{$keys};
    } else {
        return @{ $self->{ksk} };
    }
}

sub initialize_keyset () {
    my $self = shift;

    my $qname = $self->{zone};
    my $qtype = "DNSKEY";

    my $result;

    my @ksk = ();
    my @zsk = ();

    my @sig    = ();
    my @answer = ();

    $self->_reset();

    printf STDERR "initialize_keys($qname,$qtype)\n" if ($self->{debug});

    # fetch zone KSK/ZSK from zone apex
    my $packet = $self->{resolver}->send($qname, $qtype);

    if (!$packet) {
        $self->{error} = "$qname/IN/$qtype lookup failure";
        return 0;
    }

    if ($packet->header->rcode ne "NOERROR") {
        $self->{error} = "$qname/IN/$qtype not found";
        return 0;
    }

    foreach my $rr ($packet->answer) {
        if ($rr->type eq "RRSIG") {
            push @sig, $rr;
            next;
        }

        if ($rr->type eq $qtype) {
            push @answer, $rr;
        }

        if (    $rr->type eq $qtype
            and $rr->protocol == 3
            and $rr->flags & 0x0100)
        {

            if ($rr->flags & 0x01) {
                push @ksk, $rr;
            } else {
                push @zsk, $rr;
            }
        }
    }

    unless (scalar @answer > 0) {
        $self->{error} = "$qname/IN/$qtype, bad answer section";
        return 0;
    }

    unless (scalar @sig > 0) {
        $self->{error} = "$qname/IN/$qtype, no signatures found";
        return 0;
    }

    # initialize KSK & ZSK
    @{ $self->{ksk} } = @ksk unless ($self->{ksk});
    @{ $self->{zsk} } = @zsk;

    unless (scalar @{ $self->{ksk} } > 0) {
        $self->{error} = "$qname/IN/$qtype no KSK found";
        return 0;
    }

    unless (scalar @{ $self->{zsk} } > 0) {
        $self->{error} = "$qname/IN/$qtype no ZSK found";
        return 0;
    }

    # verify signatures using available KSK
    my $verified_ksk =
      verify_answer(\@answer, \@sig, \@{ $self->{ksk} }, $self->{debug});

    # verify signatures using available ZSK
    my $verified_zsk =
      verify_answer(\@answer, \@sig, \@{ $self->{zsk} }, $self->{debug});

    if ($verified_zsk && $verified_ksk) {
        $self->{message} = "$qname/IN/$qtype verified";
        return 1;
    } else {
        $self->{error} = "$qname/IN/$qtype failed verification";
        return 0;
    }
}

sub check_apex_rrsig () {
    my $self = shift;

    my $qname = $self->{zone};
    my $qtype = "RRSIG";

    my $result;

    my @answer = ();
    my @sig    = ();

    $self->_init();

    printf STDERR "check_apex_rrsig($qname,$qtype)\n" if ($self->{debug});

    # fetch zone KSK/ZSK from zone apex
    my $packet = $self->{resolver}->send($qname, $qtype);

    if (!$packet) {
        $self->{error} = "$qname/IN/$qtype lookup failure";
        return 0;
    }

    if ($packet->header->rcode ne "NOERROR") {
        $self->{error} = "$qname/IN/$qtype not found";
        return 0;
    }

    foreach my $rr ($packet->answer) {
        if ($rr->type eq "RRSIG") {
            push @sig, $rr;
            next;
        }
    }

    unless (scalar @sig > 0) {
        $self->{error} = "$qname/IN/$qtype no signatures found";
        return 0;
    }

    my $check_ksk = $self->_check_expire(
        \@sig, $self->{ksk},
        $self->{ksk_expire_critical},
        $self->{ksk_expire_warning}
    );
    return 0 unless ($check_ksk);

    my $check_zsk = $self->_check_expire(
        \@sig, $self->{zsk},
        $self->{zsk_expire_critical},
        $self->{zsk_expire_warning}
    );
    return 0 unless ($check_zsk);
}

sub _check_expire () {
    my $self     = shift;
    my $rrsig    = shift;
    my $keys     = shift;
    my $critical = shift;
    my $warning  = shift;

    my $now = time();

    $self->_reset();

    printf STDERR "check_rrsig(...)\n" if ($self->{debug});

    foreach my $s (@{$rrsig}) {

        my ($inception, $expiration) = rrsig2time($s);
        my $days = ($expiration - $now) / (60 * 60 * 24);

        printf STDERR (
            "expire %s = %.2f days\n",
            strftime("%Y-%m-%d %H:%M:%S", gmtime($expiration)),
            ($expiration - $now) / (60 * 60 * 24)
        ) if ($self->{debug});

        foreach my $k (@{$keys}) {
            if ($s->keytag == $k->keytag) {

                if ($days < 0) {
                    $self->{error} =
                      sprintf("CRITICAL: %s RRSIG %s %s has expired",
                        $s->signame, $s->typecovered, keyinfo($k), $days);
                    return 0;
                }
                if ($critical && $days <= $critical) {
                    $self->{error} =
                      sprintf(
                        "CRITICAL: %s RRSIG %s %s will expire in %.1f days",
                        $s->signame, $s->typecovered, keyinfo($k), $days);
                    return 0;
                }
                if ($warning && $days <= $warning) {
                    $self->{error} =
                      sprintf(
                        "WARNING: %s RRSIG %s %s will expire in %.1f days",
                        $s->signame, $s->typecovered, keyinfo($k), $days);
                    return 0;
                }
            }
        }
    }

    return 1;
}

sub check_exist {
    my $self  = shift;
    my $qname = shift;
    my $qtype = shift;

    my @sig    = ();
    my @answer = ();

    $self->_init();

    printf STDERR "check_exist($qname,$qtype)\n" if ($self->{debug});

    # fetch qname/IN/qtype
    my $packet = $self->{resolver}->send($qname, $qtype);

    if (!$packet) {
        $self->{error} = "$qname/IN/$qtype lookup failure";
        return 0;
    }

    if ($packet->header->rcode ne "NOERROR") {
        $self->{error} = "$qname/IN/$qtype not found";
        return 0;
    }

    foreach my $rr ($packet->answer) {
        if (    $rr->type eq "RRSIG"
            and $rr->typecovered eq $qtype)
        {
            push @sig, $rr;
            next;
        }
        if ($rr->type eq $qtype) {
            push @answer, $rr;
            next;
        }
    }

    unless (scalar @answer > 0) {
        $self->{error} = "$qname/IN/$qtype, bad answer section";
        return 0;
    }

    unless (scalar @sig > 0) {
        $self->{error} = "$qname/IN/$qtype, no signatures found";
        return 0;
    }

    # verify signatures using available ZSK
    my $verified_zsk =
      verify_answer(\@answer, \@sig, \@{ $self->{zsk} }, $self->{debug});

    if ($verified_zsk) {
        $self->{message} = "$qname/IN/$qtype verified";
        return 1;
    } else {
        $self->{error} = "$qname/IN/$qtype failed verification";
        return 0;
    }
}

sub check_nxdomain {
    my $self            = shift;
    my $qname           = shift;
    my $qtype           = shift;
    my $enable_wildcard = shift || 0;
    my $enable_nsec3    = shift || 0;

    my $zone;

    my $authority_by_name  = undef;
    my $signatures_by_name = undef;

    my $negatives  = 0;
    my $signatures = 0;

    $self->_init();

    printf STDERR "check_nonexist($qname,$qtype)\n" if ($self->{debug});

    # fetch qname/IN/qtype
    my $packet = $self->{resolver}->send($qname, $qtype);

    if (!$packet) {
        $self->{error} = "$qname/IN/$qtype lookup failure";
        return 0;
    }

    if (not $enable_wildcard) {
        if ($packet->header->rcode ne "NXDOMAIN") {
            $self->{error} = "$qname/IN/$qtype should not exist";
            return 0;
        }
    }

    # fetch SOA from authority section
    foreach my $rr ($packet->authority) {
        if ($rr->type eq "SOA") {
            $zone = $rr->name;
        }
    }

    unless ($zone) {
        $self->{error} = "no SOA found NXDOMAIN authority section";
        return 0;
    }

    foreach my $rr ($packet->authority) {

        if ($rr->type eq "NSEC" and not $enable_nsec3) {
            push @{ $authority_by_name->{ $rr->name } }, $rr;
            $negatives++;
            next;
        }

        if ($rr->type eq "NSEC3" and $enable_nsec3) {
            push @{ $authority_by_name->{ $rr->name } }, $rr;
            $negatives++;
            next;
        }

        if ($rr->type eq "RRSIG") {
            if (   ($rr->typecovered eq "NSEC" and not $enable_nsec3)
                or ($rr->typecovered eq "NSEC3" and $enable_nsec3))
            {
                push @{ $signatures_by_name->{ $rr->name } }, $rr;
                $signatures++;
            }
            next;
        }
    }

    unless ($negatives > 0) {
        $self->{error} = "no NSEC/NSEC3 found in authority section";
        return 0;
    }

    unless ($signatures > 0) {
        $self->{error} = "no NSEC/NSEC3 RRSIG found";
        return 0;
    }

    # verify signatures using available ZSK
    foreach my $owner (keys %{$authority_by_name}) {
        my $a = $authority_by_name->{$owner};
        my $s = $signatures_by_name->{$owner};

        my $verified_zsk =
          verify_answer($a, $s, \@{ $self->{zsk} }, $self->{debug});

        unless ($verified_zsk) {
            $self->{error} = "$qname/IN/$qtype failed verification (NXDOMAIN)";
            return 0;
        }

    }

    $self->{message} = "$qname/IN/$qtype verified (NXDOMAIN)";
    return 1;
}

sub verify_answer {
    my $answer = shift;
    my $sigs   = shift;
    my $keys   = shift;
    my $debug  = shift;

    my $verified = 0;

    foreach my $s (@$sigs) {
        foreach my $k (@$keys) {
            next unless ($s->keytag == $k->keytag);

            if ($s->verify($answer, $k)) {
                printf STDERR (
                    "%s/IN/%s signed by %s %s - %s \n",
                    $s->name, $s->typecovered, keytype($k), keyinfo($k), "OK"
                ) if ($debug);
                $verified = 1;
            } else {
                printf STDERR (
                    "%s/IN/%s signed %s %s - %s \n",
                    $s->name, $s->typecovered, keytype($k), keyinfo($k),
                    $s->vrfyerrstr
                ) if ($debug);
            }
        }
    }

    return $verified;
}

sub keytype {
    my $key = shift;

    return "ERROR" unless ($key->type eq "DNSKEY");

    if ($key->flags & 0x01) {
        return "KSK";
    } else {
        return "ZSK";
    }
}

sub keyinfo {
    my $key = shift;

    return "ERROR" unless ($key->type eq "DNSKEY");

    return sprintf("%s/%s/%05d",
        $key->name, algorithm2string($key->algorithm),
        $key->keytag);
}

sub rrsig2time {
    my $rrsig = shift;

    my $i = $rrsig->siginception;
    my $e = $rrsig->sigexpiration;

    $i =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:$6/;
    $e =~ s/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/$1:$2:$3 $4:$5:$6/;

    return (str2time($i, "UTC"), str2time($e, "UTC"));
}

sub algorithm2string {
    my $algorithm = shift;

    return "RSASHA1" if ($algorithm == 5);

    return $algorithm;
}

1;
