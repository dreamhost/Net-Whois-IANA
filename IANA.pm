package Net::Whois::IANA;

use 5.006;
use strict;
use warnings;
use IO::Socket;
use Carp;
use Exporter;

our @IANA = qw(ripe apnic lacnic arin);

our %IANA = (apnic=>
	     ['whois.apnic.net',43,30],
	     ripe=>
	     ['whois.ripe.net',43,30],
	     arin=>
	     ['whois.arin.net',43,30],
	     lacnic=>
	     ['whois.lacnic.net',43,30]
	    );


our @ISA = qw(Exporter);

our @EXPORT= qw(
		@IANA
		%IANA
		whois_query
		descr
		netname
		country
		inetnum
		status
		source
		server
		fullinfo
	       );

our $VERSION = '0.04';

sub new {

    my $proto = shift;
    my $class = ref $proto || $proto;
    my $self = {};

    bless $self,$class;
    return $self;
}

sub descr    {my $self = shift; return $self->{QUERY}->{descr}
		if defined $self->{QUERY}->{descr}};
sub netname  {my $self = shift; return $self->{QUERY}->{netname}
		if defined $self->{QUERY}->{netname}};
sub country  {my $self = shift; return $self->{QUERY}->{country}
		if defined $self->{QUERY}->{country}};
sub inetnum  {my $self = shift; return $self->{QUERY}->{inetnum}
		if defined $self->{QUERY}->{inetnum}};
sub status   {my $self = shift; return $self->{QUERY}->{status}
		if defined $self->{QUERY}->{status}};
sub source   {my $self = shift; return $self->{QUERY}->{source}
		if defined $self->{QUERY}->{source}};
sub server   {my $self = shift; return $self->{QUERY}->{server}
		if defined $self->{QUERY}->{server}};
sub fullinfo {my $self = shift; return $self->{QUERY}->{fullinfo}
		if defined $self->{QUERY}->{fullinfo}};

sub whois_query {

    my $self = shift;
    my %param = @_;
    my %source = %IANA;
    my @source = @IANA;

    if (! $param{-ip}) {
	print 'Usage: $iana->whois_query(-ip=>$ip,-whois=>$whois|-mywhois=>\%mywhois)';
	print "\n";
    }
    if ($param{-whois}) {
	%source = ();
	$source{$param{-whois}} = $IANA{$param{-whois}};
	@source = ($param{-whois});
    }
    if ($param{-mywhois}) {
	%source = ();
	%source = %{$param{-mywhois}};
	@source = keys %{$param{-mywhois}};
    }
    for my $server (@source) {
	my $host    = ${$source{$server}}[0];
	my $port    = ${$source{$server}}[1];
	my $timeout = ${$source{$server}}[2];
	my $sock = &whois_connect($host,$port,$timeout);
	my %query;
	if ($server eq 'ripe') {
	    %query = &ripe_query($sock,$param{-ip});
	}
	elsif ($server eq 'apnic') {
	    %query = &apnic_query($sock,$param{-ip});
	}
	elsif ($server eq 'arin') {
	    %query = &arin_query($sock,$param{-ip});
	}
	elsif ($server eq 'lacnic') {
	    %query = &lacnic_query($sock,$param{-ip});
	}
	else {
	    %query = &default_query($sock,$param{-ip});
	}
	next if (! %query);
	if ($query{permission} eq 'denied') {
	    warn "Warning: permission denied at $server server $host\n";
	    next;
	}
	$query{server} = uc $server;
	for (sort keys %query) {
	    chomp $query{$_};
	}
	$self->{QUERY} = \%query;
	return $self;
    }
    return {};
}
sub default_query {

    return &ripe_query(@_);
}
sub ripe_query {

    my $sock = shift;
    my $ip = shift;
    my %query = ();

    $query{fullinfo} = '';
    print $sock "-r $ip\n";
    while (<$sock>) {
	$query{fullinfo} .= $_;
	if (/^\%201/) {
	    close $sock;
	    return (permission=>'denied');
	}
	next if (/^\%/);
	next if (!/\:/);
	last if (/^route/);
	s/\s+$//;
	my ($field,$value) = split(/:/);
	$value =~ s/^\s+//;
	$query{$field} .= $value;
    }
    $query{permission} = 'allowed';
    close $sock;
    if (defined $query{remarks} && $query{remarks} =~ /The country is really worldwide/) {
	%query = ();
    }
    return %query;
}
sub apnic_query {

    my $sock = shift;
    my $ip = shift;
    my %query = ();
    my %tmp;

    $query{fullinfo} = '';
    print $sock "-r $ip\n";
    while (<$sock>) {
	$query{fullinfo} .= $_;
	if (/^\%201/) {
	    close $sock;
	    return (permission=>'denied');
	}
	next if (/^\%/);
	next if (!/\:/);
	s/\s+$//;
	my ($field,$value) = split(/:/);
	$value =~ s/^\s+//;
	if ($field eq 'inetnum') {
	    %tmp = %query;
	    %query = ();
	    $query{fullinfo} = $tmp{fullinfo};
	}
	$query{$field} .= $value;
    }
    for (keys %tmp) {
	if (! defined $query{$_}) {
	    $query{$_} = $tmp{$_};
	}
    }
    $query{permission} = 'allowed';
    close $sock;
    if (defined $query{remarks} && $query{remarks} =~ /address range is not administered by APNIC/) {
	%query = ();
    }
    if (defined $query{descr} && $query{descr} =~/Not allocated by APNIC/i) {
	%query = ();
    }
    return %query;
}
sub arin_query {

    my $sock = shift;
    my $ip = shift;
    my %query = ();
    my %tmp = ();

    $query{fullinfo} = '';
    print $sock "+ $ip\n";
    while (<$sock>) {
	$query{fullinfo} .= $_;
	if (/^\#201/) {
	    close $sock;
	    return (permission=>'denied');
	}
	next if (/^\#/);
	next if (!/\:/);
	s/\s+$//;
	my ($field,$value) = split(/:/);
	$value =~ s/^\s+//;
	if ($field eq 'OrgName') {
	    %tmp = %query;
	    %query = ();
	    $query{fullinfo} = $tmp{fullinfo};
	}
	$query{lc($field)} .= $value;
    }
    for (keys %tmp) {
	if (! defined $query{$_}) {
	    $query{$_} = $tmp{$_};
	}
    }
    $query{permission} = 'allowed';
    close $sock;
    if (defined $query{comment} && $query{comment} =~ /This IP address range is not registered in the ARIN/) {
	%query = ();
    }
    else {
	if (defined $query{orgid} && $query{orgid} =~/RIPE|LACNIC|APNIC/) {
	    %query = ();
	}
	else {
	    $query{descr}   = $query{orgname};
	    $query{remarks} = $query{comment};
	    $query{status}  = $query{nettype};
	    $query{inetnum} = $query{netrange};
	    $query{source}  = 'ARIN';
	}
    }
    return %query;
}
sub lacnic_query {

    my $sock = shift;
    my $ip = shift;
    my %query = ();

    $query{fullinfo} = '';
    print $sock "$ip\n";
    while (<$sock>) {
	$query{fullinfo} .= $_;
	if (/^\%201/) {
	    close $sock;
	    return (permission=>'denied');
	}
	if (/^\% Not assigned to LACNIC/) {
	    close $sock;
	    return ();
	}
	next if (/^\%/);
	next if (!/\:/);
	last if (/^nic\-hdl/);
	s/\s+$//;
	my ($field,$value) = split(/:/);
	$value =~ s/^\s+//;
	$query{lc($field)} .= $value;
    }
    $query{permission} = 'allowed';
    close $sock;
    $query{descr} = $query{owner};
    $query{netname} = $query{ownerid};
    $query{source} = 'LACNIC';
    return %query;
}
sub whois_connect {

    my ($host,$port,$timeout) = @_;

    my $sock = IO::Socket::INET->new(
				     PeerAddr=>$host,
                                     PeerPort=>$port,
                                     Timeout=>$timeout,
                                    );
    unless($sock) {
        carp("Cannot to connect to $host at port $port");
	carp("$@");
        sleep(5);
        $sock = IO::Socket::INET->new(
                                      PeerAddr=>$host,
                                      PeerPort=>$port,
                                      Timeout=>$timeout,
                                     );
        unless($sock) {
            croak("Cannot to connect to $host at port $port for the seco
nd time");
	    croak("$@");
        }
    }
    return($sock);
}
1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::Whois::IANA - A universal WHOIS data extractor.

=head1 SYNOPSIS

  use Net::Whois::IANA;
  my $ip = '132.66.16.2';
  my $iana = new Net::Whois::IANA;
  $iana->whois_query(-ip=>$ip);
  print "Country: " . $iana->country() . "\n";;
  print "Netname: " . $iana->netname() . "\n";;
  print "Descr: "   . $iana->descr()   . "\n";;
  print "Status: "  . $iana->status()  . "\n";;
  print "Source: "  . $iana->source()  . "\n";;
  print "Server: "  . $iana->server()  . "\n";;
  print "Inetnum: " . $iana->inetnum() . "\n";;


=head1 ABSTRACT

  This is a simple module to extract the descriptive whois
information about various IPs as they are stored in the four
regional whois registries of IANA - RIPE (Europe, Middle East,
North Africa), APNIC (Asia/Pacific), ARIN (North America and
Africa) and LACNIC (Latin American & Caribbean).

  It is designed to serve statistical harvesters of various
access logs and likewise, therefore it only collects partial
and [rarely] unprecise information.

=head1 DESCRIPTION

  Various Net::Whois and IP:: modules have been created.
This is just something I had to write because none of them s
uited my purpose. It is conceptually based on Net::Whois::IP
by Ben Schmitz <bschmitz@orbitz.com>, but differs from it by
a few points:

  * It is object-oriented.
  * It has a few immediate methods for representing some whois
  fields.
  * It allows the user to specify explicitly which whois servers
  to query, and those servers might even not be of the four main
  registries mentioned above.
  * It has more robust error handling.

  Net::Whois::IANA was designed to provide a mechanism to lookup
whois information and store most descriptive part of it (descr,
netname and country fields) in the object. This mechanism is
supposed to be attached to a log parser (for example an Apache
web server log) to provide various accounting and statistics
information.

  The query is performed in a roundrobin system over all four
registries until a valid entry is found. The valid entry stops
the main query loop and the object with information is returned.
Unfortunately, the output formats of each one of the registries
is not completely the same and sometimes even unsimilar but
some common ground was always found and the assignment of the
information into the query object is based upon this common
ground, whatever misleading it might be.

  The query to the RIPE and APNIC registries are always performed
with a '-r' flag to avoid blocking of the querying IP. Thus, the
contact info for the given entry is not obtainable with this
module. The query to the ARIN registry is performed with a '+'
flag to force the colon-separated output of the information.

=head2 EXPORT

  For the convenience of the user, basic list of IANA servers
(@IANA) and their mapping to host names and ports (%IANA) are
being exported.

  Also the following methods are being exported:

  $iana->whois_query(-ip=>$ip,-whois=>$whois|-mywhois=>\%mywhois) :

    Perform the query on the ip specified by $ip. You can limit
  the lookup to a single server (of the IANA list) by specifying
  '-whois=>$whois' pair or you can provide a set of your own
  servers by specifying the '-mywhois=>\%mywhois' pair. The latter
  one overrides all of the IANA list for lookup.

  $iana->descr()

    Returns some of the "descr:" field contents of the queried IP.

  $iana->netname()

    Returns the "netname:" field contents of the queried IP.

  $iana->country()

    Returns "country:" field contents of the queried IP. Useful
  to combine with the Geography::Countries module.

  $iana->inetnum()

    Returns the "inetnum:" field contents of the queried IP.

  $iana->status()

    Returns the "status:" field contents of the queried IP.

  $iana->source()

    Returns the "source:" field contents of the queried IP.

  $iana->server()

    Returns the server that returned most valuable ntents of
  the queried IP.

  $iana->fullinfo()

    Returns the complete output of the query.

=head1 BUGS

  As stated many times before, this module is not completely
homogeneous and precise because of the differences between
outputs of the IANA servers and because of some inconsistencies
within each one of them. Its primary target is to collect info
for general, shallow statistical purposes.

=head1 SEE ALSO

  Net::Whois::IP, Net::Whois::RIPE, IP::Country, Geography::Countries

=head1 AUTHOR

Roman M. Parparov, E<lt>romm@empire.tau.ac.il<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Roman M. Parparov

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
