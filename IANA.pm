package Net::Whois::IANA;

use 5.008;
use strict;
use warnings;
use IO::Socket;
use Carp;
use Exporter;

use Net::CIDR;
use Bit::Vector;

our @IANA = qw(ripe arin apnic afrinic lacnic);

our %IANA = (
	apnic=>[
		['whois.apnic.net',43,30],
	],
	ripe=>[
		['whois.ripe.net',43,30],
	],
	arin=>[
		['192.149.252.44',43,30],
		['whois.arin.net',43,30],
	],
	lacnic=>[
		['whois.lacnic.net',43,30],
	],
	afrinic=>[
		['whois.afrinic.net',43,30],
	],
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
	abuse
	fullinfo
);

our $VERSION = '0.23';

sub new {

    my $proto = shift;
    my $class = ref $proto || $proto;
    my $self = {};

    bless $self,$class;
    return $self;
}

sub descr    {my $self = shift; return $self->{QUERY}{descr} || ''
				  if defined $self->{QUERY}{descr}};
sub netname  {my $self = shift; return $self->{QUERY}{netname} || ''
				  if defined $self->{QUERY}{netname}};
sub country  {my $self = shift; return $self->{QUERY}{country} || ''
				  if defined $self->{QUERY}{country}};
sub inetnum  {my $self = shift; return $self->{QUERY}{inetnum} || ''
				  if defined $self->{QUERY}{inetnum}};
sub status   {my $self = shift; return $self->{QUERY}{status} || ''
				  if defined $self->{QUERY}{status}};
sub source   {my $self = shift; return $self->{QUERY}{source} || ''
				  if defined $self->{QUERY}{source}};
sub server   {my $self = shift; return $self->{QUERY}{server} || ''
				  if defined $self->{QUERY}{server}};
sub cidr     {my $self = shift; return $self->{QUERY}{cidr} || ''
				  if defined $self->{QUERY}{cidr}};
sub abuse    {my $self = shift; return $self->{QUERY}{abuse} || ''
				  if defined $self->{QUERY}{abuse}};
sub fullinfo {my $self = shift; return $self->{QUERY}{fullinfo} || ''
				  if defined $self->{QUERY}{fullinfo}};

sub whois_query {

    my $self = shift;
    my %param = @_;
    my %source = %IANA;
    my @source = @IANA;
    my (
		$a,
		@atom,
	);
    if (! $param{-ip} || $param{-ip} !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
		warn qq{
Usage: \$iana->whois_query(
                          -ip=>\$ip,
                          -debug=>\$debug,
                          -whois=>\$whois|-mywhois=>\%mywhois,
};
		return {};
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
    $self->{QUERY} = {};
    for my $server (@source) {
		print "Querying $server ...\n" if $param{-debug};
		my $sock;
		my $i = 0;
		my $host;
		do {
			$host    = ${$source{$server}}[$i]->[0];
			my $port    = ${$source{$server}}[$i]->[1];
			my $timeout = ${$source{$server}}[$i]->[2];
			$sock = &whois_connect($host,$port,$timeout);
			$i++;
		} until ($sock || defined ${$source{$server}}[$i]);
		next unless $sock;
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
		elsif ($server eq 'afrinic') {
            %query = &afrinic_query($sock,$param{-ip});
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
		for my $qkey (keys %query) {
			next if $qkey eq 'fullinfo';
			if ($qkey =~ /abuse/i && $query{$qkey} =~ /\@/) {
				$query{abuse} = $query{qkey};
				last;
			}
		}
		unless ($query{abuse}) {
			if ($query{fullinfo} =~ /(\S*abuse\S*\@\S+)/m) {
				$query{abuse} = $1;
			}
			elsif ($query{emai} || $query{'e-mail'} || $query{orgtechemail}) {
				$query{abuse} =
					$query{emai} || $query{'e-mail'} || $query{orgtechemail};
			}
		}
		for (sort keys %query) {
			chomp $query{$_} if defined $query{$_};
		}
		$self->{QUERY} = {%query};
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
		if (/ERROR:201/) {
			close $sock;
			return (permission=>'denied');
		}
		next if (/^\%/);
		next if (!/\:/);
		s/\s+$//;
		my ($field,$value) = split(/:/);
		$value =~ s/^\s+//;
		$query{$field} .= $value;
		last if (/^route/);
    }
    close $sock;
    return unless defined $query{country};
    if ((defined $query{remarks} &&
			 $query{remarks} =~ /The country is really world wide/) ||
				 (defined $query{netname} &&
					  $query{netname} =~ /IANA-BLK/) ||
						  (defined $query{netname} &&
							   $query{netname} =~ /AFRINIC-NET-TRANSFERRED/) ||
								   (defined $query{country} &&
										$query{country} =~ /world wide/)) {
		%query = ();
    }
    else {
		$query{permission} = 'allowed';
        @{$query{cidr}} = Net::CIDR::range2cidr($query{inetnum});
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
    close $sock;
    if ((
		defined $query{remarks} &&
		$query{remarks} =~ /address range is not administered by APNIC/) ||
		(defined $query{descr} &&
		($query{descr} =~ /not allocated to|by APNIC/i) ||
		($query{descr} =~ /General placeholder reference/i))) {
		%query = ();
    }
    else {
    	$query{permission} = 'allowed';
		$query{cidr} = [Net::CIDR::range2cidr($query{inetnum})];
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
		return () if /no match found for/i;
		next if (/^\#/);
		next if (!/\:/);
		s/\s+$//;
		my ($field,$value) = split(/:/);
		$value =~ s/^\s+//;
		if ($field eq 'OrgName' ||
				$field eq 'CustName') {
			%tmp = %query;
			%query = ();
			$query{fullinfo} = $tmp{fullinfo};
		}
		$query{lc($field)} .= $value;
    }
    $query{orgname} = $query{custname} if defined $query{custname};
    for (keys %tmp) {
		if (! defined $query{$_}) {
			$query{$_} = $tmp{$_};
		}
    }
    close $sock;
    return () unless $query{country};
    if (defined $query{comment} && $query{comment} =~ /This IP address range is not registered in the ARIN/) {
		%query = ();
    }
    else {
		if (defined $query{orgid} && $query{orgid} =~/RIPE|LACNIC|APNIC/) {
			%query = ();
		}
		else {
			$query{permission} = 'allowed';
			$query{descr}   = $query{orgname};
			$query{remarks} = $query{comment};
			$query{status}  = $query{nettype};
			$query{inetnum} = $query{netrange};
			$query{source}  = 'ARIN';
			if ($query{cidr} =~ /\,/) {
				$query{cidr} = [split(/\, /,$query{cidr})];
			}
			else {
				$query{cidr} = [$query{cidr}];
			}
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
		if (/^\%201/ ||
			/^\% Query rate limit exceeded/ ||
			/\% Permission denied/) {
			close $sock;
			return (permission=>'denied');
		}
		if (/^\% Not assigned to LACNIC/) {
			close $sock;
			return ();
		}
		next if (/^\%/);
		next if (!/\:/);
#		last if (/^nic\-hdl/);
		s/\s+$//;
		my ($field,$value) = split(/:/);
		$value =~ s/^\s+//;
		next if $field eq 'country' && $query{country};
		$query{lc($field)} .= ( $query{lc($field)} ?  ' ' : '') . $value;
    }
    $query{permission} = 'allowed';
    close $sock;
    $query{descr} = $query{owner};
    $query{netname} = $query{ownerid};
    $query{source} = 'LACNIC';
	if ($query{inetnum}) {
		my ($zone, $span) = split(/\//,$query{inetnum});
		my (@atom) = split (/\./,$zone);
		if (scalar @atom < 4) {
			$zone .= '.0' x (4 - scalar @atom);
		}
		$query{cidr} = [$zone . '/' . $span];
		$query{inetnum} = (Net::CIDR::cidr2range(@{$query{cidr}}))[0];
	}
	unless ($query{country}) {
		if ($query{nserver} =~ /\.(\w\w)$/) {
			$query{country} = uc $1;
		}
		elsif ($query{descr} =~ /\s(\w\w)$/) {
			$query{country} = uc $1;
		}
	}
    return %query;
}

sub afrinic_query {

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
#        last if (/^route/);
        s/\s+$//;
        my ($field,$value) = split(/:/);
        $value =~ s/^\s+//;
        $query{$field} .= $value;
    }
    close $sock;
    if ((defined $query{remarks} &&
			 $query{remarks} =~ /country is really worldwide/) ||
				 (defined $query{descr} &&
					  $query{descr} =~ /Here for in-addr.arpa authentication/)) {
        %query = ();
    }
    else {
		$query{permission} = 'allowed';
		@{$query{cidr}} = Net::CIDR::range2cidr($query{inetnum});
    }
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
        carp("Cannot connect to $host at port $port");
		carp("$@");
        sleep(5);
        $sock = IO::Socket::INET->new(
			PeerAddr=>$host,
			PeerPort=>$port,
			Timeout=>$timeout,
		);
        unless($sock) {
            carp("Cannot connect to $host at port $port for the seco
nd time");
			carp("$@");
        }
    }
    return($sock);
}
sub is_mine {

    my (
		$self,
		$ip,
		@cidr,
	) = @_;

    my (
		$ipvec,
		$cidrvec,
		$resvec,
		$cidrip,
		$cidrng,
		$a,
		$c,
		$ivec,
		$cvec,
		@catom,
		@atom,
	);
    
    return () unless $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    @atom = (
		$1,
		$2,
		$3,
		$4,
	);
    for $a (@atom) {
		return {} if $a > 255;
    }
    $self->{atom} = [@atom];

    @cidr = @{$self->cidr()} unless @cidr;
    for $a (@{$self->{atom}}) {
		unless ($ipvec) {
			$ipvec = Bit::Vector->new_Dec(8,$a);
		}
		else {
			$ipvec = Bit::Vector->Concat_List($ipvec,Bit::Vector->new_Dec(8,$a));
		}
    }
    for $c (@cidr) {
		($cidrip,$cidrng) = split(/\//,$c);
		@catom = split(/\./,$cidrip);
		for $a (@catom) {
			unless ($cidrvec) {
				$cidrvec = Bit::Vector->new_Dec(8,$a);
			}
			else {
				$cidrvec = Bit::Vector->Concat_List($cidrvec,Bit::Vector->new_Dec(8,$a));
			}
		}
		$resvec = Bit::Vector->new($cidrng);
		$ivec = $ipvec->Clone();
		$ivec->Interval_Reverse(0,$ipvec->Size()-1);
		$ivec->Resize($cidrng);
		$cvec = $cidrvec;
		$cvec->Interval_Reverse(0,$cidrvec->Size()-1);
		$cvec->Resize($cidrng);
		$resvec->Xor($ivec,$cvec);
		if ($resvec->is_empty()) {
			return $c;
		}
		$cidrvec = undef;
    }
    return 0;
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
  print "CIDR: "    . $iana->cidr()    . "\n";;


=head1 ABSTRACT

  This is a simple module to extract the descriptive whois
information about various IPs as they are stored in the four
regional whois registries of IANA - RIPE (Europe, Middle East)
APNIC (Asia/Pacific), ARIN (North America), AFRINIC (Africa) 
and LACNIC (Latin American & Caribbean).

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
  one overrides all of the IANA list for lookup. You can also set
  -debug option in order to trigger some verbosity in the output.

  $iana->descr()

    Returns some of the "descr:" field contents of the queried IP.

  $iana->netname()

    Returns the "netname:" field contents of the queried IP.

  $iana->country()

    Returns "country:" field contents of the queried IP. Useful
  to combine with the Geography::Countries module.

  $iana->inetnum()

    Returns the IP range of the queried IP. Often it is contained
  within the inetnum field, but it is calculated for LACNIC.

  $iana->status()

    Returns the "status:" field contents of the queried IP.

  $iana->source()

    Returns the "source:" field contents of the queried IP.

  $iana->server()

    Returns the server that returned most valuable ntents of
  the queried IP.

  $iana->cidr()

    Returns the CIDR notation (1.2.3.4/5) of the IP's registered
  range.

  $iana->fullinfo()

    Returns the complete output of the query.

  $iana->is_mine($ip,@cidrrange)

    Checks if the ip is within one of the CIDR ranges given by
  @cidrrange. Returns 0 if none, or the first range that matches.
  Uses Bit::Vector and bit operations extensively.

  $iana->abuse()

    Yields the best guess for the potential abuse report email address
  candidate. This is not a very reliable thing, but sometimes it proves
  useful.

=head1 BUGS

  As stated many times before, this module is not completely
homogeneous and precise because of the differences between
outputs of the IANA servers and because of some inconsistencies
within each one of them. Its primary target is to collect info
for general, shallow statistical purposes. The is_mine() method
might be optimized.

=head1 CAVEATS

  The introduction of AFRINIC server may create some confusion
among servers. It might be that some entries are existant either in
both ARIN and AFRINIC or in both RIPE and AFRINIC, and some do not
exist at all. Moreover, there is a border confusion between Middle
East and Africa, thus, some Egypt sites appear under RIPE and some
under AFRINIC. LACNIC server arbitrarily imposes query rate temporary
block. ARIN "subconciously" redirects the client to appropriate
server sometimes. This redirection is not reflected yet by the package.

=head1 SEE ALSO

  Net::Whois::IP, Net::Whois::RIPE, IP::Country,
  Geography::Countries, Net::CIDR, NetAddr::IP,
  Bit::Vector

=head1 AUTHOR

Roman M. Parparov, E<lt>roman@parparov.com>

=head1 COPYRIGHT AND LICENSE

Copyright 2003-2007 Bolet Consulting <bolet@parparov.com>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
