use Test::Simple tests=>2;
use Net::Whois::IANA;
my $iana = new Net::Whois::IANA;
my $ip = '202.12.29.13';
$iana->whois_query(-ip=>$ip,-whois=>'apnic');
ok(defined $iana);
ok($iana->country() eq 'AU');

