use Test::Simple tests=>2;
use Net::Whois::IANA;
my $iana = new Net::Whois::IANA;
my $ip = '192.149.252.43';
$iana->whois_query(-ip=>$ip,-whois=>'arin');
ok(defined $iana);
ok($iana->country() eq 'US');

