use Test::Simple tests=>2;
use Net::Whois::IANA;
my $iana = new Net::Whois::IANA;
my $ip = '196.216.2.1';
$iana->whois_query(-ip=>$ip,-whois=>'afrinic');
ok(defined $iana);
ok($iana->country() eq 'ZA');

