use Test::Simple tests=>2;
use Net::Whois::IANA;
my $iana = new Net::Whois::IANA;
my $ip = '200.16.98.2';
$iana->whois_query(-ip=>$ip,-whois=>'lacnic');
use Data::Dumper;
print Dumper $iana;
ok(defined $iana);
ok($iana->country() eq 'AR');

