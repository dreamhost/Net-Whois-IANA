use Test::Simple tests=>2;
#use Net::Whois::IANA;
use IANA;
my $iana = new Net::Whois::IANA;
my $ip = '200.160.2.15';
$iana->whois_query(-ip=>$ip,-whois=>'lacnic');
ok(defined $iana);
ok($iana->country() eq 'BR');

