use Test::Simple tests=>2;
use Net::Whois::IANA;
my $iana = new Net::Whois::IANA;
my $ip = '193.0.0.135';
$iana->whois_query(-ip=>$ip,-whois=>'ripe');
ok(defined $iana);
ok($iana->country() eq 'NL');

