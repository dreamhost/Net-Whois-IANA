use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::Whois::IANA',
    'VERSION_FROM'	=> 'IANA.pm', # finds $VERSION
    'PREREQ_PM'		=> {
			    Net::CIDR=>'0.05',
			    Bit::Vector=>'6.4',
			   }, # e.g., Module::Name => 1.1
    ($] >= 5.006 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'IANA.pm', # retrieve abstract from module
       AUTHOR     => 'Roman M. Parparov <romm@empire.tau.ac.il>') : ()),
);
