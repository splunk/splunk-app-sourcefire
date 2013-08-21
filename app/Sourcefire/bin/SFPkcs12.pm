# This package splits a pkcs12 file into key and crt files for use w/ the
# IO::Socket::SSL library

package SFPkcs12;

use strict;

my $verbose = 0;
my $DEFAULT_CRT_FILE = './server.crt';
my $DEFAULT_KEY_FILE = './server.key';

sub cleanUp
{
    verbose("Removing temporary CRT and KEY files\n");
    unlink $DEFAULT_CRT_FILE if (-e $DEFAULT_CRT_FILE);
    unlink $DEFAULT_KEY_FILE if (-e $DEFAULT_KEY_FILE);
}

sub processPkcs12
{
    my $opts = $_[0];

    defined($opts->{verbose}) ? ($verbose = $opts->{verbose}) : ($verbose = 0);
    $opts->{file} = findPkcs12File() if (!defined($opts->{file}));
    $opts->{password} = ''         if(!defined($opts->{password}));

    my $nodes = extractNodes($opts->{file}, $opts->{password});
    writeFile($DEFAULT_CRT_FILE, $nodes->{cert});
    writeFile($DEFAULT_KEY_FILE, $nodes->{key});
    return ($DEFAULT_CRT_FILE, $DEFAULT_KEY_FILE);
}

#
# Private functions below here
#

sub findPkcs12File
{
    my @pkcs = glob('*.pkcs12');
    my $rval = shift(@pkcs);
    die "SFPkcs12 : Unable to automatically locate pkcs12 file\n\n" unless ($rval =~ /pkcs12$/);
    verbose("Found $rval\n");
    return $rval;
}

sub extractNodes
{
    my ($pkcs12_file, $password) = @_;
    my $lines;
    my $rval;

    verbose("Processing $pkcs12_file\n");

    #
    # Slurp the whole file and strip out the stuff we dont want.
    #
    local $/;
    open SSLFH, '-|', "openssl pkcs12 -nodes -passin pass:$password -in $pkcs12_file 2> /dev/null" or die "SFPkcs12 : Unable to exec Openssl : $!\n\n";
    $lines = <SSLFH>;
    close SSLFH;

    $rval->{cert} = $rval->{key} = $lines;

    $rval->{cert} =~ s/^.*?(-----BEGIN CERTIFICATE-----.*)$/$1/s;
    $rval->{cert} =~ s/^(.+?-----END CERTIFICATE-----).*$/$1/s;
    $rval->{cert} .= "\n";


    $rval->{key} =~ s/^.*(-----BEGIN RSA PRIVATE KEY-----.*)$/$1/s;
    $rval->{key} =~ s/^(.+?-----END RSA PRIVATE KEY-----).*$/$1/s;
    $rval->{key} .= "\n";

    die "SFPkcs12 : Unable to get certificate\n\n"
        unless (defined($rval->{cert}) && $rval->{cert} =~ /BEGIN/);
    die "SFPkcs12 : Unable to get key\n\n"
        unless (defined ($rval->{key}) && $rval->{key} =~ /BEGIN/);

    return $rval;
}

sub writeFile
{
    my ($fname, $cert) = @_;

    verbose("Writing $fname\n");
    open  OUTFILE, '>', $fname or die "SFPkcs12 : Unable to open file : $fname : $!\n\n";
    print OUTFILE $cert;
    close OUTFILE;
}

sub verbose
{
    my $msg = $_[0];

    return unless $verbose;
    warn "SFPkcs12 : $msg";
}

1;
