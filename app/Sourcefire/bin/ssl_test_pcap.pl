#!/usr/bin/perl
#
# See README and/or run script for usage infomation
#
use strict;
use warnings;
use Data::Dumper;
use File::Copy;
use Getopt::Long;
use Socket;
use IO::Socket::SSL;

# Load the SF modules
use SFStreamer;
$SFStreamer::debug = 0;
use SFPkcs12;

# Look to see if the IPv6 libs are available
my $IP6_THERE;
eval {
    require Socket6;
    require IO::Socket::INET6;
};
$IP6_THERE = 1 unless $@;

#
# "Constants"
#
my $DEFAULT_PORT     = 8302;
my $BOOKMARK_FILE    = './estreamer_pcap.bmark';

#
# Set signal handler to break event loop and drop to cleanup
#
my $SIG_RECEIVED = undef;
$SIG{TERM} = \&signalHandler;
$SIG{INT}  = \&signalHandler;
$SIG{HUP}  = \&signalHandler;

# Get output methods
my %PLUGINS;
my $OUTPUT_PLUGIN;
registerPlugins();

##############################################################################
#                            Begin Main                                      #
##############################################################################

#
# Grab command line options
#
my $cli_opt = processCommandLine();

#
# Process the pkcs12
#
verbose("Setting up auth certificate\n");
my $pkcs12_opts;
$pkcs12_opts->{file} = $cli_opt->{pkcs12_file} if (defined $cli_opt->{pkcs12_file});
$pkcs12_opts->{password} = $cli_opt->{pkcs12_password} if (defined $cli_opt->{pkcs12_password});
$cli_opt->{verbose} ? ($pkcs12_opts->{verbose} = 1) : ($pkcs12_opts->{verbose} = 0);
my ($crtfile, $keyfile) = SFPkcs12::processPkcs12($pkcs12_opts);

#
# Open the bookmark file and grab the last bookmark
#
my ($bookmark_fh, $last_timestamp) = openBookmark($BOOKMARK_FILE);
verbose("Starting bookmark is $last_timestamp\n");

#
# Connect to server
#
verbose("Connecting to $cli_opt->{server} port $cli_opt->{port} \n");
my $client = new IO::Socket::SSL( Domain        => $cli_opt->{domain},
                                  PeerAddr      => $cli_opt->{server},
                                  PeerPort      => $cli_opt->{port},
                                  Proto         => 'tcp',
                                  SSL_use_cert  => 1,
                                  SSL_cert_file => $crtfile,
                                  SSL_key_file  => $keyfile) or
    die "Can't connect to $cli_opt->{server} port $cli_opt->{port}: ".IO::Socket::SSL::errstr()."\n\n";

#
# Request Events w/ Metadata
#
verbose("Requesting Event Stream\n");
SFStreamer::req_data($client, $last_timestamp, $OUTPUT_PLUGIN->{flags});
if($cli_opt->{host}){
    my $start_ip = ippack($cli_opt->{ip1});
    my $end_ip = ippack($cli_opt->{ip2});

    my $request_type = $FLAG_HOST_SINGLE_V3;
    $request_type = $FLAG_HOST_MULTI_V3 if($start_ip != $end_ip);

    SFStreamer::req_host($client, $request_type, 0, $start_ip, $end_ip);
}

#
# Main event loop
#
verbose("Entering Event Loop\n");
eval{
    while (!defined($SIG_RECEIVED))
    {
        my $record;

        # Pull a record off the wire and de-serialize it
        $record = SFStreamer::get_feed($client);

        # Handle data records
        if($record->{'header'}{'msg_type'} == $SFStreamer::TYPE_DATA){
            # Grab the bookamrk
            if (exists($record->{header}{archive_timestamp}))
            {
                $last_timestamp = $record->{header}{archive_timestamp}
                    unless $record->{header}{archive_timestamp} < $last_timestamp;
            }
            
            # send record to output plugin
            output_record($record);

            # Update the Bookmark to the just processed record.
            updateBookmark($bookmark_fh, $last_timestamp) if $last_timestamp;
        }elsif($record->{'header'}{'msg_type'} == $SFStreamer::TYPE_HOST_DATA){
            # send the record to the output plugin
            output_record($record);

             # terminate after outputting this one if a single host record
            $SIG_RECEIVED = 0;
        }elsif($record->{'header'}{'msg_type'} == $SFStreamer::TYPE_MULTI_HOST_DATA){
            # stop looping when a null message is sent
            if($record->{'header'}{'rec_length'} == 0){
                $SIG_RECEIVED = 0;
            }else{
                # send the record to the output plugin
                output_record($record);
            }
        }

        # Ack the last message
        SFStreamer::ack_data($client);
    }
};

if($@){
    warn $@;
};

#
# Clean Up
#
verbose("Received Signal: $SIG_RECEIVED\n") if $SIG_RECEIVED;
verbose("Cleaning Up\n");
close $client;
SFPkcs12::cleanUp();
close $bookmark_fh;

##############################################################################
#                              End Main                                      #
##############################################################################

#
# Open the bookmark file
#
sub openBookmark
{
    my ($filename) = @_;
    my $file_handle;
    my $rval;
    if ($cli_opt->{start} eq 'all')
    {
        $rval->{bmark}=0;
    }
    elsif ($cli_opt->{start} eq 'now')
    {
        $rval->{bmark}=time;
    }
    else
    {
        $rval->{bmark}=time;
        if (-e $filename)
        {
            open $file_handle, '<', $filename or
            die "Unable to open bookmark file ($filename) for reading\n";
            $rval->{bmark} = int(<$file_handle>) || time;
            close $file_handle;
        }
    }
    open $file_handle, '>', $filename or
        die "Unable to open bookmark file: $filename\n";
    $rval->{handle} = $file_handle;
    updateBookmark($rval->{handle}, $rval->{bmark});

    return ($rval->{handle}, $rval->{bmark}) if wantarray;
    return $rval;
}

#
# Write a new time stamp to the bookmark file
#
sub updateBookmark
{
    my ($file_handle, $time_stamp) = @_;
    seek $file_handle, 0, 0 or
        die "Fatal: Unable to reset bookmark file position\n";
    print $file_handle $time_stamp, "\n";
    truncate $file_handle, tell($file_handle) or
        die "Unable to truncate bookmark file\n";
}

#
# Print if verbose flag is set
#
sub verbose
{
    my $msg = $_[0];
    return unless $cli_opt->{verbose};
    warn $msg;
}


#
# Register output plugins
#
sub registerPlugins{
    my @plugins = glob("OutputPlugins/*.pm");
    die "No output plugins found in OutputPlugins directory\n" if !@plugins;

    for my $module (@plugins){
        my ($plugin) = ($module =~ m/OutputPlugins\/(.*)\.pm$/);
        my $info = eval "require OutputPlugins::$plugin; return OutputPlugins::$plugin"."::register();";

        if($info){
            $PLUGINS{$plugin} = $info;
        }else{
            warn "Error loading plugin '$plugin': $@\n";
        }
    }
}


#
# Process the command line
#
sub processCommandLine
{
    my $opts;
    my $ipv6_flag;
    $opts->{port} = $DEFAULT_PORT;
    $opts->{pkcs12_file} = undef;
    $opts->{pkcs12_password} = undef;
    $opts->{verbose} = 0;
    $opts->{start} = 'bookmark';
    $opts->{output} = 'print';
    $opts->{filename} = undef;
    $opts->{host} = undef;
    GetOptions ( "port=i"       => \$opts->{port},
                 "pkcs12=s"     => \$opts->{pkcs12_file},
                 "password=s"   => \$opts->{pkcs12_password},
                 "verbose"      => \$opts->{verbose},
                 "ipv6"         => \$ipv6_flag,
                 "start=s"      => \$opts->{start},
                 "output=s"     => \$opts->{output},
                 "file=s"       => \$opts->{filename},
                 "host=s"       => \$opts->{host},
                 "tshark=s"     => \$opts->{tshark},
               );

    $opts->{start} = 'bookmark' if ($opts->{start} !~ /^(now|all)$/);

    # Toggle IPv6/IPv4 Connectivity
    if ($ipv6_flag)
    {
        die "Required IPv6 perl Modules (Socket6 & IO::Socket::INET6) failed to load\n"
            unless $IP6_THERE;
        $cli_opt->{domain} = "AF_INET6";
    }
    else
    {
        $cli_opt->{domain} = "AF_INET";
    }

    # parse IP options
    if($opts->{host}){
        ($opts->{ip1}, $opts->{ip2}) = split /,/, $opts->{host};
        $opts->{ip2} = $opts->{ip1} if !defined $opts->{ip2};
    }

    # handle output type
    if(!exists $PLUGINS{$opts->{output}}){
        die "Unknown output plugin '$opts->{output}' selected.\n";
    }
    
    $OUTPUT_PLUGIN = $PLUGINS{$opts->{output}};
    &{$OUTPUT_PLUGIN->{init}}($opts);

    #
    # Grab the server from the command line OR usage
    #
    $opts->{server} = shift @ARGV;
    usage() unless (defined $opts->{server});
    return $opts;
}

#
# If we get here...stuff is wrong...print usage and exit non-zero.
#
sub usage
{
    my $prog = $0;
    if ($0 =~ /\/([^\/]+)$/)
    {
        $prog = $1;
    }

    warn "usage: $prog [options] <Server Address>\n";
    warn "Options:\n";
    warn "\t[-po]rt=<server port>               (default: $DEFAULT_PORT)\n";
    warn "\t[-pk]cs12=<path to pkcs12 file>     (default: autodetect)\n";
    warn "\t[-pa]ssword=<pkcs12 password>       (default: none)\n";
    warn "\t[-s]tart=<all | now | bookmark>     (default: bookmark)\n";
    warn "\t[-i]pv6\n";
    warn "\t\tNote: Enabling this will switch communications to IPv6 only\n";
    warn "\t[-o]utput=<plugin name>             (default: print)\n";
    for my $plugin (sort keys %PLUGINS){
        warn "\t\t$plugin\t$PLUGINS{$plugin}{description}\n";
    }
    warn "\t[-f]ile=<output filename>           (Note: required for pcap output)\n";
    warn "\t[-t]shark=<tshark binary>           (Note: required for splunk_pcap output)\n";
    warn "\t[-h]ost=<host1[,host2]>\n";
    warn "\t\tQuery stored RNA host information.\n";
    warn "\t\thost2 is optional, used to select a range.\n";
    warn "\t[-v]erbose\n";

    warn "\n";
    exit (1);
}

#
# Handle signals
#
sub signalHandler
{
    my $sig = shift;
    $sig = defined $sig ? $sig : "UNKNOWN";
    $SIG_RECEIVED = $sig;
}


#
# Pack IP addresses
#
sub ippack
{
    my ($ip) = @_;
    my @ip = split /\./, $ip;
    my $pip= $ip[3] + ($ip[2]*256) + ($ip[1]*65536) + ($ip[0]*16777216);
    return ($pip);
}


#
# Decide which output method to use
#
sub output_record{
    my ($rec) = @_;
    
    &{$OUTPUT_PLUGIN->{output}}($rec);
}
