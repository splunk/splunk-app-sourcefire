package OutputPlugins::pcap;

use strict;
use warnings;

use Data::Dumper;

use SFStreamer;

my $info = {
    init => \&init,
    output => \&output,
    description => "Stores packet captures as a pcap file",
    flags => $FLAG_PKTS | $FLAG_SEND_ARCHIVE_TIMESTAMP,
};

sub register{
    return $info;
}

sub init{
    my ($opts) = @_;

    # redirect output or use STDOUT
    if($opts->{filename}){
        open OUT, ">", $opts->{filename} or die "Unable to open $opts->{filename} for writing";
    }else{
        die "Packet capture requires an output file to be specified";
    }

    # if they requested host info, change which flags we request
    if($opts->{host}){
        die "Host querying is incompatible with this output method";
    }

    # print header
    my $pcap_header = "";
    $pcap_header .= pack("L", hex("a1b2c3d4"));         # magic
    $pcap_header .= pack("S", 2);                       # major version
    $pcap_header .= pack("S", 4);                       # minor version
    $pcap_header .= pack("L", 0);                       # timezone
    $pcap_header .= pack("L", 0);                       # timestamp accuracy
    $pcap_header .= pack("L", hex("1ffff"));            # snaplen
    $pcap_header .= pack("L", 1);                       # data link type
    print OUT $pcap_header;
}

sub output{
    my $rec = shift;

    if($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "PACKET"){
        my $packet_header = "";
        $packet_header .= pack("L", $rec->{"packet_sec"}); # tv_sec
        $packet_header .= pack("L", $rec->{"packet_usec"});# tv_usec
        $packet_header .= pack("L", $rec->{"packet_len"}); # caplen
        $packet_header .= pack("L", $rec->{"packet_len"}); # pktlen

        my $pcap_packet = $packet_header . $rec->{'packet_data'};

        #print "outputing pcap to a file...\n"; # DEBUG
        print OUT $pcap_packet;
        autoflush OUT 1;
        
    }
}

1;
