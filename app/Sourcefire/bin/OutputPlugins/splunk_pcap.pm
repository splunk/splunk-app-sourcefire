package OutputPlugins::splunk_pcap;

use strict;
use warnings;

use Data::Dumper;
use XML::Simple;
use SFStreamer;

my $info = {
    init => \&init,
    output => \&output,
    description => "Prints pcap events in Splunk (key=value) format",
    flags => $FLAG_PKTS | $FLAG_SEND_ARCHIVE_TIMESTAMP,
};

my $TSharkLocation;   # The location of tshark binary (e.g. /usr/sbin/tshark, /usr/local/bin/tshark)

sub register{
    return $info;
}

sub init{
    my ($opts) = @_;

    if($opts->{filename}){
        open OUT, ">", $opts->{filename} or die "Unable to open $opts->{filename} for writing";
    }else{
        *OUT = *STDOUT;
    }

    # if they requested host info, change which flags we request
    if($opts->{host}){
        die "Host querying is incompatible with this output method";
    }
    
    if($opts->{tshark}) {
        $TSharkLocation = $opts->{tshark};
    } else {
        die "Splunk Pcap requires a tshark binary location to be specified";
    }
}

# Parsing PDML output
sub parsePktPayload {
    my $proto = shift;
    my $payload = shift;
    my @output;
    
    # Check for undef payload
    if (defined($payload)) {
        foreach my $field_name (keys %{$payload}) {
            my $new_field_name = $field_name;
            if ($field_name eq '') {
                $new_field_name = $proto."_note";
            } else {
                $new_field_name =~ s/\./_/g;
            }
            # prefix $new_field_name, so we can search in Splunk easily.
            $new_field_name = "payload_$new_field_name";
            if (defined($payload->{$field_name}->{'show'})) {
                push @output, "$new_field_name=\"$payload->{$field_name}->{'show'}\"";
            }
        }
    }
    return @output;
}

sub output{
    my $rec = shift;

    if($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "PACKET"){
        my @fields;
        #my $TSharkLocation = "/usr/sbin/tshark";
        #my $TSharkLocation = '"c:/Program Files/Wireshark/tshark"';
        
        # TODO: Rotating pcap files from eStreamer server
        #my $MAX_PCAP_FILES = 10;
        #my $pcap_dir = "../pcap";
        #my @all_pcap_files = glob "$pcap_dir/*_eventid*";
        #my $max_pcap_num = substr($all_pcap_files[-1], rindex($all_pcap_files[-1], ".") + 1);
        #if ($max_pcap_num)
        #my $pcap_file = "$pcap_dir/$pcap_num"."_eventid_".$rec->{'event_id'}.".pcap";
        #open OUT_PCAP, ">", $pcap_file or die "Unable to open $pcap_file for writing";
        
        my $pcap_file = "../tmp/tmp.pcap";
        open OUT_PCAP, ">", $pcap_file or die "Unable to open $pcap_file for writing";
        
        # print pcap header
        my $pcap_header = "";
        $pcap_header .= pack("L", hex("a1b2c3d4"));         # magic
        $pcap_header .= pack("S", 2);                       # major version
        $pcap_header .= pack("S", 4);                       # minor version
        $pcap_header .= pack("L", 0);                       # timezone
        $pcap_header .= pack("L", 0);                       # timestamp accuracy
        $pcap_header .= pack("L", hex("1ffff"));            # snaplen
        $pcap_header .= pack("L", 1);                       # data link type
        
        my $packet_header = "";
        $packet_header .= pack("L", $rec->{"packet_sec"}); # tv_sec
        $packet_header .= pack("L", $rec->{"packet_usec"});# tv_usec
        $packet_header .= pack("L", $rec->{"packet_len"}); # caplen
        $packet_header .= pack("L", $rec->{"packet_len"}); # pktlen
        
        my $pcap_packet = $packet_header . $rec->{'packet_data'};
        print OUT_PCAP $pcap_header . $pcap_packet;
        close OUT_PCAP;
        
        open (TSHARK, '-|', "$TSharkLocation -T pdml -r $pcap_file -l") or die "Cannot open tshark!\n";
        
        my $pdml;
        while (<TSHARK>) {
            # parse pdml output
            $pdml .= $_;
        }
        close TSHARK;
        
        my $simple = XML::Simple->new(ForceArray => 1);
        my $pdml_data = $simple->XMLin($pdml);
        #print Dumper($pdml_data) . "\n";
        
        # There is only one packet processed at a time, so I can just use {'packet'}[0]
        # frame
        push @fields, "frame_time=\"$pdml_data->{'packet'}[0]->{'proto'}->{'frame'}->{'field'}->{'frame.time'}->{'show'}\"";
        push @fields, "frame_number=$pdml_data->{'packet'}[0]->{'proto'}->{'frame'}->{'field'}->{'frame.number'}->{'show'}";
        push @fields, "frame_pkt_len=$pdml_data->{'packet'}[0]->{'proto'}->{'frame'}->{'field'}->{'frame.pkt_len'}->{'show'}";
        push @fields, "frame_len=$pdml_data->{'packet'}[0]->{'proto'}->{'frame'}->{'field'}->{'frame.len'}->{'show'}";
        push @fields, "frame_cap_len=$pdml_data->{'packet'}[0]->{'proto'}->{'frame'}->{'field'}->{'frame.cap_len'}->{'show'}";
        push @fields, "frame_protocols=$pdml_data->{'packet'}[0]->{'proto'}->{'frame'}->{'field'}->{'frame.protocols'}->{'show'}";
        # eth
        push @fields, "eth_src=$pdml_data->{'packet'}[0]->{'proto'}->{'eth'}->{'field'}->{'eth.src'}->{'show'}";
        push @fields, "eth_dst=$pdml_data->{'packet'}[0]->{'proto'}->{'eth'}->{'field'}->{'eth.dst'}->{'show'}";
        push @fields, "eth_type=$pdml_data->{'packet'}[0]->{'proto'}->{'eth'}->{'field'}->{'eth.type'}->{'show'}";
        # ip
        if (defined($pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.version'}->{'show'})) {
            push @fields, "ip_version=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.version'}->{'show'}";
            push @fields, "ip_hdr_len=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.hdr_len'}->{'show'}";
            push @fields, "ip_len=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.len'}->{'show'}";
            push @fields, "ip_id=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.id'}->{'show'}";
            push @fields, "ip_flags=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.flags'}->{'show'}";
            push @fields, "ip_frag_offset=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.frag_offset'}->{'show'}";
            push @fields, "ip_ttl=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.ttl'}->{'show'}";
            push @fields, "ip_proto=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.proto'}->{'show'}";
            push @fields, "ip_src=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.src'}->{'show'}";
            push @fields, "ip_dst=$pdml_data->{'packet'}[0]->{'proto'}->{'ip'}->{'field'}->{'ip.dst'}->{'show'}";
        }
        # tcp/udp/payload
        foreach my $proto (keys %{$pdml_data->{'packet'}[0]->{'proto'}}) {
            if ($proto eq 'tcp') {
                push @fields, "tcp_src_port=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.srcport'}->{'show'}";
                push @fields, "tcp_dst_port=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.dstport'}->{'show'}";
                push @fields, "tcp_len=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.len'}->{'show'}";
                push @fields, "tcp_seq=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.seq'}->{'show'}";
                push @fields, "tcp_hdr_len=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.hdr_len'}->{'show'}";
                push @fields, "tcp_flags=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags'}->{'show'}";
                push @fields, "tcp_flags_res=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.res'}->{'show'}";
                push @fields, "tcp_flags_ns=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.ns'}->{'show'}";
                push @fields, "tcp_flags_cwr=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.cwr'}->{'show'}";
                push @fields, "tcp_flags_ecn=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.ecn'}->{'show'}";
                push @fields, "tcp_flags_urg=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.urg'}->{'show'}";
                push @fields, "tcp_flags_ack=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.ack'}->{'show'}";
                push @fields, "tcp_flags_push=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.push'}->{'show'}";
                push @fields, "tcp_flags_reset=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.reset'}->{'show'}";
                push @fields, "tcp_flags_syn=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.syn'}->{'show'}";
                push @fields, "tcp_flags_fin=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.flags.fin'}->{'show'}";
                push @fields, "tcp_window_size=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.window_size'}->{'show'}";
                push @fields, "tcp_options_mss=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.options.mss'}->{'show'}";
                push @fields, "tcp_options_mss_val=$pdml_data->{'packet'}[0]->{'proto'}->{'tcp'}->{'field'}->{'tcp.options.mss_val'}->{'show'}";
            } elsif ($proto eq 'udp') {
                push @fields, "udp_src_port=$pdml_data->{'packet'}[0]->{'proto'}->{'udp'}->{'field'}->{'udp.srcport'}->{'show'}";
                push @fields, "udp_dst_port=$pdml_data->{'packet'}[0]->{'proto'}->{'udp'}->{'field'}->{'udp.dstport'}->{'show'}";
                push @fields, "udp_length=$pdml_data->{'packet'}[0]->{'proto'}->{'udp'}->{'field'}->{'udp.length'}->{'show'}";
            } elsif ($proto ne 'geninfo' && $proto ne 'frame' && $proto ne 'eth' && $proto ne 'ip') {
                push @fields, parsePktPayload($proto, $pdml_data->{'packet'}[0]->{'proto'}->{$proto}->{'field'});
                foreach my $field_name (keys %{$pdml_data->{'packet'}[0]->{'proto'}->{$proto}->{'field'}}) {
                    push @fields, parsePktPayload($proto, $pdml_data->{'packet'}[0]->{'proto'}->{$proto}->{'field'}->{$field_name}->{'field'});
                    foreach my $field_name2 (keys %{$pdml_data->{'packet'}[0]->{'proto'}->{$proto}->{'field'}->{$field_name}->{'field'}}) {
                        push @fields, parsePktPayload($proto, $pdml_data->{'packet'}[0]->{'proto'}->{$proto}->{'field'}->{$field_name}->{'field'}->{$field_name2}->{'field'});
                    }
                }
            }
        }

        foreach my $key (@{$rec->{'order'}}) {
            if ($key ne "packet_data") {
                unshift @fields, "$key=$rec->{$key}";
            }
        }
        
        unshift @fields, scalar(localtime($rec->{event_sec}));
        
        print OUT join(" ", @fields), "\n";
        autoflush OUT 1;
    }
}

1;