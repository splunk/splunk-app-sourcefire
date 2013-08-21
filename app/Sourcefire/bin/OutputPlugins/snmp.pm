package OutputPlugins::snmp;

use strict;
use warnings;

use Data::Dumper;

use SFStreamer;

#
# Semi-configurable values
#

# The minimum priority to send traps on immediately
my $MIN_PRIORITY        = 2;

# any event with a priority greater than or equal to
# this will be completely suppressed
my $PRIORITY_SUPPRESS   = 10;

# Number of secs to delay sending non critical events
my $ALERT_DELAY         = 120;

# This will be prepended to all message texts
my $MSG_CUSTOM          = "Sourcefire Alert ";

# The path to the 'logger' binary
my $SNMPTRAP            = "snmptrap";

# Where the MIB can be found
my $MIB_PATH            = "./SF_CUSTOM_ALERT.MIB";

# What community string to use
my $COMMUNITY_STRING    = "sf_community";

#
# End of configurable section
#

my $info = {
    init => \&init,
    output => \&output,
    description => "Sends IDS events to the specified snmp server (use -f)",
    flags => $FLAG_IDS | $FLAG_METADATA_4 | $FLAG_SEND_ARCHIVE_TIMESTAMP,
};

# time last event was sent
my $last;

# hash containing bundled low priority events
my %delay;

# keep rule metadata
my %rule_map;

# trap server
my $trap_server;

sub register{
    return $info;
}

sub init{
    my ($opts) = @_;

    # Use "filename" to be the host to use as an SNMP server
    if(!$opts->{filename}){
        die "Trap server required (use -f <hostname>)";
    }
    $trap_server = $opts->{filename};

    # if they requested host info, change which flags we request
    if($opts->{host}){
        die "Host querying is incompatible with this output method";
    }

    # catch current time
    $last = time;
}

sub output{
    my ($rec) = @_;

    if (($rec->{'rec_type'} == $SFStreamer::RECORD_EVENT) || ($rec->{'rec_type'} == $SFStreamer::RECORD_EVENT2)){
        # Events are logged or queued, depending on priority.

        if ($rec->{'priority'} <= $MIN_PRIORITY) {
            # If the priority is greater than min priority send a message
            send_snmp($rec, 1);
        } else {
            # Not a high enough priority to send now
            # Hold it until later
            $delay{$rule_map{$rec->{'gen'}.":".$rec->{'sid'}}}[0] = $rec;
            $delay{$rule_map{$rec->{'gen'}.":".$rec->{'sid'}}}[1] += 1;
        }
    } elsif ($rec->{'rec_type'} == $SFStreamer::SIGNATURE_MESSAGE_V2) {
        # Rules are stored to be referenced later
        $rule_map{$rec->{'generator_id'}.":".$rec->{'rule_id'}} = $rec->{'msg'};
    }

    # send delayed alerts
    my $now = time;
    if (($now - $last) >= $ALERT_DELAY) {
        $last = $now;
        foreach my $key (keys %delay) {
            send_snmp($delay{$key}[0], $delay{$key}[1]);
        }
        %delay = ();
    }
}

# send snmp trap
sub send_snmp{
    my ($rec, $cnt) = @_;

    # Build a DateTime for the trap
    # This is a completely odd way to handle years
    (my $sec, my $min, my $hour, my $mday, my $mon, my $year, my $wday, my $yday, my $isdst) = localtime($rec->{'event_sec'});
    $year += 1900;
    $mon += 1;
    my $yy = sprintf("%02d", $year % 100);
    my $cc = sprintf("%02d", ($year - $yy) / 100);
    my $datetimestr = sprintf("%02x%02x%02x%02x%02x%02x%02x%02x", $yy, $cc, $mon, $mday, $hour, $min, $sec, $rec->{'event_usec'} / 100000);

    my @cmd = (
        $SNMPTRAP,
        '-v2c',
        '-m', '+'.$MIB_PATH,
        '-c', $COMMUNITY_STRING,
        $trap_server,
        'uptime', 'sfEvent',
        'sfAlertPriority', 'i', $rec->{'priority'},
        'sfSourceIpString', 's', $rec->{'src_addr'},
        'sfDestinationIpString', 's', $rec->{'dst_addr'},
        'sfAlertCount', 'u', $cnt,
        'sfAlertDateAndTime', 'x', $datetimestr,
        'sfSignatureGenerator', 'u', $rec->{'gen'},
        'sfSignatureId', 'u', $rec->{'sid'},
        'sfSignatureRevision', 'u', $rec->{'rev'},
        'sfIpProtocol', 'i', $rec->{'ip_proto'},
        'sfSourcePort', 'i', $rec->{'src_port'},
        'sfDestinationPort', 'i', $rec->{'dst_port'},
        'sfSourceIP', 'x', unpack('H8', Socket::inet_aton($rec->{'src_addr'})),
        'sfDestinationIP', 'x', unpack('H8', Socket::inet_aton($rec->{'dst_addr'})),
        'sfEventMessage', 's', $MSG_CUSTOM . $rule_map{$rec->{'gen'}.":".$rec->{'sid'}},
    );

    system(@cmd);
}

1;
