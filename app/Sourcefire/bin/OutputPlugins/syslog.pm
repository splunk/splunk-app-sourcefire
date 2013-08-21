package OutputPlugins::syslog;

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
my $LOGGER              = "logger";

#
# End of configurable section
#


my $info = {
    init => \&init,
    output => \&output,
    description => "Sends IDS events to the local syslog server",
    flags => $FLAG_IDS | $FLAG_METADATA_4 | $FLAG_SEND_ARCHIVE_TIMESTAMP,
};

# time last event was sent
my $last;

# hash containing bundled low priority events
my %delay;

# keep rule metadata
my %rule_map;

sub register{
    return $info;
}

sub init{
    my ($opts) = @_;

    # redirect output or use STDOUT
    if($opts->{filename}){
        open OUT, ">", $opts->{filename} or die "Unable to open $opts->{filename} for writing";
    }else{
        *OUT = *STDOUT;
    }

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
            send_syslog($rec, 1);
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
            send_syslog($delay{$key}[0], $delay{$key}[1]);
        }
        %delay = ();
    }
}

# send syslog event
sub send_syslog{
    my ($rec, $cnt) = @_;

    my @cmd = (
        $LOGGER,
        'AlertPriority', $rec->{'priority'},
        'SourceIp', $rec->{'src_addr'},
        'DestinationIp', $rec->{'dst_addr'},
        'sfAlertCount', $cnt,
        'SourcePort', $rec->{'src_port'},
        'DestinationPort', $rec->{'dst_port'},
        'EventMessage', $MSG_CUSTOM . $rule_map{$rec->{'gen'}.":".$rec->{'sid'}},
    );

    system(@cmd);
}

1;
