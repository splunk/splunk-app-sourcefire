package OutputPlugins::splunk;

use strict;
use warnings;

use Data::Dumper;
use SFStreamer;

my $info = {
    init => \&init,
    output => \&output,
    description => "Prints IDS events in Splunk (key=value) format",
    flags => $FLAG_IDS | $FLAG_METADATA_4 | $FLAG_POLICY_EVENTS_5 | $FLAG_RUA | $FLAG_RNA_EVENTS_5 | $FLAG_SEND_ARCHIVE_TIMESTAMP,
};

sub register{
    return $info;
}

sub init{
    my ($opts) = @_;

    # redirect output or use STDOUT
    if($opts->{filename}){
        open OUT, ">", $opts->{filename} or die "Unable to open $opts->{filename} for writing";
        autoflush OUT 1;
    }else{
        *OUT = *STDOUT;
    }

    # if they requested host info, don't request events.  Instead only get metadata records.
    if($opts->{host}){
        $info->{flags} = $FLAG_METADATA_4;
    }
}

sub output{
    my ($rec) = @_;
    my @fields;

    # EVENT record type
    if ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "EVENT") {
        # timestamp
        push @fields, scalar(localtime($rec->{event_sec}));
        push @fields, "archive_timestamp=$rec->{header}{archive_timestamp}";
        # print key=value pairs
        foreach my $key (@{$rec->{'order'}}){
            push @fields, "$key=".$rec->{$key} unless $key eq "pad";
        }
    # RULE record type
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "RULE") {
        push @fields, "gen=$rec->{'generator_id'}";
        push @fields, "rule_id=$rec->{'rule_id'}";
        push @fields, "rev=$rec->{'rule_rev'}";
        push @fields, "sid=$rec->{'signature_id'}";
        push @fields, "rule_msg=\"$rec->{'msg'}\"";
    # DETECTION ENGINE record type
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "DETECTION ENGINE") {
        push @fields, "sensor_id=$rec->{'id'}";
        push @fields, "sensor_name=\"$rec->{'name_string_data'}\"";
        push @fields, "sensor_desc=\"$rec->{'desc_string_data'}\"";
    # PRIORITY record type
    } elsif ($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "PRIORITY") {
        push @fields, "priority=$rec->{'priority_id'}";
        push @fields, "priority_name=$rec->{'name'}";
    }
    
    print OUT join(" ", @fields), "\n";
    autoflush OUT 1;
}

1;