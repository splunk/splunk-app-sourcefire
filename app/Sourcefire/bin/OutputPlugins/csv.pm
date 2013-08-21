package OutputPlugins::csv;

use strict;
use warnings;

use Data::Dumper;

use SFStreamer;

my $info = {
    init => \&init,
    output => \&output,
    description => "Prints IDS events in CSV format",
    flags => $FLAG_IDS | $FLAG_SEND_ARCHIVE_TIMESTAMP,
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
        *OUT = *STDOUT;
    }

    # if they requested host info, change which flags we request
    if($opts->{host}){
        die "Host querying is incompatible with this output method";
    }

    # print header line
    print OUT join("|", @{$SFRecords::event_record->{order}}), "\n";
}

sub output{
    my ($rec) = @_;

    if($SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} eq "EVENT"){
        my @fields;
        foreach my $key (@{$rec->{'order'}}){
            push @fields, $rec->{$key};
        }
        print OUT join("|", @fields), "\n";
    }
}

1;
