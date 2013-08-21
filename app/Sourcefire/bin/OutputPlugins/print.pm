package OutputPlugins::print;

use strict;
use warnings;

use Data::Dumper;

use SFStreamer;

my $info = {
    init => \&init,
    output => \&output,
    description => "Prints events in a human-readable format",
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
    }else{
        *OUT = *STDOUT;
    }

    # if they requested host info, don't request events.  Instead only get metadata records.
    if($opts->{host}){
        $info->{flags} = $FLAG_METADATA_4;
    }
}

#
# Pretty-print output
#
sub output{
    my ($rec) = @_;

    # Protect terminal from binary output.
    # For packet capturing, use pcap output mode
    my $rec_type = $SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}};
    if (defined $rec_type && $rec_type eq "PACKET")
    {
        $rec->{"packet_data"} = "Intentionally removed.";
    }

    # Make the timestamp pretty print
    if($rec->{header}{archive_timestamp}){
        $rec->{header}{archive_timestamp} = gmtime($rec->{header}{archive_timestamp});
    }

    print_block($rec->{header});
    print OUT "=============\n";
    print_block($rec);

    if (SFStreamer::is_rna_rec_type($rec))
    {
        my $rnablock = SFStreamer::parse_rna_record($rec);
        if(%$rnablock){
            print OUT "rna_block:\n";
            print_block($rnablock, 1);
        }
    }
    print OUT "\n*************\n\n";
}

sub print_block
{
    my ($rec, $indent) = @_;
    $indent = 0 if (!defined($indent));

    foreach my $key (  @{$rec->{'order'}} )
    {
        print OUT " " x (4 * $indent);
        print OUT "$key: ";
        if (defined $rec->{$key})
        {
            if (ref ($rec->{$key}) eq 'ARRAY')
            {
                print OUT "\n";
                foreach (@{$rec->{$key}})
                {
                    print_block( $_, $indent + 1);
                }
            }
            elsif (ref ($rec->{$key}) eq 'HASH')
            {
                print OUT "\n";
                print_block($rec->{$key}, $indent + 1);
            }
            else
            {
                # clean out unprintable characters
                my $value = $rec->{$key};
                $value =~ s/[[:cntrl:]]/ /g;

                print OUT $value;
                if($key eq 'block_type'){
                    print OUT " ($rec->{name})";
                }elsif($key eq 'msg_type'){
                    print OUT " ($SFStreamer::MESSAGE_TYPES->{$rec->{'msg_type'}})";
                }elsif($key eq 'rec_type'){
                    my $rec_type = $SFStreamer::RECORD_TYPES->{$rec->{'rec_type'}} || "UNKNOWN";
                    print OUT " ($rec_type)";
                }elsif($key eq 'event_subtype'){
                    my ($type, $subtype) = ($rec->{'event_type'}, $rec->{'event_subtype'});
                    if(!defined $type || !defined $subtype){
                        die "Unknown record type";
                    }
                    print OUT " ($SFStreamer::RNA_TYPE_NAMES->{$type}->{$subtype})";
                }
                print OUT "\n";
            }
        }
        else
        {
            print OUT "undef\n";
        }
    }
}

1;
