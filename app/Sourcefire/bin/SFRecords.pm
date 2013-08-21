package SFRecords;

# This module contains the definitions of various message record formats.
# RNA Blocks are defined in SFRNABlocks.pm, which is auto-generated.
#
# See comments at the head of SFStreamer.pm for the format description.

use warnings;
use strict;

#####################################################
# This is the constant format of a record header
# This is used for display purposes only; decoding is hardcoded.
#####################################################
my $record_byte_order = {
    'version'           => 'n',
    'msg_type'          => 'n',
    'msg_length'        => 'N',
    'rec_type'          => 'N',
    'rec_length'        => 'N',
    'archive_timestamp' => 'N',
};

my $record_order = [
    'version',
    'msg_type',
    'msg_length',
    'rec_type',
    'rec_length',
    'archive_timestamp',
];

my $record_map = {
};

our $record = {
    'byte_order'   => $record_byte_order,
    'order'        => $record_order,
    'map'          => $record_map,
};

#####################################################
# This forms the event record structure. The event record is a constant
# so an event_map is not required. order is always required
# because perl does not always return hash elements in the order that they
# were created
#####################################################
# The order of the fields
my $event_order = [
    'sensor_id',
    'event_id',
    'event_sec',
    'event_usec',
    'sid',
    'gen',
    'rev',
    'class',
    'priority',
    'src_addr',
    'dst_addr',
    'src_port',
    'dst_port',
    'ip_proto',
    'impact_flag',
    'pad'
];

# The byte order the fields are expected in
my $event_record_byte_order = {
    'sensor_id'     => 'N',
    'event_id'      => 'N',
    'event_sec'     => 'N',
    'event_usec'    => 'N',
    'sid'           => 'N',
    'gen'           => 'N',
    'rev'           => 'N',
    'class'         => 'N',
    'priority'      => 'N',
    'src_addr'      => 'N',
    'dst_addr'      => 'N',
    'src_port'      => 'n',
    'dst_port'      => 'n',
    'ip_proto'      => 'C',
    'impact_flag'   => 'C',
    'pad'           => 'n'
};


# The conversion map to modify data
# For each filed defined the corresponding code block gets evaluated
# $value is set before the eval and the results of any operations
# on it are returned and placed in the field named

my $event_eval = {
    'src_addr' => 'inet_ntoa(pack("N",$value))',
    'dst_addr' => 'inet_ntoa(pack("N",$value))',
};

# The definition of the event record
# This puts it all together so that parse_record knows what to do
our $event_record = {
    'order'         => $event_order,
    'eval'          => $event_eval,
    'byte_order'    => $event_record_byte_order,
};

#####################################################
# This forms the packet record structure.
# The packet record size is not a constant
# so a packet_map is required
#####################################################
my $packet_order = [
    'sensor_id',
    'event_id',
    'event_sec',
    'packet_sec',
    'packet_usec',
    'link_type',
    'packet_len',
    'packet_data'
];

my $packet_record_byte_order = {
    'sensor_id'     => 'N',
    'event_id'      => 'N',
    'event_sec'     => 'N',
    'packet_sec'    => 'N',
    'packet_usec'   => 'N',
    'link_type'     => 'N',
    'packet_len'    => 'N'
};

#####################################################
# If the value in the map hash element is non 0
# as determined by int() then we will grab that many
# bytes of data for that field otherwise it is
# assumed to be a pointer to a field within the record
# that determines the amount of data to grab
#####################################################
my $packet_map = {
    'packet_data' => 'packet_len'
};

my $packet_eval = {
};

# The definition of the packet record
our $packet_record = {
    'order'             => $packet_order,
    'eval'              => $packet_eval,
    'byte_order'        => $packet_record_byte_order,
    'map'               => $packet_map,
};

#####################################################
#  A classification record. Not a constant size, a map is required
#####################################################
my $classification_order = [
    'class_id',
    'name_length',
    'name',
    'desc_length',
    'desc'
];

my $classification_map = {
    'name' => 'name_length',
    'desc' => 'desc_length'
};

my $classification_record_byte_order = {
    'class_id'      => 'N',
    'name_length'   => 'n',
    'desc_length'   => 'n'
};

our $classification_record = {
    'order'             => $classification_order,
    'byte_order'        => $classification_record_byte_order,
    'map'               => $classification_map,
};

#####################################################
#  A classification record v2
#####################################################
my $classification_2_order = [
    'class_id',
    'name_length',
    'name',
    'desc_length',
    'desc',
    'class_uuid',
    'rev_uuid',
];

my $classification_2_map = {
    'name'              => 'name_length',
    'desc'              => 'desc_length',
    'class_uuid'        => 16,
    'rev_uuid'          => 16,
};

my $classification_2_record_byte_order = {
    'class_id'          => 'N',
    'name_length'       => 'n',
    'desc_length'       => 'n',
};

my $classification_2_eval = {
    'class_uuid'        => 'uuid_to_str($value)',
    'rev_uuid'          => 'uuid_to_str($value)',
};

our $classification_2_record = {
    'order'             => $classification_2_order,
    'byte_order'        => $classification_2_record_byte_order,
    'map'               => $classification_2_map,
    'eval'              => $classification_2_eval,
};

#####################################################
# A priority record. Not a constant size, a map is required
#####################################################
my $priority_order = [
    'priority_id',
    'name_length',
    'name'
];

my $priority_record_byte_order = {
    'priority_id'   => 'N',
    'name_length'   => 'n',
};

my $priority_map = {
    'name' => 'name_length'
};

our $priority_record = {
    'order'             => $priority_order,
    'byte_order'        => $priority_record_byte_order,
    'map'               => $priority_map,
};

#####################################################
# A rule record. Not a constant size, a map is required
#####################################################
my $rule_order = [
    'generator_id',
    'rule_id',
    'rule_rev',
    'msg_len',
    'msg'
];

my $rule_record_byte_order = {
    'generator_id'  => 'N',
    'rule_id'       => 'N',
    'rule_rev'      => 'N',
    'msg_len'       => 'n',
};

my $rule_map = {
    'msg' => 'msg_len'
};

our $rule_record = {
    'order'             => $rule_order,
    'byte_order'        => $rule_record_byte_order,
    'map'               => $rule_map,
};

#####################################################
# Signature Message v2
#####################################################
my $rule_2_order = [
    'generator_id',
    'rule_id',
    'rule_rev',
    'signature_id',
    'msg_len',
    'rule_uuid',
    'rev_uuid',
    'msg'
];

my $rule_2_record_byte_order = {
    'generator_id'      => 'N',
    'rule_id'           => 'N',
    'rule_rev'          => 'N',
    'signature_id'      => 'N',
    'msg_len'           => 'n',
};

my $rule_2_eval = {
    'rule_uuid' => 'uuid_to_str($value)',
    'rev_uuid'  => 'uuid_to_str($value)',
};

my $rule_2_map = {
    'msg'       => 'msg_len',
    'rule_uuid' => 16,
    'rev_uuid'  => 16,
};

our $rule_2_record = {
    'order'             => $rule_2_order,
    'byte_order'        => $rule_2_record_byte_order,
    'map'               => $rule_2_map,
    'eval'              => $rule_2_eval,
};

#####################################################
# An error record. Not a constant size, a map is required
#####################################################

my $error_order = [
    'error_code',
    'error_txt_len',
    'error_txt'
];

my $error_record_byte_order = {
    'error_code'    => 'N',
    'error_txt_len' => 'n'
};


my $error_map = {
    'error_txt' => 'error_txt_len'
};

our $error_record = {
    'order'         => $error_order,
    'byte_order'    => $error_record_byte_order,
    'map'           => $error_map,
};


#####################################################
# Common Metadata Record
#####################################################
my $metadata_record_order = [
    'id',
    'name_string_length',
    'name_string_data',
];

my $metadata_record_byte_order = {
    'id'                        => 'N',
    'name_string_length'        => 'N',
};


my $metadata_record_map = {
    'name_string_data'          => 'name_string_length',
};

our $metadata_record = {
    'map'                       => $metadata_record_map,
    'order'                     => $metadata_record_order,
    'byte_order'                => $metadata_record_byte_order,
};


#####################################################
# Detection Engine Metadata (v2)
#####################################################
my $de_metadata_2_record_order = [
    'id',
    'name_string_length',
    'name_string_data',
    'desc_string_length',
    'desc_string_data',
    'de_uuid',
];

my $de_metadata_2_record_byte_order = {
    'id'                        => 'N',
    'name_string_length'        => 'n',
    'desc_string_length'        => 'n',
};


my $de_metadata_2_record_map = {
    'name_string_data'          => 'name_string_length',
    'desc_string_data'          => 'desc_string_length',
    'de_uuid'                   => 16,
};

my $de_metadata_2_record_eval = {
    'de_uuid'                   => 'uuid_to_str($value)',
};

our $de_metadata_2_record = {
    'map'                       => $de_metadata_2_record_map,
    'eval'                      => $de_metadata_2_record_eval,
    'order'                     => $de_metadata_2_record_order,
    'byte_order'                => $de_metadata_2_record_byte_order,
};


#####################################################
# RUA User Record
#####################################################
my $rua_user_record_order = [
    'id',
    'protocol',
    'name_string_length',
    'name_string_data',
];

my $rua_user_record_byte_order = {
    'id'                        => 'N',
    'protocol'                  => 'N',
    'name_string_length'        => 'N',
};


my $rua_user_record_map = {
    'name_string_data'          => 'name_string_length',
};

our $rua_user_record = {
    'map'                       => $rua_user_record_map,
    'order'                     => $rua_user_record_order,
    'byte_order'                => $rua_user_record_byte_order,
};


#####################################################
# RNA Vulnerability Record
#####################################################
my $vuln_record_order = [
    'vuln_id',
    'impact',
    'exploits',
    'remote',
    'entry_date_length',
    'entry_date_string',
    'published_date_length',
    'published_date_string',
    'modified_date_length',
    'modified_date_string',
    'title_length',
    'title_string',
    'short_desc_length',
    'short_desc_string',
    'desc_length',
    'desc_string',
    'tech_desc_length',
    'tech_desc_string',
];

my $vuln_record_byte_order = {
    'vuln_id'                   => 'N',
    'impact'                    => 'N',
    'exploits'                  => 'C',
    'remote'                    => 'C',
    'entry_date_length'         => 'N',
    'published_date_length'     => 'N',
    'modified_date_length'      => 'N',
    'title_length'              => 'N',
    'short_desc_length'         => 'N',
    'desc_length'               => 'N',
    'tech_desc_length'          => 'N',
};


my $vuln_record_map = {
    'entry_date_string'         => 'entry_date_length',
    'published_date_string'     => 'published_date_length',
    'modified_date_string'      => 'modified_date_length',
    'title_string'              => 'title_length',
    'short_desc_string'         => 'short_desc_length',
    'desc_string'               => 'desc_length',
    'tech_desc_string'          => 'tech_desc_length',
};

our $vuln_record = {
    'map'                       => $vuln_record_map,
    'order'                     => $vuln_record_order,
    'byte_order'                => $vuln_record_byte_order,
};


#####################################################
# Scan Vulnerability Record
#####################################################
my $scan_vuln_record_order = [
    'vuln_id',
    'type',
    'title_length',
    'title_string',
    'desc_length',
    'desc_string',
    'cve_length',
    'cve_string',
    'bugtraq_length',
    'bugtraq_string',
];

my $scan_vuln_record_byte_order = {
    'vuln_id'                   => 'N',
    'type'                      => 'N',
    'title_length'              => 'N',
    'desc_length'               => 'N',
    'cve_length'                => 'N',
    'bugtraq_length'            => 'N',
};


my $scan_vuln_record_map = {
    'title_string'              => 'title_length',
    'desc_string'               => 'desc_length',
    'cve_string'                => 'cve_length',
    'bugtraq_string'            => 'bugtraq_length',
};

our $scan_vuln_record = {
    'map'                       => $scan_vuln_record_map,
    'order'                     => $scan_vuln_record_order,
    'byte_order'                => $scan_vuln_record_byte_order,
};


#####################################################
# Compliance policy/rule metadata
#####################################################
my $compliance_metadata_record_order = [
    'id',
    'name_string_length',
    'name_string_data',
    'desc_string_length',
    'desc_string_data',
    'uuid',
    'rev_uuid',
];

my $compliance_metadata_record_byte_order = {
    'id'                        => 'N',
    'name_string_length'        => 'n',
    'desc_string_length'        => 'n',
};


my $compliance_metadata_record_map = {
    'name_string_data'          => 'name_string_length',
    'desc_string_data'          => 'desc_string_length',
    'uuid'                      => 16,
    'rev_uuid'                  => 16,
};

my $compliance_metadata_record_eval = {
    'uuid'                      => 'uuid_to_str($value)',
    'rev_uuid'                  => 'uuid_to_str($value)',
};

our $compliance_metadata_record = {
    'map'               => $compliance_metadata_record_map,
    'eval'              => $compliance_metadata_record_eval,
    'order'             => $compliance_metadata_record_order,
    'byte_order'        => $compliance_metadata_record_byte_order,
};


#####################################################
#  RNA fingerprint record
#####################################################
my $rna_fingerprint_order = [
    'fpuuid',
    'os_name_length',
    'os_name_data',
    'os_vendor_length',
    'os_vendor_data',
    'os_version_length',
    'os_version_data',
];

my $rna_fingerprint_map = {
    'os_name_data'      => 'os_name_length',
    'os_vendor_data'    => 'os_vendor_length',
    'os_version_data'   => 'os_version_length',
    'fpuuid'            => 16,
};

my $rna_fingerprint_eval = {
    'fpuuid'            => 'uuid_to_str($value)',
};

my $rna_fingerprint_record_byte_order = {
    'os_name_length'    => 'N',
    'os_vendor_length'  => 'N',
    'os_version_length' => 'N',
};

our $rna_fingerprint_record = {
    'order'             => $rna_fingerprint_order,
    'byte_order'        => $rna_fingerprint_record_byte_order,
    'map'               => $rna_fingerprint_map,
    'eval'              => $rna_fingerprint_eval,
};

#####################################################
# This forms the RNA event record structure.
#####################################################
my $rna_event_order = [
    'sensor_id',
    'ip_address',
    'mac_address',
    'reserved',
    'event_sec',
    'event_usec',
    'event_type',
    'event_subtype',
    'filenum',
    'filepos',
];

my $rna_event_record_byte_order = {
    'sensor_id'         => 'N',
    'ip_address'        => 'N',
    'reserved'          => 'n',
    'event_sec'         => 'N',
    'event_usec'        => 'N',
    'event_type'        => 'N',
    'event_subtype'     => 'N',
    'filenum'           => 'N',
    'filepos'           => 'N',
};


my $rna_event_map = {
    'mac_address'       => 6,
};

my $rna_event_eval = {
    'ip_address'        => 'inet_ntoa(pack("N",$value))',
    'mac_address'       => 'mac_to_str($value)',
};

# The definition of the event record
# This puts it all together so that parse_record knows what to do
our $rna_event_record = {
    'order'             => $rna_event_order,
    'byte_order'        => $rna_event_record_byte_order,
    'eval'              => $rna_event_eval,
    'map'               => $rna_event_map,
};

1;
