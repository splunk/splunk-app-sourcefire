package SFRNABlocks;

use warnings;
use strict;

our $rna_blocks = [
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {
      'block_length' => '$value - 8'
    },
    'index' => 0,
    'map' => {
      'data' => 'block_length'
    },
    'name' => 'String',
    'order' => [
      'block_type',
      'block_length',
      'data'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 1,
    'map' => {
      'service' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'ServiceSubtype',
    'order' => [
      'block_type',
      'block_length',
      'service',
      'vendor',
      'version'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n'
    },
    'eval' => {},
    'index' => 2,
    'map' => {
      'legacy_product' => 'BLOCK',
      'legacy_service' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'HostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'legacy_service',
      'vendor',
      'legacy_product',
      'version',
      'subtypelist',
      'confidence',
      'last_used'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'legacy_fpid' => 'N'
    },
    'eval' => {},
    'index' => 3,
    'map' => {
      'name' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'OS',
    'order' => [
      'block_type',
      'block_length',
      'name',
      'vendor',
      'version',
      'confidence',
      'legacy_fpid'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'proto' => 'n'
    },
    'eval' => {},
    'index' => 4,
    'map' => {},
    'name' => 'PndProtocol',
    'order' => [
      'block_type',
      'block_length',
      'proto'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'primary' => 'C',
      'ttl' => 'C'
    },
    'eval' => {
      'mac' => 'mac_to_str($value)'
    },
    'index' => 5,
    'map' => {
      'mac' => 6
    },
    'name' => 'HostMAC',
    'order' => [
      'block_type',
      'block_length',
      'ttl',
      'mac',
      'primary'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'legacy_fpid' => 'N',
      'pmtu' => 'N'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 6,
    'map' => {
      'hostname' => 'BLOCK',
      'mac' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'os name' => 'BLOCK',
      'os vendor' => 'BLOCK',
      'os version' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'HostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hostname',
      'hops',
      'pmtu',
      'os name',
      'os vendor',
      'os version',
      'confidence',
      'legacy_fpid',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'vuln_id' => 'N'
    },
    'eval' => {},
    'index' => 7,
    'map' => {},
    'name' => 'INT32',
    'order' => [
      'block_type',
      'block_length',
      'vuln_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n'
    },
    'eval' => {},
    'index' => 8,
    'map' => {
      'proto' => 'BLOCK',
      'subservice' => 'BLOCK',
      'vuln_list' => 'BLOCK'
    },
    'name' => 'VulnRef',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'proto',
      'subservice',
      'vuln_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'bytes_recv' => 'N',
      'bytes_sent' => 'N',
      'first_packet' => 'N',
      'initiator' => 'V',
      'initiator_port' => 'n',
      'last_packet' => 'N',
      'packets_recv' => 'N',
      'packets_sent' => 'N',
      'protocol' => 'C',
      'responder' => 'V',
      'responder_port' => 'n'
    },
    'eval' => {
      'initiator' => 'inet_ntoa(pack("N", $value))',
      'responder' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 9,
    'map' => {},
    'name' => 'FlowStats',
    'order' => [
      'block_type',
      'block_length',
      'initiator',
      'responder',
      'initiator_port',
      'responder_port',
      'first_packet',
      'last_packet',
      'packets_sent',
      'packets_recv',
      'bytes_sent',
      'bytes_recv',
      'protocol'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {
      'block_length' => '$value - 8'
    },
    'index' => 10,
    'map' => {
      'data' => 'block_length'
    },
    'name' => 'Blob',
    'order' => [
      'block_type',
      'block_length',
      'data'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 11,
    'map' => {
      'data' => 'LIST'
    },
    'name' => 'List',
    'order' => [
      'block_type',
      'block_length',
      'data'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n'
    },
    'eval' => {},
    'index' => 12,
    'map' => {
      'banner' => 'BLOCK',
      'legacy_product' => 'BLOCK',
      'legacy_service' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'HostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'legacy_service',
      'vendor',
      'legacy_product',
      'version',
      'subtypelist',
      'confidence',
      'last_used',
      'banner'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'legacy_fpid' => 'N',
      'pmtu' => 'N',
      'secondary' => 'C'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 13,
    'map' => {
      'hostname' => 'BLOCK',
      'mac' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'os name' => 'BLOCK',
      'os vendor' => 'BLOCK',
      'os version' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'HostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hostname',
      'hops',
      'secondary',
      'pmtu',
      'os name',
      'os vendor',
      'os version',
      'confidence',
      'legacy_fpid',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'priority' => 'C',
      'type' => 'C',
      'vid' => 'n'
    },
    'eval' => {},
    'index' => 14,
    'map' => {},
    'name' => 'VLAN',
    'order' => [
      'block_type',
      'block_length',
      'vid',
      'type',
      'priority'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'legacy_fpid' => 'N',
      'pmtu' => 'N',
      'priority' => 'C',
      'secondary' => 'C',
      'type' => 'C',
      'vid' => 'n'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 15,
    'map' => {
      'mac' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'HostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hops',
      'secondary',
      'pmtu',
      'confidence',
      'legacy_fpid',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type',
      'vid',
      'type',
      'priority'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'legacy_fpid' => 'N'
    },
    'eval' => {},
    'index' => 16,
    'map' => {},
    'name' => 'OS',
    'order' => [
      'block_type',
      'block_length',
      'confidence',
      'legacy_fpid'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'df' => 'C',
      'gateway' => 'N',
      'id' => 'N',
      'ipid_trend' => 'N',
      'mss_follows_syn' => 'n',
      'remote_cmd' => 'N',
      'remote_id' => 'N',
      'sensor_id' => 'N',
      'source_addr' => 'N',
      'source_mask' => 'N',
      'status' => 'N',
      'target_addr' => 'N',
      'target_distance' => 'C',
      'target_port' => 'n',
      'ttl' => 'C',
      'type' => 'n',
      'wscale' => 'N',
      'wsize_high' => 'n',
      'wsize_low' => 'n'
    },
    'eval' => {},
    'index' => 17,
    'map' => {
      'interface' => 8,
      'topts' => 'BLOCK'
    },
    'name' => 'fingerprint',
    'order' => [
      'block_type',
      'block_length',
      'remote_cmd',
      'status',
      'id',
      'remote_id',
      'sensor_id',
      'target_addr',
      'source_addr',
      'source_mask',
      'gateway',
      'wscale',
      'ipid_trend',
      'type',
      'target_port',
      'wsize_low',
      'wsize_high',
      'interface',
      'target_distance',
      'ttl',
      'df',
      'mss_follows_syn',
      'topts'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'bytes_recv' => 'N',
      'bytes_sent' => 'N',
      'first_packet' => 'N',
      'initiator' => 'V',
      'initiator_port' => 'n',
      'last_packet' => 'N',
      'packets_recv' => 'N',
      'packets_sent' => 'N',
      'protocol' => 'C',
      'responder' => 'V',
      'responder_port' => 'n'
    },
    'eval' => {
      'initiator' => 'inet_ntoa(pack("N", $value))',
      'responder' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 18,
    'map' => {
      'legacy_service' => 'BLOCK'
    },
    'name' => 'FlowStats',
    'order' => [
      'block_type',
      'block_length',
      'initiator',
      'responder',
      'initiator_port',
      'responder_port',
      'first_packet',
      'last_packet',
      'packets_sent',
      'packets_recv',
      'bytes_sent',
      'bytes_recv',
      'protocol',
      'legacy_service'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'dst_ip_address' => 'N',
      'ip_address' => 'N',
      'pe_id' => 'N',
      'pe_sensor_id' => 'N',
      'pe_time' => 'N',
      'policy_id' => 'N',
      'priority' => 'N',
      'rule_id' => 'N'
    },
    'eval' => {
      'dst_ip_address' => 'inet_ntoa(pack("N", $value))',
      'ip_address' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 19,
    'map' => {
      'description' => 'BLOCK'
    },
    'name' => 'PVEvent',
    'order' => [
      'block_type',
      'block_length',
      'pe_id',
      'pe_sensor_id',
      'pe_time',
      'policy_id',
      'rule_id',
      'priority',
      'ip_address',
      'dst_ip_address',
      'description'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'dst_ip_address' => 'N',
      'event_id' => 'N',
      'impact' => 'N',
      'sensor_id' => 'N',
      'src_ip_address' => 'N',
      'time' => 'N'
    },
    'eval' => {
      'dst_ip_address' => 'inet_ntoa(pack("N", $value))',
      'src_ip_address' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 20,
    'map' => {
      'description' => 'BLOCK'
    },
    'name' => 'ImpactAlert',
    'order' => [
      'block_type',
      'block_length',
      'event_id',
      'sensor_id',
      'time',
      'impact',
      'src_ip_address',
      'dst_ip_address',
      'description'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 21,
    'map' => {
      'val1' => 'BLOCK',
      'val10' => 'BLOCK',
      'val2' => 'BLOCK',
      'val3' => 'BLOCK',
      'val4' => 'BLOCK',
      'val5' => 'BLOCK',
      'val6' => 'BLOCK',
      'val7' => 'BLOCK',
      'val8' => 'BLOCK',
      'val9' => 'BLOCK'
    },
    'name' => 'fp_values',
    'order' => [
      'block_type',
      'block_length',
      'val1',
      'val2',
      'val3',
      'val4',
      'val5',
      'val6',
      'val7',
      'val8',
      'val9',
      'val10'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ipaddr' => 'N',
      'port' => 'n',
      'proto' => 'n',
      'vuln_id' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 22,
    'map' => {
      'subservice' => 'BLOCK'
    },
    'name' => 'Deprecated_VulnAck',
    'order' => [
      'block_type',
      'block_length',
      'ipaddr',
      'port',
      'proto',
      'subservice',
      'vuln_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ipaddr' => 'N',
      'uid' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 23,
    'map' => {
      'vuln_list' => 'BLOCK'
    },
    'name' => 'Deprecated_UserHostVulns',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'ipaddr',
      'vuln_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ip' => 'N',
      'mask' => 'N'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 24,
    'map' => {},
    'name' => 'Deprecated_IPMask',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'mask'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 25,
    'map' => {
      'ip_list' => 'BLOCK'
    },
    'name' => 'Deprecated_UserIPMasks',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'ip_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ip' => 'N',
      'port' => 'n',
      'proto' => 'n'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 26,
    'map' => {},
    'name' => 'Deprecated_UserService',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'port',
      'proto'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 27,
    'map' => {
      'service_list' => 'BLOCK'
    },
    'name' => 'Deprecated_UserServiceList',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'service_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'criticality' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 28,
    'map' => {
      'ip_list' => 'BLOCK'
    },
    'name' => 'Deprecated_UserCriticality',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'criticality',
      'ip_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'hits' => 'N',
      'id' => 'N',
      'last_used' => 'N'
    },
    'eval' => {},
    'index' => 29,
    'map' => {
      'version' => 'BLOCK'
    },
    'name' => 'HostClientApp',
    'order' => [
      'block_type',
      'block_length',
      'hits',
      'last_used',
      'id',
      'version'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'criticality' => 'n',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'legacy_fpid' => 'N',
      'priority' => 'C',
      'secondary' => 'C',
      'type' => 'C',
      'vid' => 'n'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 30,
    'map' => {
      'apps' => 'BLOCK',
      'mac' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'HostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hops',
      'secondary',
      'confidence',
      'legacy_fpid',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type',
      'criticality',
      'vid',
      'type',
      'priority',
      'apps'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 31,
    'map' => {
      'data' => 'LIST'
    },
    'name' => 'GenericList',
    'order' => [
      'block_type',
      'block_length',
      'data'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'bytes_recv' => 'N',
      'bytes_sent' => 'N',
      'clnt_app_id' => 'N',
      'first_packet' => 'N',
      'initiator' => 'V',
      'initiator_port' => 'n',
      'last_packet' => 'N',
      'packets_recv' => 'N',
      'packets_sent' => 'N',
      'protocol' => 'C',
      'responder' => 'V',
      'responder_port' => 'n'
    },
    'eval' => {
      'initiator' => 'inet_ntoa(pack("N", $value))',
      'responder' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 32,
    'map' => {
      'info' => 'BLOCK',
      'legacy_service' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'FlowStats',
    'order' => [
      'block_type',
      'block_length',
      'initiator',
      'responder',
      'initiator_port',
      'responder_port',
      'first_packet',
      'last_packet',
      'packets_sent',
      'packets_recv',
      'bytes_sent',
      'bytes_recv',
      'protocol',
      'legacy_service',
      'clnt_app_id',
      'version',
      'info'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'defined_mask' => 'N',
      'dest_criticality' => 'n',
      'dest_host_type' => 'C',
      'dest_ip_addr' => 'N',
      'dest_os_fingerprint_id' => 'N',
      'dest_port' => 'n',
      'dest_vlan_id' => 'n',
      'event_id' => 'N',
      'event_type' => 'C',
      'impact_flags' => 'N',
      'ip_protocol' => 'C',
      'net_protocol' => 'n',
      'policy_event_id' => 'N',
      'policy_id' => 'N',
      'policy_sensor_id' => 'C',
      'policy_tv_sec' => 'N',
      'priority' => 'N',
      'rule_id' => 'N',
      'sensor_id' => 'C',
      'sig_gen' => 'N',
      'sig_id' => 'N',
      'src_criticality' => 'n',
      'src_host_type' => 'C',
      'src_ip_addr' => 'N',
      'src_os_fingerprint_id' => 'N',
      'src_port' => 'n',
      'src_vlan_id' => 'n',
      'tv_sec' => 'N',
      'tv_usec' => 'N'
    },
    'eval' => {
      'dest_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'src_ip_addr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 33,
    'map' => {
      'description' => 'BLOCK',
      'dest_service' => 'BLOCK',
      'src_service' => 'BLOCK'
    },
    'name' => 'PolicyEvent',
    'order' => [
      'block_type',
      'block_length',
      'policy_sensor_id',
      'policy_tv_sec',
      'policy_event_id',
      'policy_id',
      'rule_id',
      'priority',
      'description',
      'event_type',
      'sensor_id',
      'sig_id',
      'sig_gen',
      'tv_sec',
      'tv_usec',
      'event_id',
      'defined_mask',
      'impact_flags',
      'ip_protocol',
      'net_protocol',
      'src_ip_addr',
      'src_host_type',
      'src_vlan_id',
      'src_os_fingerprint_id',
      'src_criticality',
      'src_port',
      'src_service',
      'dest_ip_addr',
      'dest_host_type',
      'dest_vlan_id',
      'dest_os_fingerprint_id',
      'dest_criticality',
      'dest_port',
      'dest_service'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'priority' => 'C',
      'secondary' => 'C',
      'type' => 'C',
      'vid' => 'n',
      'vlan_tag_present' => 'C'
    },
    'eval' => {
      'fpuuid' => 'uuid_to_str($value)',
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 34,
    'map' => {
      'apps' => 'BLOCK',
      'fpuuid' => 16,
      'mac' => 'BLOCK',
      'netbios_name' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'HostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hops',
      'secondary',
      'confidence',
      'fpuuid',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type',
      'vlan_tag_present',
      'vid',
      'type',
      'priority',
      'apps',
      'netbios_name'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 35,
    'map' => {
      'value' => 'BLOCK'
    },
    'name' => 'StringInfo',
    'order' => [
      'block_type',
      'block_length',
      'value'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n',
      'service_id' => 'n'
    },
    'eval' => {},
    'index' => 36,
    'map' => {
      'legacy_product' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'HostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'service_id',
      'vendor',
      'legacy_product',
      'version',
      'subtypelist',
      'confidence',
      'last_used'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n',
      'protocol' => 'C'
    },
    'eval' => {},
    'index' => 37,
    'map' => {
      'banner' => 'BLOCK'
    },
    'name' => 'ServiceBanner',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'protocol',
      'banner'
    ]
  },
  {
    'byte_order' => {
      'bits' => 'N',
      'block_length' => 'N',
      'block_type' => 'N',
      'id' => 'N',
      'ipaddr' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 38,
    'map' => {},
    'name' => 'AttributeAddress',
    'order' => [
      'block_type',
      'block_length',
      'id',
      'ipaddr',
      'bits'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'id' => 'N'
    },
    'eval' => {},
    'index' => 39,
    'map' => {
      'name' => 'BLOCK'
    },
    'name' => 'AttributeListItem',
    'order' => [
      'block_type',
      'block_length',
      'id',
      'name'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'end' => 'N',
      'id' => 'N',
      'ip_assigned' => 'N',
      'start' => 'N',
      'type' => 'N',
      'uid' => 'N'
    },
    'eval' => {
      'ip_assigned' => 'inet_ntoa(pack("N", $value))',
      'uuid' => 'uuid_to_str($value)'
    },
    'index' => 40,
    'map' => {
      'address_list' => 'BLOCK',
      'list' => 'BLOCK',
      'name' => 'BLOCK',
      'uuid' => 16
    },
    'name' => 'AttributeDef',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'uuid',
      'id',
      'name',
      'type',
      'start',
      'end',
      'ip_assigned',
      'list',
      'address_list'
    ]
  },
  {
    'byte_order' => {
      'attr_id' => 'N',
      'block_length' => 'N',
      'block_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 41,
    'map' => {
      'ip_list' => 'BLOCK',
      'value' => 'BLOCK'
    },
    'name' => 'Deprecated_UserAttrValue',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'attr_id',
      'ip_list',
      'value'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'hits' => 'N',
      'id' => 'N',
      'last_used' => 'N',
      'type_id' => 'N'
    },
    'eval' => {},
    'index' => 42,
    'map' => {
      'version' => 'BLOCK'
    },
    'name' => 'HostClientApp',
    'order' => [
      'block_type',
      'block_length',
      'hits',
      'last_used',
      'type_id',
      'id',
      'version'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'bytes_recv' => 'N',
      'bytes_sent' => 'N',
      'clnt_app_id' => 'N',
      'clnt_app_type_id' => 'N',
      'first_packet' => 'N',
      'initiator' => 'V',
      'initiator_port' => 'n',
      'last_packet' => 'N',
      'packets_recv' => 'N',
      'packets_sent' => 'N',
      'protocol' => 'C',
      'responder' => 'V',
      'responder_port' => 'n',
      'service_id' => 'n'
    },
    'eval' => {
      'initiator' => 'inet_ntoa(pack("N", $value))',
      'responder' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 43,
    'map' => {
      'domain' => 'BLOCK',
      'info' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'FlowStats',
    'order' => [
      'block_type',
      'block_length',
      'initiator',
      'responder',
      'initiator_port',
      'responder_port',
      'first_packet',
      'last_packet',
      'packets_sent',
      'packets_recv',
      'bytes_sent',
      'bytes_recv',
      'protocol',
      'service_id',
      'clnt_app_type_id',
      'clnt_app_id',
      'version',
      'info',
      'domain'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'id' => 'N',
      'port' => 'n',
      'proto' => 'n'
    },
    'eval' => {},
    'index' => 44,
    'map' => {
      'bugtraq_ids' => 'BLOCK',
      'cve_ids' => 'BLOCK',
      'desc' => 'BLOCK',
      'name' => 'BLOCK'
    },
    'name' => 'ScanVuln',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'proto',
      'id',
      'name',
      'desc',
      'bugtraq_ids',
      'cve_ids'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ipaddr' => 'N',
      'port' => 'n',
      'proto' => 'n',
      'type' => 'N',
      'uid' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 45,
    'map' => {
      'vulns' => 'BLOCK'
    },
    'name' => 'ScanResult',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'type',
      'ipaddr',
      'port',
      'proto',
      'vulns'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ipaddr' => 'N',
      'type' => 'N',
      'uid' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 46,
    'map' => {
      'vuln_list' => 'BLOCK'
    },
    'name' => 'Deprecated_UserHostVulns',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'ipaddr',
      'type',
      'vuln_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'criticality' => 'n',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'priority' => 'C',
      'type' => 'C',
      'vid' => 'n'
    },
    'eval' => {
      'fpuuid' => 'uuid_to_str($value)',
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 47,
    'map' => {
      'apps' => 'BLOCK',
      'attribute_list' => 'BLOCK',
      'fpuuid' => 16,
      'mac' => 'BLOCK',
      'netbios_name' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'notes' => 'BLOCK',
      'scan_vuln_list' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'vuln_list' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'FullHostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hops',
      'confidence',
      'fpuuid',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type',
      'criticality',
      'vid',
      'type',
      'priority',
      'apps',
      'netbios_name',
      'notes',
      'vuln_list',
      'scan_vuln_list',
      'attribute_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'i_value' => 'N',
      'id' => 'N',
      'type' => 'N'
    },
    'eval' => {},
    'index' => 48,
    'map' => {
      't_value' => 'BLOCK'
    },
    'name' => 'AttributeValue',
    'order' => [
      'block_type',
      'block_length',
      'id',
      'type',
      'i_value',
      't_value'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'invalid' => 'C',
      'vuln_id' => 'N'
    },
    'eval' => {},
    'index' => 49,
    'map' => {},
    'name' => 'VulnList',
    'order' => [
      'block_type',
      'block_length',
      'vuln_id',
      'invalid'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n',
      'service_id' => 'n'
    },
    'eval' => {},
    'index' => 50,
    'map' => {
      'banner' => 'BLOCK',
      'legacy_product' => 'BLOCK',
      'scan_vuln_list' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK',
      'vuln_list' => 'BLOCK'
    },
    'name' => 'FullHostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'service_id',
      'vendor',
      'legacy_product',
      'version',
      'confidence',
      'last_used',
      'banner',
      'vuln_list',
      'scan_vuln_list',
      'subtypelist'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 51,
    'map' => {
      'scan_vuln_list' => 'BLOCK',
      'service' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK',
      'vuln_list' => 'BLOCK'
    },
    'name' => 'FullServiceSubtype',
    'order' => [
      'block_type',
      'block_length',
      'service',
      'vendor',
      'version',
      'vuln_list',
      'scan_vuln_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'defined_mask' => 'N',
      'dest_criticality' => 'n',
      'dest_host_type' => 'C',
      'dest_ip_addr' => 'N',
      'dest_port' => 'n',
      'dest_service_id' => 'n',
      'dest_vlan_id' => 'n',
      'event_id' => 'N',
      'event_type' => 'C',
      'impact_flags' => 'N',
      'ip_protocol' => 'C',
      'net_protocol' => 'n',
      'policy_event_id' => 'N',
      'policy_id' => 'N',
      'policy_sensor_id' => 'N',
      'policy_tv_sec' => 'N',
      'priority' => 'N',
      'rule_id' => 'N',
      'sensor_id' => 'N',
      'sig_gen' => 'N',
      'sig_id' => 'N',
      'src_criticality' => 'n',
      'src_host_type' => 'C',
      'src_ip_addr' => 'N',
      'src_port' => 'n',
      'src_service_id' => 'n',
      'src_vlan_id' => 'n',
      'tv_sec' => 'N',
      'tv_usec' => 'N'
    },
    'eval' => {
      'dest_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'dest_os_fingerprint_uuid' => 'uuid_to_str($value)',
      'src_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'src_os_fingerprint_uuid' => 'uuid_to_str($value)'
    },
    'index' => 52,
    'map' => {
      'description' => 'BLOCK',
      'dest_os_fingerprint_uuid' => 16,
      'src_os_fingerprint_uuid' => 16
    },
    'name' => 'PolicyEvent',
    'order' => [
      'block_type',
      'block_length',
      'policy_sensor_id',
      'policy_tv_sec',
      'policy_event_id',
      'policy_id',
      'rule_id',
      'priority',
      'description',
      'event_type',
      'sensor_id',
      'sig_id',
      'sig_gen',
      'tv_sec',
      'tv_usec',
      'event_id',
      'defined_mask',
      'impact_flags',
      'ip_protocol',
      'net_protocol',
      'src_ip_addr',
      'src_host_type',
      'src_vlan_id',
      'src_os_fingerprint_uuid',
      'src_criticality',
      'src_port',
      'src_service_id',
      'dest_ip_addr',
      'dest_host_type',
      'dest_vlan_id',
      'dest_os_fingerprint_uuid',
      'dest_criticality',
      'dest_port',
      'dest_service_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N'
    },
    'eval' => {
      'fpuuid' => 'uuid_to_str($value)'
    },
    'index' => 53,
    'map' => {
      'fpuuid' => 16
    },
    'name' => 'OS',
    'order' => [
      'block_type',
      'block_length',
      'confidence',
      'fpuuid'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'type' => 'N'
    },
    'eval' => {},
    'index' => 54,
    'map' => {
      'message' => 'BLOCK'
    },
    'name' => 'PolicyEngineControlMsg',
    'order' => [
      'block_type',
      'block_length',
      'type',
      'message'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'category' => 'N',
      'end' => 'N',
      'id' => 'N',
      'ip_assigned' => 'N',
      'start' => 'N',
      'type' => 'N',
      'uid' => 'N'
    },
    'eval' => {
      'ip_assigned' => 'inet_ntoa(pack("N", $value))',
      'uuid' => 'uuid_to_str($value)'
    },
    'index' => 55,
    'map' => {
      'address_list' => 'BLOCK',
      'list' => 'BLOCK',
      'name' => 'BLOCK',
      'uuid' => 16
    },
    'name' => 'AttributeDef',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'uuid',
      'id',
      'name',
      'type',
      'category',
      'start',
      'end',
      'ip_assigned',
      'list',
      'address_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'bytes_recv' => 'N',
      'bytes_sent' => 'N',
      'clnt_app_id' => 'N',
      'clnt_app_type_id' => 'N',
      'first_packet' => 'N',
      'flow_type' => 'C',
      'initiator' => 'N',
      'initiator_port' => 'n',
      'last_packet' => 'N',
      'packets_recv' => 'N',
      'packets_sent' => 'N',
      'protocol' => 'C',
      'responder' => 'N',
      'responder_port' => 'n',
      'service_id' => 'N',
      'src_device' => 'N',
      'tcp_flags' => 'C'
    },
    'eval' => {
      'initiator' => 'inet_ntoa(pack("N", $value))',
      'responder' => 'inet_ntoa(pack("N", $value))',
      'src_device' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 56,
    'map' => {
      'domain' => 'BLOCK',
      'info' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'FlowStats',
    'order' => [
      'block_type',
      'block_length',
      'initiator',
      'responder',
      'initiator_port',
      'responder_port',
      'first_packet',
      'last_packet',
      'flow_type',
      'src_device',
      'tcp_flags',
      'packets_sent',
      'packets_recv',
      'bytes_sent',
      'bytes_recv',
      'protocol',
      'service_id',
      'clnt_app_type_id',
      'clnt_app_id',
      'version',
      'info',
      'domain'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'proto' => 'n',
      'proto_type' => 'C'
    },
    'eval' => {},
    'index' => 57,
    'map' => {
      'ip_range_list' => 'BLOCK',
      'mac_list' => 'BLOCK'
    },
    'name' => 'UserProtocol',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'mac_list',
      'proto_type',
      'proto'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 58,
    'map' => {
      'protos' => 'BLOCK'
    },
    'name' => 'UserProtocolList',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'protos'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'id' => 'N',
      'type_id' => 'N'
    },
    'eval' => {},
    'index' => 59,
    'map' => {
      'ip_range_list' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'UserClientApp',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'type_id',
      'id',
      'version'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'source_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 60,
    'map' => {
      'apps' => 'BLOCK'
    },
    'name' => 'UserClientAppList',
    'order' => [
      'block_type',
      'block_length',
      'source_type',
      'uid',
      'apps'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'end' => 'N',
      'start' => 'N'
    },
    'eval' => {
      'end' => 'inet_ntoa(pack("N", $value))',
      'start' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 61,
    'map' => {},
    'name' => 'IPRangeSpec',
    'order' => [
      'block_type',
      'block_length',
      'start',
      'end'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 62,
    'map' => {
      'name' => 'BLOCK',
      'value' => 'BLOCK'
    },
    'name' => 'AttrSpec',
    'order' => [
      'block_type',
      'block_length',
      'name',
      'value'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {
      'macaddr' => 'mac_to_str($value)'
    },
    'index' => 63,
    'map' => {
      'macaddr' => 6
    },
    'name' => 'MacSpec',
    'order' => [
      'block_type',
      'block_length',
      'macaddr'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 64,
    'map' => {
      'ip_range_list' => 'BLOCK',
      'mac_list' => 'BLOCK'
    },
    'name' => 'AddressSpec',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'mac_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'drop_user_product' => 'N',
      'port' => 'n',
      'product_id' => 'N',
      'proto' => 'n',
      'service_id' => 'N',
      'software_id' => 'N',
      'source_type' => 'N',
      'uid' => 'N',
      'vendor_id' => 'N'
    },
    'eval' => {
      'uuid' => 'uuid_to_str($value)'
    },
    'index' => 65,
    'map' => {
      'build' => 'BLOCK',
      'custom_product_str' => 'BLOCK',
      'custom_vendor_str' => 'BLOCK',
      'custom_version_str' => 'BLOCK',
      'extension' => 'BLOCK',
      'fix_list' => 'BLOCK',
      'ip_range_list' => 'BLOCK',
      'major' => 'BLOCK',
      'minor' => 'BLOCK',
      'patch' => 'BLOCK',
      'revision' => 'BLOCK',
      'to_major' => 'BLOCK',
      'to_minor' => 'BLOCK',
      'to_revision' => 'BLOCK',
      'uuid' => 16
    },
    'name' => 'UserProduct',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'source_type',
      'ip_range_list',
      'port',
      'proto',
      'drop_user_product',
      'custom_vendor_str',
      'custom_product_str',
      'custom_version_str',
      'software_id',
      'service_id',
      'vendor_id',
      'product_id',
      'major',
      'minor',
      'revision',
      'to_major',
      'to_minor',
      'to_revision',
      'build',
      'patch',
      'extension',
      'uuid',
      'fix_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'bucket_stime' => 'N',
      'bytes_recv' => 'N',
      'bytes_sent' => 'N',
      'connections_n' => 'N',
      'flow_type' => 'C',
      'initiator' => 'N',
      'packets_recv' => 'N',
      'packets_sent' => 'N',
      'protocol' => 'C',
      'responder' => 'N',
      'responder_port' => 'n',
      'service_id' => 'N',
      'src_device' => 'N'
    },
    'eval' => {
      'initiator' => 'inet_ntoa(pack("N", $value))',
      'responder' => 'inet_ntoa(pack("N", $value))',
      'src_device' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 66,
    'map' => {},
    'name' => 'FlowChunk',
    'order' => [
      'block_type',
      'block_length',
      'initiator',
      'responder',
      'bucket_stime',
      'service_id',
      'responder_port',
      'protocol',
      'flow_type',
      'src_device',
      'packets_sent',
      'packets_recv',
      'bytes_sent',
      'bytes_recv',
      'connections_n'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'fix_id' => 'N'
    },
    'eval' => {},
    'index' => 67,
    'map' => {},
    'name' => 'FixList',
    'order' => [
      'block_type',
      'block_length',
      'fix_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n',
      'service_id' => 'N',
      'source_id' => 'N',
      'source_type' => 'N'
    },
    'eval' => {},
    'index' => 68,
    'map' => {
      'legacy_product' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'HostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'service_id',
      'vendor',
      'legacy_product',
      'version',
      'subtypelist',
      'confidence',
      'last_used',
      'source_type',
      'source_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n',
      'service_id' => 'N',
      'source_id' => 'N',
      'source_type' => 'N'
    },
    'eval' => {},
    'index' => 69,
    'map' => {
      'banner' => 'BLOCK',
      'legacy_product' => 'BLOCK',
      'scan_vuln_list' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vendor' => 'BLOCK',
      'version' => 'BLOCK',
      'vuln_list' => 'BLOCK'
    },
    'name' => 'FullHostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'service_id',
      'vendor',
      'legacy_product',
      'version',
      'confidence',
      'last_used',
      'source_type',
      'source_id',
      'banner',
      'vuln_list',
      'scan_vuln_list',
      'subtypelist'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'defined_mask' => 'N',
      'dest_criticality' => 'n',
      'dest_host_type' => 'C',
      'dest_ip_addr' => 'N',
      'dest_port' => 'n',
      'dest_service_id' => 'N',
      'dest_vlan_id' => 'n',
      'event_id' => 'N',
      'event_type' => 'C',
      'impact_flags' => 'N',
      'ip_protocol' => 'C',
      'net_protocol' => 'n',
      'policy_event_id' => 'N',
      'policy_id' => 'N',
      'policy_sensor_id' => 'N',
      'policy_tv_sec' => 'N',
      'priority' => 'N',
      'rule_id' => 'N',
      'sensor_id' => 'N',
      'sig_gen' => 'N',
      'sig_id' => 'N',
      'src_criticality' => 'n',
      'src_host_type' => 'C',
      'src_ip_addr' => 'N',
      'src_port' => 'n',
      'src_service_id' => 'N',
      'src_vlan_id' => 'n',
      'tv_sec' => 'N',
      'tv_usec' => 'N'
    },
    'eval' => {
      'dest_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'dest_os_fingerprint_uuid' => 'uuid_to_str($value)',
      'src_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'src_os_fingerprint_uuid' => 'uuid_to_str($value)'
    },
    'index' => 70,
    'map' => {
      'description' => 'BLOCK',
      'dest_os_fingerprint_uuid' => 16,
      'src_os_fingerprint_uuid' => 16
    },
    'name' => 'PolicyEvent',
    'order' => [
      'block_type',
      'block_length',
      'policy_sensor_id',
      'policy_tv_sec',
      'policy_event_id',
      'policy_id',
      'rule_id',
      'priority',
      'description',
      'event_type',
      'sensor_id',
      'sig_id',
      'sig_gen',
      'tv_sec',
      'tv_usec',
      'event_id',
      'defined_mask',
      'impact_flags',
      'ip_protocol',
      'net_protocol',
      'src_ip_addr',
      'src_host_type',
      'src_vlan_id',
      'src_os_fingerprint_uuid',
      'src_criticality',
      'src_port',
      'src_service_id',
      'dest_ip_addr',
      'dest_host_type',
      'dest_vlan_id',
      'dest_os_fingerprint_uuid',
      'dest_criticality',
      'dest_port',
      'dest_service_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n',
      'proto' => 'n'
    },
    'eval' => {},
    'index' => 71,
    'map' => {
      'subtype_string' => 'BLOCK',
      'value' => 'BLOCK'
    },
    'name' => 'genericScanResults',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'proto',
      'subtype_string',
      'value'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ipaddr' => 'N',
      'port' => 'n',
      'proto' => 'n',
      'type' => 'N',
      'uid' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 72,
    'map' => {
      'generic_scan_results' => 'BLOCK',
      'services' => 'BLOCK',
      'vulns' => 'BLOCK'
    },
    'name' => 'ScanResult',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'type',
      'ipaddr',
      'port',
      'proto',
      'vulns',
      'generic_scan_results',
      'services'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'id' => 'N',
      'ipaddr' => 'N',
      'protocol' => 'N',
      'timestamp' => 'N'
    },
    'eval' => {
      'ipaddr' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 73,
    'map' => {
      'email' => 'BLOCK',
      'username' => 'BLOCK'
    },
    'name' => 'UserLoginInfo',
    'order' => [
      'block_type',
      'block_length',
      'timestamp',
      'ipaddr',
      'username',
      'id',
      'protocol',
      'email'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 74,
    'map' => {
      'address' => 'BLOCK',
      'building' => 'BLOCK',
      'city' => 'BLOCK',
      'company' => 'BLOCK',
      'country_region' => 'BLOCK',
      'dept' => 'BLOCK',
      'division' => 'BLOCK',
      'email' => 'BLOCK',
      'email_alias1' => 'BLOCK',
      'email_alias2' => 'BLOCK',
      'email_alias3' => 'BLOCK',
      'first_name' => 'BLOCK',
      'full_name' => 'BLOCK',
      'initials' => 'BLOCK',
      'ip_phone' => 'BLOCK',
      'last_name' => 'BLOCK',
      'location' => 'BLOCK',
      'mailstop' => 'BLOCK',
      'office' => 'BLOCK',
      'phone' => 'BLOCK',
      'postal_code' => 'BLOCK',
      'room' => 'BLOCK',
      'staff_idn' => 'BLOCK',
      'state' => 'BLOCK',
      'title' => 'BLOCK',
      'user1' => 'BLOCK',
      'user2' => 'BLOCK',
      'user3' => 'BLOCK',
      'user4' => 'BLOCK',
      'username' => 'BLOCK'
    },
    'name' => 'UserAccountUpdateMsg',
    'order' => [
      'block_type',
      'block_length',
      'username',
      'first_name',
      'initials',
      'last_name',
      'full_name',
      'title',
      'staff_idn',
      'address',
      'city',
      'state',
      'country_region',
      'postal_code',
      'building',
      'location',
      'room',
      'company',
      'division',
      'dept',
      'office',
      'mailstop',
      'email',
      'phone',
      'ip_phone',
      'user1',
      'user2',
      'user3',
      'user4',
      'email_alias1',
      'email_alias2',
      'email_alias3'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'id' => 'N',
      'protocol' => 'N'
    },
    'eval' => {},
    'index' => 75,
    'map' => {
      'dept' => 'BLOCK',
      'email' => 'BLOCK',
      'first_name' => 'BLOCK',
      'last_name' => 'BLOCK',
      'phone' => 'BLOCK',
      'username' => 'BLOCK'
    },
    'name' => 'UserInfo',
    'order' => [
      'block_type',
      'block_length',
      'id',
      'username',
      'protocol',
      'first_name',
      'last_name',
      'email',
      'dept',
      'phone'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n',
      'proto' => 'n'
    },
    'eval' => {},
    'index' => 76,
    'map' => {
      'ip_range_list' => 'BLOCK'
    },
    'name' => 'UserService',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'port',
      'proto'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'source_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 77,
    'map' => {
      'service_list' => 'BLOCK'
    },
    'name' => 'UserServiceList',
    'order' => [
      'block_type',
      'block_length',
      'source_type',
      'uid',
      'service_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'source_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 78,
    'map' => {
      'ip_range_list' => 'BLOCK',
      'mac_list' => 'BLOCK'
    },
    'name' => 'UserHosts',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'mac_list',
      'uid',
      'source_type'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n',
      'proto' => 'n',
      'vuln_id' => 'N'
    },
    'eval' => {
      'uuid' => 'uuid_to_str($value)'
    },
    'index' => 79,
    'map' => {
      'ip_range_list' => 'BLOCK',
      'uuid' => 16,
      'vuln_str' => 'BLOCK'
    },
    'name' => 'VulnAck',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'port',
      'proto',
      'vuln_id',
      'uuid',
      'vuln_str'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'source_type' => 'N',
      'type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 80,
    'map' => {
      'vuln_list' => 'BLOCK'
    },
    'name' => 'UserHostVulns',
    'order' => [
      'block_type',
      'block_length',
      'uid',
      'source_type',
      'type',
      'vuln_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'criticality' => 'N',
      'source_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 81,
    'map' => {
      'ip_range_list' => 'BLOCK'
    },
    'name' => 'UserCriticality',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'uid',
      'source_type',
      'criticality'
    ]
  },
  {
    'byte_order' => {
      'attr_id' => 'N',
      'block_length' => 'N',
      'block_type' => 'N',
      'source_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 82,
    'map' => {
      'ip_range_list' => 'BLOCK',
      'value' => 'BLOCK'
    },
    'name' => 'UserAttrValue',
    'order' => [
      'block_type',
      'block_length',
      'ip_range_list',
      'uid',
      'source_type',
      'attr_id',
      'value'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'source_type' => 'N',
      'uid' => 'N'
    },
    'eval' => {},
    'index' => 83,
    'map' => {
      'protos' => 'BLOCK'
    },
    'name' => 'UserProtocolList',
    'order' => [
      'block_type',
      'block_length',
      'source_type',
      'uid',
      'protos'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'defined_mask' => 'N',
      'dest_criticality' => 'n',
      'dest_host_type' => 'C',
      'dest_ip_addr' => 'N',
      'dest_port' => 'n',
      'dest_service_id' => 'N',
      'dest_uid' => 'N',
      'dest_vlan_id' => 'n',
      'event_id' => 'N',
      'event_type' => 'C',
      'impact_flags' => 'N',
      'ip_protocol' => 'C',
      'net_protocol' => 'n',
      'policy_event_id' => 'N',
      'policy_id' => 'N',
      'policy_sensor_id' => 'N',
      'policy_tv_sec' => 'N',
      'priority' => 'N',
      'rule_id' => 'N',
      'sensor_id' => 'N',
      'sig_gen' => 'N',
      'sig_id' => 'N',
      'src_criticality' => 'n',
      'src_host_type' => 'C',
      'src_ip_addr' => 'N',
      'src_port' => 'n',
      'src_service_id' => 'N',
      'src_uid' => 'N',
      'src_vlan_id' => 'n',
      'tv_sec' => 'N',
      'tv_usec' => 'N'
    },
    'eval' => {
      'dest_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'dest_os_fingerprint_uuid' => 'uuid_to_str($value)',
      'src_ip_addr' => 'inet_ntoa(pack("N", $value))',
      'src_os_fingerprint_uuid' => 'uuid_to_str($value)'
    },
    'index' => 84,
    'map' => {
      'description' => 'BLOCK',
      'dest_os_fingerprint_uuid' => 16,
      'src_os_fingerprint_uuid' => 16
    },
    'name' => 'PolicyEvent',
    'order' => [
      'block_type',
      'block_length',
      'policy_sensor_id',
      'policy_tv_sec',
      'policy_event_id',
      'policy_id',
      'rule_id',
      'priority',
      'description',
      'event_type',
      'sensor_id',
      'sig_id',
      'sig_gen',
      'tv_sec',
      'tv_usec',
      'event_id',
      'defined_mask',
      'impact_flags',
      'ip_protocol',
      'net_protocol',
      'src_ip_addr',
      'src_host_type',
      'src_vlan_id',
      'src_os_fingerprint_uuid',
      'src_criticality',
      'src_uid',
      'src_port',
      'src_service_id',
      'dest_ip_addr',
      'dest_host_type',
      'dest_vlan_id',
      'dest_os_fingerprint_uuid',
      'dest_criticality',
      'dest_uid',
      'dest_port',
      'dest_service_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'invalid' => 'C',
      'type' => 'N',
      'vuln_id' => 'N'
    },
    'eval' => {},
    'index' => 85,
    'map' => {},
    'name' => 'VulnList',
    'order' => [
      'block_type',
      'block_length',
      'vuln_id',
      'invalid',
      'type'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n',
      'proto' => 'n'
    },
    'eval' => {},
    'index' => 86,
    'map' => {
      'bugtraq_ids' => 'BLOCK',
      'cve_ids' => 'BLOCK',
      'desc' => 'BLOCK',
      'id' => 'BLOCK',
      'name' => 'BLOCK'
    },
    'name' => 'ScanVuln',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'proto',
      'id',
      'name',
      'desc',
      'bugtraq_ids',
      'cve_ids'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'fp_source_id' => 'N',
      'fp_source_type' => 'N',
      'fp_type' => 'N',
      'last_seen' => 'N',
      'ttl_diff' => 'C'
    },
    'eval' => {
      'fpuuid' => 'uuid_to_str($value)'
    },
    'index' => 87,
    'map' => {
      'fpuuid' => 16
    },
    'name' => 'OSFP',
    'order' => [
      'block_type',
      'block_length',
      'fpuuid',
      'fp_type',
      'fp_source_type',
      'fp_source_id',
      'last_seen',
      'ttl_diff'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'last_used' => 'N',
      'service_id' => 'N',
      'source_id' => 'N',
      'source_type' => 'N'
    },
    'eval' => {},
    'index' => 88,
    'map' => {
      'vendor' => 'BLOCK',
      'version' => 'BLOCK'
    },
    'name' => 'ServiceInfo',
    'order' => [
      'block_type',
      'block_length',
      'service_id',
      'vendor',
      'version',
      'last_used',
      'source_type',
      'source_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'last_used' => 'N',
      'port' => 'n'
    },
    'eval' => {},
    'index' => 89,
    'map' => {
      'info[SERVICE_TYPE_RNA]' => 'BLOCK',
      'subtypelist' => 'BLOCK'
    },
    'name' => 'HostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'last_used',
      'info[SERVICE_TYPE_RNA]',
      'subtypelist',
      'confidence'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'confidence' => 'N',
      'hits' => 'N',
      'port' => 'n'
    },
    'eval' => {},
    'index' => 90,
    'map' => {
      'banner' => 'BLOCK',
      'info[SERVICE_TYPE_APP]' => 'BLOCK',
      'info[SERVICE_TYPE_RNA]' => 'BLOCK',
      'info[SERVICE_TYPE_SCAN]' => 'BLOCK',
      'info[SERVICE_TYPE_USER]' => 'BLOCK',
      'scan_orig_vuln_list' => 'BLOCK',
      'scan_vuln_list' => 'BLOCK',
      'subtypelist' => 'BLOCK',
      'vuln_list' => 'BLOCK'
    },
    'name' => 'FullHostService',
    'order' => [
      'block_type',
      'block_length',
      'port',
      'hits',
      'info[SERVICE_TYPE_RNA]',
      'info[SERVICE_TYPE_USER]',
      'info[SERVICE_TYPE_SCAN]',
      'info[SERVICE_TYPE_APP]',
      'confidence',
      'banner',
      'vuln_list',
      'scan_vuln_list',
      'scan_orig_vuln_list',
      'subtypelist'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'priority' => 'C',
      'secondary' => 'C',
      'type' => 'C',
      'vid' => 'n',
      'vlan_tag_present' => 'C'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 91,
    'map' => {
      'apps' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_CLIENT]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_DHCP]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_SERVER]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_SMB]' => 'BLOCK',
      'mac' => 'BLOCK',
      'netbios_name' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'HostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hops',
      'secondary',
      'fp_list[FINGERPRINT_TYPE_SERVER]',
      'fp_list[FINGERPRINT_TYPE_CLIENT]',
      'fp_list[FINGERPRINT_TYPE_SMB]',
      'fp_list[FINGERPRINT_TYPE_DHCP]',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type',
      'vlan_tag_present',
      'vid',
      'type',
      'priority',
      'apps',
      'netbios_name'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'criticality' => 'n',
      'hops' => 'C',
      'host_type' => 'N',
      'ip' => 'N',
      'last_seen' => 'N',
      'priority' => 'C',
      'type' => 'C',
      'vid' => 'n'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 92,
    'map' => {
      'apps' => 'BLOCK',
      'attribute_list' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_APP]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_CLIENT]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_CONFLICT]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_DERIVED]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_DHCP]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_SCAN]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_SERVER]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_SMB]' => 'BLOCK',
      'fp_list[FINGERPRINT_TYPE_USER]' => 'BLOCK',
      'mac' => 'BLOCK',
      'netbios_name' => 'BLOCK',
      'network_protos' => 'BLOCK',
      'notes' => 'BLOCK',
      'scan_orig_vuln_list' => 'BLOCK',
      'scan_vuln_list' => 'BLOCK',
      'tcpsvclist' => 'BLOCK',
      'udpsvclist' => 'BLOCK',
      'vuln_list' => 'BLOCK',
      'xport_protos' => 'BLOCK'
    },
    'name' => 'FullHostTracker',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'hops',
      'fp_list[FINGERPRINT_TYPE_DERIVED]',
      'fp_list[FINGERPRINT_TYPE_SERVER]',
      'fp_list[FINGERPRINT_TYPE_CLIENT]',
      'fp_list[FINGERPRINT_TYPE_SMB]',
      'fp_list[FINGERPRINT_TYPE_DHCP]',
      'fp_list[FINGERPRINT_TYPE_USER]',
      'fp_list[FINGERPRINT_TYPE_SCAN]',
      'fp_list[FINGERPRINT_TYPE_APP]',
      'fp_list[FINGERPRINT_TYPE_CONFLICT]',
      'tcpsvclist',
      'udpsvclist',
      'network_protos',
      'xport_protos',
      'mac',
      'last_seen',
      'host_type',
      'criticality',
      'vid',
      'type',
      'priority',
      'apps',
      'netbios_name',
      'notes',
      'vuln_list',
      'scan_vuln_list',
      'scan_orig_vuln_list',
      'attribute_list'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N'
    },
    'eval' => {},
    'index' => 93,
    'map' => {
      'val1' => 'BLOCK',
      'val10' => 'BLOCK',
      'val11' => 'BLOCK',
      'val12' => 'BLOCK',
      'val2' => 'BLOCK',
      'val3' => 'BLOCK',
      'val4' => 'BLOCK',
      'val5' => 'BLOCK',
      'val6' => 'BLOCK',
      'val7' => 'BLOCK',
      'val8' => 'BLOCK',
      'val9' => 'BLOCK'
    },
    'name' => 'fp_values',
    'order' => [
      'block_type',
      'block_length',
      'val1',
      'val2',
      'val3',
      'val4',
      'val5',
      'val6',
      'val7',
      'val8',
      'val9',
      'val10',
      'val11',
      'val12'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'port' => 'n',
      'protocol' => 'n',
      'sm_id' => 'N',
      'source_id' => 'N',
      'source_type' => 'N'
    },
    'eval' => {
      'uuid' => 'uuid_to_str($value)'
    },
    'index' => 94,
    'map' => {
      'uuid' => 16
    },
    'name' => 'IdentityData',
    'order' => [
      'block_type',
      'block_length',
      'source_type',
      'source_id',
      'uuid',
      'port',
      'protocol',
      'sm_id'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'last_seen' => 'N',
      'primary' => 'C',
      'ttl' => 'C'
    },
    'eval' => {
      'mac' => 'mac_to_str($value)'
    },
    'index' => 95,
    'map' => {
      'mac' => 6
    },
    'name' => 'HostMAC',
    'order' => [
      'block_type',
      'block_length',
      'ttl',
      'mac',
      'primary',
      'last_seen'
    ]
  },
  {
    'byte_order' => {
      'block_length' => 'N',
      'block_type' => 'N',
      'ip' => 'N'
    },
    'eval' => {
      'ip' => 'inet_ntoa(pack("N", $value))'
    },
    'index' => 96,
    'map' => {
      'mac' => 'BLOCK'
    },
    'name' => 'SecondaryHostUpdate',
    'order' => [
      'block_type',
      'block_length',
      'ip',
      'mac'
    ]
  }
];

1;
