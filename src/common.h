#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"

struct container_identity_key {
    u32 ifindex;
};

struct container_identity_val {
    u8 mac_address[6];
    u32 ip_address;
    u32 flags;
    u64 packets_count;
    u16 __pad; /* Padding for alignment */
};

struct dnat_map_key {
    u16 dst_port;
    u8  proto;
    u8  __pad; /* Padding for alignment */
};

struct dnat_map_val {
    u32 new_dst_ip;
    u16 new_dst_port;
    u32 dst_ifindex;
    u16 flags;
};

struct snat_map_key {
    u32 prefixlen;
    u32 src_ip;
};

struct snat_map_val {
    u32 snat_ip;
    u16 flags;
    u16 __pad; /* Padding for alignment */
};

struct forward_policy_key {
    u32 prefixlen;
    u32 src_ip;
};

struct forward_policy_val {
    u8 action;   /* 0 = DROP, 1 = FORWARD */
    u8 __pad[3]; /* Padding for alignment */
};

struct conntrack_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  proto;
    u8 direction; /* 0 = ingress, 1 = egress */
    u16 __pad;    /* Padding for alignment */
};

struct conntrack_val {
    u8 state;    /* 0 = NEW, 1 = ESTABLISHED, 2 = RELATED */
    u8 nat_type; /* 0 = NONE, 1 = SNAT, 2 = DNAT */
    u16 __pad;   /* Padding for alignment */
    u32 nat_ip;  /* Original value before NAT */
    u16 nat_port;
    u16 __pad2; /* Padding for alignment */
    u64 timestamp;
    u64 packets;
};

struct global_config {
    u32 host_ip;
    u16 host_port;
    u16 __pad;             /* Padding for alignment */
    u8 default_fwd_action; /* 0 = DROP, 1 = FORWARD */
    u8 enable_conntrack;
    u8 enable_logging;
    u8 log_level; /* 0 = ERROR, 1 = INFO, 2 = DEBUG */
    u32 ct_timeour_tcp;
    u32 ct_timeout_udp;
    u32 ct_timeout_icmp;
    u32 ct_timeout_other;
};

struct metrics_map_key {
    u32 entity_id;  /* ifindex, or hash of rule key, or user-defined ID */
    u8 entity_type; /* 0=container, 1=network, 2=dnat_rule, 3=snat_rule */
    u8 __pad[3];    /* Padding for alignment */
};

struct metrics_map_val {
    u64 packets;
    u64 bytes;
};

struct event {
    u64 timestamp_ns;
    u32 ifindex;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 event_type;
    u16 reason;
    u8 proto;
    u8 action;
    u8 src_mac[6];
};

#endif /* COMMON_H */