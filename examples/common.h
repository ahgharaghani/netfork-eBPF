/* =============================================================================
 * common.h — shared structs, constants, helpers used across all programs
 * ============================================================================= */

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

/* =============================================================================
 * Constants
 * ============================================================================= */

#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define ETH_P_ARP       0x0806

#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_REDIRECT 7

#define XDP_DROP        1
#define XDP_PASS        2
#define XDP_TX          3
#define XDP_REDIRECT    4

#define ACTION_DROP     0
#define ACTION_ALLOW    1
#define ACTION_RATELIMIT 2
#define ACTION_DNS_BLOCK 3

#define REASON_NO_RULE    0
#define REASON_BLOCKLIST  1
#define REASON_RATE_LIMIT 2
#define REASON_DNS_BLOCK  3
#define REASON_MALFORMED  4

#define TCP_FLAG_FIN    (1 << 0)
#define TCP_FLAG_SYN    (1 << 1)
#define TCP_FLAG_RST    (1 << 2)
#define TCP_FLAG_ACK    (1 << 3)
#define TCP_FLAG_URG    (1 << 4)

#define MAX_DOMAIN_LEN  128
#define DNS_PORT        53

#define RATE_LIMIT_BURST         100
#define RATE_LIMIT_NS_PER_TOKEN  10000000ULL  /* 1 token per 10ms */

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* =============================================================================
 * Structs
 * ============================================================================= */

/* 5-tuple — key for firewall rule lookup and connection tracking */
struct five_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];    /* keep 4-byte aligned */
};

/* parsed packet — filled by parse_packet() */
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  tcp_flags;
    __u16 pkt_len;
};

/* firewall rule stored in fw_rules map */
struct fw_rule {
    __u8  action;        /* ACTION_DROP or ACTION_ALLOW */
    __u8  reason;
    __u16 pad;
    __u64 container_id;
};

/* connection tracking state */
struct conn_state {
    __u8  established;
    __u8  pad[7];
    __u64 last_seen_ns;
    __u64 container_id;
    __u64 bytes;
};

/* per-container policy */
struct container_policy {
    __u8  default_action;   /* ACTION_DROP or ACTION_ALLOW */
    __u8  log_drops;
    __u8  log_allows;
    __u8  pad;
    __u32 max_pps;          /* max packets per second */
};

/* per-container packet counters */
struct pkt_counters {
    __u64 rx_packets;
    __u64 tx_packets;
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u64 dropped;
    __u64 rate_limited;
};

/* endpoint — used in per-container egress allowlist */
struct endpoint {
    __u32 ip;
    __u16 port;
    __u8  proto;
    __u8  pad;
};

/* event emitted to userspace via ring buffer */
struct fw_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  action;
    __u8  reason;
    __u8  pad;
    __u16 pkt_len;
    __u8  tcp_flags;
    __u8  pad2;
};

/* rate limiter — token bucket per source IP */
struct rate_key {
    __u32 src_ip;
    __u64 cgroup_id;
    __u8  proto;
    __u8  pad[3];
};

struct rate_val {
    __u64 tokens;
    __u64 last_refill_ns;
};

/* =============================================================================
 * Packet parser — inline, reused by all programs
 * ============================================================================= */

static __always_inline int
parse_packet(struct __sk_buff *skb, struct packet_info *pkt) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* --- Ethernet --------------------------------------------------------- */
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;    /* ignore non-IPv4 for now */

    /* --- IPv4 ------------------------------------------------------------- */
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return -1;

    pkt->src_ip  = ip->saddr;
    pkt->dst_ip  = ip->daddr;
    pkt->proto   = ip->protocol;
    pkt->pkt_len = bpf_ntohs(ip->tot_len);

    /* --- TCP -------------------------------------------------------------- */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + sizeof(struct iphdr));
        if ((void *)(tcp + 1) > data_end)
            return -1;

        pkt->src_port  = bpf_ntohs(tcp->source);
        pkt->dst_port  = bpf_ntohs(tcp->dest);
        pkt->tcp_flags = (tcp->fin)
                       | (tcp->syn << 1)
                       | (tcp->rst << 2)
                       | (tcp->ack << 3)
                       | (tcp->urg << 4);
        return 0;
    }

    /* --- UDP -------------------------------------------------------------- */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + sizeof(struct iphdr));
        if ((void *)(udp + 1) > data_end)
            return -1;

        pkt->src_port  = bpf_ntohs(udp->source);
        pkt->dst_port  = bpf_ntohs(udp->dest);
        pkt->tcp_flags = 0;
        return 0;
    }

    /* --- ICMP ------------------------------------------------------------- */
    if (ip->protocol == IPPROTO_ICMP) {
        pkt->src_port  = 0;
        pkt->dst_port  = 0;
        pkt->tcp_flags = 0;
        return 0;
    }

    return -1;  /* unsupported protocol */
}

/* XDP variant of parse_packet */
static __always_inline int
parse_packet_xdp(struct xdp_md *ctx, struct packet_info *pkt) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *ip = (struct iphdr *)(eth + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return -1;

    pkt->src_ip  = ip->saddr;
    pkt->dst_ip  = ip->daddr;
    pkt->proto   = ip->protocol;
    pkt->pkt_len = bpf_ntohs(ip->tot_len);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + sizeof(struct iphdr));
        if ((void *)(tcp + 1) > data_end)
            return -1;
        pkt->src_port  = bpf_ntohs(tcp->source);
        pkt->dst_port  = bpf_ntohs(tcp->dest);
        pkt->tcp_flags = (tcp->fin)
                       | (tcp->syn << 1)
                       | (tcp->rst << 2)
                       | (tcp->ack << 3);
        return 0;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + sizeof(struct iphdr));
        if ((void *)(udp + 1) > data_end)
            return -1;
        pkt->src_port  = bpf_ntohs(udp->source);
        pkt->dst_port  = bpf_ntohs(udp->dest);
        pkt->tcp_flags = 0;
        return 0;
    }

    if (ip->protocol == IPPROTO_ICMP) {
        pkt->src_port  = 0;
        pkt->dst_port  = 0;
        pkt->tcp_flags = 0;
        return 0;
    }

    return -1;
}

/* =============================================================================
 * FNV-1a hash — for DNS domain hashing
 * ============================================================================= */

#define FNV_OFFSET_BASIS 2166136261U
#define FNV_PRIME        16777619U

static __always_inline __u32
fnv1a_hash(const __u8 *data, int len) {
    __u32 hash = FNV_OFFSET_BASIS;

    #pragma unroll
    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        if (i >= len) break;
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

#endif /* __COMMON_H__ */