/* =============================================================================
 * maps.h — all shared eBPF maps
 * ============================================================================= */

#ifndef __MAPS_H__
#define __MAPS_H__

#include "common.h"

/* =============================================================================
 * 1. IP blocklist
 *    key   : u32 src IP
 *    value : u8  reason code
 *    JS pushes bad IPs here
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key,   __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

/* =============================================================================
 * 2. Firewall rules
 *    key   : five_tuple (src_ip, dst_ip, src_port, dst_port, proto)
 *    value : fw_rule (action, container_id)
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key,   struct five_tuple);
    __type(value, struct fw_rule);
} fw_rules SEC(".maps");

/* =============================================================================
 * 3. Connection tracking
 *    LRU so old entries are evicted automatically
 *    key   : five_tuple
 *    value : conn_state
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 200000);
    __type(key,   struct five_tuple);
    __type(value, struct conn_state);
} conntrack SEC(".maps");

/* =============================================================================
 * 4. Per-container policy
 *    key   : u64 cgroup_id
 *    value : container_policy
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);
    __type(value, struct container_policy);
} container_policies SEC(".maps");

/* =============================================================================
 * 5. Packet stats — PERCPU so no lock contention
 *    key   : u64 cgroup_id
 *    value : pkt_counters
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);
    __type(value, struct pkt_counters);
} pkt_stats SEC(".maps");

/* =============================================================================
 * 6. Rate limiter — token bucket per (src_ip, cgroup_id, proto)
 *    LRU so idle entries are evicted
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 200000);
    __type(key,   struct rate_key);
    __type(value, struct rate_val);
} rate_limiter SEC(".maps");

/* =============================================================================
 * 7. DNS domain blocklist
 *    key   : u32 FNV-1a hash of domain name
 *    value : u8  (1 = blocked)
 *    Collision is acceptable — false positives just block extra domains
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key,   __u32);
    __type(value, __u8);
} blocked_domains SEC(".maps");

/* =============================================================================
 * 8. Ring buffer — events streamed to userspace (JS)
 *    All programs write fw_event structs here
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);  /* 4MB */
} fw_events SEC(".maps");

/* =============================================================================
 * 9. Per-container egress allowlist
 *    key   : endpoint (ip + port + proto)
 *    value : u8 (1 = allowed)
 *    Used by cgroup program for strict egress whitelisting
 * ============================================================================= */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key,   struct endpoint);
    __type(value, __u8);
} egress_allowlist SEC(".maps");

/* =============================================================================
 * Helpers that write to shared maps — inlined into each program
 * ============================================================================= */

/* emit a firewall event to the ring buffer */
static __always_inline void
emit_fw_event(struct packet_info *pkt, __u64 cgroup_id,
              __u8 action, __u8 reason) {

    struct fw_event *e = bpf_ringbuf_reserve(&fw_events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = cgroup_id;
    e->src_ip       = pkt->src_ip;
    e->dst_ip       = pkt->dst_ip;
    e->src_port     = pkt->src_port;
    e->dst_port     = pkt->dst_port;
    e->proto        = pkt->proto;
    e->action       = action;
    e->reason       = reason;
    e->pkt_len      = pkt->pkt_len;
    e->tcp_flags    = pkt->tcp_flags;
    e->pad          = 0;
    e->pad2         = 0;

    bpf_ringbuf_submit(e, 0);
}

/* increment drop counter for a container */
static __always_inline void
inc_drop_counter(__u64 cgroup_id) {
    struct pkt_counters *c = bpf_map_lookup_elem(&pkt_stats, &cgroup_id);
    if (c) {
        __sync_fetch_and_add(&c->dropped, 1);
    } else {
        struct pkt_counters init = {};
        init.dropped = 1;
        bpf_map_update_elem(&pkt_stats, &cgroup_id, &init, BPF_NOEXIST);
    }
}

/* increment allow counter for a container */
static __always_inline void
inc_allow_counter(__u64 cgroup_id, __u16 pkt_len, int direction) {
    struct pkt_counters *c = bpf_map_lookup_elem(&pkt_stats, &cgroup_id);
    if (c) {
        if (direction == 0) {
            __sync_fetch_and_add(&c->rx_packets, 1);
            __sync_fetch_and_add(&c->rx_bytes, pkt_len);
        } else {
            __sync_fetch_and_add(&c->tx_packets, 1);
            __sync_fetch_and_add(&c->tx_bytes, pkt_len);
        }
    } else {
        struct pkt_counters init = {};
        if (direction == 0) { init.rx_packets = 1; init.rx_bytes = pkt_len; }
        else                 { init.tx_packets = 1; init.tx_bytes = pkt_len; }
        bpf_map_update_elem(&pkt_stats, &cgroup_id, &init, BPF_NOEXIST);
    }
}

#endif /* __MAPS_H__ */