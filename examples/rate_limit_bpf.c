/* =============================================================================
 * rate_limit.bpf.c
 *
 * Attach point : TC ingress (on host-side veth or bridge)
 * Purpose      : Token bucket rate limiter per (src_ip, container, proto)
 *                Protects against:
 *                  - SYN flood
 *                  - UDP flood
 *                  - ICMP flood
 *                  - Port scan (high rate of SYN to different ports)
 * ============================================================================= */

#include "common.h"
#include "maps.h"

/* =============================================================================
 * check_rate_limit
 * Returns 1 = within limit (allow), 0 = over limit (drop)
 * ============================================================================= */
static __always_inline int
check_rate_limit(__u32 src_ip, __u64 cgroup_id, __u8 proto) {
    struct rate_key key = {
        .src_ip    = src_ip,
        .cgroup_id = cgroup_id,
        .proto     = proto,
    };

    __u64 now = bpf_ktime_get_ns();

    struct rate_val *val = bpf_map_lookup_elem(&rate_limiter, &key);

    if (!val) {
        /* first packet from this source — create bucket */
        struct rate_val init = {
            .tokens         = RATE_LIMIT_BURST - 1,
            .last_refill_ns = now,
        };
        bpf_map_update_elem(&rate_limiter, &key, &init, BPF_ANY);
        return 1;  /* allow first packet */
    }

    /* refill tokens based on elapsed time */
    __u64 elapsed    = now - val->last_refill_ns;
    __u64 new_tokens = elapsed / RATE_LIMIT_NS_PER_TOKEN;

    if (new_tokens > 0) {
        val->tokens = MIN(val->tokens + new_tokens,
                          (__u64)RATE_LIMIT_BURST);
        val->last_refill_ns = now;
    }

    /* check if any tokens left */
    if (val->tokens == 0)
        return 0;  /* over limit — drop */

    val->tokens--;
    return 1;  /* within limit — allow */
}

/* =============================================================================
 * tc_rate_limit — main rate limiting program
 * ============================================================================= */
SEC("tc")
int tc_rate_limit(struct __sk_buff *skb) {
    struct packet_info pkt = {};

    if (parse_packet(skb, &pkt) < 0)
        return TC_ACT_OK;  /* pass non-parseable packets */

    __u64 cgroup_id = bpf_skb_cgroup_id(skb);

    /* -------------------------------------------------------------------------
     * Only rate-limit new connection attempts (SYN) and UDP/ICMP
     * Established TCP connections (ACK) are not rate limited
     * ------------------------------------------------------------------------- */
    int should_check = 0;

    if (pkt.proto == IPPROTO_TCP) {
        /* only check SYN packets — new connection attempts */
        if (pkt.tcp_flags & TCP_FLAG_SYN &&
           !(pkt.tcp_flags & TCP_FLAG_ACK)) {
            should_check = 1;
        }
    } else if (pkt.proto == IPPROTO_UDP) {
        should_check = 1;
    } else if (pkt.proto == IPPROTO_ICMP) {
        should_check = 1;
    }

    if (!should_check)
        return TC_ACT_OK;

    /* -------------------------------------------------------------------------
     * Check rate limit
     * ------------------------------------------------------------------------- */
    if (!check_rate_limit(pkt.src_ip, cgroup_id, pkt.proto)) {
        emit_fw_event(&pkt, cgroup_id, ACTION_RATELIMIT, REASON_RATE_LIMIT);
        inc_drop_counter(cgroup_id);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";