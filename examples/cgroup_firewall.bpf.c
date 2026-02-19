/* =============================================================================
 * cgroup_firewall.bpf.c
 *
 * Attach point : cgroup_skb/ingress + cgroup_skb/egress
 * Purpose      : Per-container network policy via cgroup hierarchy
 *                One program instance per container cgroup
 *                Cleaner than TC because cgroup membership = container
 *
 * Attach from JS:
 *   bpftool prog load cgroup_firewall.bpf.o /sys/fs/bpf/cgroup_fw
 *   bpftool cgroup attach /sys/fs/cgroup/system.slice/docker-<id>.scope \
 *           egress pinned /sys/fs/bpf/cgroup_fw
 * ============================================================================= */

#include "common.h"
#include "maps.h"

/* =============================================================================
 * is_endpoint_allowed — check egress allowlist for this destination
 * ============================================================================= */
static __always_inline int
is_endpoint_allowed(__u32 dst_ip, __u16 dst_port, __u8 proto) {
    struct endpoint key = {
        .ip    = dst_ip,
        .port  = dst_port,
        .proto = proto,
        .pad   = 0,
    };
    __u8 *allowed = bpf_map_lookup_elem(&egress_allowlist, &key);
    return (allowed != NULL);
}

/* =============================================================================
 * cgroup_egress — all packets leaving any process in this cgroup
 * Returns 1 = allow, 0 = drop
 * ============================================================================= */
SEC("cgroup_skb/egress")
int container_egress_policy(struct __sk_buff *skb) {
    /* get container identity from cgroup */
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);

    /* get policy for this container */
    struct container_policy *policy =
        bpf_map_lookup_elem(&container_policies, &cgroup_id);

    if (!policy)
        return 0;  /* no policy — default deny */

    /* parse packet */
    struct packet_info pkt = {};
    if (parse_packet(skb, &pkt) < 0)
        return 0;  /* drop malformed */

    /* -------------------------------------------------------------------------
     * Check global IP blocklist — never allow traffic to blocked IPs
     * ------------------------------------------------------------------------- */
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &pkt.dst_ip);
    if (blocked) {
        emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_BLOCKLIST);
        inc_drop_counter(cgroup_id);
        return 0;
    }

    /* -------------------------------------------------------------------------
     * Check conntrack — established connection, fast path
     * ------------------------------------------------------------------------- */
    struct conn_state *state = bpf_map_lookup_elem(&conntrack,
        &(struct five_tuple){
            .src_ip   = pkt.src_ip,
            .dst_ip   = pkt.dst_ip,
            .src_port = pkt.src_port,
            .dst_port = pkt.dst_port,
            .proto    = pkt.proto,
        });

    if (state && state->established) {
        state->last_seen_ns = bpf_ktime_get_ns();
        __sync_fetch_and_add(&state->bytes, pkt.pkt_len);
        inc_allow_counter(cgroup_id, pkt.pkt_len, 1);
        return 1;
    }

    /* -------------------------------------------------------------------------
     * Check egress allowlist
     * ------------------------------------------------------------------------- */
    if (!is_endpoint_allowed(pkt.dst_ip, pkt.dst_port, pkt.proto)) {
        if (policy->log_drops)
            emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_NO_RULE);
        inc_drop_counter(cgroup_id);
        return 0;
    }

    /* allowed — track connection */
    struct five_tuple conn_key = {
        .src_ip   = pkt.src_ip,
        .dst_ip   = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port,
        .proto    = pkt.proto,
    };

    struct conn_state new_state = {
        .established  = 1,
        .last_seen_ns = bpf_ktime_get_ns(),
        .container_id = cgroup_id,
        .bytes        = pkt.pkt_len,
    };

    bpf_map_update_elem(&conntrack, &conn_key, &new_state, BPF_ANY);

    if (policy->log_allows)
        emit_fw_event(&pkt, cgroup_id, ACTION_ALLOW, REASON_NO_RULE);

    inc_allow_counter(cgroup_id, pkt.pkt_len, 1);
    return 1;
}

/* =============================================================================
 * cgroup_ingress — all packets arriving to any process in this cgroup
 * Returns 1 = allow, 0 = drop
 * ============================================================================= */
SEC("cgroup_skb/ingress")
int container_ingress_policy(struct __sk_buff *skb) {
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);

    struct container_policy *policy =
        bpf_map_lookup_elem(&container_policies, &cgroup_id);

    if (!policy)
        return 0;

    struct packet_info pkt = {};
    if (parse_packet(skb, &pkt) < 0)
        return 0;

    /* -------------------------------------------------------------------------
     * Check IP blocklist
     * ------------------------------------------------------------------------- */
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &pkt.src_ip);
    if (blocked) {
        emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_BLOCKLIST);
        inc_drop_counter(cgroup_id);
        return 0;
    }

    /* -------------------------------------------------------------------------
     * Check conntrack — reply packets for established egress connections
     * ------------------------------------------------------------------------- */
    /* reverse the tuple to match the original egress direction */
    struct five_tuple reverse_key = {
        .src_ip   = pkt.dst_ip,    /* reversed */
        .dst_ip   = pkt.src_ip,    /* reversed */
        .src_port = pkt.dst_port,  /* reversed */
        .dst_port = pkt.src_port,  /* reversed */
        .proto    = pkt.proto,
    };

    struct conn_state *state = bpf_map_lookup_elem(&conntrack, &reverse_key);
    if (state && state->established) {
        state->last_seen_ns = bpf_ktime_get_ns();
        __sync_fetch_and_add(&state->bytes, pkt.pkt_len);
        inc_allow_counter(cgroup_id, pkt.pkt_len, 0);
        return 1;  /* reply to known connection — allow */
    }

    /* -------------------------------------------------------------------------
     * Check container policy default action
     * ------------------------------------------------------------------------- */
    if (policy->default_action == ACTION_DROP) {
        if (policy->log_drops)
            emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_NO_RULE);
        inc_drop_counter(cgroup_id);
        return 0;
    }

    inc_allow_counter(cgroup_id, pkt.pkt_len, 0);
    return 1;
}

char LICENSE[] SEC("license") = "GPL";