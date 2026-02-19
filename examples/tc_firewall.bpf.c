/* =============================================================================
 * tc_firewall.bpf.c
 *
 * Attach point : TC ingress + TC egress on container veth interface
 * Purpose      : Full stateful firewall with connection tracking
 *                Runs after XDP, has access to full sk_buff
 *
 * Attach from JS (per container veth):
 *   tc qdisc add dev veth0 clsact
 *   tc filter add dev veth0 ingress bpf obj tc_firewall.bpf.o sec tc_ingress
 *   tc filter add dev veth0 egress  bpf obj tc_firewall.bpf.o sec tc_egress
 * ============================================================================= */

#include "common.h"
#include "maps.h"

/* =============================================================================
 * conntrack_lookup — check if packet belongs to established connection
 * ============================================================================= */
static __always_inline struct conn_state *
conntrack_lookup(struct packet_info *pkt) {
    struct five_tuple key = {
        .src_ip   = pkt->src_ip,
        .dst_ip   = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .proto    = pkt->proto,
    };
    return bpf_map_lookup_elem(&conntrack, &key);
}

/* =============================================================================
 * conntrack_insert — record a new allowed connection
 * ============================================================================= */
static __always_inline void
conntrack_insert(struct packet_info *pkt, __u64 container_id) {
    struct five_tuple key = {
        .src_ip   = pkt->src_ip,
        .dst_ip   = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .proto    = pkt->proto,
    };

    struct conn_state state = {
        .established  = 1,
        .last_seen_ns = bpf_ktime_get_ns(),
        .container_id = container_id,
        .bytes        = pkt->pkt_len,
    };

    bpf_map_update_elem(&conntrack, &key, &state, BPF_ANY);
}

/* =============================================================================
 * conntrack_delete — remove connection (on FIN/RST)
 * ============================================================================= */
static __always_inline void
conntrack_delete(struct packet_info *pkt) {
    struct five_tuple key = {
        .src_ip   = pkt->src_ip,
        .dst_ip   = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .proto    = pkt->proto,
    };
    bpf_map_delete_elem(&conntrack, &key);
}

/* =============================================================================
 * apply_firewall — shared logic for ingress and egress
 * Returns TC_ACT_OK or TC_ACT_SHOT
 * ============================================================================= */
static __always_inline int
apply_firewall(struct __sk_buff *skb, int direction) {
    struct packet_info pkt = {};

    /* drop malformed packets */
    if (parse_packet(skb, &pkt) < 0)
        return TC_ACT_SHOT;

    /* get cgroup id of socket owning this packet */
    __u64 cgroup_id = bpf_skb_cgroup_id(skb);

    /* -------------------------------------------------------------------------
     * Step 1: check connection tracking (fast path for established conns)
     * ------------------------------------------------------------------------- */
    struct conn_state *state = conntrack_lookup(&pkt);
    if (state && state->established) {

        /* update last seen timestamp and byte count */
        state->last_seen_ns = bpf_ktime_get_ns();
        __sync_fetch_and_add(&state->bytes, pkt.pkt_len);

        /* remove connection on FIN or RST */
        if (pkt.proto == IPPROTO_TCP &&
            (pkt.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST))) {
            conntrack_delete(&pkt);
        }

        inc_allow_counter(cgroup_id, pkt.pkt_len, direction);
        return TC_ACT_OK;
    }

    /* -------------------------------------------------------------------------
     * Step 2: check IP blocklist
     * ------------------------------------------------------------------------- */
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &pkt.src_ip);
    if (blocked) {
        emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_BLOCKLIST);
        inc_drop_counter(cgroup_id);
        return TC_ACT_SHOT;
    }

    /* -------------------------------------------------------------------------
     * Step 3: check explicit 5-tuple firewall rule
     * ------------------------------------------------------------------------- */
    struct five_tuple key = {
        .src_ip   = pkt.src_ip,
        .dst_ip   = pkt.dst_ip,
        .src_port = pkt.src_port,
        .dst_port = pkt.dst_port,
        .proto    = pkt.proto,
    };

    struct fw_rule *rule = bpf_map_lookup_elem(&fw_rules, &key);
    if (rule) {
        if (rule->action == ACTION_DROP) {
            emit_fw_event(&pkt, rule->container_id, ACTION_DROP, rule->reason);
            inc_drop_counter(rule->container_id);
            return TC_ACT_SHOT;
        }

        /* allowed — insert into conntrack */
        conntrack_insert(&pkt, rule->container_id);
        inc_allow_counter(rule->container_id, pkt.pkt_len, direction);
        return TC_ACT_OK;
    }

    /* -------------------------------------------------------------------------
     * Step 4: check container policy (default action)
     * ------------------------------------------------------------------------- */
    struct container_policy *policy =
        bpf_map_lookup_elem(&container_policies, &cgroup_id);

    if (!policy) {
        /* no policy at all — default deny */
        emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_NO_RULE);
        inc_drop_counter(cgroup_id);
        return TC_ACT_SHOT;
    }

    if (policy->default_action == ACTION_DROP) {
        if (policy->log_drops)
            emit_fw_event(&pkt, cgroup_id, ACTION_DROP, REASON_NO_RULE);
        inc_drop_counter(cgroup_id);
        return TC_ACT_SHOT;
    }

    /* default allow — track new connection */
    conntrack_insert(&pkt, cgroup_id);
    if (policy->log_allows)
        emit_fw_event(&pkt, cgroup_id, ACTION_ALLOW, REASON_NO_RULE);
    inc_allow_counter(cgroup_id, pkt.pkt_len, direction);

    return TC_ACT_OK;
}

/* =============================================================================
 * tc_ingress — packets coming INTO the container
 * ============================================================================= */
SEC("tc")
int tc_ingress_firewall(struct __sk_buff *skb) {
    return apply_firewall(skb, 0 /* ingress = rx */);
}

/* =============================================================================
 * tc_egress — packets going OUT of the container
 * ============================================================================= */
SEC("tc")
int tc_egress_firewall(struct __sk_buff *skb) {
    return apply_firewall(skb, 1 /* egress = tx */);
}

char LICENSE[] SEC("license") = "GPL";