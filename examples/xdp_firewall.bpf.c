/* =============================================================================
 * xdp_firewall.bpf.c
 *
 * Attach point : XDP (on container veth or host interface)
 * Purpose      : Drop packets from blocked IPs before sk_buff allocation
 *                Fastest possible drop — runs at NIC driver level
 *
 * Attach from JS:
 *   bpftool net attach xdp dev eth0 pinned /sys/fs/bpf/xdp_firewall
 * ============================================================================= */

#include "common.h"
#include "maps.h"

/* =============================================================================
 * lookup_rule — check fw_rules map for a matching 5-tuple
 * Returns pointer to rule or NULL if no match
 * ============================================================================= */
static __always_inline struct fw_rule *
lookup_rule(struct packet_info *pkt) {
    struct five_tuple key = {
        .src_ip   = pkt->src_ip,
        .dst_ip   = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .proto    = pkt->proto,
    };
    return bpf_map_lookup_elem(&fw_rules, &key);
}

/* =============================================================================
 * xdp_firewall — main XDP program
 * ============================================================================= */
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    struct packet_info pkt = {};

    /* parse packet — drop malformed */
    if (parse_packet_xdp(ctx, &pkt) < 0)
        return XDP_PASS;   /* pass non-IP traffic (ARP etc.) */

    /* -------------------------------------------------------------------------
     * Step 1: check global IP blocklist
     * This is the fastest check — single hash lookup
     * ------------------------------------------------------------------------- */
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &pkt.src_ip);
    if (blocked) {
        /* emit drop event to ring buffer */
        emit_fw_event(&pkt, 0, ACTION_DROP, REASON_BLOCKLIST);
        return XDP_DROP;
    }

    /* -------------------------------------------------------------------------
     * Step 2: check explicit firewall rules (5-tuple)
     * ------------------------------------------------------------------------- */
    struct fw_rule *rule = lookup_rule(&pkt);
    if (rule) {
        if (rule->action == ACTION_DROP) {
            emit_fw_event(&pkt, rule->container_id, ACTION_DROP, rule->reason);
            inc_drop_counter(rule->container_id);
            return XDP_DROP;
        }
        /* ACTION_ALLOW — pass to TC/netfilter for further processing */
        inc_allow_counter(rule->container_id, pkt.pkt_len, 0);
        return XDP_PASS;
    }

    /* -------------------------------------------------------------------------
     * Step 3: block RST flood — drop RST packets with no matching rule
     * Protects against TCP RST injection attacks
     * ------------------------------------------------------------------------- */
    if (pkt.proto == IPPROTO_TCP &&
        (pkt.tcp_flags & TCP_FLAG_RST) &&
       !(pkt.tcp_flags & TCP_FLAG_ACK)) {
        emit_fw_event(&pkt, 0, ACTION_DROP, REASON_NO_RULE);
        return XDP_DROP;
    }

    /* -------------------------------------------------------------------------
     * Step 4: no explicit rule — pass to TC layer for conntrack check
     * Default policy is enforced at TC layer
     * ------------------------------------------------------------------------- */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";