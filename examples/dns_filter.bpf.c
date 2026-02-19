/* =============================================================================
 * dns_filter.bpf.c
 *
 * Attach point : TC ingress on container veth (catches outgoing DNS queries)
 * Purpose      : Intercept DNS queries, block forbidden domains
 *                Parses UDP DNS wire format directly in eBPF
 *
 * DNS packet layout (after UDP header):
 *   [2] transaction id
 *   [2] flags
 *   [2] questions count
 *   [2] answers count
 *   [2] authority count
 *   [2] additional count
 *   [N] query name (label encoding)
 *   [2] query type
 *   [2] query class
 * ============================================================================= */

#include "common.h"
#include "maps.h"

/* DNS header offsets after UDP payload start */
#define DNS_HDR_LEN     12
#define DNS_NAME_OFFSET (14 + 8 + DNS_HDR_LEN)  /* eth + ip + udp + dns_hdr */

/* max labels we will walk in the DNS name */
#define MAX_DNS_LABELS  10
#define MAX_LABEL_LEN   63

/* =============================================================================
 * extract_dns_name
 * Reads DNS query name from packet and copies into output buffer
 * Converts label format (3www6google3com0) → "www.google.com"
 * Returns length of domain string, or -1 on error
 * ============================================================================= */
static __always_inline int
extract_dns_name(struct __sk_buff *skb, __u8 *out, int out_len) {
    /* DNS query name starts at byte offset DNS_NAME_OFFSET */
    int offset  = DNS_NAME_OFFSET;
    int out_pos = 0;

    /* walk labels — eBPF verifier requires bounded loop */
    #pragma unroll
    for (int label = 0; label < MAX_DNS_LABELS; label++) {
        /* read label length byte */
        __u8 label_len = 0;
        if (bpf_skb_load_bytes(skb, offset, &label_len, 1) < 0)
            return -1;

        /* label_len == 0 means end of name */
        if (label_len == 0)
            break;

        /* guard against pointer compression (label_len >= 0xC0) */
        if (label_len >= 0xC0)
            break;

        offset++;  /* move past length byte */

        /* add separator dot (skip for first label) */
        if (out_pos > 0 && out_pos < out_len - 1)
            out[out_pos++] = '.';

        /* copy label bytes */
        #pragma unroll
        for (int i = 0; i < MAX_LABEL_LEN; i++) {
            if (i >= label_len) break;
            if (out_pos >= out_len - 1) break;

            __u8 ch = 0;
            if (bpf_skb_load_bytes(skb, offset + i, &ch, 1) < 0)
                return -1;

            /* lowercase the character */
            if (ch >= 'A' && ch <= 'Z')
                ch += 32;

            out[out_pos++] = ch;
        }

        offset += label_len;
    }

    out[out_pos] = '\0';
    return out_pos;
}

/* =============================================================================
 * emit_dns_block_event — specialized ring buffer event for DNS blocks
 * ============================================================================= */
static __always_inline void
emit_dns_block_event(struct packet_info *pkt, __u64 cgroup_id,
                     const __u8 *domain, __u32 domain_hash) {
    struct fw_event *e = bpf_ringbuf_reserve(&fw_events, sizeof(*e), 0);
    if (!e) return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = cgroup_id;
    e->src_ip       = pkt->src_ip;
    e->dst_ip       = pkt->dst_ip;
    e->src_port     = pkt->src_port;
    e->dst_port     = pkt->dst_port;
    e->proto        = pkt->proto;
    e->action       = ACTION_DROP;
    e->reason       = REASON_DNS_BLOCK;
    e->pkt_len      = pkt->pkt_len;
    e->tcp_flags    = 0;
    e->pad          = 0;
    e->pad2         = 0;

    bpf_ringbuf_submit(e, 0);
}

/* =============================================================================
 * dns_filter — main DNS filtering program
 * ============================================================================= */
SEC("tc")
int dns_filter(struct __sk_buff *skb) {
    struct packet_info pkt = {};

    /* parse ethernet + ip + transport headers */
    if (parse_packet(skb, &pkt) < 0)
        return TC_ACT_OK;

    /* we only care about UDP DNS queries */
    if (pkt.proto    != IPPROTO_UDP) return TC_ACT_OK;
    if (pkt.dst_port != DNS_PORT)    return TC_ACT_OK;

    __u64 cgroup_id = bpf_skb_cgroup_id(skb);

    /* extract domain name from DNS query */
    __u8 domain[MAX_DOMAIN_LEN] = {};
    int  domain_len = extract_dns_name(skb, domain, MAX_DOMAIN_LEN);

    if (domain_len <= 0)
        return TC_ACT_OK;  /* could not parse — pass */

    /* hash the domain and look it up in the blocklist */
    __u32 domain_hash = fnv1a_hash(domain, domain_len);
    __u8 *blocked     = bpf_map_lookup_elem(&blocked_domains, &domain_hash);

    if (blocked) {
        emit_dns_block_event(&pkt, cgroup_id, domain, domain_hash);
        inc_drop_counter(cgroup_id);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";