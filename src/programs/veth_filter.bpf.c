#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

#define ETH_P_IP      0x0800
#define ETH_P_ARP     0x0806
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_IPV6    0x86DD
#define ETH_ALEN      6

#define ARP_ETH_IPV4_LEN 28

SEC("xdp")
int veth_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end) {
#ifdef DEBUG
        static const char fmt[] = "Packet too short for Ethernet header: data=%d, data_end=%d\n";
        void *args[] = { &data, &data_end };
        bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
        return XDP_DROP;
    }

    struct ethhdr *eth = (struct ethhdr *)data;
    u16 ethertype = eth->h_proto;
    void *l3_hdr = data + sizeof(struct ethhdr);

    if (bpf_ntohs(ethertype) == ETH_P_8021Q || bpf_ntohs(ethertype) ==  ETH_P_8021AD) {
        if (l3_hdr + sizeof(struct vlan_hdr) > data_end) {
#ifdef DEBUG
            static const char fmt[] = "Packet too short for VLAN header: data=%d, data_end=%d\n";
            void *args[] = { &data, &data_end };
            bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
            return XDP_DROP;
        }
        struct vlan_hdr *vhdr = (struct vlan_hdr *)l3_hdr;
        ethertype = vhdr->h_vlan_encapsulated_proto;
        l3_hdr += sizeof(struct vlan_hdr);
    }

    struct container_identity_key identity_key = {
        .ifindex = ctx->ingress_ifindex,
    };

    struct container_identity_val *identity = bpf_map_lookup_elem(&container_identity_map, &identity_key);
    /* Check identity existence */
    if (!identity) {
        struct event *e;
        // e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            // TODO: log failure to reserve space in ring buffer
        } else {
            // TODO: emit event for packet from unknown interface
        }
#ifdef DEBUG
        static const char fmt[] = "Unknown interface: ifindex=%d\n";
        void *args[] = { &ctx->ingress_ifindex };
        bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
        return XDP_DROP;
    }
    /* Check MAC Address */
    if (__builtin_memcmp(eth->h_source, identity->mac_address, 6) != 0) {
        struct event *e;
        // e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            // TODO: log failure to reserve space in ring buffer
        } else {
            // TODO: emit event for spoofed mac_address
        }
#ifdef DEBUG
        static const char fmt[] = "MAC address mismatch: packet=%02x:%02x:%02x:%02x:%02x:%02x, identity=%02x:%02x:%02x:%02x:%02x:%02x\n";
        void *args[] = {
            &eth->h_source[0], &eth->h_source[1], &eth->h_source[2], &eth->h_source[3], &eth->h_source[4], &eth->h_source[5],
            &identity->mac_address[0], &identity->mac_address[1], &identity->mac_address[2], &identity->mac_address[3], &identity->mac_address[4], &identity->mac_address[5]
        };
        bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
        return XDP_DROP;
    }

    switch (bpf_ntohs(ethertype))
    {
    case ETH_P_IP: {
        if (l3_hdr + sizeof(struct iphdr) > data_end) {
            return XDP_DROP;
        }
        struct iphdr *ip_hdr = (struct iphdr *)l3_hdr;
        u32 src_ip = ip_hdr->saddr;
        if (src_ip == bpf_htonl(identity->ip_address)) {
            // TODO: increment passed packet count for this identity
            return XDP_PASS;
        } else {
            struct event *e;
            // e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e) {
                // TODO: log failure to reserve space in ring buffer
            } else {
                // TODO: emit event for spoofed ip_address
            }
            // TODO: increment dropped packet count for this identity
#ifdef DEBUG
            static const char fmt[] = "IP address mismatch: packet=%d.%d.%d.%d, identity=%d.%d.%d.%d\n";
            void *args[] = {
                (bpf_ntohl(src_ip) >> 24) & 0xFF, (bpf_ntohl(src_ip) >> 16) & 0xFF, (bpf_ntohl(src_ip) >> 8) & 0xFF, bpf_ntohl(src_ip) & 0xFF,
                (bpf_ntohl(identity->ip_address) >> 24) & 0xFF, (bpf_ntohl(identity->ip_address) >> 16) & 0xFF, (bpf_ntohl(identity->ip_address) >> 8) & 0xFF, bpf_ntohl(identity->ip_address) & 0xFF
            };
            bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
            return XDP_DROP;
        }
    }
    
    case ETH_P_ARP: {
        if (l3_hdr + ARP_ETH_IPV4_LEN > data_end) {
            return XDP_DROP;
        }
        struct arphdr *arp_hdr = (struct arphdr *)l3_hdr;
        if (arp_hdr->ar_hln != ETH_ALEN || arp_hdr->ar_pln != 4) {
            return XDP_DROP;
        }

        /* Read SHA via raw offsets */
        u8 *sha = (u8 *)arp_hdr + sizeof(struct arphdr);
        
        u32 sha_lo = ((u32)sha[0] << 24) | ((u32)sha[1] << 16) | ((u32)sha[2] << 8)  |  (u32)sha[3];
        u16 sha_hi = ((u16)sha[4] << 8)  |  (u16)sha[5];

        u32 mac_lo = 
            identity->mac_address[0] << 24 |
            identity->mac_address[1] << 16 |
            identity->mac_address[2] <<  8 |
            identity->mac_address[3];
        u16 mac_hi = (identity->mac_address[4] << 8) | identity->mac_address[5];

        if (sha_lo != mac_lo || sha_hi != mac_hi) {
            struct event *e;
            // e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e) {
                // TODO: log failure to reserve space in ring buffer
            } else {
                // TODO: emit event for spoofed mac_address in ARP packet
            }
#ifdef DEBUG
            static const char fmt[] = "MAC address mismatch in ARP: packet=%02x:%02x:%02x:%02x:%02x:%02x, identity=%02x:%02x:%02x:%02x:%02x:%02x\n";
            void *args[] = {
                &sha[0], &sha[1], &sha[2], &sha[3], &sha[4], &sha[5],
                &identity->mac_address[0], &identity->mac_address[1], &identity->mac_address[2], &identity->mac_address[3], &identity->mac_address[4], &identity->mac_address[5]
            };
            bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
            return XDP_DROP;
        }
        
        /* Read SPA via raw offsets */
        u8 *spa = sha + ETH_ALEN;
        if ((void *)(spa + 4) > data_end) {
            return XDP_DROP;
        }

        u32 spa_ip = ((u32)spa[0] << 24) | ((u32)spa[1] << 16) | ((u32)spa[2] << 8) | (u32)spa[3];
        if (spa_ip != bpf_ntohl(identity->ip_address)) {
            struct event *e;
            // e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e) {
                // TODO: log failure to reserve space in ring buffer
            } else {
                // TODO: emit event for spoofed ip_address in ARP packet
            }
#ifdef DEBUG
            static const char fmt[] = "IP address mismatch in ARP: packet=%d.%d.%d.%d, identity=%d.%d.%d.%d\n";
            void *args[] = {
                (bpf_ntohl(spa_ip) >> 24) & 0xFF, (bpf_ntohl(spa_ip) >> 16) & 0xFF, (bpf_ntohl(spa_ip) >> 8) & 0xFF, bpf_ntohl(spa_ip) & 0xFF,
                (bpf_ntohl(identity->ip_address) >> 24) & 0xFF, (bpf_ntohl(identity->ip_address) >> 16) & 0xFF, (bpf_ntohl(identity->ip_address) >> 8) & 0xFF, bpf_ntohl(identity->ip_address) & 0xFF
            };
            bpf_trace_vprintk(fmt, sizeof(fmt), args, sizeof(args));
#endif
            return XDP_DROP;
        } else {
            // TODO: increment passed packet count for this identity
            return XDP_PASS;
        }
    }

    default:
        return XDP_PASS;
    }
}