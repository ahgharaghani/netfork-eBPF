#ifndef MAPS_H
#define MAPS_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct container_identity_key);
    __type(value, struct container_identity_val);
} container_identity_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dnat_map_key);
    __type(value, struct dnat_map_val);
} dnat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct snat_map_key);
    __type(value, struct snat_map_val);
} snat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct forward_policy_key);
    __type(value, struct forward_policy_val);
} forward_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conntrack_key);
    __type(value, struct conntrack_val);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32); /* bridge interface ifindex */
    __type(value, u32); /* reserved; 0 = member of isolation group */
} bridge_isolation_set SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32); /* must be 0 */
    __type(value, struct global_config);
} global_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, fd); /* program fd */
} prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct metrics_map_key);
    __type(value, struct metrics_map_val);
} metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256KB */
    __type(value, struct event_record);
} events_ringbuf SEC(".maps");

#endif /* MAPS_H */