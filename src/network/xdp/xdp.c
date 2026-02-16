//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

struct datarec {
	__u64 bytes;     // Cumulative byte count
	__u64 last_seen; // Timestamp of the last packet in nanoseconds
};

// Define an LRU hash map for storing byte count and timestamp by veth interface
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);            // Virtual interface index
	__type(value, struct datarec); // Bytes and timestamp
} xdp_stats_map SEC(".maps");

static __always_inline int parse_eth_pkt(struct xdp_md *ctx, __u64 *pkt_size) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse the Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    // TODO: take into account ipv6
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Not an IPv4 packet
        return 0;
    }

    // Calculate packet size in bytes
    *pkt_size = data_end - data;
    return 1;
}

SEC("xdp.frags")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	__u64 pkt_size;
	__u64 current_time = bpf_ktime_get_ns(); // Current time in nanoseconds
	__u32 ifindex = ctx->ingress_ifindex;

    // Parse eth packet
    if (!parse_eth_pkt(ctx, &pkt_size)) {
      // We're not interested in this packet, so skip for now
      goto done;
    }

	// Retrieve data record for this IP
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &ifindex);
	if (!rec) {
		// No entry in the map for this interface yet, so initialize it
		struct datarec init_data = {.bytes = pkt_size, .last_seen = current_time};
		bpf_map_update_elem(&xdp_stats_map, &ifindex, &init_data, BPF_ANY);
	} else {
		// Update byte count
		rec->bytes += pkt_size;
		rec->last_seen = current_time;
	}
done:
	return XDP_PASS;
}
