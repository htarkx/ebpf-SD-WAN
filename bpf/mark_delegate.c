#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct cfg_val {
	__u32 mark;
};

struct stats_val {
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg_val);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats_val);
} stats SEC(".maps");

static __always_inline int update_stats(__u64 bytes)
{
	__u32 key = 0;
	struct stats_val *cur;

	cur = bpf_map_lookup_elem(&stats, &key);
	if (!cur)
		return 0;

	__sync_fetch_and_add(&cur->packets, 1);
	__sync_fetch_and_add(&cur->bytes, bytes);
	return 0;
}

SEC("tc")
int tc_mark_delegate(struct __sk_buff *skb)
{
	__u32 cfg_key = 0;
	struct cfg_val *cfg_val;
	__u32 mark = 0x66;

	cfg_val = bpf_map_lookup_elem(&cfg, &cfg_key);
	if (cfg_val)
		mark = cfg_val->mark;

	skb->mark = mark;
	update_stats((__u64)(skb->len));
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
