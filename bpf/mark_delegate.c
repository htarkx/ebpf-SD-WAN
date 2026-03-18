#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

struct cfg_val {
	__u32 mark;
	__u32 dns_redirect;
	__u32 dns_ip_be;
	__u16 dns_port_be;
	__u16 _pad;
};

struct stats_val {
	__u64 packets;
	__u64 bytes;
};

struct flow_key {
	__u32 client_ip_be;
	__u16 client_port_be;
	__u8 proto;
	__u8 _pad;
};

struct flow_val {
	__u32 orig_dns_ip_be;
	__u16 orig_dns_port_be;
	__u16 _pad;
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

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} dns_flows SEC(".maps");

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

static __always_inline int maybe_redirect_dns(struct __sk_buff *skb, struct cfg_val *cfg_val)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data;
	__u32 l4_off;
	__u16 old_sport, old_dport, old_check = 0;
	__u32 old_daddr;
	__u8 proto;
	int is_udp;
	struct flow_key fkey = {};
	struct flow_val fval = {};

	if (!cfg_val || cfg_val->dns_redirect == 0)
		return 0;

	if ((void *)(iph + 1) > data_end)
		return 0;
	if (iph->version != 4)
		return 0;

	proto = iph->protocol;
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return 0;

	l4_off = ((__u32)iph->ihl) * 4;
	if (l4_off < sizeof(*iph))
		return 0;
	if (data + l4_off + sizeof(struct udphdr) > data_end)
		return 0;

	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source), &old_sport, sizeof(old_sport)) < 0)
		return 0;
	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest), &old_dport, sizeof(old_dport)) < 0)
		return 0;
	if (old_dport != bpf_htons(53))
		return 0;

	old_daddr = iph->daddr;
	is_udp = (proto == IPPROTO_UDP);
	if (is_udp &&
	    bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, check), &old_check, sizeof(old_check)) < 0)
		return 0;

	fkey.client_ip_be = iph->saddr;
	fkey.client_port_be = old_sport;
	fkey.proto = proto;
	fval.orig_dns_ip_be = old_daddr;
	fval.orig_dns_port_be = old_dport;
	bpf_map_update_elem(&dns_flows, &fkey, &fval, BPF_ANY);

	if (bpf_skb_store_bytes(skb, offsetof(struct iphdr, daddr), &cfg_val->dns_ip_be, sizeof(cfg_val->dns_ip_be), 0) < 0)
		return 0;
	if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, dest), &cfg_val->dns_port_be, sizeof(cfg_val->dns_port_be), 0) < 0)
		return 0;

	if (bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_daddr, cfg_val->dns_ip_be, sizeof(cfg_val->dns_ip_be)) < 0)
		return 0;

	if (!is_udp || old_check != 0) {
		__u32 csum_off = l4_off + (is_udp ? offsetof(struct udphdr, check) : offsetof(struct tcphdr, check));

		if (bpf_l4_csum_replace(skb, csum_off, old_daddr, cfg_val->dns_ip_be,
					BPF_F_PSEUDO_HDR | sizeof(cfg_val->dns_ip_be)) < 0)
			return 0;
		if (bpf_l4_csum_replace(skb, csum_off, old_dport, cfg_val->dns_port_be, sizeof(cfg_val->dns_port_be)) < 0)
			return 0;
	}

	return 0;
}

static __always_inline int maybe_restore_dns(struct __sk_buff *skb, struct cfg_val *cfg_val)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data;
	__u32 l4_off;
	__u16 old_sport, old_dport, old_check = 0;
	__u32 old_saddr;
	__u8 proto;
	int is_udp;
	struct flow_key fkey = {};
	struct flow_val *fval;

	if (!cfg_val || cfg_val->dns_redirect == 0)
		return 0;

	if ((void *)(iph + 1) > data_end)
		return 0;
	if (iph->version != 4)
		return 0;

	proto = iph->protocol;
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return 0;

	l4_off = ((__u32)iph->ihl) * 4;
	if (l4_off < sizeof(*iph))
		return 0;
	if (data + l4_off + sizeof(struct udphdr) > data_end)
		return 0;

	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source), &old_sport, sizeof(old_sport)) < 0)
		return 0;
	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest), &old_dport, sizeof(old_dport)) < 0)
		return 0;
	if (iph->saddr != cfg_val->dns_ip_be || old_sport != cfg_val->dns_port_be)
		return 0;

	old_saddr = iph->saddr;
	is_udp = (proto == IPPROTO_UDP);
	if (is_udp &&
	    bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, check), &old_check, sizeof(old_check)) < 0)
		return 0;

	fkey.client_ip_be = iph->daddr;
	fkey.client_port_be = old_dport;
	fkey.proto = proto;
	fval = bpf_map_lookup_elem(&dns_flows, &fkey);
	if (!fval)
		return 0;

	if (bpf_skb_store_bytes(skb, offsetof(struct iphdr, saddr), &fval->orig_dns_ip_be, sizeof(fval->orig_dns_ip_be), 0) < 0)
		return 0;
	if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, source), &fval->orig_dns_port_be, sizeof(fval->orig_dns_port_be), 0) < 0)
		return 0;

	if (bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_saddr, fval->orig_dns_ip_be, sizeof(fval->orig_dns_ip_be)) < 0)
		return 0;

	if (!is_udp || old_check != 0) {
		__u32 csum_off = l4_off + (is_udp ? offsetof(struct udphdr, check) : offsetof(struct tcphdr, check));

		if (bpf_l4_csum_replace(skb, csum_off, old_saddr, fval->orig_dns_ip_be,
					BPF_F_PSEUDO_HDR | sizeof(fval->orig_dns_ip_be)) < 0)
			return 0;
		if (bpf_l4_csum_replace(skb, csum_off, old_sport, fval->orig_dns_port_be, sizeof(fval->orig_dns_port_be)) < 0)
			return 0;
	}

	return 0;
}

SEC("tc")
int tc_mark_delegate_ingress(struct __sk_buff *skb)
{
	__u32 cfg_key = 0;
	struct cfg_val *cfg_item;
	__u32 mark = 0x66;

	cfg_item = bpf_map_lookup_elem(&cfg, &cfg_key);
	if (cfg_item)
		mark = cfg_item->mark;

	maybe_redirect_dns(skb, cfg_item);
	skb->mark = mark;
	update_stats((__u64)(skb->len));
	return TC_ACT_OK;
}

SEC("tc")
int tc_mark_delegate_egress(struct __sk_buff *skb)
{
	__u32 cfg_key = 0;
	struct cfg_val *cfg_item;

	cfg_item = bpf_map_lookup_elem(&cfg, &cfg_key);
	maybe_restore_dns(skb, cfg_item);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
