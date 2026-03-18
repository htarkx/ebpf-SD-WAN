#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct dns_cfg_val {
	__u32 enabled;
	__u32 dns_ip_be;
	__u16 dns_port_be;
	__u16 _pad;
};

struct dns_flow_key {
	__u32 client_ip_be;
	__u16 client_port_be;
	__u8 proto;
	__u8 _pad;
};

struct dns_flow_val {
	__u32 orig_dns_ip_be;
	__u16 orig_dns_port_be;
	__u16 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_cfg_val);
} dns_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct dns_flow_key);
	__type(value, struct dns_flow_val);
} dns_flows SEC(".maps");

static __always_inline int redirect_dns_query(struct __sk_buff *skb, struct dns_cfg_val *cfg)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data;
	__u32 l4_off;
	__u16 old_sport;
	__u16 old_dport;
	__u16 old_check = 0;
	__u32 old_daddr;
	__u8 proto;
	int is_udp;
	struct dns_flow_key fkey = {};
	struct dns_flow_val fval = {};

	if (!cfg || cfg->enabled == 0)
		return TC_ACT_OK;

	if ((void *)(iph + 1) > data_end || iph->version != 4)
		return TC_ACT_OK;

	proto = iph->protocol;
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return TC_ACT_OK;

	l4_off = ((__u32)iph->ihl) * 4;
	if (l4_off < sizeof(*iph) || data + l4_off + sizeof(struct udphdr) > data_end)
		return TC_ACT_OK;

	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source), &old_sport, sizeof(old_sport)) < 0)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest), &old_dport, sizeof(old_dport)) < 0)
		return TC_ACT_OK;

	/* Prevent self-loop when packet already targets hijack DNS endpoint. */
	if (iph->daddr == cfg->dns_ip_be && old_dport == cfg->dns_port_be)
		return TC_ACT_OK;
	if (old_dport != bpf_htons(53))
		return TC_ACT_OK;

	old_daddr = iph->daddr;
	is_udp = (proto == IPPROTO_UDP);
	if (is_udp && bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, check), &old_check, sizeof(old_check)) < 0)
		return TC_ACT_OK;

	fkey.client_ip_be = iph->saddr;
	fkey.client_port_be = old_sport;
	fkey.proto = proto;
	fval.orig_dns_ip_be = old_daddr;
	fval.orig_dns_port_be = old_dport;
	bpf_map_update_elem(&dns_flows, &fkey, &fval, BPF_ANY);

	if (bpf_skb_store_bytes(skb, offsetof(struct iphdr, daddr), &cfg->dns_ip_be, sizeof(cfg->dns_ip_be), 0) < 0)
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, dest), &cfg->dns_port_be, sizeof(cfg->dns_port_be), 0) < 0)
		return TC_ACT_OK;

	if (bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_daddr, cfg->dns_ip_be, sizeof(cfg->dns_ip_be)) < 0)
		return TC_ACT_OK;

	if (!is_udp || old_check != 0) {
		__u32 csum_off = l4_off + (is_udp ? offsetof(struct udphdr, check) : offsetof(struct tcphdr, check));

		if (bpf_l4_csum_replace(skb, csum_off, old_daddr, cfg->dns_ip_be, BPF_F_PSEUDO_HDR | sizeof(cfg->dns_ip_be)) < 0)
			return TC_ACT_OK;
		if (bpf_l4_csum_replace(skb, csum_off, old_dport, cfg->dns_port_be, sizeof(cfg->dns_port_be)) < 0)
			return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

static __always_inline int restore_dns_reply(struct __sk_buff *skb, struct dns_cfg_val *cfg)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph = data;
	__u32 l4_off;
	__u16 old_sport;
	__u16 old_dport;
	__u16 old_check = 0;
	__u32 old_saddr;
	__u8 proto;
	int is_udp;
	struct dns_flow_key fkey = {};
	struct dns_flow_val *fval;

	if (!cfg || cfg->enabled == 0)
		return TC_ACT_OK;

	if ((void *)(iph + 1) > data_end || iph->version != 4)
		return TC_ACT_OK;

	proto = iph->protocol;
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return TC_ACT_OK;

	l4_off = ((__u32)iph->ihl) * 4;
	if (l4_off < sizeof(*iph) || data + l4_off + sizeof(struct udphdr) > data_end)
		return TC_ACT_OK;

	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source), &old_sport, sizeof(old_sport)) < 0)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest), &old_dport, sizeof(old_dport)) < 0)
		return TC_ACT_OK;

	if (iph->saddr != cfg->dns_ip_be || old_sport != cfg->dns_port_be)
		return TC_ACT_OK;

	old_saddr = iph->saddr;
	is_udp = (proto == IPPROTO_UDP);
	if (is_udp && bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, check), &old_check, sizeof(old_check)) < 0)
		return TC_ACT_OK;

	fkey.client_ip_be = iph->daddr;
	fkey.client_port_be = old_dport;
	fkey.proto = proto;
	fval = bpf_map_lookup_elem(&dns_flows, &fkey);
	if (!fval)
		return TC_ACT_OK;

	if (bpf_skb_store_bytes(skb, offsetof(struct iphdr, saddr), &fval->orig_dns_ip_be, sizeof(fval->orig_dns_ip_be), 0) < 0)
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, source), &fval->orig_dns_port_be, sizeof(fval->orig_dns_port_be), 0) < 0)
		return TC_ACT_OK;

	if (bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_saddr, fval->orig_dns_ip_be, sizeof(fval->orig_dns_ip_be)) < 0)
		return TC_ACT_OK;

	if (!is_udp || old_check != 0) {
		__u32 csum_off = l4_off + (is_udp ? offsetof(struct udphdr, check) : offsetof(struct tcphdr, check));

		if (bpf_l4_csum_replace(skb, csum_off, old_saddr, fval->orig_dns_ip_be, BPF_F_PSEUDO_HDR | sizeof(fval->orig_dns_ip_be)) < 0)
			return TC_ACT_OK;
		if (bpf_l4_csum_replace(skb, csum_off, old_sport, fval->orig_dns_port_be, sizeof(fval->orig_dns_port_be)) < 0)
			return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

SEC("tc")
int tc_dns_hijack_ingress(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct dns_cfg_val *cfg = bpf_map_lookup_elem(&dns_cfg, &key);
	return redirect_dns_query(skb, cfg);
}

SEC("tc")
int tc_dns_hijack_egress(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct dns_cfg_val *cfg = bpf_map_lookup_elem(&dns_cfg, &key);
	return restore_dns_reply(skb, cfg);
}

char _license[] SEC("license") = "GPL";
