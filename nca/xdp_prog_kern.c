/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <errno.h>
#include <limits.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_KEY_LENGTH 256
#define MAX_CACHE_DATA_SIZE 1024
#define MAX_PACKET_LENGTH 1518
#define RECURSION_UPPER_LIMIT 33
#define CACHE_QUEUE_SIZE 512
#define CACHE_ENTRY_COUNT 1024

#define MAX_STRINT_SIZE 4

#define FNV_OFFSET_BASIS_32 2166136261
#define FNV_PRIME_32 16777619

#define assert_bound_err(target, end) \
    if (target + 1 > end) \
        return -EACCES;

#define assert_bound_pass(target, end) \
    if (target + 1 > end) \
        return XDP_PASS;

// enum {
//     XDP_RX_FILTER = 0,
//     XDP_HASH,
// };
// struct {
//     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
// 	   __type(key, int);
// 	   __type(value, int);
// 	   __uint(max_entries, RECURSION_UPPER_LIMIT);
// } map_xdp_progs SEC(".maps");

// enum {
// 	PARSING_INGRESS = 0,
// 	PARSING_EGRESS,
// 	PARSING_MAX,
// };
// struct parsing_context {
//     __u32 key_hash;
//     unsigned int key_len;
//     unsigned int key_offset;
// };
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__type(key, int);
// 	__type(value, struct parsing_context);
// 	__uint(max_entries, PARSING_MAX);
// } map_parsing_context SEC(".maps");

struct cache_entry {
	struct bpf_spin_lock lock;
	unsigned int key_len;
	unsigned int data_len;
	__u32 hash;
    char valid;
	char key[MAX_KEY_LENGTH];
	char data[MAX_CACHE_DATA_SIZE];
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct cache_entry);
	__uint(max_entries, CACHE_ENTRY_COUNT);
} map_cache SEC(".maps");

struct cache_key {
    __u32 hash;
    unsigned int len;
    char data[MAX_KEY_LENGTH];
};
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(key, 0);
	__type(value, struct cache_key);
	__uint(max_entries, CACHE_QUEUE_SIZE);
} map_invalid_key SEC(".maps");


struct hdr_cursor {
	void *pos;
};

struct pseudo_ip {
    __u32  saddr;
    __u32  daddr;
    __u8   dummy;
    __u8   protocol;
    __be16 ip_len;
};

enum method {
    GET,
    SET,
    NONE
};

static __always_inline int isdigit(char c) {
    return '0' <= c && c <= '9';
}

static __always_inline int strtoi(struct hdr_cursor *nh, 
                        void *data_end,
                        int *res)
{
    int i, n = 0, neg = 0;
    assert_bound_err(nh->pos, data_end);
    if (nh->pos + 1 > data_end) return -EACCES;
    switch (*(char*)nh->pos) {
        case '-': neg = 1;
        case '+': nh->pos++;
    }
    
    for (i = 0; nh->pos + 1 <= data_end && isdigit(*(char*)nh->pos) && i < MAX_STRINT_SIZE; i++) {
        n = 10 * n - (*(char*)nh->pos++ - '0');
    }

    *res = neg ? n : -n;

    return 0;
}

static __always_inline int calc_key_hash(struct hdr_cursor *nh,
                            void *data_end,
                            int key_size,
                            __u32 *key_hashed) 
{
    int off;
    __u32 hash = FNV_OFFSET_BASIS_32;
    char *c = nh->pos;

    for (off = 0; c + off + 1 <= data_end && off < key_size && off < MAX_KEY_LENGTH; off++) {
        hash ^= c[off];
        hash *= FNV_PRIME_32;
    }

    *key_hashed = hash;

    return 0;
}

static __always_inline enum method determine_method(struct hdr_cursor *nh,
                        void *data_end) 
{
    if (nh->pos + 11 > data_end)
        return (enum method)NONE;
    
    char *c = nh->pos;

    if (c[5] != '3')
        return (enum method)NONE;

    if (c[8] == 'g' && c[9] == 'e' && c[10] == 't')
        return (enum method)GET;
    if (c[8] == 's' && c[9] == 'e' && c[10] == 't')
        return (enum method)SET;
    
    return (enum method)NONE;
}

// static __always_inline int parse_elem(struct hdr_cursor *nh, 
//                         void *data_end,
//                         struct elem_str *e) 
// {
//     assert_bound_err(nh->pos, data_end);
//     if (*(char*)nh->pos++ != '$') 
//         return -EFAULT;
    
//     assert_bound_err(nh->pos, data_end);
//     bpf_printk("now: %c\n", *(char*)nh->pos);
//     if (strtoi(nh, data_end, &e->len)) 
//         return -EFAULT;

//     if (nh->pos + 2 > data_end)
//         return -EACCES;
//     nh->pos += 2;  // skip "/r/n"

//     bpf_printk("size = %d\n", e->len);

//     if (e->len < 1) {
//         return -EFAULT;
//     }
    

//     if (nh->pos + 1 > data_end) 
//         return -EACCES;
    
//     if (nh->pos + e->len > data_end) 
//         return -EACCES;
    
//     nh->pos += e->len; // skip elem + "/r/n"
//     e->addr = nh->pos;

//    // bpf_printk("elem[0] = %c\n", *e->addr);

//     return 0;
// }

static __always_inline int keycmp(const char *k1, const char *k2, void *data_end, int n) {
    unsigned int i;
    for (i = 0; i < n && i < MAX_KEY_LENGTH && k1 + i + 1 <= data_end; i++) {
        if (k1[i] != k2[i])  return 1;
    }
    return 0;
}

static __always_inline void swap_mac_src_dst(struct ethhdr *eth) {
    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
}

static __always_inline void swap_ip4_src_dst(struct iphdr *iph) {
  	__be32 tmp = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp;
}

static __always_inline void swap_tcpport_src_dst(struct tcphdr *tcph) {
    __be16 tmp = tcph->source;
    tcph->source = tcph->dest;
    tcph->dest = tmp;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

    return 0;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
                                        void *data_end, 
										struct iphdr **ip4hdr)
{
	struct iphdr *iph = nh->pos;

	if (iph + 1 > data_end)
		return -1;

	int hdrsize = iph->ihl << 2;

	if (hdrsize < sizeof(*iph))
		return -1;
	
	if (nh->pos + hdrsize > data_end) 
		return -1;

	nh->pos += hdrsize;
	*ip4hdr = iph;

	return 0;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                        void *data_end, 
										struct tcphdr **_tcphdr)
{
	struct tcphdr *tcph = nh->pos;

	if (tcph + 1 > data_end)
		return -1;

	unsigned int hdrsize = tcph->doff <<  2;

	if (nh->pos + hdrsize > data_end) 
		return -1;

	nh->pos += hdrsize;
	*_tcphdr = tcph;

	return 0;
}

SEC("xdp/rx_filter")
int xdp_rx_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct hdr_cursor nh;
    enum method m;
    int key_len;
    __u32 key_hash;
    struct cache_entry *entry;

    nh.pos = data;

    if (parse_ethhdr(&nh, data_end, &eth))
        goto out;

    if (parse_ip4hdr(&nh, data_end, &iph))
        goto out;

    if (iph->protocol != IPPROTO_TCP) 
        goto out;

    if (parse_tcphdr(&nh, data_end, &tcph))
        goto out;

    if (bpf_ntohs(tcph->dest) != 6379)
        goto out;

    if ((m = determine_method(&nh, data_end)) == NONE)
        goto out;

    //bpf_printk("message\n%s", (char*)nh.pos);

    // skip " * 3 /r /n $ 3 /r /n [gs] e t /r /n "
    __u16 payload_len = data_end - nh.pos;
    nh.pos += 13;

    if (nh.pos + 1 > data_end || *(char*)nh.pos++ != '$')
        goto out;
        
    if (strtoi(&nh, data_end, &key_len)) 
        goto out;

    // skip " \r \n "
    nh.pos +=  2;

    if (calc_key_hash(&nh, data_end, key_len, &key_hash)) 
        goto out;
    __u32 cache_idx = key_hash % CACHE_ENTRY_COUNT;
    
    char *key_data = nh.pos;

    switch (m) {
    case GET:
        entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
        if (!entry)
            goto out;

        bpf_spin_lock(&entry->lock);

        if (entry->valid && key_hash == entry->hash 
                && !keycmp(key_data, entry->key, data_end, key_len)) {
            bpf_spin_unlock(&entry->lock);

            bpf_printk("GET HIT hook");

            if (bpf_xdp_adjust_tail(ctx, entry->data_len - payload_len)) {
                bpf_printk("failed to adjust tail.\n");
                goto out;
            }

            // re calculate after tailgrow
            data_end = (void *)(long)ctx->data_end;
            data = (void *)(long)ctx->data;
            nh.pos = data;
            if (parse_ethhdr(&nh, data_end, &eth))
                goto out;
            if (parse_ip4hdr(&nh, data_end, &iph))
                goto out;
            if (parse_tcphdr(&nh, data_end, &tcph))
                goto out;

            char *payload = nh.pos;
            for (unsigned int off = 0; payload + off + 1 <= data_end && off < entry->data_len && off < 100; off++)
                payload[off] = entry->data[off];
            
            swap_mac_src_dst(eth);
            swap_ip4_src_dst(iph);
            swap_tcpport_src_dst(tcph);

            __u16 old_csum = iph->check;
            iph->check = 0;
            struct iphdr old_iph = *iph;
            iph->tot_len = bpf_htons((iph->ihl << 2) + (tcph->doff << 2) + entry->data_len);
            iph->check = csum_fold_helper(bpf_csum_diff((__be32 *)&old_iph, sizeof(struct iphdr), (__be32 *)iph, sizeof(struct iphdr), ~old_csum));

            tcph->check = 0;
            __u32 csum = 0;

            __be32 new_seq = tcph->ack_seq;
            tcph->ack_seq = bpf_htonl(bpf_ntohl(tcph->seq) + payload_len);
            tcph->seq = new_seq;

            __u32 new_ecr = *(__u32*)(nh.pos - 8);
            *(__u32*)(nh.pos - 8) = bpf_htonl(bpf_ntohl(*(__u32*)(nh.pos - 4)) + 10000);
            *(__u32*)(nh.pos - 4) = new_ecr;

            struct pseudo_ip p_ip = {
                .saddr = iph->saddr,
                .daddr = iph->daddr,
                .protocol = iph->protocol,
                .ip_len = bpf_htons(bpf_ntohs(iph->tot_len) - (iph->ihl << 2)),
            };
            
            __u16 *pos = (__u16*)&p_ip;
            for (unsigned int i = 0; i < sizeof(struct pseudo_ip); i += 2) {
                csum += *pos;
                if (csum & 0x80000000)
                    csum = (csum & 0xFFFF) + (csum >> 16);
                pos++;
            }

            pos = (__u16*)tcph;
            unsigned int i;
            for (i = 0; pos + 1 <= data_end && i < 130; i++) {
                csum += *pos;
                if (csum & 0x80000000)
                    csum = (csum & 0xFFFF) + (csum >> 16);
                pos++;
            }
            __u8 *tail = (__u8*)pos;
            if (tail + 1 <= data_end) 
                csum += *tail;
            while (csum >> 16)
                csum = (csum & 0xFFFF) + (csum >> 16);
            tcph->check = (__u16)~csum;

            return XDP_TX;
        } else {
            bpf_spin_unlock(&entry->lock);
        }
        // bpf_printk("GET MISS hook\n");

        struct cache_key key_entry = {
            .hash = key_hash,
            .len = key_len
        };

        unsigned int off;
        for (off = 0; key_data + off + 1 <= data_end && off < key_len && off < MAX_KEY_LENGTH; off++) 
            key_entry.data[off] = key_data[off];
        

        if (off >= MAX_KEY_LENGTH || key_data + off + 1 > data_end) 
            goto out;

        if (bpf_map_push_elem(&map_invalid_key, &key_entry, BPF_ANY)) {
            bpf_printk("push failed.\n");
        }
        break;
    case SET:
        // bpf_printk("SET hook\n");
        
        entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
        if (!entry)
            goto out;

        bpf_spin_lock(&entry->lock);

        if (entry->valid) {
            if (key_hash == entry->hash 
                    && !keycmp(key_data, entry->key, data_end, key_len)) {
                entry->valid = 0;
            }
            
        }
        bpf_spin_unlock(&entry->lock);
        break;
    case NONE:
        break;
    }
    
out:
    return XDP_PASS;
}

SEC("tc/tx_filter")
int tc_tx_filter_func(struct __sk_buff *skb) {
    bpf_skb_pull_data(skb, skb->len);
    void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct hdr_cursor nh;

    nh.pos = data;

    if (parse_ethhdr(&nh, data_end, &eth))
        goto out;

    if (parse_ip4hdr(&nh, data_end, &iph))
        goto out;

    if (iph->protocol != IPPROTO_TCP) 
        goto out;

    if (parse_tcphdr(&nh, data_end, &tcph))
        goto out;

    if (bpf_ntohs(tcph->source) != 6379)
        goto out;

    if (nh.pos == data_end)
        goto out;

    char *payload = nh.pos; 
    
    if (nh.pos + 1 > data_end || *(char*)nh.pos++ != '$') 
        goto out;

    struct cache_key key_entry;
    if (bpf_map_pop_elem(&map_invalid_key, &key_entry)) {
        bpf_printk("pop failed.\n");
        goto out;
    }
    
    int value_len;
    if (strtoi(&nh, data_end, &value_len) || value_len < 0)
        goto out;

    // skip " \r \n "
    nh.pos += 2;

    __u32 cache_idx = key_entry.hash % CACHE_ENTRY_COUNT;
    struct cache_entry *entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
    if (!entry) {
        bpf_printk("cache_entry[%u] not found.\n", cache_idx);
        goto out;
    }

    bpf_spin_lock(&entry->lock);

    entry->hash = key_entry.hash;
    entry->key_len = key_entry.len;
    entry->data_len = data_end - (void*)payload;
    
    unsigned int off;
    for (off = 0; off < key_entry.len && off < MAX_KEY_LENGTH; off++)
        entry->key[off] = key_entry.data[off];
    for (off = 0; payload + off + 1 <= data_end && off < entry->data_len && off < MAX_CACHE_DATA_SIZE; off++) 
        entry->data[off] = payload[off];

    entry->valid = 1;

    bpf_spin_unlock(&entry->lock);
    
out:
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";