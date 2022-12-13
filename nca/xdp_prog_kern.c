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
#define MAX_L4_CSUM_LOOP 742
#define RECURSION_UPPER_LIMIT 33
#define CACHE_QUEUE_SIZE 512
#define CACHE_ENTRY_COUNT 1024
#define MAX_STRINT_SIZE 4

#define FNV_OFFSET_BASIS_32 2166136261
#define FNV_PRIME_32 16777619

#define assert_bound_err(target, end) \
    if (target + 1 > end) \
        return -EACCES;

#define DEBUG_BUILD
#ifdef DEBUG_BUILD
# define DEBUG_PRINTK(fmt, ...)  bpf_printk(fmt, ## __VA_ARGS__);                   
#else
# define DEBUG_PRINTK(fmt, ...)
#endif

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
    DEBUG_PRINTK("%u, %u\n", nh->pos, data_end);
    if (nh->pos + 11 > data_end)
        return (enum method)NONE;
    
    char *c = nh->pos;

    DEBUG_PRINTK("%c\n", c[5]);
    DEBUG_PRINTK("%c, %c, %c\n", c[8], c[9], c[10]);

    if (c[5] != '3')
        return (enum method)NONE;

    if (c[8] == 'G' && c[9] == 'E' && c[10] == 'T')
        return (enum method)GET;
    if (c[8] == 'S' && c[9] == 'E' && c[10] == 'T')
        return (enum method)SET;
    
    return (enum method)NONE;
}

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

    // redis-server port
    if (bpf_ntohs(tcph->dest) != 6379)
        goto out;

    DEBUG_PRINTK("message\n%s", (char*)nh.pos);

    if ((m = determine_method(&nh, data_end)) == NONE)
        goto out;

    __u16 payload_len = data_end - nh.pos;

    // skip " * 3 /r /n $ 3 /r /n [gs] e t /r /n "
    nh.pos += 13;

    if (nh.pos + 1 > data_end) goto out;

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

            DEBUG_PRINTK("GET HIT hook.\n");

            if (bpf_xdp_adjust_tail(ctx, entry->data_len - payload_len)) {
                DEBUG_PRINTK("failed to adjust tail.\n");
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
            for (unsigned int off = 0; payload + off + 1 <= data_end && off < entry->data_len && off < MAX_CACHE_DATA_SIZE; off++)
                payload[off] = entry->data[off];
            
            swap_mac_src_dst(eth);
            swap_ip4_src_dst(iph);
            swap_tcpport_src_dst(tcph);

	        __u16 *pos = (__u16*)iph;
	        __u32 csum = 0;

            iph->check = 0;
            iph->tot_len = bpf_htons((iph->ihl << 2) + (tcph->doff << 2) + entry->data_len);

	        for (unsigned int i = 0; i < 10; i++) {
                csum += *pos;
		        pos++;
	        }	

            while (csum >> 16) {
                csum = (csum & 0xFFFF) + (csum >> 16);
            }

	        iph->check = (__u16)~csum;

            tcph->check = 0;
            csum = 0;

            __be32 new_seq = tcph->ack_seq;
            tcph->ack_seq = bpf_htonl(bpf_ntohl(tcph->seq) + payload_len);
            tcph->seq = new_seq;

            __u32 new_ecr = *(__u32*)(nh.pos - 8);
            *(__u32*)(nh.pos - 8) = bpf_htonl(bpf_ntohl(*(__u32*)(nh.pos - 4)) + 100);
            *(__u32*)(nh.pos - 4) = new_ecr;

            csum += (iph->saddr & 0xFFFF) + (iph->saddr >> 16);
            csum += (iph->daddr & 0xFFFF) + (iph->daddr >> 16);
            csum += iph->protocol << 8;
            csum += bpf_htons(bpf_ntohs(iph->tot_len) - (iph->ihl << 2));

            pos = (__u16*)tcph;
            unsigned int i;
            for (i = 0; pos + 1 <= data_end && i < MAX_PACKET_LENGTH; i++) {
                csum += *pos;
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
        DEBUG_PRINTK("GET MISS hook\n");

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
            DEBUG_PRINTK("push failed.\n");
        }
        break;
    case SET:
        DEBUG_PRINTK("SET hook\n");
        
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
    DEBUG_PRINTK("tc:\n%s", payload);
    
    if (nh.pos + 1 > data_end || *(char*)nh.pos++ != '$') 
        goto out;

    struct cache_key key_entry;
    if (bpf_map_pop_elem(&map_invalid_key, &key_entry)) {
        DEBUG_PRINTK("pop failed.\n");
        goto out;
    }

    DEBUG_PRINTK("tc: key = '%s'\n", key_entry.data);
    
    int value_len;
    if (strtoi(&nh, data_end, &value_len) || value_len < 0)
        goto out;

    // skip " \r \n "
    nh.pos += 2;

    __u32 cache_idx = key_entry.hash % CACHE_ENTRY_COUNT;
    struct cache_entry *entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
    if (!entry) {
        DEBUG_PRINTK("cache_entry[%u] not found.\n", cache_idx);
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
