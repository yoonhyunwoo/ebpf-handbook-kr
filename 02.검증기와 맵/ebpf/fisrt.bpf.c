#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

struct key_t {
    char k[10];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct key_t);
    __type(value, __u32);
} first_map SEC(".maps");


SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    struct key_t key = {};
    __builtin_memcpy(key.k, "hello", sizeof("hello"));

    __u32 value = ctx->data_end - ctx->data;

    bpf_map_update_elem(&first_map, &key, &value, BPF_ANY);
    
    bpf_printk("Map updated with key 'hello' and value 10\n");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";