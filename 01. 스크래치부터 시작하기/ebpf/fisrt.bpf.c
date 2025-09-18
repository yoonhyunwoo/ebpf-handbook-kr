#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    int a = 1, b = 2, c = 3, d = 4, e = 5;
    bpf_printk("Values: %d %d %d %d %d\n", a, b, c, d, e);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";