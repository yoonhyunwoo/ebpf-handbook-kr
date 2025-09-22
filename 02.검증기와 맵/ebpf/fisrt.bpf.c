#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h> // memcpy를 위해 추가

// 문자열을 키로 사용하기 위한 구조체 정의
struct key_t {
    char k[10];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH); // HASH 맵으로 변경
    __uint(max_entries, 1024);
    __type(key, struct key_t);      // 키 타입을 구조체로 변경
    __type(value, __u32);
} first_map SEC(".maps");


SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    struct key_t key = {}; // 키 구조체 변수 선언
    // 키에 "hello" 복사
    __builtin_memcpy(key.k, "hello", sizeof("hello"));

    __u32 value = ctx->data_end - ctx->data; // 값 계산 (패킷 길이)


    // HASH 맵 업데이트
    bpf_map_update_elem(&first_map, &key, &value, BPF_ANY);
    
    bpf_printk("Map updated with key 'hello' and value 10\n");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";