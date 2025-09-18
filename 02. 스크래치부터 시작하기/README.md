## 02. 스크래치부터 시작하기
두말할 필요 없이 BPF 프로그램을 작성해봅시다. BPF 프로그램을 처음 작성하는 데는 약간의 혼란스러움이 따라오는데, 이는 BPF 프로그램의 종류와 그를 다루는 방법들에 차이가 있기 때문입니다.

이를테면 최근에 화제를 일으켰던 BPFDoor의 경우 cBPF(Classic BPF)로 작성된 프로그램입니다.

초기형태의 BPF는 특정 조건의 네트워크 패킷을 필터링하는 기능이였습니다. 그러다 확장된 형태의 BPF 프로그램인 eBPF(extended BPF)가 등장하게됩니다. 자연스럽게 기존의 BPF 프로그램은 cBPF(classic BPF)가 되었습니다.
현대시대에 이르러서 BPF라고 한다면 대부분 eBPF를 지칭하게 됩니다.


간단한 BPF 프로그램의 예시는 다음과 같습니다.

`ebpf/first.bpf.c`
```c
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
```

SEC은 bpf_helper에서 제공하는 매크로로 매개변수로 받은 부분에 변수등을 위치시킵니다.
이를테면 위 코드에는 다음과 같은 라인이 있습니다.
> * eBPF 프로그램은 license 섹션에 GPL 라이선스를 비치해야 합니다
```c
 char _license[] SEC("license") = "GPL";
```
이를 go generate를 통해 빌드한 후 ELF형식을 확인 가능한 readelf 유틸리티를 통해<br> license에 비치된 값을 확인 가능합니다.
```bash
readelf -x license first_bpfel.o

Hex dump of section 'license':
  0x00000000 47504c00                            GPL.
```


마찬가지로 SEC을 통해 비치된 xdp 섹션의 값도 확인 가능합니다. 여기서는 eBPF가 사용하는 레지스터들을 엿볼 수 있습니다. cBPF에 비해 eBPF는 레지스터 갯수가 2개에서 10개로 늘어났습니다. 10개의 레지스터는 각각 아래와 같은 역할을 수행합니다.
* r0 : 결과 반환 레지스터
* r1~r5 : 인자 전달 레지스터
* r6~r9 : 피호출자 레지스터
* r10 : 프레임 포인터

실제로 llvm-objdump를 통해 확인해보면 아래와 같은 결과를 얻을 수 있습니다. 

먼저 인자 전달용 레지스터인 r1에 정의한 변수들이 들어갑니다. 0x5와 같은 값은 16진수로 표현되는 5를 뜻하고, 위에서 정의한 a,b,c,d,e가 r1 레지스터를 거쳐 스택의 주소에 쌓입니다. r10(프레임 포인터) -8,-16, ...-40과 같습니다.

이렇게 프레임 포인터에 쌓인 r10 - 40까지의 인자들의 시작 주소를 r3 레지스터에 저장합니다. 이후 r1, r2 레지스터를 포맷 문자열과 그 길이로 채웁니다.

코드상에서 포맷 문자열은 "Values: %d %d %d %d %d\n"로 총 24(0x18)개 입니다.

```bash
llvm-objdump -S first_bpfel.o 

first_bpfel.o:  file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <xdp_prog_simple>:
; int xdp_prog_simple(struct xdp_md *ctx)
       0:       b7 01 00 00 05 00 00 00 r1 = 0x5
;     bpf_printk("Values: %d %d %d %d %d\n", a, b, c, d, e);
       1:       7b 1a f8 ff 00 00 00 00 *(u64 *)(r10 - 0x8) = r1
       2:       b7 01 00 00 04 00 00 00 r1 = 0x4
       3:       7b 1a f0 ff 00 00 00 00 *(u64 *)(r10 - 0x10) = r1
       4:       b7 01 00 00 03 00 00 00 r1 = 0x3
       5:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 0x18) = r1
       6:       b7 01 00 00 01 00 00 00 r1 = 0x1
       7:       7b 1a d8 ff 00 00 00 00 *(u64 *)(r10 - 0x28) = r1
       8:       b7 01 00 00 02 00 00 00 r1 = 0x2
       9:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 0x20) = r1
      10:       bf a3 00 00 00 00 00 00 r3 = r10
      11:       07 03 00 00 d8 ff ff ff r3 += -0x28
      12:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0x0 ll
      14:       b7 02 00 00 18 00 00 00 r2 = 0x18
      15:       b7 04 00 00 28 00 00 00 r4 = 0x28
      16:       85 00 00 00 b1 00 00 00 call 0xb1
;     return XDP_PASS;
      17:       b7 00 00 00 02 00 00 00 r0 = 0x2
      18:       95 00 00 00 00 00 00 00 exit
```

이렇게 BPF ELF 양식에 맞게 프로그램을 컴파일하여 실행시킬 수 있습니다. 