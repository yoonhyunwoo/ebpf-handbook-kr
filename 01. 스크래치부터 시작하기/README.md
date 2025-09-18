# 01. 일단 손을 놀리세요..
이론적인 이야기는 잠시 접어두고 BPF 프로그램을 작성해봅시다.

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

이렇게 작성되는 프로그램은 eBPF 바이너리로 빌드되어 go 프로그램상에서 로드됩니다. 이를 로드하고 사용하는 go program은 다음과 같습니다.

`main.go`
```go
package main

import (
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go first ebpf/fisrt.bpf.c --

func main() {
	var objs firstObjects
	err := loadFirstObjects(&objs, nil)
	if err != nil {
		panic(err)
	}

	defer objs.XdpProgSimple.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	objs.XdpProgSimple.Run(nil)

	<-sigCh

}
```

먼저 go generate를 통해 first.bpf.c를 컴파일하고 go run .으로 BPF 프로그램을 로딩하여 실행할 수 있습니다. 

bpf2go는 작성한 C 소스코드를 BPF 바이트파일로 컴파일해주고, 그에 맞는 go파일을 생성해줍니다.이후 빌드된 *_bpfeb.o,  *_bpfel.o파일들을 임베딩하여 사용하는 방식입니다. 이를테면 아래와 같습니다.
```go
//go:embed first_bpfel.o
var _FirstBytes []byte
```

또한, cilium/bpf 라이브러리에서는 그렇게 만들어진 eBPF 바이트코드를 bpf systemcall을 통해 커널에 로딩합니다.

준비가 완료되었다면 generate && run으로 만들어진 eBPF 프로그램을 실행시킬 수 있습니다.
```bash
go generate
go run .
```

이를 실행한 이후 `/sys/kernel/debug/tracing/trace_pipe`를 확인해보면 bpf_printk를 통해 찍은 로그를 확인할 수 있습니다.

```bash
cat /sys/kernel/debug/tracing/trace_pipe 
           first-591077  [005] b...1.1 844240.839655: bpf_trace_printk: Values: 1 2 3 4 5
```

## SEC 매크로와 eBPF 바이트코드
앞서 작성된 first.bpf.c에서 SEC(section) 매크로를 사용했습니다. SEC은 bpf_helper에서 제공하는 매크로로 그 이름답게 매개변수로 받은 부분에 변수등을 위치시킵니다.


이를테면 앞서 작성한 코드에는 다음과 같은 라인이 있습니다.
```c
 char _license[] SEC("license") = "GPL";
```
이는 license SECTION에 "GPL"을 값으로 지닌 캐릭터 배열을 할당한다는 뜻입니다.

이는 readelf등의 유틸리티를 통해 license에 비치된 값을 확인 가능합니다.
```bash
readelf -x license first_bpfel.o

Hex dump of section 'license':
  0x00000000 47504c00                            GPL.
```
GPL 문자열을 확인할 수 있습니다.

실제로 bpf systemcall에서는 라이선스를 검증합니다.

[`linux/kernel/bpf/syscall.c`](https://github.com/torvalds/linux/blob/8b789f2b7602a818e7c7488c74414fae21392b63/kernel/bpf/syscall.c#L2926)
```c
	/* eBPF programs must be GPL compatible to use GPL-ed functions */
	prog->gpl_compatible = license_is_gpl_compatible(license) ? 1 : 0;
```

[`include/linux/license.h`](https://github.com/torvalds/linux/blob/master/include/linux/license.h)
```
/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LICENSE_H
#define __LICENSE_H

static inline int license_is_gpl_compatible(const char *license)
{
	return (strcmp(license, "GPL") == 0
		|| strcmp(license, "GPL v2") == 0
		|| strcmp(license, "GPL and additional rights") == 0
		|| strcmp(license, "Dual BSD/GPL") == 0
		|| strcmp(license, "Dual MIT/GPL") == 0
		|| strcmp(license, "Dual MPL/GPL") == 0);
}

#endif
```

때문에 사용하는 헬퍼 함수가 GPL 전용인 경우, GPL 호환 라이선스를 위와 같이 코드에 명시해주어야 합니다.

마찬가지로 SEC을 통해 비치된 xdp 섹션의 값도 확인 가능합니다. 여기서는 eBPF가 사용하는 레지스터들을 엿볼 수 있습니다. 10개의 레지스터는 각각 아래와 같은 역할을 수행합니다.
* r0 : 결과 반환 레지스터
* r1~r5 : 인자 전달 레지스터
* r6~r9 : 피호출자 레지스터
* r10 : 프레임 포인터

실제로 llvm-objdump를 통해 확인해보면 아래와 같은 결과를 얻을 수 있습니다. 

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

먼저 인자 전달용 레지스터인 r1에 정의한 변수들이 들어갑니다. 0x5와 같은 값은 16진수로 표현되는 5를 뜻하고, 위에서 정의한 a,b,c,d,e가 r1 레지스터를 거쳐 스택의 주소에 쌓입니다. r10(프레임 포인터) -8,-16, ...-40과 같습니다.

이렇게 프레임 포인터에 쌓인 r10 - 40까지의 인자들의 시작 주소를 r3 레지스터에 저장합니다. 이후 r1, r2 레지스터를 포맷 문자열과 그 길이로 채웁니다.

코드상에서 포맷 문자열은 "Values: %d %d %d %d %d\n"로 총 24(0x18)개 입니다.

이렇게 BPF 바이트코드 양식에 맞게 프로그램을 컴파일하여 실행시킬 수 있습니다. 

## BPF? cBPF? eBPF?
BPF관련 자료들을 찾아보면 혼선이 찾아오진 않으신가요? 어디선 BPF, 어디선 cBPF, 어디선 eBPF... 이러한 차이는 각 문서마다 지칭하는 BPF가 다르기 때문입니다. 

처음 BPF가 등장했을 땐 2개의 레지스터와 네트워크 필터링에 집중된 기술이었고, 이후 BPF기술이 확장(extend)되며 extended BPF(eBPF)가 등장하게 되었습니다. 이 둘은 흑백논리로 분리하기에는 무리가 있습니다. 둘다 BPF로 지칭될 수 있습니다.

그러나 기술적으로 둘은 명확히 달라졌습니다. 이에 eBPF 등장 이전의 BPF 기술을 Classic BPF, 확장 이후를 eBPF로 나누게 되면서 용어적으로 이를 분리했습니다.

이를테면 최근에 화제를 일으켰던 BPFDoor의 경우 cBPF(Classic BPF)로 작성된 프로그램입니다.

작금에 이르러서 BPF라고 하면 대부분 eBPF를 지칭하지만 워낙 자료가 부족한지라 이에대해 검색해보면 각자가 다른 소리를 보며 헷갈릴 수 있습니다. 둘에 대한 차이를 알아야 관련 문서를 볼 때 슬기롭게 이를 구분할 수 있습니다.