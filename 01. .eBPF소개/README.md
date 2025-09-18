# BPF 소개

이 섹션에서는 BPF(버클리 패킷 필터)의 역사와 기본적인 개념들을 설명합니다. 이후 섹션에서도 차근차근 다를 예정이니 넘어가셔도 무방합니다. 그러나 모든 기술에는 등장배경이 있는 법이고, 등장배경을 알 때 적절한 곳에 기술을 활용할 수 있게 된다고 믿습니다.

유저들은 유저레벨에서 원시적 패킷을 관측하고 싶은 욕구가 있었습니다. 현재의 BPF 등장 전에도 SunOS NIT(Network Interface Tap), Ultrix UPF(Unix Packet Filter) 등 수많은 패킷 필터링 시스템이 있었습니다. 

참고자료
- https://en.wikipedia.org/wiki/Berkeley_Packet_Filter
- [The BSD Packet Filter: A New Architecture for User-level Packet Capture](https://www.tcpdump.org/papers/bpf-usenix93.pdf)
- https://lore.kernel.org/lkml/
- https://raw.githubusercontent.com/torvalds/linux/5aca7966d2a7255ba92fd5e63268dd767b223aa5/Documentation/networking/filter.rst