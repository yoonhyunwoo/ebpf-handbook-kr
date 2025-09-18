네, 해당 문서를 한국어로 번역해 드릴게요.

---

.. SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

.. _program_types_and_elf:

## 프로그램 유형과 ELF 섹션

아래 표는 프로그램 유형, 관련 있는 경우의 연결(attach) 유형, 그리고 libbpf가 지원하는 ELF 섹션 이름을 나열합니다. ELF 섹션 이름은 다음 규칙을 따릅니다:

* `type`은 정확히 일치해야 합니다. (예: `SEC("socket")`)
* `type+`는 정확한 일치 `SEC("type")` 또는 `type`과 `extras` 사이에 '`/`' 구분 기호가 있는 잘 구성된 `SEC("type/extras")` 형식을 의미합니다.

`extras`가 지정되면, BPF 프로그램을 자동으로 연결하는 방법에 대한 세부 정보를 제공합니다. `extras`의 형식은 프로그램 유형에 따라 다릅니다. 예를 들어, 트레이스포인트는 `SEC("tracepoint/<category>/<name>")` 형식이고, USDT 프로브는 `SEC("usdt/<path>:<provider>:<name>")` 형식입니다. `extras`에 대한 자세한 내용은 각주에 설명되어 있습니다.

[표: BPF 프로그램 유형, 연결 유형, ELF 섹션 이름 및 슬립 가능 여부]
| 프로그램 유형 | 연결(Attach) 유형 | ELF 섹션 이름 | 슬립(Sleep) 가능 |
| :--- | :--- | :--- | :--- |
| `BPF_PROG_TYPE_CGROUP_DEVICE` | `BPF_CGROUP_DEVICE` | `cgroup/dev` | |
| `BPF_PROG_TYPE_CGROUP_SKB` | | `cgroup/skb` | |
| | `BPF_CGROUP_INET_EGRESS` | `cgroup_skb/egress` | |
| | `BPF_CGROUP_INET_INGRESS` | `cgroup_skb/ingress` | |
| `BPF_PROG_TYPE_CGROUP_SOCKOPT` | `BPF_CGROUP_GETSOCKOPT` | `cgroup/getsockopt` | |
| | `BPF_CGROUP_SETSOCKOPT` | `cgroup/setsockopt` | |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `BPF_CGROUP_INET4_BIND` | `cgroup/bind4` | |
| | `BPF_CGROUP_INET4_CONNECT` | `cgroup/connect4` | |
| | `BPF_CGROUP_INET4_GETPEERNAME` | `cgroup/getpeername4` | |
| | `BPF_CGROUP_INET4_GETSOCKNAME` | `cgroup/getsockname4` | |
| | `BPF_CGROUP_INET6_BIND` | `cgroup/bind6` | |
| | `BPF_CGROUP_INET6_CONNECT` | `cgroup/connect6` | |
| | `BPF_CGROUP_INET6_GETPEERNAME` | `cgroup/getpeername6` | |
| | `BPF_CGROUP_INET6_GETSOCKNAME` | `cgroup/getsockname6` | |
| | `BPF_CGROUP_UDP4_RECVMSG` | `cgroup/recvmsg4` | |
| | `BPF_CGROUP_UDP4_SENDMSG` | `cgroup/sendmsg4` | |
| | `BPF_CGROUP_UDP6_RECVMSG` | `cgroup/recvmsg6` | |
| | `BPF_CGROUP_UDP6_SENDMSG` | `cgroup/sendmsg6` | |
| | `BPF_CGROUP_UNIX_CONNECT` | `cgroup/connect_unix` | |
| | `BPF_CGROUP_UNIX_SENDMSG` | `cgroup/sendmsg_unix` | |
| | `BPF_CGROUP_UNIX_RECVMSG` | `cgroup/recvmsg_unix` | |
| | `BPF_CGROUP_UNIX_GETPEERNAME` | `cgroup/getpeername_unix` | |
| | `BPF_CGROUP_UNIX_GETSOCKNAME` | `cgroup/getsockname_unix` | |
| `BPF_PROG_TYPE_CGROUP_SOCK` | `BPF_CGROUP_INET4_POST_BIND` | `cgroup/post_bind4` | |
| | `BPF_CGROUP_INET6_POST_BIND` | `cgroup/post_bind6` | |
| | `BPF_CGROUP_INET_SOCK_CREATE` | `cgroup/sock_create` | |
| | | `cgroup/sock` | |
| | `BPF_CGROUP_INET_SOCK_RELEASE` | `cgroup/sock_release` | |
| `BPF_PROG_TYPE_CGROUP_SYSCTL` | `BPF_CGROUP_SYSCTL` | `cgroup/sysctl` | |
| `BPF_PROG_TYPE_EXT` | | `freplace+` [#fentry]_ | |
| `BPF_PROG_TYPE_FLOW_DISSECTOR` | `BPF_FLOW_DISSECTOR` | `flow_dissector` | |
| `BPF_PROG_TYPE_KPROBE` | | `kprobe+` [#kprobe]_ | |
| | | `kretprobe+` [#kprobe]_ | |
| | | `ksyscall+` [#ksyscall]_ | |
| | | `kretsyscall+` [#ksyscall]_ | |
| | | `uprobe+` [#uprobe]_ | |
| | | `uprobe.s+` [#uprobe]_ | 예 |
| | | `uretprobe+` [#uprobe]_ | |
| | | `uretprobe.s+` [#uprobe]_ | 예 |
| | | `usdt+` [#usdt]_ | |
| | `BPF_TRACE_KPROBE_MULTI` | `kprobe.multi+` [#kpmulti]_ | |
| | | `kretprobe.multi+` [#kpmulti]_ | |
| `BPF_PROG_TYPE_LIRC_MODE2` | `BPF_LIRC_MODE2` | `lirc_mode2` | |
| `BPF_PROG_TYPE_LSM` | `BPF_LSM_CGROUP` | `lsm_cgroup+` | |
| | `BPF_LSM_MAC` | `lsm+` [#lsm]_ | |
| | | `lsm.s+` [#lsm]_ | 예 |
| `BPF_PROG_TYPE_LWT_IN` | | `lwt_in` | |
| `BPF_PROG_TYPE_LWT_OUT` | | `lwt_out` | |
| `BPF_PROG_TYPE_LWT_SEG6LOCAL` | | `lwt_seg6local` | |
| `BPF_PROG_TYPE_LWT_XMIT` | | `lwt_xmit` | |
| `BPF_PROG_TYPE_NETFILTER` | | `netfilter` | |
| `BPF_PROG_TYPE_PERF_EVENT` | | `perf_event` | |
| `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE` | | `raw_tp.w+` [#rawtp]_ | |
| | | `raw_tracepoint.w+` | |
| `BPF_PROG_TYPE_RAW_TRACEPOINT` | | `raw_tp+` [#rawtp]_ | |
| | | `raw_tracepoint+` | |
| `BPF_PROG_TYPE_SCHED_ACT` | | `action` [#tc_legacy]_ | |
| `BPF_PROG_TYPE_SCHED_CLS` | | `classifier` [#tc_legacy]_ | |
| | | `tc` [#tc_legacy]_ | |
| | `BPF_NETKIT_PRIMARY` | `netkit/primary` | |
| | `BPF_NETKIT_PEER` | `netkit/peer` | |
| | `BPF_TCX_INGRESS` | `tc/ingress` | |
| | `BPF_TCX_EGRESS` | `tc/egress` | |
| | `BPF_TCX_INGRESS` | `tcx/ingress` | |
| | `BPF_TCX_EGRESS` | `tcx/egress` | |
| `BPF_PROG_TYPE_SK_LOOKUP` | `BPF_SK_LOOKUP` | `sk_lookup` | |
| `BPF_PROG_TYPE_SK_MSG` | `BPF_SK_MSG_VERDICT` | `sk_msg` | |
| `BPF_PROG_TYPE_SK_REUSEPORT` | `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` | `sk_reuseport/migrate` | |
| | `BPF_SK_REUSEPORT_SELECT` | `sk_reuseport` | |
| `BPF_PROG_TYPE_SK_SKB` | | `sk_skb` | |
| | `BPF_SK_SKB_STREAM_PARSER` | `sk_skb/stream_parser` | |
| | `BPF_SK_SKB_STREAM_VERDICT` | `sk_skb/stream_verdict` | |
| `BPF_PROG_TYPE_SOCKET_FILTER` | | `socket` | |
| `BPF_PROG_TYPE_SOCK_OPS` | `BPF_CGROUP_SOCK_OPS` | `sockops` | |
| `BPF_PROG_TYPE_STRUCT_OPS` | | `struct_ops+` [#struct_ops]_ | |
| | | `struct_ops.s+` [#struct_ops]_ | 예 |
| `BPF_PROG_TYPE_SYSCALL` | | `syscall` | 예 |
| `BPF_PROG_TYPE_TRACEPOINT` | | `tp+` [#tp]_ | |
| | | `tracepoint+` [#tp]_ | |
| `BPF_PROG_TYPE_TRACING` | `BPF_MODIFY_RETURN` | `fmod_ret+` [#fentry]_ | |
| | | `fmod_ret.s+` [#fentry]_ | 예 |
| | `BPF_TRACE_FENTRY` | `fentry+` [#fentry]_ | |
| | | `fentry.s+` [#fentry]_ | 예 |
| | `BPF_TRACE_FEXIT` | `fexit+` [#fentry]_ | |
| | | `fexit.s+` [#fentry]_ | 예 |
| | `BPF_TRACE_ITER` | `iter+` [#iter]_ | |
| | | `iter.s+` [#iter]_ | 예 |
| | `BPF_TRACE_RAW_TP` | `tp_btf+` [#fentry]_ | |
| `BPF_PROG_TYPE_XDP` | `BPF_XDP_CPUMAP` | `xdp.frags/cpumap` | |
| | | `xdp/cpumap` | |
| | `BPF_XDP_DEVMAP` | `xdp.frags/devmap` | |
| | | `xdp/devmap` | |
| | `BPF_XDP` | `xdp.frags` | |
| | | `xdp` | |

---

### **각주**

.. [#fentry] `fentry` 연결 형식은 `fentry[.s]/<function>` 입니다.
.. [#kprobe] `kprobe` 연결 형식은 `kprobe/<function>[+<offset>]` 입니다. `function`에 유효한 문자는 `a-zA-Z0-9_.`이며, `offset`은 유효한 음이 아닌 정수여야 합니다.
.. [#ksyscall] `ksyscall` 연결 형식은 `ksyscall/<syscall>` 입니다.
.. [#uprobe] `uprobe` 연결 형식은 `uprobe[.s]/<path>:<function>[+<offset>]` 입니다.
.. [#usdt] `usdt` 연결 형식은 `usdt/<path>:<provider>:<name>` 입니다.
.. [#kpmulti] `kprobe.multi` 연결 형식은 `kprobe.multi/<pattern>`이며, `pattern`은 `*`와 `?` 와일드카드를 지원합니다. `pattern`에 유효한 문자는 `a-zA-Z0-9_.*?` 입니다.
.. [#lsm] `lsm` 연결 형식은 `lsm[.s]/<hook>` 입니다.
.. [#rawtp] `raw_tp` 연결 형식은 `raw_tracepoint[.w]/<tracepoint>` 입니다.
.. [#tc_legacy] `tc`, `classifier`, `action` 연결 유형은 더 이상 사용되지 않으므로(deprecated), 대신 `tcx/*`를 사용하십시오.
.. [#struct_ops] `struct_ops` 연결 형식은 `struct_ops[.s]/<name>` 규칙을 지원하지만, `name`은 무시되므로 그냥 `SEC("struct_ops[.s]")`를 사용하는 것이 권장됩니다. 연결(attachment)은 `SEC(".struct_ops[.link]")`로 태그된 구조체 초기자(initializer)에 정의됩니다.
.. [#tp] `tracepoint` 연결 형식은 `tracepoint/<category>/<name>` 입니다.
.. [#iter] `iter` 연결 형식은 `iter[.s]/<struct-name>` 입니다.