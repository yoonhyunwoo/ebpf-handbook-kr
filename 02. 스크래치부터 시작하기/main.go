package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go first ebpf/fisrt.bpf.c --

func main() {
	var objs firstObjects
	err := loadFirstObjects(&objs, nil)
	if err != nil {
		panic(err)
	}

	defer objs.XdpProgSimple.Close()

	objs.XdpProgSimple.Run(nil)

}
