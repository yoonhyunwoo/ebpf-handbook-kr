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
