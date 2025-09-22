package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go first ebpf/fisrt.bpf.c --

type KeyT struct {
	K [10]byte
}

func main() {
	objs := firstObjects{}
	if err := loadFirstObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ifaceName := "enp2s0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("getting interface %s: %s", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgSimple,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attaching XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("eBPF program attached to %s. Press Ctrl+C to exit.", ifaceName)
	log.Println("Send some network traffic to trigger the program (e.g., `ping localhost`).")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			key := KeyT{}
			copy(key.K[:], "hello")

			var value uint32
			if err := objs.FirstMap.Lookup(&key, &value); err != nil {
				log.Printf("Error looking up map: %v", err)
			} else {
				log.Printf("Value for key 'hello' is: %d", value)
			}
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}
}
