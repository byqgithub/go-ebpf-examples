// 统计不同进程的数据包数量

package main

import (
	// "bytes"
	// "encoding/binary"
	// "errors"
	"context"
	"fmt"
	"log"

	// "net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tcprtt.c -- -I../headers -D__TARGET_ARCH_x86

const NAMELENMAX = 16

func main() {
	stopper := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	uploadFn := "ip_rcv"
	uploadKp, err := link.Kprobe(uploadFn, objs.StatisticUploadFlow, nil)
	if err != nil {
		log.Fatalf("Kprobe %s: %v", uploadFn, err)
	}
	defer uploadKp.Close()

	downloadFn := "ip_output"
	downloadkp, err := link.Kprobe(downloadFn, objs.StatisticDownloadFlow, nil)
	if err != nil {
		log.Fatalf("Kprobe %s: %v", downloadFn, err)
	}
	defer downloadkp.Close()

	// linkUpload, err := link.AttachTracing(link.TracingOptions{
	// 	Program: objs.bpfPrograms.StatisticUploadFlow,
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer linkUpload.Close()

	// linkDownload, err := link.AttachTracing(link.TracingOptions{
	// 	Program: objs.bpfPrograms.StatisticDownloadFlow,
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer linkDownload.Close()

	wg.Add(1)
	go readLoop(ctx, &wg, &objs)

	// Wait
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("Stop sign")
	cancel()
	wg.Wait()
}

func iterBpfMap(pidCommMap *ebpf.Map, bpfMap *ebpf.Map, flowType string, flow *map[string]uint64) {
	var (
		pid  uint32
		curFlow  uint64
		comm [NAMELENMAX]byte
	)

	iter := bpfMap.Iterate()
	for iter.Next(&pid, &curFlow) {
		err := pidCommMap.Lookup(&pid, &comm)
		if err != nil {
			log.Printf("Can not find pid %d comm: %v\n", pid, err)
			continue
		}
		commPid := fmt.Sprintf("%s-%d", string(comm[:]), pid)

		if preFlow, ok := (*flow)[commPid]; !ok {
			(*flow)[commPid] = curFlow
			log.Printf("[%s] Add comm-pid: %s, flow: %d\n", flowType, commPid, curFlow)
		} else {
			if curFlow >= preFlow {
				traffic := curFlow - preFlow
				log.Printf("[%s][%s] pre flow: %d, cur flow: %d; traffic: %d\n", flowType, commPid, preFlow, curFlow, traffic)
				(*flow)[commPid] = curFlow
			} else if curFlow < preFlow {
				(*flow)[commPid] = curFlow
				log.Printf("[%s][%s] curFlow < preFlow, reset preFlow: %d\n", flowType, commPid, curFlow)
			} else {
				log.Printf("[%s date error] comm-pid: %s, flow: %d\n", flowType, commPid, curFlow)
			}
		}
	}

	if err := iter.Err(); err != nil {
		log.Printf("Bpf map %sFlow iterate err: %v", flowType, err)
	}
}

func readLoop(ctx context.Context, wg *sync.WaitGroup, objs *bpfObjects) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var (
		uploadFlow   map[string]uint64 = make(map[string]uint64, 10)
		downloadFlow map[string]uint64 = make(map[string]uint64, 10)
	)

outLoop:
	for {
		select {
		case <- ctx.Done():
			break outLoop
		case <- ticker.C:
			iterBpfMap(objs.PidComm, objs.UploadTraffic, "Upload", &uploadFlow)
			iterBpfMap(objs.PidComm, objs.DownloadTraffic, "Download", &downloadFlow)
		}
	}
}