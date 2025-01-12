// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf kprobe.c -- -I../headers -I /lib/modules/$(uname -r)/build/include -O2 -g -target bpfel -D__TARGET_ARCH_x86
// BPF2GO_FLAGS="-O2 -g -target bpfel -D__TARGET_ARCH_x86"
// const mapKey uint32 = 0

const NAMELENMAX = 16

// func bpfObjectsSpecial(obj interface{}, opts *ebpf.CollectionOptions) error {
// 	collectionSpec, err := loadBpf()
// 	if err != nil {
// 		log.Fatalf("loading bpf: %v", err)
// 	}

// 	if progSpec, ok := collectionSpec.Programs["record_cgroup_mkdir"]; ok {
// 		progSpec.Type = ebpf.Kprobe
// 	} else {
// 		log.Fatalf("BPF Program not found")
// 	}

// 	return collectionSpec.LoadAndAssign(obj, opts)
// }

func main() {

	// Name of the kernel function to trace.
	// fn := "sys_execve"
	cgroupMkdir := "cgroup_mkdir"
	cgroupRmdir := "cgroup_rmdir"

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

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kpCM, err := link.Kprobe(cgroupMkdir, objs.RecordCgroupMkdir, nil)
	if err != nil {
		log.Fatalf("opening cgroup mkdir kprobe: %s", err)
	}
	defer kpCM.Close()

	kpRM, err := link.Kprobe(cgroupRmdir, objs.RecordCgroupRmdir, nil)
	if err != nil {
		log.Fatalf("opening cgroup rmdir kprobe: %s", err)
	}
	defer kpRM.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		deleteKey, err := disposeMapContents(objs.KprobCgroupName)
		if err != nil {
			log.Printf("dispose map error: %v\n", err)
			continue
		}

		if len(deleteKey) > 0 {
			for _, key := range deleteKey {
				log.Printf("Delete cgroup dir: %s", string(key[:]))
				err = objs.KprobCgroupName.Delete(key[:])
				if err != nil {
					log.Printf("Delete map error: %v", err)
				}
			}
		}
	}
}

func disposeMapContents(m *ebpf.Map) ([][]byte ,error) {
	var (
		key [NAMELENMAX]byte
		val uint32 = 0
		deleteKey [][]byte
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		cgroupName := string(key[:])
		if len(cgroupName) > 0 {
			log.Printf("Create cgroup dir %s, count: %d\n", cgroupName, val)
		} else {
			log.Println("No have cgroup be created")
			continue
		}

		if val > 1 {
			deleteKey = append(deleteKey, key[:])
		}
	}
	return deleteKey, iter.Err()
}
