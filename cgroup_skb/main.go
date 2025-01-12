// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter,
// receiving an `__sk_buff` pointer for each outgoing packet.
// It prints the count of total packets every second.
package main

import (
	"bufio"
	"log"
	"os"
	// "path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf cgroup_skb.c -- -I../headers

// var (
// 	cgroupClass = "net_cls"
// 	cgroupName = "docker"
// 	fileName = "net_cls.classid"
// 	moduleID = "6ccb57f"
// )

// func loadBpfObjectsWithOpts(obj interface{}, opts *ebpf.CollectionOptions) error {
// 	spec, err := loadBpf()
// 	if err != nil {
// 		return err
// 	}

// 	if progSpec, ok := spec.Programs["count_egress_packets"]; ok {
// 		progSpec.Type = ebpf.CGroupSKB
// 	} else {
// 		log.Fatalf("Program record_cgroup_mkdir not found")
// 	}

// 	return spec.LoadAndAssign(obj, opts)
// }

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v\n", err)
	}
	defer objs.Close()

	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		log.Fatalf("Detect cgroup path err: %v\n", err)
	} else {
		log.Printf("Cgroup path: %s\n", cgroupPath)
	}
	cgroupFd, err := unix.Open(cgroupPath, unix.O_RDONLY, 0)
	if err != nil {
		log.Fatalf("Failed to open cgroup path: %v", err)
	}
	defer unix.Close(cgroupFd)

	objs.bpfPrograms.CountEgressPackets.Type()
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target: cgroupFd,
		Program: objs.CountEgressPackets,
		Attach: ebpf.AttachCGroupInetEgress,
	})
	if err != nil {
		log.Fatalf("Failed to attach cgroup program: %v\n", err)
	}
	defer closeBpf(cgroupFd, &objs)
	// Link the count_egress_packets program to the cgroup2.
	// l, err := link.AttachCgroup(link.CgroupOptions{
	// 	Path:    cgroupPath,
	// 	Attach:  ebpf.AttachCGroupInetEgress,
	// 	Program: objs.CountEgressPackets,
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer l.Close()

	log.Println("Counting packets...")

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var value uint64
		if err := objs.PktCount.Lookup(uint32(0), &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("number of packets: %d\n", value)
	}
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	var (
		// basePath string
		fullPath string
	)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			fullPath = fields[1]
			break
		}
	}

	// basePath = filepath.Join(basePath, cgroupName)
	// fullPath = basePath
	// filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
	// 	if err != nil {
	// 		return err
	// 	}

	// 	// log.Printf("Current path: %s\n", path)
	// 	if d.IsDir() {
	// 		if strings.Contains(d.Name(), nameKey) {
	// 			fullPath = path
	// 			return filepath.SkipAll
	// 		}
	// 	}

	// 	return nil
	// })

	return fullPath, err
}

func closeBpf(fs int, objs *bpfObjects) {
	// 自动卸载挂载的程序
	err := link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  fs,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CountEgressPackets,
	})
	if err != nil {
		log.Printf("Failed to detach eBPF program: %v\n", err)
	}
}
