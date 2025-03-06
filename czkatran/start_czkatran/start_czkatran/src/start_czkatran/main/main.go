package main

import (
	"flag"
	"fmt"
	"start_czkatran/affinitize"
	"start_czkatran/czkatranc"
	"start_czkatran/start_binary"
	"start_czkatran/topology_parser"
	"strconv"
	"strings"
)

var (
	binaryPath = flag.String("binary", "", "path to binary")
	hcProg = flag.String("hc_bpf", "", "path to hc_bpf")
	balancerProg = flag.String("balancer_bpf", "", "path to balancer_bpf")
	ipipintf = flag.String("ipip_intf", "ipip0", "name of the ipip interface")
	ipip6intf = flag.String("ipip6_intf", "ipip6", "name of the ipip6 interface")
	mapPath = flag.String("map_path", "", "path to map root array for shared mode")
	progPos = flag.Int("map_pos", 2, "position of map in map root array for shared mode")
	priority = flag.Int("priority", 2307, "priority of the czkatran")
	shutDelay = flag.Int("shutdown_delay", 1000, "delay before shutdown")
	enableHc = flag.Bool("enable_hc", false, "enable healthchecking")
	run = flag.Bool("run", false, "run czkatran")
	shouldAffinitize = flag.Bool("affinitize", false, "affinitize czkatran")
	affinitizeOnly = flag.Bool("affinitize_only", false, "affinitize czkatran only")
	lruSize = flag.Int("lru_size", 1000000, "size of connection table in entries")
	strategy = flag.Int("strategy", affinitize.ALL_NODE, "affinitize NIC 0 -seq, 1 -same, 2 -all")
	intf = flag.String("intf", "ens33", "interface where to attach xdp proggram")
)

func prepareczkatranArgs() string {
	cpus := " -forwarding_cores="
	numa := " -numa_nodes="
	forwarding_cpus := affinitize.GetAffinitizeMapping(*intf, *strategy)
	topology := topologyparser.GetCpuTopology()
	numa_nodes := topology.GetNumaListForCpus(forwarding_cpus)
	args := fmt.Sprintf(("-balancer_prog=%s -intf=%s -hc_forwarding=%t -map_path=%s" + 
	  					 " -prog_pos=%d -ipip_intf=%s -ipip6_intf=%s -priority=%d" + 
						 " -lru_size=%d -shutdown_delay=%d"),
						*balancerProg,
					    *intf,
						*enableHc,
						*mapPath,
						*progPos,
						*ipipintf,
						*ipip6intf,
						*priority,
						*lruSize,
						*shutDelay)
	if *enableHc {
		args += (" -healthchecker_prog=" + *hcProg)
	}
	sep := ""
	for _, cpu := range forwarding_cpus {
		cpus = strings.Join([]string{cpus, strconv.Itoa(cpu)}, sep)
		if sep == "" {
			sep = ","
		}
	}
	sep = ""
	for _, node := range numa_nodes {
		numa = strings.Join([]string{numa, strconv.Itoa(node)}, sep)
		if sep == "" {
			sep = ","
		}
	}
	args += cpus
	args += numa

	fmt.Println(args)
	return args
}

func main() {
	flag.Parse()
	if *shouldAffinitize {
		affinitize.AffinitizeIntf(*intf, *strategy)
		if *affinitizeOnly {
			return
		}
	}
	args := prepareczkatranArgs()
	var client czkatranc.CzkatranClient
	cmd := startbinary.StartczkatranArgs{*binaryPath, args}
	if *run {
		startbinary.Startczkatran(&client, cmd)
	}
}