package affinitize

import (
	"fmt"
	"log"
	"os"
	irq_parser "start_czkatran/irq_parser"
	topologyparser "start_czkatran/topology_parser"
	"strconv"
)

const (
	IRQ_DIR string = "/proc/irq/"
	IRQ_FILE_SUFFIX string = "/smp_affinity"
)

const (
	SEQ_NODES int = iota
	SAME_NODE
	ALL_NODE
)

const (
	NUMA_NODE int = 0
)

func searchSlice(i int, s []int) bool {
    for _, v := range s {
        if v == i {
            return true
        }
    }
    return false
}

func writeAffinityToFile(irq int, cpu uint64, ncpus int) {
	mask := make([]string, ncpus / 32 + 1, ncpus / 32 + 1)
	for i := range mask {
		mask[i] = "00000000"
	}
	mask[cpu / 32] = fmt.Sprintf("%08x", 1 << (cpu % 32))
	cpu_flag_str := mask[len(mask) - 1]
	for i := len(mask) - 2; i >= 0; i-- {
		cpu_flag_str += ("," + mask[i])
	}
	irq_str := strconv.Itoa(irq)
	log.Printf("affinitizing irq %d to cpu %d mask %s\n", irq, cpu, cpu_flag_str)
	filename := IRQ_DIR + irq_str + IRQ_FILE_SUFFIX
	err := os.WriteFile(filename, []byte(cpu_flag_str), 0644)
	if err != nil {
		log.Fatal("can not write to ", filename, cpu, err)
	}
}

func affinitizeSeqNodes(intf string, write bool)[]int {
	var forwarding_cpus []int
	irqs := irq_parser.GetInterfaceIrq(intf)
	topo := topologyparser.GetCpuTopology()

	for i, irq := range irqs {
		cpu := i % topo.Ncpus
		if !searchSlice(cpu, forwarding_cpus) {
			forwarding_cpus = append(forwarding_cpus, cpu)
		}
		if write {
			writeAffinityToFile(irq, uint64(cpu), topo.Ncpus)
		}
	}
	return forwarding_cpus
}

func affinitizeSameNode(intf string, write bool) []int {
	var forwarding_cpus []int
	irqs := irq_parser.GetInterfaceIrq(intf)
	topo := topologyparser.GetCpuTopology()
	for i, irq := range irqs {
		cpu_idx := i % len(topo.Numa2Cpu[NUMA_NODE])
		cpu := topo.Numa2Cpu[NUMA_NODE][cpu_idx]
		if !searchSlice(cpu, forwarding_cpus) {
			forwarding_cpus = append(forwarding_cpus, cpu)
		}
		if write {
			writeAffinityToFile(irq, uint64(cpu), topo.Ncpus)
		}
	}
	return forwarding_cpus
}

func affinitizeAllNodes(intf string, write bool) []int {
	var forwarding_cores []int
	irqs := irq_parser.GetInterfaceIrq(intf)
	topo := topologyparser.GetCpuTopology()
	for i, irq := range irqs {
		numa_idx := i % len(topo.Numa2Cpu)
		cpu_idx := (i / len(topo.Numa2Cpu)) % len(topo.Numa2Cpu[NUMA_NODE])
		cpu := topo.Numa2Cpu[numa_idx][cpu_idx]
		if !searchSlice(cpu, forwarding_cores) {
			forwarding_cores = append(forwarding_cores, cpu)
		}
		if write {
			writeAffinityToFile(irq, uint64(cpu), topo.Ncpus)
		}
	}
	return forwarding_cores
}

func AffinitizeIntf(intf string, strategy int) {
	switch strategy {
	case SEQ_NODES:
		affinitizeSeqNodes(intf, true)
		break
	case SAME_NODE:
		affinitizeSameNode(intf, true)
		break
	case ALL_NODE:
		affinitizeAllNodes(intf, true)
		break
	default:
		log.Println("unknown affinitize strategy ", strategy)
	}
}

func GetAffinitizeMapping(intf string, strategy int) []int {
	switch strategy {
	case SEQ_NODES:
		return affinitizeSeqNodes(intf, false)
	case SAME_NODE:
		return affinitizeSameNode(intf, false)
	case ALL_NODE:
		return affinitizeAllNodes(intf, false)
	default:
		log.Println("unknown affinitize strategy ", strategy)
	}
	return []int {}
}