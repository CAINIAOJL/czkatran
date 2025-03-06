package topologyparser

import (
	"fmt"
	"bytes"
	"log"
	"runtime"
	"strconv"
	"os"
)

const (
	TOPOLOGY_DIR  string = "/sys/devices/system/cpu/cpu"
	NUMA_NODE_FILE string = "/topology/physical_package_id"
)

type CpuTopology struct {
	Cpu2Numa map[int]int //cpu对应numa节点的映射
	Numa2Cpu map[int][]int //numa节点对应numa的映射
	Ncpus int //cpu总数
}


func getNumaNodeOfCpu(i int) int {
	filename := TOPOLOGY_DIR + strconv.Itoa(i) + NUMA_NODE_FILE
	numa_bytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal("can not read ", filename, err)
	}
	numa_slice := bytes.Split(numa_bytes, []byte{'\n'})
	if len(numa_slice) < 1 {
		log.Fatal("invalid numa node file format", string(numa_bytes))
	}
	numa, err := strconv.Atoi(string(numa_slice[0]))
	if err != nil {
		log.Fatal("can not parse numa to int")
	}
	return numa
}


func (topo *CpuTopology) GetNumaListForCpus(cpus []int) []int {
	var numa_nodes []int
	for _, cpu := range cpus {
		if node, exists := topo.Cpu2Numa[cpu]; exists {
			numa_nodes = append(numa_nodes, node)
		} else {
			log.Fatal("can not find numa mapping for cpu: ", cpu)
		}
	}
	return numa_nodes
}

func GetCpuTopology() CpuTopology {
	ncpus := runtime.NumCPU() //当前运行的cpu总数
	fmt.Println("number of CPUS ", ncpus)
	var topology CpuTopology
	topology.Cpu2Numa = make(map[int]int)
	topology.Numa2Cpu = make(map[int][]int)
	topology.Ncpus = ncpus

	for i := 0; i < ncpus; i++ {
		numa := getNumaNodeOfCpu(i)
		topology.Cpu2Numa[i] = numa
		topology.Numa2Cpu[numa] = append(topology.Numa2Cpu[numa], i)
	}
	return topology
}