package main
 
import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
 
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"k8s.io/klog/v2"
)
 
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type ipv4_lpm_key bpf ../icmp/drop-icmp.c
 
func IPv4StringToUint32(ip string) (uint32, error) {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return 0, fmt.Errorf("invalid ipv4 format")
	}
 
	return uint32(p[3])<<24 | uint32(p[2])<<16 | uint32(p[1])<<8 | uint32(p[0]), nil
}
 
func SetupSignalHandler() (stopCh <-chan struct{}) {
	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, []os.Signal{os.Interrupt, syscall.SIGTERM}...)
	go func() {
		<-c
		close(c)
		close(stop)
	}()
 
	return stop
}
 
func DelTcEbpf() {
	cmds := []string{
		"tc qdisc del dev ens33 clsact",
	}
	for _, cmd := range cmds {
		exec.Command("bash", "-c", cmd).CombinedOutput()
	}
}
 
func main() {
	stopCh := SetupSignalHandler()
 
	DelTcEbpf()
	defer DelTcEbpf()
 
	// eBPF先删再加
	cmds := []string{
		"tc qdisc add dev ens33 clsact",
		"tc filter add dev ens33 egress bpf da obj icmp/drop-icmp.o sec tc",
		"tc filter add dev ens33 ingress bpf da obj icmp/drop-icmp.o sec tc",
	}
	for i, cmd := range cmds {
		if _, err := exec.Command("bash", "-c", cmd).CombinedOutput(); err != nil && i > 0 {
			klog.Errorf("exec %s failed, err is %v", cmd, err)
			return
		}
	}
 
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.Errorf("rlimit remove memory lock failed, err is %v", err)
		return
	}
 
	ipv4LpmMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/ipv4_lpm_map", nil)
	if err != nil {
		klog.Errorf("load pinned map ipv4_lpm_map failed, err is %v", err)
		return
	}
	defer ipv4LpmMap.Close()
 
	ip, err := IPv4StringToUint32("192.168.0.105")
	if err != nil {
		klog.Errorf("ipv4 string to uint32 failed, err is %v", err)
		return
	}
 
	lpmKey := bpfIpv4LpmKey{
		Prefixlen: 32,
		Data:      ip,
	}
	if err := ipv4LpmMap.Put(lpmKey, uint32(0)); err != nil {
		klog.Errorf("put ipv4 lpm map failed, err is %v", err)
		return
	}
 
	<-stopCh
}