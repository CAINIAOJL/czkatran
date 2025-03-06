package main

import (
	"czkatranc/czkatranc"
	"flag"
	"fmt"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
)

var (
	addService      = flag.Bool("A", false, "Add new virtual service")
	editService     = flag.Bool("E", false, "Edit existing virtual service")
	delService      = flag.Bool("D", false, "Delete existing virtual service")
	addServer       = flag.Bool("a", false, "Add new real server")
	delServer       = flag.Bool("d", false, "Delete existing real server")
	editServer      = flag.Bool("e", false, "Edit existing real server")
	tcpService      = flag.String("t", "", "TCP service address, must be in format: <addr>:<port>")
	udpService      = flag.String("u", "", "UDP service address, must be in format: <addr>:<port>")
	realServer      = flag.String("r", "", "Address of the real server")
	realWeight      = flag.Int64("w", 1, "Weight of the real server")
	showStats       = flag.Bool("s", false, "Show stats/counters")
	showSumStats    = flag.Bool("sum", false, "Show summary stats")
	showLruStats    = flag.Bool("lru", false, "Show LRU stats")
	showIcmpStats   = flag.Bool("icmp", false, "Show ICMP Too Big stats")
	listServices    = flag.Bool("l", false, "list configured services")
	vipChangeFlags  = flag.String("vf", "", "change vip flags. Possible values: NO_SPORT, NO_LRU, QUIC_VIP, DPORT_HASH, LOCAL_VIP")
	realChangeFlags = flag.String("rf", "", "change real flags. Possible values: LOCAL_REAL")
	unsetFlags      = flag.Bool("unset", false, "Unset specified flags")
	newHc           = flag.String("new_hc", "", "Address of new backend to healthcheckdst")
	somark          = flag.Uint64("somark", 0, "socket mark to specified backend")
	delHc           = flag.Bool("del_hc", false, "Delete backend specified somark")
	listHc          = flag.Bool("list_hc", false, "List configured healthcheck dst")
	listMac         = flag.Bool("list_mac", false, "List configured mac address of default router")
	changeMac       = flag.String("change_mac", "", "Change mac address of default router")
	clearAll        = flag.Bool("c", false, "Clear all configs")
	quicMapping     = flag.String("quic_mapping", "", "mapping of real to connectionId must be in format <addr>=<id> format")
	delQuicMapping  = flag.Bool("del_qm", false, "Delete quic mapping")
	listQuicMapping = flag.Bool("list_qm", false, "List quic mapping")
	czkatranServer  = flag.String("server", "127.0.0.1:50051", "czkatran server listen address")
)

func main() {
	flag.Parse()
	var service string
	var proto int
	if *tcpService != "" {
		service = *tcpService
		proto = IPPROTO_TCP
	} else if *udpService != "" {
		service = *udpService
		proto = IPPROTO_UDP
	}
	var kc czkatranc.CzkatranClient
	kc.Init(*czkatranServer)
	if *changeMac != "" {
		kc.ChangeMac(*changeMac)
	} else if *listMac {
		kc.GetMac()
	} else if *addService {
		kc.AddOrModifyService(service, *vipChangeFlags, proto, false, true)
	} else if *listServices {
		kc.List("", 0)
	} else if *delService {
		kc.DelService(service, proto)
	} else if *editService {
		kc.AddOrModifyService(service, *vipChangeFlags, proto, true, true)
	} else if *addServer || *editServer {
		kc.UpdateServerForVip(service, proto, *realServer, *realWeight, *realChangeFlags, false)
	} else if *delServer {
		kc.UpdateServerForVip(service, proto, *realServer, *realWeight, *realChangeFlags, true)
	} else if *delQuicMapping {
		kc.ModifyQuicMapping(*quicMapping, true)
	} else if *quicMapping != "" {
		kc.ModifyQuicMapping(*quicMapping, false)
	} else if *listQuicMapping {
		kc.ListQm()
	} else if *clearAll {
		kc.ClearAll()
	} else if *newHc != "" {
		kc.Addhc(*newHc, *somark)
	} else if *delHc {
		kc.DelHc(*somark)
	} else if *listHc {
		kc.ListHc()
	} else if *showStats {
		if *showIcmpStats {
			kc.ShowIcmpStats()
		} else if *showLruStats {
			kc.ShowLruStats()
		} else if *showSumStats {
			kc.ShowSumStats()
		} else {
			kc.ShowPerVipStats()
		}
	}
	fmt.Printf("exiting\n")
}
