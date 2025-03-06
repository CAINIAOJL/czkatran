package czkatranc

import (
	lb_czkatran "czkatranc/lb_czkatran"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	NO_SPORT    = 1
	NO_LRU      = 2
	QUIC_VIP    = 4
	DPORT_HASH  = 8
	LOCAL_VIP   = 32
	LOCAL_REAL  = 2
)

const (
	ADD_VIP = iota
	DEL_VIP
	MODIFY_VIP
)

var (
	vipFlagTranslationTable = map[string]int64{
		"NO_SPORT":   NO_SPORT,
		"NO_LRU":     NO_LRU,
		"QUIC_VIP":   QUIC_VIP,
		"DPORT_HASH": DPORT_HASH,
		"LOCAL_VIP":  LOCAL_VIP,
	}
	realFlagTranslationTable = map[string]int32{
		"LOCAL_REAL": LOCAL_REAL,
	}
)

func checkError(err error) {
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}

type CzkatranClient struct {
	client lb_czkatran.CzKatranServiceClient
}

func (kc *CzkatranClient) Init(serverAddr string) {
	var opts []grpc.DialOption
	//源码修改更新
	opts = append(opts, grpc.WithTransportCredentials((insecure.NewCredentials())))
	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		log.Fatalf("can not connect to local czkatran server! err is %v\n", err)
	}
	kc.client = lb_czkatran.NewCzKatranServiceClient(conn)
}

func (kc *CzkatranClient) ChangeMac(mac string) {
	newMac := lb_czkatran.Mac{Mac: mac}
	res, err := kc.client.ChangeMac(context.Background(), &newMac)
	checkError(err)
	if res.Success {
		log.Print("Mac address changed!")
	} else {
		log.Print("Mac address change failed!")
	}
}

func (kc *CzkatranClient) GetMac() {
	mac, err := kc.client.GetMac(context.Background(), &lb_czkatran.Empty{})
	checkError(err)
	log.Printf("Mac address is %v\n", mac.GetMac())
}

func parseToVip(addr string, proto int) lb_czkatran.Vip {
	var vip lb_czkatran.Vip
	vip.Protocol = int32(proto)
	//修改源码
	if strings.Contains(addr, "[") {
		//v6 address format [<addr>]:<port>
		v6re := regexp.MustCompile(`\[(.*?)\]:(.*)`)
		addr_port := v6re.FindStringSubmatch(addr)
		if addr_port == nil {
			log.Fatalf("invalid vip address format: %v\n", addr)

		}
		vip.Address = addr_port[1]
		port, err := strconv.ParseInt(addr_port[2], 10, 32) //10进制，32位
		checkError(err)
		vip.Port = int32(port)
	} else {
		//v4 address format <addr>:<port>
		addr_port := strings.Split(addr, ":")
		if len(addr_port) != 2 {
			log.Fatalf("incorrect vip address format : %v\n", addr)
		}
		vip.Address = addr_port[0]
		port, err := strconv.ParseInt(addr_port[1], 10, 32)
		checkError(err)
		vip.Port = int32(port)
	}
	return vip
}

func parseToReal(addr string, weight int64, flags int32) lb_czkatran.Real {
	var real lb_czkatran.Real
	real.Address = addr
	real.Weight = int32(weight)
	real.Flags = flags
	return real
}

func parseToQuicReal(mapping string) lb_czkatran.QuicReal {
	addr_id := strings.Split(mapping, "=")
	if len(addr_id) != 2 {
		log.Fatalf("incorrect quic real mapping format: %v\n", mapping)
	}
	id, err := strconv.ParseInt(addr_id[1], 10, 32)
	checkError(err)
	var qr lb_czkatran.QuicReal
	qr.Address = addr_id[0]
	qr.Id = int32(id)
	return qr
}

func (kc *CzkatranClient) AddOrModifyService(
	addr string, flagsString string, proto int, modify bool, setFlags bool) {
	log.Printf("Adding service: %v %v\n", addr, proto)
	vip := parseToVip(addr, proto)
	var flags int64
	var exists bool
	if flagsString != "" {
		if flags, exists = vipFlagTranslationTable[flagsString]; !exists {
			log.Printf("unrecognized flag: %v\n", flagsString)
			return
		}
	}
	if modify {
		kc.UpdateService(vip, flags, MODIFY_VIP, setFlags)
	} else {
		kc.UpdateService(vip, flags, ADD_VIP, setFlags)
	}
}

func (kc *CzkatranClient) DelService(addr string, proto int) {
	log.Printf("Deleting service: %v %v\n", addr, proto)
	vip := parseToVip(addr, proto)
	kc.UpdateService(vip, 0, DEL_VIP, false)
}

func (kc *CzkatranClient) UpdateService(vip lb_czkatran.Vip, flags int64, action int, setFlags bool) {
	var vmeta lb_czkatran.VipMeta
	var ok *lb_czkatran.Bool
	var err error
	vmeta.Vip = &vip
	vmeta.Flags = flags
	vmeta.Setflags = setFlags
	switch action {
	case MODIFY_VIP:
		ok, err = kc.client.ModifyVip(context.Background(), &vmeta)
		break
	case ADD_VIP:
		ok, err = kc.client.AddVip(context.Background(), &vmeta)
		break
	case DEL_VIP:
		ok, err = kc.client.DelVip(context.Background(), &vip)
		break
	default:
		break
	}
	checkError(err)
	if ok.Success {
		log.Printf("vip modified\n")
	}
}

func (kc *CzkatranClient) UpdateReal(addr string, flags int32, setFlags bool) {
	var rmeta lb_czkatran.RealMeta
	rmeta.Address = addr
	rmeta.Flags = flags
	rmeta.Setflags = setFlags
	ok, err := kc.client.ModifyReal(context.Background(), &rmeta)
	checkError(err)
	if ok.Success {
		log.Printf("real modified\n")
	}
}

func (kc *CzkatranClient) UpdateServerForVip(vipAddr string, proto int, realAddr string, weight int64, realFlags string, delete bool) {
	vip := parseToVip(vipAddr, proto)
	var flags int32
	var exists bool
	if realFlags != "" {
		if flags, exists = realFlagTranslationTable[realFlags]; !exists {
			log.Printf("unrecognized flag: %v\n", realFlags)
			return
		}
	}
	real := parseToReal(realAddr, weight, flags)
	var action lb_czkatran.Action
	if delete {
		action = lb_czkatran.Action_DEl
	} else {
		action = lb_czkatran.Action_ADD
	}
	var reals lb_czkatran.Reals
	reals.Reals = append(reals.Reals, &real) //添加到数组中
	kc.ModifyRealsForVip(&vip, &reals, action)
}

func (kc *CzkatranClient) ModifyRealsForVip(vip *lb_czkatran.Vip, reals *lb_czkatran.Reals, action lb_czkatran.Action) {
	var mReals lb_czkatran.ModifiedRealForVip
	mReals.Action = action
	mReals.Vip = vip
	mReals.Real = reals
	ok, err := kc.client.ModifyRealsForVip(context.Background(), &mReals)
	checkError(err)
	if ok.Success {
		log.Printf("reals modified\n")
	}
}

func (kc *CzkatranClient) ModifyQuicMapping(mapping string, delete bool) {
	var action lb_czkatran.Action
	if delete {
		action = lb_czkatran.Action_DEl
	} else {
		action = lb_czkatran.Action_ADD
	}
	qr := parseToQuicReal(mapping)
	var qrs lb_czkatran.QuicReals
	qrs.Qreals = append(qrs.Qreals, &qr)
	var mqr lb_czkatran.ModifiedQuicReals
	mqr.Action = action
	mqr.Qreals = &qrs
	ok, err := kc.client.ModifyQuicRealsMapping(context.Background(), &mqr)
	checkError(err)
	if ok.Success {
		log.Printf("quic mapping modified\n")
	}
}

func (kc *CzkatranClient) GetAllVips() lb_czkatran.Vips {
	vips, err := kc.client.GetAllVips(context.Background(), &lb_czkatran.Empty{})
	checkError(err)
	return *vips
}

func (kc *CzkatranClient) GetAllhcs() lb_czkatran.HcMap {
	hcs, err := kc.client.GetHealthcheckersDst(context.Background(), &lb_czkatran.Empty{})
	checkError(err)
	return *hcs
}

func (hc *CzkatranClient) GetRealsForVip(vip *lb_czkatran.Vip) lb_czkatran.Reals {
	reals, err := hc.client.GetRealsForVip(context.Background(), vip)
	checkError(err)
	return *reals
}

func (hc *CzkatranClient) GetVipFlags(vip *lb_czkatran.Vip) uint64 {
	flags, err := hc.client.GetVipFlags(context.Background(), vip)
	checkError(err)
	return flags.Flags
}

func parseVipFlags(flags uint64) string {
	flags_str := ""
	if flags&uint64(NO_SPORT) > 0 {
		flags_str += " NO_SPORT "
	}
	if flags&uint64(NO_LRU) > 0 {
		flags_str += " NO_LRU "
	}
	if flags&uint64(QUIC_VIP) > 0 {
		flags_str += " QUIC_VIP "
	}
	if flags&uint64(DPORT_HASH) > 0 {
		flags_str += " DPORT_HASH "
	}
	if flags&uint64(LOCAL_VIP) > 0 {
		flags_str += " LOCAL_VIP "
	}
	return flags_str
}

func parseRealFlags(flags int32) string {
	if flags < 0 {
		log.Fatalf("invalid real flags passed: %v\n", flags)
	}
	flags_str := ""
	if flags&LOCAL_REAL > 0 {
		flags_str += " LOCAL_REAL "
	}
	return flags_str
}

func (kc *CzkatranClient) ListVipAndReals(vip *lb_czkatran.Vip) {
	reals := kc.GetRealsForVip(vip)
	proto := ""
	if vip.Protocol == IPPROTO_TCP {
		proto = "tcp"
	} else {
		proto = "udp"
	}

	fmt.Printf("VIP: %20v Port: %6v Protocol: %v\n", vip.Address, vip.Port, proto)

	flags := kc.GetVipFlags(vip)
	fmt.Printf("Vip's flags: %v\n", parseVipFlags(flags))
	for _, real := range reals.Reals {
		fmt.Printf("%-20v weight: %v flags: %v\n",
			"->"+real.Address,
			real.Weight, parseRealFlags(real.Flags))
	}
}

func (kc *CzkatranClient) List(addr string, proto int) {
	vips := kc.GetAllVips()
	log.Printf("vips len %v", len(vips.Vips))
	for _, vip := range vips.Vips {
		kc.ListVipAndReals(vip)
	}
}

func (kc *CzkatranClient) ClearAll() {
	fmt.Printf("Deleting vips")
	vips := kc.GetAllVips()
	for _, vip := range vips.Vips {
		ok, err := kc.client.DelVip(context.Background(), vip)
		if err != nil || !ok.Success {
			fmt.Printf("error when deleting vip: %v", vip.Address)
		}
	}
	fmt.Println("Deleting Healthchecks")
	hcs := kc.GetAllhcs()
	var Somark lb_czkatran.Somark
	for somark := range hcs.Healthchecks {
		Somark.Somark = uint32(somark)
		ok, err := kc.client.DelHealthcheckerDst(context.Background(), &Somark)
		if err != nil || !ok.Success {
			fmt.Printf("error when deleting hc dst, somark: %v", somark)
		}
	}
}

func (kc *CzkatranClient) ListQm() {
	fmt.Printf("printing address to quic's connection id mapping\n")
	qreals, err := kc.client.GetQuicRealsMapping(context.Background(), &lb_czkatran.Empty{})
	checkError(err)
	for _, qr := range qreals.Qreals {
		fmt.Printf("real: %20v = connection id: %6v\n", qr.Address, qr.Id)
	}
}

func (kc *CzkatranClient) Addhc(addr string, somark uint64) {
	var hc lb_czkatran.Healthcheck
	hc.Somark = uint32(somark)
	hc.Address = addr
	ok, err := kc.client.AddHealthcheckerDst(context.Background(), &hc)
	checkError(err)
	if !ok.Success {
		fmt.Printf("error when Add hc dst, somark: %v and address: %v", somark, addr)
	}
}

func (kc *CzkatranClient) DelHc(somark uint64) {
	var sm lb_czkatran.Somark
	sm.Somark = uint32(somark)
	ok, err := kc.client.DelHealthcheckerDst(context.Background(), &sm)
	checkError(err)
	if !ok.Success {
		fmt.Printf("error when deleting hc dst, somark: %v", somark)
	}
}

func (kc *CzkatranClient) ListHc() {
	hcs := kc.GetAllhcs()
	for somark, addr := range hcs.Healthchecks {
		fmt.Printf("somark: %10v addr: %10v\n", somark, addr)
	}
}

func (kc *CzkatranClient) ShowSumStats() {
	oldPkts := uint64(0)
	oldBytes := uint64(0)
	vips := kc.GetAllVips()
	for true {
		pkts := uint64(0)
		bytes := uint64(0)
		for _, vip := range vips.Vips {
			stats, err := kc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			pkts += stats.V1
			bytes += stats.V2
		}
		diffPckts := pkts - oldPkts
		diffBytes := bytes - oldBytes
		fmt.Printf("summary: %v pkts/sec %v bytes/sec\n", diffPckts, diffBytes)
		oldPkts = pkts
		oldBytes = bytes
		time.Sleep(1 * time.Second)
	}
}

func (kc *CzkatranClient) ShowLruStats() {
	oldTotalPkts := uint64(0)
	oldMiss := uint64(0)
	oldTcpMiss := uint64(0)
	oldTcpNonSynMiss := uint64(0)
	oldFallbackLru := uint64(0)
	for true {
		//形成概率
		lruMiss := float64(0)
		lruHit := float64(0)
		tcpMiss := float64(0)
		tcpNonSynMiss := float64(0)
		udpMiss := float64(0)

		stats, err := kc.client.GetLruStats(context.Background(), &lb_czkatran.Empty{})
		if err != nil {
			continue
		}
		missStats, err := kc.client.GetLruMissStats(context.Background(), &lb_czkatran.Empty{})
		if err != nil {
			continue
		}
		fallbackStats, err := kc.client.GetLruFailbackStats(context.Background(), &lb_czkatran.Empty{})
		if err != nil {
			continue
		}

		diffTotal := stats.V1 - oldTotalPkts
		diffMiss := stats.V2 - oldMiss
		diffTcpMiss := missStats.V1 - oldTcpMiss
		diffTcpNonSynMiss := missStats.V2 - oldTcpNonSynMiss
		diffFallbackLru := fallbackStats.V1 - oldFallbackLru

		if diffTotal != 0 {
			lruMiss = float64(diffMiss) / float64(diffTotal)
			tcpMiss = float64(diffTcpMiss) / float64(diffTotal)
			tcpNonSynMiss = float64(diffTcpNonSynMiss) / float64(diffTotal)
			udpMiss = 1 - (tcpMiss + tcpNonSynMiss)
			lruHit = 1 - lruMiss
		}
		fmt.Printf("summary: %d pkts/sec. lru hit: %.2f%% lru miss: %.2f%% ", diffTotal, 100*lruHit, 100*lruMiss)
		fmt.Printf("(tcp syn: %.2f%% tcp non-syn: %.2f%% udp: %.2f%%)", tcpMiss, tcpNonSynMiss, udpMiss)
		fmt.Printf(" fallback lru hit: %d pkts/sec\n", diffFallbackLru)

		oldTotalPkts = stats.V1
		oldMiss = stats.V2
		oldTcpMiss = missStats.V1
		oldTcpNonSynMiss = missStats.V2
		oldFallbackLru = fallbackStats.V1
		time.Sleep(1 * time.Second)
	}
}

func (kc *CzkatranClient) ShowPerVipStats() {
	vips := kc.GetAllVips()
	statsMap := make(map[string]uint64)
	for _, vip := range vips.Vips {
		key := strings.Join([]string{
			vip.Address,
			strconv.Itoa(int(vip.Port)),
			strconv.Itoa(int(vip.Protocol))}, ":")
		statsMap[key+":pkts"] = 0
		statsMap[key+":bytes"] = 0
	}
	for true {
		for _, vip := range vips.Vips {
			key := strings.Join([]string{
				vip.Address,
				strconv.Itoa(int(vip.Port)),
				strconv.Itoa(int(vip.Protocol))}, ":")
			stats, err := kc.client.GetStatsForVip(context.Background(), vip)
			if err != nil {
				continue
			}
			diffPkts := stats.V1 - statsMap[key+":pkts"]
			diffBytes := stats.V2 - statsMap[key+":bytes"]
			fmt.Printf("vip: %16s : %8d pkts/sec %8d bytes/sec\n", key, diffPkts, diffBytes)
			statsMap[key+":pkts"] = stats.V1
			statsMap[key+":bytes"] = stats.V2
		}
		time.Sleep(1 * time.Second)
	}
}

func (kc *CzkatranClient) ShowIcmpStats() {
	oldTcmpV4 := uint64(0)
	oldTcmpV6 := uint64(0)
	for true {
		icmps, err := kc.client.GetIcmpTooBigStats(context.Background(), &lb_czkatran.Empty{})
		checkError(err)
		diffIcmpV4 := icmps.V1 - oldTcmpV4
		diffIcmpV6 := icmps.V2 - oldTcmpV6
		fmt.Printf("ICMP \"packet too big\": V4 %v pkts/sec V6 %v pkts/sec\n", diffIcmpV4, diffIcmpV6)
		oldTcmpV4 = icmps.V1
		oldTcmpV6 = icmps.V2
		time.Sleep(1 * time.Second)
	}
}
