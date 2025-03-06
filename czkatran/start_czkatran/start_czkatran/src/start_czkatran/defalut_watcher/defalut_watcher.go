package defalutwatcher

import (
	"bytes"
	"log"
	"os/exec"
	"start_czkatran/czkatranc"
	"strings"
	"time"
)

const (
	GET_DEFAULT_IP_ADDRESS string = "route show default"
	PING_CMD string = "-c 1 -q -w 1"
	MAC_CMD string = "neighbor show"
)

func getCmdOutput(binary_name string, args string) string {
	var out bytes.Buffer
	args_slice := strings.Fields(args)
	cmd := exec.Command(binary_name, args_slice...)
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("error when running %s cmd %s args: %v\n", cmd, args, err)
		return ""
	}
	return out.String()
}

func getDefaultGateWayIp() string {
	ip_line := getCmdOutput("ip", GET_DEFAULT_IP_ADDRESS)
	if len(ip_line) == 0 {
		return ip_line
	}
	//default via 172.28.128.1 dev eth0 proto kernel
	ip_line_slice := strings.Fields(ip_line)
	if len(ip_line_slice) < 3 {
		return ""
	}
	return ip_line_slice[2]
}

func pingIp(ip string) {
	args := PING_CMD + ip
	getCmdOutput("ping", args)
}

func getDefaultMac(ip string) string {
	args := MAC_CMD + ip;
	out := getCmdOutput("ip", args)
	if len(out) == 0 {
		return out
	}
	//172.28.128.1 dev eth0 lladdr 00:15:5d:61:fa:3d REACHABLE
	out_slice := strings.Fields(out)
	if len(out_slice) < 5 { //返回【4】
		return ""
	}
	return out_slice[4]
}

func GetDefaultGateWayMac() string {
	ip := getDefaultGateWayIp()
	pingIp(ip)
	return getDefaultMac(ip)
}

func CheckDefaultGwMac(kc *czkatranc.CzkatranClient, mac string) {
	current_mac := mac
	for {
		new_mac := GetDefaultGateWayMac()
		if len(new_mac) > 0 && new_mac != current_mac {
			kc.ChangeMac(new_mac)
			current_mac = new_mac
		}
		time.Sleep(1 * time.Minute)
	}
}