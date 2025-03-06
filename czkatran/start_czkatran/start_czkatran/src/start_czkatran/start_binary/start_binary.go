package startbinary

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"start_czkatran/czkatranc"
	"start_czkatran/defalut_watcher"
	"strings"
	"time"
)

type StartczkatranArgs struct {
	BinaryPath string
	Args string
}

const (
	//max_retries
	MAX_RETRIES int = 60
)

func readLog(log io.ReadCloser) {
	scanner := bufio.NewScanner(log)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}

func Startczkatran(kc *czkatranc.CzkatranClient, cmd StartczkatranArgs) {
	default_mac := defalutwatcher.GetDefaultGateWayMac()
	if len(default_mac) == 0 {
		log.Fatal("can not get default mac of default gateway")
	}
	cmd.Args = cmd.Args + " -default_mac=" + default_mac
	args := strings.Split(cmd.Args, " ")
	//./balancer -default_mac=00:11:22:33:44:55
	start_cmd := exec.Command(cmd.BinaryPath, args...)
	stdout, err := start_cmd.StdoutPipe()
	if err != nil {
		log.Fatal("can not get stdout pipe stdout: ", err)
	}
	stderr, err := start_cmd.StderrPipe()
	if err != nil {
		log.Fatal("can not get stderr pipe stderr: ", err)
	}
	if err := start_cmd.Start(); err != nil {
		log.Fatal("error when trying to start czkatran ", err)
	}
	go readLog(stdout)
	go readLog(stderr)
	kc.Init()
	cur_entry := 0
	for !kc.GetMac() {
		if cur_entry++; cur_entry == MAX_RETRIES {
			log.Fatal("can not connect to local czkatran server")
		}
		log.Printf("can not get czkatran server, retrying is doing now")
		time.Sleep(1 * time.Second)
	}
	log.Printf("czkatran is up and running")
	go defalutwatcher.CheckDefaultGwMac(kc, default_mac)
	if err := start_cmd.Wait(); err != nil {
		log.Fatal("error when trying to wait czkatran ", err)
	}
}