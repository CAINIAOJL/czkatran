package czkatranc

import (
	"log"
	lb_czkatran "start_czkatran/lb_czkatran"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func checkError(err error) {
	if err != nil {
		log.Fatal("Error: ", err)
	}
}

type CzkatranClient struct {
	client lb_czkatran.CzKatranServiceClient
}

func (kc * CzkatranClient) Init() {
	var opt []grpc.DialOption
	opt = append(opt, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient("127.0.0.1:50051", opt...)
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
		log.Print("Mac was not changed!")
	}
}

func (kc *CzkatranClient) GetMac() bool {
	mac, err := kc.client.GetMac(context.Background(), &lb_czkatran.Empty{})
	if err != nil {
		log.Print("Error when getting mac address!")
		return false
	}
	log.Printf("Mac address is %v\n", mac.GetMac())
	return true
}

