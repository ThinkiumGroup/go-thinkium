package ethrpc

import (
	"os"
	"os/signal"
	"testing"

	"github.com/ThinkiumGroup/go-thinkium/api"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

func TestRunEthRpc(t *testing.T) {
	conf, err := config.LoadConfig("../start/mchainconfs/gtkm0.yaml")
	models.ETHSigner = models.NewLondonSigner()
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
		return
	}
	ethrpcsrv, _ := NewServer(conf.NetworkConf.ETHRPC.GetRpcEndpoint())
	rpcAPI := []API{
		{
			Namespace: "eth",
			Public:    true,
			Service:   api.NewPublicBlockChainAPI(nil, nil, nil, nil),
			Version:   "1.0",
		},
		{
			Namespace: "web3",
			Public:    true,
			Service:   &api.PublicWeb3API{},
			Version:   "2.0",
		},
	}
	if err := RegisterApis(rpcAPI, []string{"eth", "web3"}, ethrpcsrv, false); err != nil {
		panic(err)
	}
	err = ethrpcsrv.Initializer()
	if err != nil {
		return
	}
	err = ethrpcsrv.Starter()
	if err != nil {
		return
	}
	systemsignal := make(chan os.Signal, 1)
	signal.Notify(systemsignal, os.Interrupt, os.Kill)
	select {
	case <-systemsignal:
		break
	}
}
