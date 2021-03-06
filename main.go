// +build go1.9

package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/yvasiyarov/gorelic"

	"github.com/sammy007/open-ethereum-pool/api"
	"github.com/sammy007/open-ethereum-pool/payouts"
	"github.com/sammy007/open-ethereum-pool/proxy"
	"github.com/sammy007/open-ethereum-pool/storage"
	"github.com/sammy007/open-ethereum-pool/rpc"
	//"github.com/ethereum/go-ethereum/core/headerchain"
)

var cfg proxy.Config
var backend *storage.RedisClient

func startProxy() {
	s := proxy.NewProxy(&cfg, backend)
	s.Start()
}

func startApi() {
	s := api.NewApiServer(&cfg.Api, backend)
	s.Start()
}

func startBlockUnlocker() {
	u := payouts.NewBlockUnlocker(&cfg.BlockUnlocker, backend)
	u.Start()
}

func startPayoutsProcessor() {
	u := payouts.NewPayoutsProcessor(&cfg.Payouts, backend)
	u.Start()
}

func startNewrelic() {
	if cfg.NewrelicEnabled {
		nr := gorelic.NewAgent()
		nr.Verbose = cfg.NewrelicVerbose
		nr.NewrelicLicense = cfg.NewrelicKey
		nr.NewrelicName = cfg.NewrelicName
		nr.Run()
	}
}

func readConfig(cfg *proxy.Config) {
	configFileName := "config.json"
	if len(os.Args) > 1 {
		configFileName = os.Args[1]
	}
	configFileName, _ = filepath.Abs(configFileName)
	log.Printf("Loading config: %v", configFileName)

	configFile, err := os.Open(configFileName)
	if err != nil {
		log.Fatal("File error: ", err.Error())
	}
	defer configFile.Close()
	jsonParser := json.NewDecoder(configFile)
	if err := jsonParser.Decode(&cfg); err != nil {
		log.Fatal("Config error: ", err.Error())
	}
}

func main() {
	readConfig(&cfg)
	rand.Seed(time.Now().UnixNano())

	if cfg.Threads > 0 {
		runtime.GOMAXPROCS(cfg.Threads)
		log.Printf("Running with %v threads", cfg.Threads)
	}

	log.Printf("===============>")
	tempRpcClient := rpc.NewRPCClient("tempRpcClient", cfg.Payouts.Daemon, cfg.Payouts.Timeout)
	//blockRlp 	  := GetBlockRLP(tempRpcClient, 13500)
	//GetBlockRLP(tempRpcClient, 13500)
	
	//ret := tempRpcClient.GetBlockRLP(13500)
	// tempRpcClient.GetBlockHeaderRLP(13500)
	tempRpcClient.GetHeaderRLP(13500)
	
	//log.Printf("@@@@@@@@: ", ret)
	log.Printf("<===============")
	
	startNewrelic()

	backend = storage.NewRedisClient(&cfg.Redis, cfg.Coin)
	pong, err := backend.Check()
	if err != nil {
		log.Printf("Can't establish connection to backend: %v", err)
	} else {
		log.Printf("Backend check reply: %v", pong)
	}

	if cfg.Proxy.Enabled {
		go startProxy()
	}
	if cfg.Api.Enabled {
		go startApi()
	}
	if cfg.BlockUnlocker.Enabled {
		go startBlockUnlocker()
	}
	if cfg.Payouts.Enabled {
		go startPayoutsProcessor()
	}
	
	quit := make(chan bool)
	<-quit
}
