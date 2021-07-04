// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"plugin"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

var VMPlugin *plugin.Plugin

func NewConsensusEngine(enginePlug *plugin.Plugin, eventer Eventer, nmanager NetworkManager,
	dmanager DataManager, conf *config.Config) Engine {
	NewEngine, err := enginePlug.Lookup("NewEngine")
	if err != nil {
		panic(err)
	}
	return NewEngine.(func(Eventer, NetworkManager, DataManager, *config.Config) Engine)(eventer, nmanager, dmanager, conf)
}

func NewEventer(eventerPlug *plugin.Plugin, queueSize, barrelSize, workerSize int, shutingdownFunc func()) Eventer {
	NewEventController, err := eventerPlug.Lookup("NewEventController")
	if err != nil {
		panic(err)
	}
	return NewEventController.(func(int, int, int, func()) Eventer)(queueSize, barrelSize, workerSize, shutingdownFunc)
}

func NewDManager(dataPlugin *plugin.Plugin, path string, eventer Eventer) (DataManager, error) {
	NewDManager, err := dataPlugin.Lookup("NewManager")
	if err != nil {
		panic(err)
	}
	return NewDManager.(func(string, Eventer) (DataManager, error))(path, eventer)
}

func NewStateDB(chainID common.ChainID, shardInfo common.ShardInfo, t *trie.Trie, dbase db.Database,
	dmanager DataManager) StateDB {

	NewStateDB, err := VMPlugin.Lookup("NewStateDB")
	if err != nil {
		panic(err)
	}
	return NewStateDB.(func(common.ChainID, common.ShardInfo, *trie.Trie, db.Database, DataManager) StateDB)(
		chainID, shardInfo, t, dbase, dmanager)
}

func LoadNoticer(sopath string, queueSize int, chainID common.ChainID, redisAddr string, redisPwd string,
	redisDB int, redisQueue string) Noticer {
	p, err := common.InitSharedObjectWithError(sopath)
	if err != nil {
		log.Warnf("load Noticer failed at %s: %v", sopath, err)
		return nil
	}
	newMethod, err := p.Lookup("NewNotice")
	if err != nil {
		log.Warnf("bind NewNotice with plugin at %s failed: %v", sopath, err)
		return nil
	}
	m, ok := newMethod.(func(int, common.ChainID, string, string, int, string) Noticer)
	if !ok || m == nil {
		log.Warnf("binding NewNotice with plugin at %s failed: %v", sopath, err)
		return nil
	}
	return m(queueSize, chainID, redisAddr, redisPwd, redisDB, redisQueue)
}

type ChainStats struct {
	CurrentHeight      uint64          `json:"currentheight"`      // current height of the chain
	SumTxCount         uint64          `json:"txcount"`            // The number of current chain transactions after this launch
	AllTps             uint64          `json:"tps"`                // Current chain TPS after this launch
	LastEpochTps       uint64          `json:"tpsLastEpoch"`       // TPS of the previous epoch after this launch
	LastNTps           uint64          `json:"tpsLastN"`           // TPS of previous %N blocks
	Lives              uint64          `json:"lives"`              // Running time after this launch (in seconds)
	AccountCount       uint64          `json:"accountcount"`       // 0
	EpochLength        uint64          `json:"epochlength"`        // The number of blocks in one epoch
	AvgEpochDuration   uint64          `json:"epochduration"`      // Average time of an epoch (in seconds)
	LastEpochDuration  uint64          `json:"lastepochduration"`  // The time spent in the last epoch (in seconds)
	LastNDuration      uint64          `json:"lastNduration"`      // Time spent in the previous %N blocks (in seconds)
	LastEpochBlockTime uint64          `json:"lastEpochBlockTime"` // The average block time of the last epcoh (in milliseconds)
	LastNBlockTime     uint64          `json:"lastNBlockTime"`     // Average block time of previous %N blocks (in milliseconds)
	N                  uint64          `json:"N"`                  // The value of N
	GasLimit           uint64          `json:"gaslimit"`           // Current chain default GasLimit
	GasPrice           string          `json:"gasprice"`           // Current chain default GasPrice
	CurrentComm        []common.NodeID `json:"currentcomm"`        // The node list of the current committee of the chain
	Version            string          `json:"version"`            // Version of current node
}
