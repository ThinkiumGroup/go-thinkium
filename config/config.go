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

package config

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"gopkg.in/yaml.v2"
)

type LogType uint8

const (
	BasicLog LogType = iota
	NetLog
	NetDebugLog
	ConsensusLog
	ConsensusDebugLog
	DataLog
	DataDebugLog
	QueueLog
	QueueDebugLog
	VmLog
	VmDebugLog
	BalanceLog
	LengthOfLogType
)

func (l LogType) String() string {
	switch l {
	case BasicLog:
		return "BasicLog"
	case NetLog:
		return "NetLog"
	case NetDebugLog:
		return "NetDebugLog"
	case ConsensusLog:
		return "ConsensusLog"
	case ConsensusDebugLog:
		return "ConsensusDebugLog"
	case DataLog:
		return "DataLog"
	case DataDebugLog:
		return "DataDebugLog"
	case QueueLog:
		return "QueueLog"
	case QueueDebugLog:
		return "QueueDebugLog"
	case VmLog:
		return "VmLog"
	case VmDebugLog:
		return "VmDebugLog"
	case BalanceLog:
		return "BalanceLog"
	default:
		return "LogType-" + strconv.Itoa(int(l))
	}
}

var (
	logTypeArray [LengthOfLogType]bool
	SystemConf   *Config

	FullHashBigInt *big.Int = new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	})

	validatorInterface = reflect.TypeOf(new(ConfValidator)).Elem()
)

type ElectConf struct {
	ChainID   common.ChainID      `yaml:"chainid"`   // ID of the chain
	Election  common.ElectionType `yaml:"election"`  // Election type, default NONE
	SyncBlock bool                `yaml:"syncblock"` // no use
}

func (cc ElectConf) String() string {
	return fmt.Sprintf("{ChainID:%d Election:%s SyncBlock:%t}", cc.ChainID, cc.Election, cc.SyncBlock)
}

type DConfig struct {
	Path string `yaml:"datapath"` // db path
}

type ConfValidator interface {
	Validate() error
}

const DefaultLoadLimit = 1

type Config struct {
	PriKeyString string               `yaml:"priKey"`      // hex string of private key of the node
	LoadLimit    int                  `yaml:"loadlimit"`   // Load upper limit. Configure the current node to make consensus on several chains at the same time. Default loadlimit = 2
	NetworkConf  NConfig              `yaml:"network"`     // network config
	DataConf     DConfig              `yaml:"data"`        // data node config
	LogTypes     []LogType            `yaml:"logs"`        // log types should print
	LogPath      string               `yaml:"logpath"`     // log file path
	Chains       ChainConfs           `yaml:"chains"`      // configs for genesis chains
	TxCount      uint64               `yaml:"txCount"`     //
	NetDelay     []int                `yaml:"netDelay"`    // range of network delay (for debugging)
	WaitingTime  *time.Duration       `yaml:"waitingTime"` // delay for consensus
	NodeType     *common.NodeType     `yaml:"nodetype"`    // type of node: Consensus:0, Data:1, Memo:2
	ForChain     *common.ChainID      `yaml:"forchain"`    // specifies the chain of node services
	FullData     bool                 `yaml:"fulldata"`    // whether a full data node
	CheckData    bool                 `yaml:"checkdata"`   // whether need to check old data
	Compatible   *bool                `yaml:"compatible"`  //
	Nid          *common.NodeID       `yaml:"-"`           // The nodeid object obtained by parsing Nodeidstring
	PrivKey      cipher.ECCPrivateKey `yaml:"-"`           // The private key object obtained by parsing PriKeyString
	StandAlone   bool                 `yaml:"standAlone"`  // whether start in single chain mode
	Noticer      *NoticeConf          `yaml:"notice"`
	Starter      *Starter             `yaml:"starter"` // starter private key
}

func LoadConfig(path string) (*Config, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("reading config ", path, " error: ", err)
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(contents, &config)
	if err != nil {
		log.Error("unmarshal config ", path, " error: ", err)
		return nil, err
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	// log.Info("load config from ", path, " success")
	SystemConf = &config
	return &config, nil
}

func (c *Config) validate() error {
	prikeybytes, err := hex.DecodeString(c.PriKeyString)
	if err != nil {
		return common.NewDvppError("parse private key error: ", err)
	}
	// ecsk, err := common.ToECDSAPrivateKey(prikeybytes)
	ecsk, err := common.RealCipher.BytesToPriv(prikeybytes)
	if err != nil {
		return common.NewDvppError("unmarshal private key error: ", err)
	}
	c.PrivKey = ecsk

	pnid := common.BytesToNodeID(c.PrivKey.GetPublicKey().ToNodeIDBytes())
	c.Nid = &pnid

	if c.Starter == nil {
		c.Starter = &Starter{}
	}

	// validate all ConfValidators
	val := reflect.ValueOf(c).Elem()
	typ := val.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Implements(validatorInterface) {
			if val.FieldByName(f.Name).IsNil() {
				continue
			}
			validator := val.FieldByName(f.Name).Interface().(ConfValidator)
			if validator != nil {
				err = validator.Validate()
				if err != nil {
					panic(fmt.Errorf("[CONFIG] validate field %s with error: %v", f.Name, err))
					return err
				}
			}
		}
	}

	return nil
}

func (c *Config) IsCompatible() bool {
	if c.Compatible == nil {
		return common.DefaultCompatible
	}
	return *c.Compatible
}

func (c *Config) MakeLogTypeMap() {
	ver := make([]string, 0)

	for i := 0; i < len(c.LogTypes); i++ {
		if c.LogTypes[i] < 0 || c.LogTypes[i] >= LengthOfLogType {
			continue
		}
		logTypeArray[c.LogTypes[i]] = true
		ver = append(ver, c.LogTypes[i].String())
	}
	log.Infof("LogTypes: %v", ver)
}

func IsLogOn(logType LogType) bool {
	return logTypeArray[logType]
}
