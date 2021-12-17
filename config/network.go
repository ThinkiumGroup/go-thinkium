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
	"github.com/ThinkiumGroup/go-common"
)

var (
	DefaultEthRpcEndpoint = common.Endpoint{NetType: "tcp", Address: common.DefaultEthRpcAddress}
)

type NConfig struct {
	DataServers []common.Dataserver `yaml:"bootservers" json:"bootservers"`
	P2Ps        *P2PConfig          `yaml:"p2p",omitempty json:"p2p"`
	RPCs        *RPCConfig          `yaml:"rpc",omitempty json:"rpc"`
	ETHRPC      *ETHRPCConfig       `yaml:"ethrpc",omitempty json:"ethrpc"`
	Pprof       *string             `yaml:"pprof",omitempty json:"pprof"`

	DataServerMap map[common.NodeID][]common.Dataserver `yaml:"-" json:"-"` // nodeid -> []Dataserver
}

type P2PConfig struct {
	PortRange *[2]uint16 `yaml:"portRange",omitempty json:"portRange"`
}

func (p *P2PConfig) GetPortRange() *[2]uint16 {
	if p == nil {
		return nil
	}
	return p.PortRange
}

type RPCConfig struct {
	MessageBufferSize uint16           `yaml:"buffersize" json:"-"`
	KeepaliveInterval int64            `yaml:"keepaliveinterval" json:"-"`
	RPCServerAddr     *common.Endpoint `yaml:"rpcserver" json:"rpcserver"`
}

func (rpc *RPCConfig) GetRpcEndpoint() common.Endpoint {
	if rpc == nil || rpc.RPCServerAddr == nil {
		return common.DefaultRpcEndpoint
	}
	return *rpc.RPCServerAddr
}

func (rpc *RPCConfig) GetRpcAddress() string {
	if rpc == nil || rpc.RPCServerAddr == nil {
		return common.DefaultRpcAddress
	}
	return rpc.RPCServerAddr.Address
}

type ETHRPCConfig struct {
	MessageBufferSize uint16           `yaml:"buffersize" json:"-"`
	KeepaliveInterval int64            `yaml:"keepaliveinterval" json:"-"`
	EthRPCServerAddr  *common.Endpoint `yaml:"ethrpcserver" json:"ethrpcserver"`
}

func (rpc *ETHRPCConfig) GetRpcEndpoint() common.Endpoint {
	if rpc == nil || rpc.EthRPCServerAddr == nil {
		return DefaultEthRpcEndpoint
	}
	return *rpc.EthRPCServerAddr
}
