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
	"errors"
	"fmt"

	"github.com/ThinkiumGroup/go-common"
)

type ChainConf struct {
	ID                   common.ChainID      `yaml:"id" json:"id"`                     // ID of the chain
	ParentID             common.ChainID      `yaml:"parentid" json:"parentid"`         // ID of the parent chain，if there's no parent chain (main chain no parent)，should be '1048576'，IsNil()==true
	GenesisDataservers   []string            `yaml:"gdataservers" json:"gdataservers"` // string array of nodeid of the genesis data node
	GenesisDataserverIds []common.NodeID     `yaml:"-" json:"-"`                       // the nodeid array of genesis data node, convert from GenesisDataservers in validate()
	Dataservers          []string            `yaml:"dataservers" json:"dataservers"`   // String array of nodeid of non genesis data node
	DataserverIds        []common.NodeID     `yaml:"-" json:"-"`                       // nodeid array of genesis and non-genesis data nodes, created in validate()
	ElectType            common.ElectionType `yaml:"election" json:"election"`         // election type：VRF，Managed
	CommitteeIdStrings   []string            `yaml:"committee" json:"committee"`       // Array of nodeid strings for the initial committee
	CommitteeIds         []common.NodeID     `yaml:"-" json:"-"`                       // Array of NodeID for the initial committee
	Admins               []string            `yaml:"admins" json:"-"`                  // string array of account address of chain administrators
	AdminAddrs           []common.Address    `yaml:"-" json:"-"`                       // Address array of chain administrators
	SecondCoinId         uint32              `yaml:"coinId" json:"coinId"`             // local currency id
	SecondCoinName       string              `yaml:"coinName" json:"coinName"`         // local currency name
	Attributes           []string            `yaml:"attributes"`                       // attribute strings of the chain
}

func (c *ChainConf) Validate() error {
	if c == nil {
		return nil
	}
	if c.ElectType.IsVrf() == false {
		return errors.New("only VRF(1) ElectType supported")
	}
	commIds, err := common.StringsToNodeIDs(c.CommitteeIdStrings)
	if err != nil {
		return common.NewDvppError("parse committee nodeids error: ", err)
	}
	c.CommitteeIds = commIds

	gdataIds, err := common.StringsToNodeIDs(c.GenesisDataservers)
	if err != nil {
		return common.NewDvppError("parse genesis data nodeids error: ", err)
	}
	c.GenesisDataserverIds = gdataIds

	dataIds, err := common.StringsToNodeIDs(c.Dataservers)
	if err != nil {
		return common.NewDvppError("parse data nodeids error: ", err)
	}
	c.DataserverIds = make([]common.NodeID, 0)
	c.DataserverIds = append(c.DataserverIds, c.GenesisDataserverIds...)
	c.DataserverIds = append(c.DataserverIds, dataIds...)

	c.AdminAddrs = common.StringsToAddresses(c.Admins)
	return nil
}

func (c *ChainConf) String() string {
	return fmt.Sprintf("{ID:%d ParentID:%d GDatas:%s Datas:%s ElectType:%s Comm:%s Admins:%x}",
		c.ID, c.ParentID, c.GenesisDataserverIds, c.DataserverIds, c.ElectType, c.CommitteeIds, c.AdminAddrs)
}

type ChainConfs []*ChainConf

func (cc ChainConfs) Validate() error {
	if cc == nil {
		return nil
	}
	for i := 0; i < len(cc); i++ {
		if err := cc[i].Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (cc ChainConfs) GetInitCommittee(chainid common.ChainID) []common.NodeID {
	for i := 0; i < len(cc); i++ {
		if cc[i] != nil && cc[i].ID == chainid {
			return cc[i].CommitteeIds
		}
	}
	return nil
}

func (cc ChainConfs) GetGenesisDataNodeIds(chainid common.ChainID) []common.NodeID {
	for i := 0; i < len(cc); i++ {
		if cc[i] != nil && cc[i].ID == chainid {
			return cc[i].GenesisDataserverIds
		}
	}
	return nil
}

func (cc ChainConfs) GetChainElectType(chainid common.ChainID) (common.ElectionType, error) {
	for i := 0; i < len(cc); i++ {
		if cc[i] != nil && cc[i].ID == chainid {
			return cc[i].ElectType, nil
		}
	}
	return common.ETNone, common.ErrNil
}

func (cc ChainConfs) Len() int {
	return len(cc)
}

func (cc ChainConfs) Swap(i, j int) {
	cc[i], cc[j] = cc[j], cc[i]
}

func (cc ChainConfs) Less(i, j int) bool {
	return cc[i].ID < cc[j].ID
}
