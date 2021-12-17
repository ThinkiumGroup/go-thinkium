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
	"errors"
	"fmt"
	"reflect"

	"github.com/ThinkiumGroup/go-common"
)

var (
	ErrDuplicatedDeltaFrom = errors.New("duplicated deltas")
)

const (
	PocDeadlineAddrName            = "pocdeadline"
	PocTryNewBlockContractAddrName = "poctrynewblockcontract"
	PocTryNewBlockMethodName       = "poctrynewblockmethod"
	PocDeadlinePrefixName          = "pocdeadlineprefix"
	PocDeadlineAbiJson             = "pocdeadlineabijson"
	PocBindAddrName                = "pocbind"
	PocBindPrefixName              = "pocbindprefix"
	PocBindAbiJson                 = "pocbindabijson"

	// // PosCommNodeRewardName = "poscommnodereward"
	// PosCommNodeRewardName = "poscommnodereward1w.202012"
	PosCommNodeRewardName = "poscommnodereward1k.202107"
	PosDataNodeRewardName = "posdatanodereward5w.202012"
	GasLimitName          = "gaslimit"
	GasPriceName          = "gasprice"
	RRStatusAuth          = "rrstatusauth"

	ManagedCommNodeIdsName = "managedcommnodeids"
)

func init() {
	common.RegisterSystemContract(false,
		AddressOfRequiredReserve,
		AddressOfWriteCashCheck,
		AddressOfCurrencyExchanger,
		AddressOfLocalCurrencyMinter,
	)

	common.RegisterSystemContract(true,
		AddressOfCashCashCheck,
		AddressOfCancelCashCheck,
		AddressOfChainInfoManage,
		AddressOfManageChains,
		AddressOfChainSettings,
		AddressOfNewChainSettings,
		AddressOfManageCommittee,
		AddressOfBlackHole,
	)

	common.RegisterNoCheckAddress(
		AddressOfRewardFrom,
		AddressOfTryPocFrom,
		AddressOfPenalty,
		// AddressOfGasReward,
		// AddressOfRewardForGenesis,
	)
}

// Global chain currency query
type GlobalCurrencier interface {
	// Query the chain currency by chain ID, and return (local currency ID, local currency name),
	// when the local currency ID==0, it is the basic currency, when there is no local currency,
	// CoinID returns 0
	GetChainLocalCurrencyInfo(chainID common.ChainID) (common.CoinID, string)
	// Get the list of administrator public keys of the specific chain. If there is a valid value,
	// the second return value will return true, otherwise it will return false
	GetChainAdmins(chainID common.ChainID) ([][]byte, bool)
	// Whether the specific chain is a PoC (Proof of Capacity) chain
	IsPocChain(chainID common.ChainID) bool
}

type GlobalCurrencierAdapter struct {
	dmanager DataManager
}

func NewGlobalCurrencierAdapter(dmanager DataManager) GlobalCurrencier {
	adapter := &GlobalCurrencierAdapter{dmanager: dmanager}
	return adapter
}

func (g *GlobalCurrencierAdapter) GetChainLocalCurrencyInfo(chainID common.ChainID) (coinId common.CoinID, coinName string) {
	info, ok := g.dmanager.GetChainInfos(chainID)
	if ok && !info.SecondCoinId.IsSovereign() {
		return info.SecondCoinId, info.SecondCoinName
	}
	return 0, "TKM"
}

func (g *GlobalCurrencierAdapter) GetChainAdmins(chainID common.ChainID) ([][]byte, bool) {
	var admins [][]byte
	info, ok := g.dmanager.GetChainInfos(chainID)
	if ok {
		admins = info.AdminPubs
		if len(admins) > 0 {
			return admins, true
		}
	}
	if chainID != common.MainChainID {
		return g.GetChainAdmins(common.MainChainID)
	}
	return nil, false
}

func (g *GlobalCurrencierAdapter) IsPocChain(chainID common.ChainID) bool {
	info, ok := g.dmanager.GetChainInfos(chainID)
	if !ok {
		return false
	}
	return info.IsPocChain()
}

// Used to determine whether there is a local currency in the current chain, and if so, what
// is the type of the local currency
type ChainCurrencier interface {
	GlobalCurrencier
	// Whether there is a local currency, if so, the last one method will return the local currency
	// information. Otherwise, the latter one method return basic currency information
	HasLocalCurrency() bool
	// Return (local currency ID, local currency name), when the local currency ID==0, it is the
	// basic currency
	GetLocalCurrency() (common.CoinID, string)
	// Get the list of administrator public keys of the current chain. If there is a valid value,
	// the second return value will return true, otherwise it will return false
	GetAdmins() ([][]byte, bool)
	// Whether the current chain is a PoC (Proof of Capacity) chain
	IsPoc() bool
}

type ChainCurrencierAdapter struct {
	GlobalCurrencier
	CID common.ChainID
}

func NewChainCurrencier(global GlobalCurrencier, chainid common.ChainID) ChainCurrencierAdapter {
	return ChainCurrencierAdapter{
		GlobalCurrencier: global,
		CID:              chainid,
	}
}

func (a ChainCurrencierAdapter) HasLocalCurrency() bool {
	id, _ := a.GetLocalCurrency()
	return id > 0
}

func (a ChainCurrencierAdapter) GetLocalCurrency() (common.CoinID, string) {
	return a.GlobalCurrencier.GetChainLocalCurrencyInfo(a.CID)
}

func (a ChainCurrencierAdapter) GetAdmins() ([][]byte, bool) {
	return a.GlobalCurrencier.GetChainAdmins(a.CID)
}

func (a ChainCurrencierAdapter) IsPoc() bool {
	return a.GlobalCurrencier.IsPocChain(a.CID)
}

type LongValue struct {
	KeyHash common.Hash // long storage key
	Value   []byte      // long value，could be any type of data serialization, resolved by the upper business layer
}

var TypeOfLongStoragePtr = reflect.TypeOf((*LongValue)(nil))

func (v *LongValue) Key() []byte {
	return v.KeyHash[:]
}

func (v *LongValue) HashValue() ([]byte, error) {
	// In this way, the longvalue under the same key will be covered to save space
	return v.KeyHash[:], nil
}

func (v *LongValue) String() string {
	if v == nil {
		return "<nil>"
	}
	if len(v.Value) > 32 {
		return fmt.Sprintf("Long{KeyHash:%x Len(Value):%d}", v.KeyHash[:], len(v.Value))
	} else {
		return fmt.Sprintf("Long{KeyHash:%x Value:%x}", v.KeyHash[:], v.Value)
	}
}

// The Key in LongStorage is composed of account address and additional value (generally attribute
// name), used for system contracts usually
func SCLongStorageKey(addr common.Address, name []byte) common.Hash {
	if len(name) == 0 {
		return common.Hash256(addr[:])
	}
	var source []byte
	source = append(source, addr[:]...)
	source = append(source, name...)
	return common.Hash256(source)
}

func SCLongStorageKey2(addr common.Address, name string) common.Hash {
	return SCLongStorageKey(addr, []byte(name))
}
