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
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

var (
	TypeOfAccountPtr      = reflect.TypeOf((*Account)(nil))
	TypeOfAccountDeltaPtr = reflect.TypeOf((*AccountDelta)(nil))
)

var (
	// build-in accounts
	// MainAccountAddr private key: 684b01785f1deae43c5cac91d75305bff4665a1b9ae7efea020aeb4ae50c77cc
	MainAccountAddr              = common.HexToAddress("3461c3beb33b646d1174551209377960cbce5259")
	AddressOfChainInfoManage     = common.BytesToAddress([]byte{1, 0, 0})
	AddressOfManageChains        = common.BytesToAddress([]byte{1, 1, 0})
	AddressOfChainSettings       = common.BytesToAddress([]byte{1, 0, 1})
	AddressOfNewChainSettings    = common.BytesToAddress([]byte{1, 1, 1})
	AddressOfRequiredReserve     = common.BytesToAddress([]byte{1, 0, 2})
	AddressOfPenalty             = common.BytesToAddress([]byte{1, 0, 3})
	AddressOfManageCommittee     = common.BytesToAddress([]byte{1, 0, 4})
	AddressOfWriteCashCheck      = common.BytesToAddress([]byte{2, 0, 0})
	AddressOfCashCashCheck       = common.BytesToAddress([]byte{3, 0, 0})
	AddressOfCancelCashCheck     = common.BytesToAddress([]byte{4, 0, 0})
	AddressOfCurrencyExchanger   = common.BytesToAddress([]byte{5, 0, 0})
	AddressOfLocalCurrencyMinter = common.BytesToAddress([]byte{5, 0, 1})
	AddressOfTryPocFrom          = common.BytesToAddress([]byte{6, 0, 0})
	AddressOfRewardFrom          = common.HexToAddress("1111111111111111111111111111111111111111") // reward account
	AddressOfBlackHole           = common.HexToAddress("2222222222222222222222222222222222222222") // melt down currency
	// AddressOfRewardForGenesis private key: 01972b6aaa9f577ea0d6e32b63c3d138ff53db953e223ecd03d84cdc9c26e877
	AddressOfRewardForGenesis = common.HexToAddress("0xbb72feb361a0a383777fac3d6ac230d7d7586694") // binding account of genesis nodes
	// AddressOfGasReward private key: ab66fab847b6d15356d2257281fefb1920ca6f56a7bc44d699b5e82e9c133a94
	AddressOfGasReward = common.HexToAddress("0xd82a6555eaaaa022e89be40cffe4b7506112c04e") // gas fee account
)

// 1. currency type can be determinded in a normal transfer, default is basic currency
// 2. in contract calling, value type can be determinded. solidity contract can only use local currency if
// it has a local currency in the chain.
type Account struct {
	Addr            common.Address `json:"address"`         // account address
	Nonce           uint64         `json:"nonce"`           // next transaction nonce
	Balance         *big.Int       `json:"balance"`         // basic currency, never be nil
	LocalCurrency   *big.Int       `json:"localCurrency"`   // local currency (if exist), could be nil
	StorageRoot     []byte         `json:"storageRoot"`     // storage for contract，Trie(key: Hash, value: Hash)
	CodeHash        []byte         `json:"codeHash"`        // hash of contract code
	LongStorageRoot []byte         `json:"longStorageRoot"` // more complex storage for contract, Trie(key: Hash, value: []byte)
}

type CompatibleAccount struct {
	Addr        common.Address
	Nonce       uint64
	Balance     *big.Int
	StorageRoot []byte
	CodeHash    []byte
}

func NewAccount(addr common.Address, balance *big.Int) *Account {
	if balance == nil {
		balance = big.NewInt(0)
	} else {
		balance = big.NewInt(0).Set(balance)
	}
	return &Account{
		Addr:    addr,
		Nonce:   0,
		Balance: balance,
	}
}

// for compatible with old version, if there's no local currency and LongStorage, hash should same
// with the hash of old version account.
// TODO delete compatible when restart the chain with new version
func (a *Account) HashValue() ([]byte, error) {
	if a == nil {
		return common.EncodeAndHash(a)
	}
	if a.LocalCurrency == nil &&
		(len(a.LongStorageRoot) == 0 || bytes.Equal(a.LongStorageRoot, trie.EmptyNodeHashSlice)) {
		return common.EncodeAndHash(&CompatibleAccount{
			Addr:        a.Addr,
			Nonce:       a.Nonce,
			Balance:     a.Balance,
			StorageRoot: a.StorageRoot,
			CodeHash:    a.CodeHash,
		})
	} else {
		return common.EncodeAndHash(a)
	}
}

func (a *Account) Clone() *Account {
	ret := &Account{
		Addr:            a.Addr.Clone(),
		Nonce:           a.Nonce,
		Balance:         new(big.Int).Set(a.Balance),
		StorageRoot:     common.CloneByteSlice(a.StorageRoot),
		CodeHash:        common.CloneByteSlice(a.CodeHash),
		LongStorageRoot: common.CloneByteSlice(a.LongStorageRoot),
	}
	if a.LocalCurrency != nil {
		ret.LocalCurrency = new(big.Int).Set(a.LocalCurrency)
	}
	return ret
}

func (a *Account) String() string {
	return fmt.Sprintf("Acc{Addr:%s Nonce:%d Balance:%s (%s) Local:%s Storage:%x CodeHash:%x LongStorage:%x}",
		a.Addr, a.Nonce, a.Balance, math.BigIntForPrint(a.Balance), a.LocalCurrency,
		common.ForPrint(a.StorageRoot),
		common.ForPrint(a.CodeHash),
		common.ForPrint(a.LongStorageRoot))
}

func (a *Account) Address() common.Address {
	return a.Addr
}

func (a *Account) AddLocalCurrency(amount *big.Int) error {
	if amount == nil || amount.Sign() == 0 {
		return nil
	}
	if amount.Sign() > 0 {
		if a.LocalCurrency == nil {
			a.LocalCurrency = big.NewInt(0).Set(amount)
		} else {
			a.LocalCurrency.Set(big.NewInt(0).Add(a.LocalCurrency, amount))
		}
	} else {
		if a.LocalCurrency == nil || a.LocalCurrency.Sign() == 0 {
			return common.ErrInsufficientBalance
		}
		b := big.NewInt(0).Add(a.LocalCurrency, amount)
		if b.Sign() < 0 {
			return common.ErrInsufficientBalance
		} else if b.Sign() == 0 {
			a.LocalCurrency = nil
		} else {
			a.LocalCurrency.Set(b)
		}
	}
	return nil
}

func (a *Account) IsUserContract() bool {
	if a == nil {
		return false
	}
	if len(a.CodeHash) != common.HashLength ||
		bytes.Equal(a.CodeHash, common.NilHashSlice) ||
		bytes.Equal(a.CodeHash, common.EmptyHash[:]) {
		return false
	}
	return true
}

type AccountDelta struct {
	Addr          common.Address
	Delta         *big.Int // Balance modification
	CurrencyDelta *big.Int // LocalCurrency modification (if has)
}

// for compatible with old version hash of AccountDelta
// TODO delete compatible when restart the chain with new version
type CompatibleDelta struct {
	Addr  common.Address
	Delta *big.Int
}

func NewAccountDelta(addr common.Address, delta *big.Int, currencyDelta *big.Int) *AccountDelta {
	if (delta == nil && currencyDelta == nil) ||
		(delta != nil && delta.Sign() <= 0) ||
		(currencyDelta != nil && currencyDelta.Sign() <= 0) {
		return nil
	}
	ret := &AccountDelta{Addr: addr}
	if delta != nil {
		ret.Delta = new(big.Int).Set(delta)
	}
	if currencyDelta != nil {
		ret.CurrencyDelta = new(big.Int).Set(currencyDelta)
	}
	return ret
}

func (d *AccountDelta) Address() common.Address {
	return d.Addr
}

func (d *AccountDelta) Add(delta *big.Int) {
	if delta == nil {
		return
	}
	if d.Delta == nil {
		d.Delta = new(big.Int).Set(delta)
	} else {
		d.Delta.Add(d.Delta, delta)
	}
}

func (d *AccountDelta) AddCurrency(delta *big.Int) {
	if delta == nil {
		return
	}
	if d.CurrencyDelta == nil {
		d.CurrencyDelta = new(big.Int).Set(delta)
	} else {
		d.CurrencyDelta.Add(d.CurrencyDelta, delta)
	}
}

func (d *AccountDelta) String() string {
	return fmt.Sprintf("Delta{%x, %v, %v}", d.Addr[:], d.Delta, d.CurrencyDelta)
}

// TODO delete compatible when restart the chain with new version
func (d *AccountDelta) HashValue() ([]byte, error) {
	if d == nil {
		return common.EncodeAndHash(d)
	}
	if d.CurrencyDelta == nil {
		stream, err := rtl.Marshal(&CompatibleDelta{Addr: d.Addr, Delta: d.Delta})
		if err != nil {
			return nil, err
		}
		return common.Hash256s(stream)
	} else {
		return common.EncodeAndHash(d)
	}
}

type DeltaFromKey struct {
	ShardID common.ChainID
	Height  common.Height
}

func (d DeltaFromKey) Bytes() []byte {
	shardbytes := d.ShardID.Bytes()
	heightbytes := d.Height.Bytes()
	bytes := make([]byte, common.ChainBytesLength+common.HeightBytesLength)
	copy(bytes, shardbytes)
	copy(bytes[common.ChainBytesLength:], heightbytes)
	return bytes
}

func (d DeltaFromKey) Cmp(to DeltaFromKey) int {
	if d.ShardID == to.ShardID {
		if d.Height == to.Height {
			return 0
		} else if d.Height < to.Height {
			return -1
		} else {
			return 1
		}
	} else if d.ShardID < to.ShardID {
		return -1
	} else {
		return 1
	}
}

func (d DeltaFromKey) String() string {
	return fmt.Sprintf("{ShardID:%d, Height:%d}", d.ShardID, d.Height)
}

func BytesToDeltaFromKey(bytes []byte) DeltaFromKey {
	var buf []byte
	l, should := len(bytes), common.ChainBytesLength+common.HeightBytesLength
	if l == should {
		buf = bytes
	} else if l < should {
		buf = make([]byte, should)
		copy(buf[should-l:], bytes)
	} else {
		buf = bytes[l-should:]
	}
	shardid := common.BytesToChainID(buf[:common.ChainBytesLength])
	height := common.BytesToHeight(buf[common.ChainBytesLength:])
	return DeltaFromKey{
		ShardID: shardid,
		Height:  height,
	}
}

// used by printing summary of DeltaFroms
type dfsummary struct {
	from  common.Height
	to    common.Height
	count int
}

func (d *dfsummary) add(height common.Height, count int) {
	if height < d.from {
		d.from = height
	}
	if height > d.to {
		d.to = height
	}
	d.count += count
}

func (d *dfsummary) String() string {
	if d == nil {
		return "<nil>"
	}
	return fmt.Sprintf("[%d,%d](c:%d)", d.from, d.to, d.count)
}

func toSummaryString(prefix string, size int, getter func(i int) (id common.ChainID, height common.Height, count int, exist bool)) string {
	if size <= 0 {
		return fmt.Sprintf("%s<>", prefix)
	}
	m := make(map[common.ChainID]*dfsummary)
	var ks common.ChainIDs
	for i := 0; i < size; i++ {
		id, height, count, exist := getter(i)
		if !exist {
			continue
		}
		s, _ := m[id]
		if s == nil {
			s = &dfsummary{from: common.NilHeight, to: 0, count: 0}
			m[id] = s
			ks = append(ks, id)
		}
		s.add(height, count)
	}
	if len(ks) == 1 {
		return fmt.Sprintf("%s%s", prefix, m)
	}
	sort.Sort(ks)
	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(buf)
	buf.Reset()
	buf.WriteString(prefix)
	buf.WriteByte('{')
	for i, k := range ks {
		s, _ := m[k]
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(fmt.Sprintf("{From:%d %s}", k, s))
	}
	buf.WriteByte('}')
	return buf.String()
}

type DeltaFrom struct {
	Key    DeltaFromKey
	Deltas []*AccountDelta
}

func (d DeltaFrom) String() string {
	return fmt.Sprintf("{FROM:%d H:%d Dlts:%d}", d.Key.ShardID, d.Key.Height, len(d.Deltas))
}

type DeltaFroms []DeltaFrom

func (f DeltaFroms) Summary() string {
	return toSummaryString("DeltaFroms", len(f), func(i int) (id common.ChainID, height common.Height, count int, exist bool) {
		return f[i].Key.ShardID, f[i].Key.Height, len(f[i].Deltas), true
	})
}

func (f DeltaFroms) Len() int {
	return len(f)
}

func (f DeltaFroms) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

func (f DeltaFroms) Less(i, j int) bool {
	return f[i].Key.Cmp(f[j].Key) < 0
}
