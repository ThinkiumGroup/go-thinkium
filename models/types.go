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
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/sirupsen/logrus"
)

type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	// Engine() consensus.Engine   //

	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *BlockHeader
}

// When the data block is generated, after the transaction is executed, the callback function
// executed before the stateRoot is generated
// header: generating block header
// result: proposing data
type GenerateCallback func(header *BlockHeader, result *ProposeResult) error

// The callback function executed after the transaction is executed when the data block is verified
// block: verifying block
type VerifyCallback func(block *BlockEMessage) error

// When the data block is confirmed, the callback function executed after the transaction is executed.
// At this time the block has been confirmed by the committee and all nodes must execute
type CommitCallback func(block *BlockEMessage) error

// StateDB is an EVM database for full state querying.
type StateDB interface {
	// Whether there is a local currency, if so, the last one method will return the local currency
	// information. Otherwise, the latter one method return basic currency information
	HasLocalCurrency() bool
	GetChainLocalCurrencyInfo(chainID common.ChainID) (common.CoinID, string)
	// Get the list of administrator public keys of the current chain. If there is a valid value,
	// the second return value will return true, otherwise it will return false
	GetAdmins() ([][]byte, bool)
	ResetState(stateTrie *trie.Trie)

	CreateAccount(common.Address)

	HasToken(addr common.Address) bool

	NoBalance(addr common.Address) bool
	SubBalance(common.Address, *big.Int)
	AddBalance(common.Address, *big.Int)
	GetBalance(common.Address) *big.Int

	NoLocalCurrency(addr common.Address) bool
	SubLocalCurrency(common.Address, *big.Int)
	AddLocalCurrency(common.Address, *big.Int)
	GetLocalCurrency(common.Address) *big.Int

	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)

	GetCodeHash(common.Address) common.Hash
	GetCode(common.Address) []byte
	SetCode(common.Address, []byte)
	GetCodeByHash(codeHash common.Hash) []byte
	GetCodeSize(common.Address) int

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)

	GetLong(addr common.Address, key common.Hash) []byte
	GetConsistantLong(addr common.Address, key common.Hash) []byte
	SetLong(addr common.Address, key common.Hash, value []byte)

	GetLongAsObject(addr common.Address, key common.Hash, obj interface{}) error
	SetLongAsObject(addr common.Address, key common.Hash, obj interface{}) error

	Suicide(common.Address) bool
	HasSuicided(common.Address) bool

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for suicided accounts.
	Exist(common.Address) bool
	Empty(common.Address) bool

	ClearObjectCache()

	RevertToSnapshot(int)
	Snapshot() int

	AddLog(common.Hash, uint, *Log)
	AddPreimage(common.Hash, []byte)

	GetOrNewStateObject(addr common.Address) AccountState

	GetLogs(hash common.Hash) []*Log

	// Finalise(deleteEmptyObjects bool)

	Prepare(block *BlockEMessage, operations ...VerifyCallback) error
	// PreCommit(rootShouldBe []byte) ([]byte, error)
	Commit(block *BlockEMessage, verifies []VerifyCallback, commits []CommitCallback) error

	RestoreDeltasLocked()
	ListAllDeltaFroms() DeltaFroms
	PutAllDeltaFroms(deltaFroms DeltaFroms)
	SyncWaterlines(waterlines []ShardWaterline, logger logrus.FieldLogger)
	GetDeltaToBeSent() common.Height
	SetDeltaToBeSent(height common.Height)
	ProposeWaterlines() (Waterlines, error)

	GetOriginHash() ([]byte, error)
	DeltasSnapShot() []ShardWaterline
	SaveReceivedDelta(fromID common.ChainID, height common.Height, deltas []*AccountDelta) (
		overflow bool, waterline common.Height, overflowed []*DeltaFrom, missing bool,
		missingLength int, err error)
	SaveDeltasGroup(fromID common.ChainID, group DeltasGroup) (overflow bool,
		waterline common.Height, overflowed []*DeltaFrom, missing bool, missingLength int, err error)
	GetWaterLine(fromID common.ChainID) common.Height
	PopDeltaFroms() DeltaFroms
	ReadOnlyCall(tx *Transaction, senderSig *PubAndSig, blockHeader *BlockHeader) (interface{}, error)
	ReadOnly() StateDB
	Propose(froms DeltaFroms, deltaTrie *AccountDeltaTrie, txs []*Transaction, pas []*PubAndSig,
		header *BlockHeader, result *ProposeResult, operations ...GenerateCallback) (err error)
	ForceCommit() error
	GetOriginAccount(addr common.Address) (*Account, bool)
	CreateTestAccount(addr common.Address, balance *big.Int) error
	Rollback()
	GetSettingGasLimit(tx *Transaction) uint64
	GetSettingGasPrice(tx *Transaction) *big.Int
}

type AccountState interface {
	Address() common.Address
	GetAccount() *Account
}
type (
	cipher struct {
		priv, pub []byte
	}

	identity struct {
		cipher
		addr common.Address
	}

	nodeIdentity struct {
		cipher
		nodeid common.NodeID
	}
)

func (c cipher) Priv() []byte {
	return common.CopyBytes(c.priv)
}

func (c cipher) Pub() []byte {
	return common.CopyBytes(c.pub)
}

func (id *identity) Address() common.Address {
	return id.addr
}

func (id *identity) AddressP() *common.Address {
	a := id.addr
	return &a
}

func (id *identity) String() string {
	if id == nil {
		return "ID<nil>"
	}
	return fmt.Sprintf("ID{Addr:%s}", id.addr)
}

func (n *nodeIdentity) NodeID() common.NodeID {
	return n.nodeid
}

func (n *nodeIdentity) NodeIDP() *common.NodeID {
	a := n.nodeid
	return &a
}

func (n *nodeIdentity) String() string {
	if n == nil {
		return "NID<nil>"
	}
	return fmt.Sprintf("NID{NodeID:%s}", n.nodeid)
}

func NewIdentifier(priv []byte) (common.Identifier, error) {
	pub, err := common.PrivateToPublicSlice(priv)
	if err != nil {
		return nil, err
	}
	addr, err := common.AddressFromPubSlice(pub)
	if err != nil {
		return nil, err
	}
	return &identity{
		cipher: cipher{
			priv: priv,
			pub:  pub,
		},
		addr: addr,
	}, nil
}

func NewIdentifierByHex(privHexString string) (common.Identifier, error) {
	p, err := hex.DecodeString(privHexString)
	if err != nil {
		return nil, err
	}
	return NewIdentifier(p)
}

func NewNodeIdentifier(priv []byte) (common.NodeIdentifier, error) {
	pub, err := common.PrivateToPublicSlice(priv)
	if err != nil {
		return nil, err
	}
	nid, err := common.PubToNodeID(pub)
	if err != nil {
		return nil, err
	}
	return &nodeIdentity{
		cipher: cipher{
			priv: priv,
			pub:  pub,
		},
		nodeid: nid,
	}, nil
}

func NewNodeIdentifierByHex(privHexString string) (common.NodeIdentifier, error) {
	p, err := hex.DecodeString(privHexString)
	if err != nil {
		return nil, err
	}
	return NewNodeIdentifier(p)
}

func NewNodeIdentifierByHexWithoutError(privHexString string) common.NodeIdentifier {
	ni, _ := NewNodeIdentifierByHex(privHexString)
	return ni
}

type Accounts []*Account

func (a Accounts) Len() int {
	return len(a)
}

func (a Accounts) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a Accounts) Less(i, j int) bool {
	if a[i] == nil || a[j] == nil {
		if a[i] == a[j] {
			return false
		} else if a[i] == nil {
			return true
		} else {
			return false
		}
	}
	return bytes.Compare(a[i].Addr[:], a[j].Addr[:]) < 0
}

type EntryHashHash struct {
	K common.Hash
	V common.Hash
}

type StorageEntry struct {
	All int
	Num int
	K   common.Hash
	V   []EntryHashHash
}

func (e StorageEntry) Count() int {
	return len(e.V)
}

type StorageEntries []StorageEntry

func (es StorageEntries) String() string {
	if len(es) == 0 {
		return "0"
	}
	sum, max := 0, 0
	for _, entry := range es {
		c := entry.Count()
		if c > 0 {
			sum += c
			if c > max {
				max = c
			}
		}
	}
	return fmt.Sprintf("(Count:%d Sum:%d Max:%d)", len(es), sum, max)
}

type CodeEntry struct {
	K common.Hash
	V []byte
}

type LongEntry struct {
	K common.Hash
	V []*LongValue
}
