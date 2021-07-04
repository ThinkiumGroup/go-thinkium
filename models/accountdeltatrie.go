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
	"io"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

type AccountDeltaTrie struct {
	trie.SmallCombinedTrie
	shardInfo common.ShardInfo
	dbase     db.Database

	nodeAdapter  db.DataAdapter
	valueAdapter db.DataAdapter
	valueCodec   *rtl.StructCodec
}

func NewAccountDeltaTrie(shardInfo common.ShardInfo, dbase db.Database) *AccountDeltaTrie {
	combined := trie.NewCombinedTrie(db.NewKeyPrefixedDataAdapter(dbase, db.KPDeltaTrie))
	valueCodec, err := rtl.NewStructCodec(TypeOfAccountDeltaPtr)
	if err != nil {
		panic("create account delta trie code error: " + err.Error())
	}
	return &AccountDeltaTrie{
		SmallCombinedTrie: *combined,
		shardInfo:         shardInfo,
		dbase:             dbase,
		nodeAdapter:       db.NewKeyPrefixedDataAdapter(dbase, db.KPDeltaNodeNode),
		valueAdapter:      db.NewKeyPrefixedDataAdapter(dbase, db.KPDeltaNodeValue),
		valueCodec:        valueCodec,
	}
}

func (t *AccountDeltaTrie) Reset() {
	if t.shardInfo == nil {
		return
	}
	shardIds := t.shardInfo.AllIDs()
	for i := 0; i < len(shardIds); i++ {
		if shardIds[i] == t.shardInfo.LocalID() {
			continue
		}
		sub := t.createSubTrie()
		t.SmallCombinedTrie.Put(shardIds[i].Formalize(), sub)
	}
}

func (t *AccountDeltaTrie) createSubTrie() *trie.Trie {
	return trie.NewTrieWithValueCodec(nil, t.nodeAdapter, t.valueAdapter, t.valueCodec.Encode, t.valueCodec.Decode)
}

func (t *AccountDeltaTrie) getChainID(addrKey []byte) (common.ChainID, bool) {
	if addrKey == nil {
		log.Error("address key is nil")
		return common.NilChainID, false
	}
	addr := common.BytesToAddress(addrKey)
	chainid := t.shardInfo.ShardTo(addr)
	if chainid == t.shardInfo.LocalID() {
		return common.NilChainID, false
	}
	return chainid, true
}

func (t *AccountDeltaTrie) getChainKey(addrKey []byte) ([]byte, bool) {
	chainid, ok := t.getChainID(addrKey)
	if !ok {
		return nil, false
	}
	key := chainid.Formalize()
	return key, true
}

func (t *AccountDeltaTrie) getSubTrieByChainKeyLocked(chainKey []byte, create bool) (trie.ITrie, bool) {
	subv, ok := t.SmallCombinedTrie.Get(chainKey)
	var sub trie.ITrie
	if !ok || subv == nil {
		if create {
			sub = t.createSubTrie()
			t.SmallCombinedTrie.Put(chainKey, sub)
		} else {
			return nil, false
		}
	} else {
		sub, ok = subv.(trie.ITrie)
		if !ok {
			panic("expecting a trie.ITrie")
		}
	}
	return sub, true
}

func (t *AccountDeltaTrie) getSubTrieLocked(addrKey []byte) (trie.ITrie, bool) {
	chainKey, ok := t.getChainKey(addrKey)
	if !ok {
		return nil, false
	}

	return t.getSubTrieByChainKeyLocked(chainKey, true)
}

func (t *AccountDeltaTrie) GetSub(id common.ChainID) (trie.ITrie, bool) {
	chainKey := id.Formalize()
	return t.getSubTrieByChainKeyLocked(chainKey, false)
}

func (t *AccountDeltaTrie) HashValue() (HashValue []byte, err error) {
	return t.SmallCombinedTrie.HashValue()
}

func (t *AccountDeltaTrie) Get(key []byte) (value interface{}, ok bool) {
	if subtrie, ok := t.getSubTrieLocked(key); ok {
		return subtrie.Get(key)
	}
	return nil, false
}

// Put key is Address
func (t *AccountDeltaTrie) Put(key []byte, value interface{}) bool {
	if subtrie, ok := t.getSubTrieLocked(key); ok {
		return subtrie.Put(key, value)
	}
	return false
}

func (t *AccountDeltaTrie) PutValue(value trie.TrieValue) bool {
	key := value.Key()
	if subtrie, ok := t.getSubTrieLocked(key); ok {
		return subtrie.PutValue(value)
	}
	return false
}

func (t *AccountDeltaTrie) Delete(key []byte) (changed bool, oldValue interface{}) {
	if subtrie, ok := t.getSubTrieLocked(key); ok {
		return subtrie.Delete(key)
	}
	return false, nil
}

// func (t *AccountDeltaTrie) GetProof(addrKey []byte) (interface{}, common.ProofHash, bool) {
func (t *AccountDeltaTrie) GetProof(addrKey []byte) (interface{}, trie.ProofChain, bool) {
	chainid, ok := t.getChainID(addrKey)
	if !ok {
		return nil, nil, false
	}
	subTrie, ok := t.GetSub(chainid)
	if !ok || subTrie == nil {
		return nil, nil, false
	}
	value, proof, ok := subTrie.GetProof(addrKey)
	if !ok {
		return nil, nil, false
	}
	_, subproof, ok := t.GetSubProof(chainid)
	if !ok || len(subproof) < 1 {
		return nil, nil, false
	}
	fullProof := make(trie.ProofChain, len(proof)+len(subproof))
	copy(fullProof, proof)
	copy(fullProof[len(proof):], subproof)
	return value, fullProof, true
	//
	// if chainKey, ok := t.getChainKey(key); ok {
	// 	fullKey := make([]byte, len(chainKey)+len(key))
	// 	copy(fullKey, chainKey)
	// 	copy(fullKey[len(chainKey):], key)
	//
	// 	return t.SmallCombinedTrie.GetProof(fullKey)
	// }
	// return nil, nil, false
}

func (t *AccountDeltaTrie) GetExistenceProof(key []byte) (exist bool, proofs trie.ProofChain, err error) {
	return false, nil, common.ErrUnsupported
}

func (t *AccountDeltaTrie) ValueIterator() trie.ValueIterator {
	return &deltaTrieIterator{
		trieIterator: t.SmallCombinedTrie.ValueIterator(),
	}
}

func (t *AccountDeltaTrie) GetSubProof(id common.ChainID) (value trie.ITrie, proof trie.ProofChain, ok bool) {
	chainKey := id.Formalize()
	v, proof, ok := t.SmallCombinedTrie.GetProof(chainKey)
	if !ok {
		return nil, nil, false
	}
	if v == nil {
		return
	}
	value, ok = v.(trie.ITrie)
	if !ok {
		return nil, nil, false
	}
	return
}

func (t *AccountDeltaTrie) Serialization(w io.Writer) error {
	it := t.ValueIterator()
	for it.Next() {
		_, v := it.Current()
		if v == nil {
			continue
		}
		delta, ok := v.(*AccountDelta)
		if !ok {
			panic("expecting a *AccountDelta")
		}
		if err := rtl.Encode(delta, w); err != nil {
			return err
		}
	}
	return nil
}

func (t *AccountDeltaTrie) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	reader, ok := r.(rtl.ValueReader)
	if !ok {
		reader = rtl.NewValueReader(r, 0)
	}

	for reader.HasMore() {
		newDelta := new(AccountDelta)
		if err = rtl.Decode(reader, newDelta); err != nil {
			if err == io.EOF {
				return false, nil
			}
			return
		}
		t.Put(newDelta.Addr[:], newDelta)
	}
	return false, nil
}

type deltaTrieIterator struct {
	trieIterator  trie.ValueIterator
	valueIterator trie.ValueIterator
	lock          sync.Mutex
}

func (it *deltaTrieIterator) Next() bool {
	it.lock.Lock()
	defer it.lock.Unlock()

	for {
		if it.valueIterator == nil {
			if it.trieIterator == nil {
				return false
			}
			if it.trieIterator.Next() {
				_, tv := it.trieIterator.Current()
				if tv == nil {
					return false
				}
				t, ok := tv.(trie.ITrie)
				if !ok {
					panic("expecting a trie.ITrie")
				}
				it.valueIterator = t.ValueIterator()
			} else {
				return false
			}
		}

		ok := it.valueIterator.Next()
		if ok {
			return true
		}
		it.valueIterator = nil
	}
}

func (it *deltaTrieIterator) Current() (key []byte, value interface{}) {
	it.lock.Lock()
	defer it.lock.Unlock()
	if it.valueIterator == nil {
		return nil, nil
	}
	return it.valueIterator.Current()
}
