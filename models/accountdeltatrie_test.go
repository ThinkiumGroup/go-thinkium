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
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/stephenfire/go-rtl"
)

func makeShardInfo(deltaCurrentChainID common.ChainID) common.ShardInfo {
	chainstruct := common.ChainStruct{
		ID:       common.ChainID(1),
		ParentID: common.ChainID(0),
		Mode:     common.Branch,
	}
	return common.NewShardInfo(chainstruct, deltaCurrentChainID, []common.ChainID{106, 107, 108, 103, 104, 105, 101, 102})
}

var (
	addressGeneBuf                     = make([]byte, 8)
	deltaaddrNumber     uint64         = 256
	deltachainids                      = []common.ChainID{101, 102, 103, 104, 105, 106, 107, 108}
	deltacurrentchainid common.ChainID = 103
)

func toAddress(i uint64) (addr common.Address) {
	binary.LittleEndian.PutUint64(addressGeneBuf, i)
	copy(addr[:], addressGeneBuf)
	return
}

func makeAddresses(length uint64) []common.Address {
	addrs := make([]common.Address, length)
	var i uint64 = 0
	for ; i < length; i++ {
		addrs[i] = toAddress(i)
	}
	return addrs
}

func initDeltaTrie(dtrie trie.ITrie, addrs []common.Address) {
	var delta *AccountDelta
	for i := 0; i < 4*len(addrs); i++ {
		j := i % len(addrs)
		deltav, ok := dtrie.Get(addrs[j][:])
		if !ok || deltav == nil {
			delta = &AccountDelta{
				Addr:  addrs[j],
				Delta: big.NewInt(0),
			}
		} else {
			delta, ok = deltav.(*AccountDelta)
			if !ok {
				panic("expecting a *AccountDelta")
			}
		}
		delta.Add(big.NewInt(int64(j)))
		dtrie.Put(addrs[j][:], delta)
	}
}

func newDeltaTrie(chainIdIndex int) *AccountDeltaTrie {
	dbase := db.NewMemDB()
	chainID := deltachainids[chainIdIndex%len(deltachainids)]
	shardInfo := makeShardInfo(chainID)
	dtrie := NewAccountDeltaTrie(shardInfo, dbase)
	addrs := makeAddresses(deltaaddrNumber)
	initDeltaTrie(dtrie, addrs)
	return dtrie
}

func TestIterateAll(t *testing.T) {
	dtrie := newDeltaTrie(2)
	it := dtrie.ValueIterator()
	var count uint64 = 0
	for it.Next() {
		k, v := it.Current()
		if k == nil || v == nil {
			t.Error("iterate on a nil element")
			return
		}
		d, ok := v.(*AccountDelta)
		if !ok {
			t.Error("iterate on a wrong element")
			return
		}
		i := binary.LittleEndian.Uint64(k[:8])
		if d.Delta.Uint64() != i*4 {
			t.Errorf("expecting %d but %d", i*4, d.Delta)
			return
		}
		count++
	}
	if count != deltaaddrNumber-(deltaaddrNumber/uint64(len(deltachainids))) {
		t.Errorf("expecting %d but %d accountdeltas", deltaaddrNumber, count)
		return
	}
	t.Log("iterate All success")
}

func TestIterateSub(t *testing.T) {
	dtrie := newDeltaTrie(2)
	shouldlength := deltaaddrNumber / uint64(len(deltachainids))
	for i := 0; i < len(deltachainids); i++ {
		sub, ok := dtrie.GetSub(deltachainids[i])
		if !ok {
			if deltachainids[i] == deltacurrentchainid {
				t.Logf("no sub trie for %s is ok", deltacurrentchainid)
				continue
			} else {
				t.Error("no sub trie found for " + deltachainids[i].String())
				return
			}
		}
		t.Logf("starting subtrie [%d] check", deltachainids[i])
		var count uint64 = 0
		it := sub.ValueIterator()
		for it.Next() {
			k, v := it.Current()
			if k == nil || v == nil {
				t.Error("iterate on a nil element")
				return
			}
			d, ok := v.(*AccountDelta)
			if !ok {
				t.Error("iterate on a wrong element")
				return
			}
			t.Logf("%x -> %v", k, v)
			j := binary.LittleEndian.Uint64(k[:8])
			var should uint64 = j * 4
			if d.Delta.Uint64() != should {
				t.Errorf("expecting %d but %d", should, d.Delta)
			}
			count++
		}

		if count != shouldlength {
			t.Errorf("expecting %d but %d accountdeltas @ %s", shouldlength, count, deltachainids[i])
			// return
		}
	}
	t.Log("iterate sub success")
}

func TestSerialization(t *testing.T) {
	dtrie := newDeltaTrie(2)

	rootHash, err := dtrie.HashValue()
	if err != nil {
		t.Error("hash error: ", err)
		return
	}

	if bytes.Compare(rootHash, common.NilHashSlice) == 0 || bytes.Compare(rootHash, common.EmptyHash[:]) == 0 {
		t.Error("hash value nil or empty")
		return
	}

	buf := new(bytes.Buffer)
	if err := rtl.Encode(dtrie, buf); err != nil {
		t.Error("encoding error: ", err)
		return
	}

	dbase := db.NewMemDB()
	shardInfo := makeShardInfo(deltachainids[2])
	ndtrie := NewAccountDeltaTrie(shardInfo, dbase)

	if err := rtl.Decode(buf, ndtrie); err != nil {
		t.Error("decoding error: ", err)
		return
	}

	nrootHash, err := ndtrie.HashValue()
	if err != nil {
		t.Error("new trie hash error: ", err)
		return
	}

	if bytes.Compare(rootHash, nrootHash) != 0 {
		t.Error("serialization/deserialization failed")
	} else {
		t.Logf("serialization/deserialization success, hash=%X", rootHash)
	}

	for i := 0; i < len(deltachainids); i++ {
		sub, ok := dtrie.GetSub(deltachainids[i])
		if !ok {
			if deltachainids[i] == deltacurrentchainid {
				t.Logf("no sub trie for %s is ok", deltacurrentchainid)
				continue
			}
			t.Error("sub trie for ", deltachainids[i], " not found")
			continue
		}
		nsub, ok := ndtrie.GetSub(deltachainids[i])
		if !ok {
			t.Error("new new trie for ", deltachainids[i], " not found")
			continue
		}
		hash1, err := sub.HashValue()
		if err != nil {
			t.Error("hash of subtrie ", deltachainids[i], " error: ", err)
			continue
		}
		hash2, err := nsub.HashValue()
		if err != nil {
			t.Error("hash of new subtrie ", deltachainids[i], " error: ", err)
			continue
		}
		if bytes.Compare(hash1, hash2) != 0 {
			t.Error("subtrie ", deltachainids[i], " serialization/deserialization error")
		} else {
			t.Logf("subtrie %s serialization/deserialization success %X", deltachainids[i], hash1)
		}
	}
}

func TestVerify(t *testing.T) {
	dtrie := newDeltaTrie(2)

	rootHash, err := dtrie.HashValue()
	if err != nil {
		t.Error("trie hash error: ", err)
		return
	}

	it := dtrie.ValueIterator()
	for it.Next() {
		k, v := it.Current()
		if k == nil || v == nil {
			t.Errorf("iterate on a nil element")
			continue
		}
		v, proof, ok := dtrie.GetProof(k)
		if !ok {
			t.Errorf("get proof for %X failed", k)
			continue
		}
		h := common.EncodeHash(v)
		if trie.VerifyProofChain(h, proof, rootHash) {
			t.Logf("proof of %X verified, from %X", k, h[:])
		} else {
			t.Errorf("proof of %X verify failed", k)
		}
	}
}
