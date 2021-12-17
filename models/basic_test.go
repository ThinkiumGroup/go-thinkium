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
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/stephenfire/go-rtl"
)

func TestBlockHeaderMarshal(t *testing.T) {
	header := &BlockHeader{
		PreviousHash:     common.BytesToHash([]byte{0}),
		ChainID:          1,
		Height:           10,
		Empty:            false,
		ParentHeight:     9,
		ParentHash:       common.BytesToHashP([]byte{1}),
		RewardAddress:    common.BytesToAddress([]byte{2}),
		CommitteeHash:    common.BytesToHashP([]byte{3}),
		ElectedNextRoot:  nil,
		NewCommitteeSeed: nil,
		MergedDeltaRoot:  nil,
		BalanceDeltaRoot: nil,
		StateRoot:        common.BytesToHash(common.NilHashSlice),
		ChainInfoRoot:    nil,
		VCCRoot:          common.BytesToHashP(trie.EmptyNodeHashSlice),
		CashedRoot:       common.BytesToHashP(trie.EmptyNodeHashSlice),
		TransactionRoot:  nil,
		ReceiptRoot:      nil,
		TimeStamp:        1,
	}

	fmt.Printf("%v\n", header)

	bs, _ := rtl.Marshal(header)
	h2 := &BlockHeader{}
	if err := rtl.Unmarshal(bs, h2); err != nil {
		t.Errorf("unmarshal error: %v", err)
		return
	}

	if reflect.DeepEqual(header, h2) {
		t.Logf("check")
	} else {
		t.Errorf("failed")
		fmt.Printf("%v\n", h2)
	}
}

func TestTransactionString(t *testing.T) {
	tx := &Transaction{
		ChainID:  1,
		From:     common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
		To:       common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
		Nonce:    43,
		UseLocal: true,
		Val:      big.NewInt(23232323),
		Input:    nil,
		Extra:    nil,
		Version:  TxVersion,
	}

	s := TransactionStringForHash(tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, tx.Val, tx.Input, tx.Extra)
	h := tx.Hash()
	hh := common.Hash256([]byte(s))
	t.Logf("%s -> string:%s (%x) -> Hash:%x", tx, s, hh[:], h[:])
}

func TestEthTx(t *testing.T) {
	{
		tx := &Transaction{
			ChainID:  1,
			From:     common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			To:       common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			Nonce:    43,
			UseLocal: false,
			Val:      big.NewInt(23232323),
			Input:    nil,
			Extra:    []byte("{\"gas\":3000000}"),
			Version:  TxVersion,
		}
		h := tx.Hash()
		// buf := new(bytes.Buffer)
		// err := rlp.Encode(buf, tx)
		// if err != nil {
		// 	t.Fatalf("rlp encode failed: %v", err)
		// } else {
		// 	t.Logf("%s encoded %x", tx, buf.Bytes())
		// }
		t.Logf("%s Hash: %x", tx, h[:])
	}

	{
		// check different tx hash
		tx1 := &Transaction{
			ChainID: 1,
			// From:     common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			To:       common.BytesToAddressP(common.RandomBytes(common.AddressLength)),
			Nonce:    43,
			UseLocal: false,
			Val:      big.NewInt(23232323),
			Input:    nil,
			Version:  TxVersion,
		}
		tx2 := tx1.Clone()
		{
			mp := map[string]uint64{
				consts.JsonKeyChain:  1,
				consts.JsonKeyEpoch:  111,
				consts.JsonKeyTurn:   0,
				consts.JsonKeyBlock:  222222,
				consts.JsonKeyFactor: 55,
			}
			extra, err := json.Marshal(mp)
			if err == nil {
				tx1.SetTkmExtra(extra)
			}
		}

		{
			mp := map[string]uint64{
				consts.JsonKeyChain:  1,
				consts.JsonKeyEpoch:  111,
				consts.JsonKeyTurn:   1,
				consts.JsonKeyBlock:  222222,
				consts.JsonKeyFactor: 55,
			}
			extra, err := json.Marshal(mp)
			if err == nil {
				tx2.SetTkmExtra(extra)
			}
		}

		t.Logf("tx1:%s\ntx2:%s", tx1.FullString(), tx2.FullString())
		h1 := tx1.Hash()
		h2 := tx2.Hash()
		if h1 == h2 {
			t.Fatalf("different tx with same hash: %x", h1[:])
		} else {
			t.Logf("Hash(tx1):%x Hash(tx2):%x", h1[:], h2[:])
		}
	}
}
