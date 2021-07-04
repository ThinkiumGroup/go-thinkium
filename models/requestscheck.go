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
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
)

// Verifiable Cash Check, for cross chain transfer
// In order to avoid synchronous recovery of ChainInfos in main chain when recovering data, the
// chain information is input by the user, and it is enough to check whether the local data is
// legal when executing (because even if the main chain data is not synchronized, the local chain
// information can still be known). If the input error can be retrieved through cancel
type CashCheck struct {
	ParentChain  common.ChainID `json:"ParentChain"`  // parent of source chain
	IsShard      bool           `json:"IsShard"`      // whether the source chain is a sharding chain
	FromChain    common.ChainID `json:"FromChain"`    // id of source chain
	FromAddress  common.Address `json:"FromAddr"`     // address of source account
	Nonce        uint64         `json:"Nonce"`        // nonce of the tx to write the CashCheck
	ToChain      common.ChainID `json:"ToChain"`      // target chain id
	ToAddress    common.Address `json:"ToAddr"`       // address of the target account
	ExpireHeight common.Height  `json:"ExpireHeight"` // The expired height refers to that when the height of the target chain exceeds (excluding) this value, the check cannot be withdrawn and can only be returned
	UserLocal    bool           `json:"UseLocal"`     // true: local currency, false: basic currency, default is false
	Amount       *big.Int       `json:"Amount"`       // amount of the check
	CurrencyID   common.CoinID  `json:"CoinID"`       // Currency ID, new field, 0 when uselocal==false, currency ID when =true, and 0 for old version data
}

func (c *CashCheck) String() string {
	return fmt.Sprintf("Check{ParentChain:%d IsShard:%t From:[%d,%x] Nonce:%d To:[%d,%x]"+
		" Expire:%d Local:%t Amount:%s CoinID:%d}", c.ParentChain, c.IsShard, c.FromChain, c.FromAddress[:],
		c.Nonce, c.ToChain, c.ToAddress[:], c.ExpireHeight, c.UserLocal, math.BigIntForPrint(c.Amount), c.CurrencyID)
}

func (c *CashCheck) Equal(o *CashCheck) bool {
	if c == o {
		return true
	}
	if c == nil || o == nil {
		return false
	}
	if c.ParentChain != o.ParentChain || c.IsShard != o.IsShard || c.FromChain != o.FromChain ||
		c.FromAddress != o.FromAddress || c.Nonce != o.Nonce || c.ToChain != o.ToChain ||
		c.ToAddress != o.ToAddress || c.ExpireHeight != o.ExpireHeight || c.UserLocal != o.UserLocal ||
		c.CurrencyID != o.CurrencyID {
		return false
	}
	if c.Amount == o.Amount {
		return true
	}
	if c.Amount == nil || o.Amount == nil {
		return false
	}
	return c.Amount.Cmp(o.Amount) == 0
}

// In order to be compatible with previous clients and historical data, it is necessary to make
// the serialization of CashCheck when the default uselocal==false consistent with the previous
// version, to ensure the consistency of hash value. When the starting ChainID==ReservedMaxChainID,
// it means that the object version and special value will be followed
// Version 0x0: it will be followed by a byte version number (0), indicating uselocal==true
// Version 0x1: followed by useLocal(1 byte), ParentChain(4 bytes), IsShard(1 byte), CurrencyID(2 bytes)
func (c *CashCheck) serialPrefix() []byte {
	var version byte = 0x0
	if c.ParentChain == 0 && c.IsShard == false && c.CurrencyID == 0 {
		if c.UserLocal == false {
			// Original version, no version number required
			return nil
		} else {
			// Version 0x0 supports uselocal, but in fact it should not be here, that is to say,
			// the local currency ID must be known when useLocal is true
			version = 0x0
			panic("wrong data: UseLocal==true without CurrencyID")
		}
	} else {
		// Version 0x1 supports ParentChain/IsShard/CurrencyID
		version = 0x1
		// (4bytes prefix)+(1byte version)+(1byte uselocal)+(4bytes ParentChain)+(1byte IsShard)+(2bytes CurrencyID) = 13bytes
		buf := make([]byte, 13)
		binary.BigEndian.PutUint32(buf[:4], uint32(common.ReservedMaxChainID))
		buf[4] = version
		if c.UserLocal {
			buf[5] = 0x1
		} else {
			buf[5] = 0x0
		}
		binary.BigEndian.PutUint32(buf[6:10], uint32(c.ParentChain))
		if c.IsShard {
			buf[10] = 0x1
		} else {
			buf[10] = 0x0
		}
		binary.BigEndian.PutUint16(buf[11:13], uint16(c.CurrencyID))
		return buf
	}
}

// 4 bytes FromChain + 20 bytes FromAddress + 8 bytes Nonce + 4 bytes ToChain + 20 bytes ToAddress +
// 8 bytes ExpireHeight + 1 byte len(Amount.Bytes()) + Amount.Bytes()
// all BigEndian
func (c *CashCheck) Serialization(w io.Writer) error {
	buf4 := make([]byte, 4)
	buf8 := make([]byte, 8)

	var err error
	prefix := c.serialPrefix()
	if len(prefix) > 0 {
		_, err = w.Write(prefix)
		if err != nil {
			return err
		}
	}

	binary.BigEndian.PutUint32(buf4, uint32(c.FromChain))
	_, err = w.Write(buf4)
	if err != nil {
		return err
	}

	_, err = w.Write(c.FromAddress[:])
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint64(buf8, uint64(c.Nonce))
	_, err = w.Write(buf8)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(buf4, uint32(c.ToChain))
	_, err = w.Write(buf4)
	if err != nil {
		return err
	}

	_, err = w.Write(c.ToAddress[:])
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint64(buf8, uint64(c.ExpireHeight))
	_, err = w.Write(buf8)
	if err != nil {
		return err
	}

	var mbytes []byte
	if c.Amount != nil {
		mbytes = c.Amount.Bytes()
	}
	err = writeByteSlice(w, 1, mbytes)
	if err != nil {
		return err
	}

	return nil
}

func (c *CashCheck) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	buf4 := make([]byte, 4)
	buf8 := make([]byte, 8)

	_, err = io.ReadFull(r, buf4)
	if err != nil {
		return
	}
	first := common.ChainID(binary.BigEndian.Uint32(buf4))
	if first.IsNil() {
		// The special ChainID will be followed by the version number to indicate useLocal==true
		// Read one more byte as the version number
		_, err = io.ReadFull(r, buf4[:1])
		if err != nil {
			return
		}

		switch buf4[0] { // version
		case 0x0:
			c.UserLocal = true
			c.ParentChain = 0
			c.IsShard = false
			c.CurrencyID = 0 // currency id not known for old version
		case 0x1:
			_, err = io.ReadFull(r, buf8)
			if err != nil {
				return
			}
			if buf8[0] == 0x0 {
				c.UserLocal = false
			} else {
				c.UserLocal = true
			}
			c.ParentChain = common.ChainID(binary.BigEndian.Uint32(buf8[1:5]))
			if buf8[5] == 0x0 {
				c.IsShard = false
			} else {
				c.IsShard = true
			}
			c.CurrencyID = common.CoinID(binary.BigEndian.Uint16(buf8[6:8]))
		default:
			err = fmt.Errorf("unknown version of check %x", buf4[0])
			return
		}

		// next is the real FromChain
		_, err = io.ReadFull(r, buf4)
		if err != nil {
			return
		}
		c.FromChain = common.ChainID(binary.BigEndian.Uint32(buf4))
	} else {
		c.FromChain = first
	}

	_, err = io.ReadFull(r, c.FromAddress[:])
	if err != nil {
		return
	}

	_, err = io.ReadFull(r, buf8)
	if err != nil {
		return
	}
	c.Nonce = binary.BigEndian.Uint64(buf8)

	_, err = io.ReadFull(r, buf4)
	if err != nil {
		return
	}
	c.ToChain = common.ChainID(binary.BigEndian.Uint32(buf4))

	_, err = io.ReadFull(r, c.ToAddress[:])
	if err != nil {
		return
	}

	_, err = io.ReadFull(r, buf8)
	if err != nil {
		return
	}
	c.ExpireHeight = common.Height(binary.BigEndian.Uint64(buf8))

	bs, err := readByteSlice(r, 1)
	if err != nil {
		return false, err
	}
	if len(bs) > 0 {
		c.Amount = new(big.Int).SetBytes(bs)
	} else {
		c.Amount = big.NewInt(0)
	}

	return false, nil
}

// Check cashing request object is generated by RPC interface and submitted to the target chain
// through TX. the whole transmission process uses the serialization of this object
type CashRequest struct {
	Check           *CashCheck      `json:"check"`  // check information to be cashed
	ProofedChainID  common.ChainID  `json:"chain"`  // the target chain of the proof (main chain)
	ProofHeight     common.Height   `json:"height"` // proof from check hash to block.hash of source chain, and then to main chain block.hash. this is the corresponding main chain block height
	ProofHeaderHash common.Hash     `json:"header"` // block hash which height is specified by ProofHeight
	Proofs          trie.ProofChain `json:"proofs"` // proof of check
}

func (r *CashRequest) Verify() (hashOfCheck []byte, err error) {
	if r == nil || r.Check == nil || r.Proofs == nil {
		return nil, common.ErrNil
	}
	h, err := common.HashObject(r.Check)
	if err != nil {
		return nil, err
	}
	p, err := r.Proofs.Proof(common.BytesToHash(h))
	if err != nil {
		return nil, err
	}
	// ProofedChainID/ProofHeight/ProofHeaderHash validated at business logic layer
	if !bytes.Equal(p, r.ProofHeaderHash[:]) {
		log.Errorf("Proof root miss match %x %x", p, r.ProofHeaderHash[:])
		return nil, trie.ErrMismatchProof
	}
	return h, nil
}

// a valid cancel request must:
// 1. CCCProofs.IsExist(Hash(Check))==false, means the check not cashed
// 2. Proofs[0].PType==trie.ProofHeaderCCCRoot, to proof it's a CashedTrie proof
// 3. Proofs[0].IsHeaderOf(Check.ToChain, AbsenceHeight)==true, to proof that the current proof
//    is actually generated by the block of target height of the target chain
// 4. AbsenceHeaderHash==Hash(Block(ChainID:MainChainID, Height:ConfirmedHeight)), the proof target
//    is the main chain block hash at ConfirmedHeight
// 5. Proofs.Proof(CCCProofs.ExistenceHash())==AbsenceHeaderHash, that is the proof required.
type CancelCashCheckRequest struct {
	Check             *CashCheck      `json:"check"`           // cheque to be voided
	AbsenceChainID    common.ChainID  `json:"chain"`           // the target chain of the proof
	AbsenceHeight     common.Height   `json:"height"`          // block height of target chain which proof prove to
	AbsenceHeaderHash common.Hash     `json:"header"`          // the proof target hash of Proofs
	CCCProofs         trie.ProofChain `json:"absence"`         // CashedTrie's proof of non-existence of check
	Proofs            trie.ProofChain `json:"proofs"`          // from CashedTrie.Root Proof chain to the target of proof
	ConfirmedHeight   common.Height   `json:"confirmedHeight"` // the main chain block height which confirmed target block header
}

func (c *CancelCashCheckRequest) String() string {
	if c == nil {
		return "CCCR<nil>"
	}
	return fmt.Sprintf("CCCR{%s ChainID:%d Height:%d Header:%x nil(CCCProof):%t nil(Proof):%t}",
		c.Check, c.AbsenceChainID, c.AbsenceHeight, c.AbsenceHeaderHash[:5], c.CCCProofs == nil, c.Proofs == nil)
}

func (c *CancelCashCheckRequest) Verify(existence bool) (hashOfCheck []byte, hashOfTrie []byte, hashOfProof []byte, err error) {
	if c == nil || c.Check == nil || c.CCCProofs == nil || c.Proofs == nil {
		return nil, nil, nil, common.ErrNil
	}
	if c.Check.ToChain != c.AbsenceChainID {
		return nil, nil, nil, errors.New("absence chain id not match")
	}
	hashOfCheck, err = common.HashObject(c.Check)
	if err != nil {
		return nil, nil, nil, err
	}
	exist := false
	exist, err = c.CCCProofs.IsExist(hashOfCheck)
	if err != nil {
		return nil, nil, nil, err
	}
	if exist != existence {
		return hashOfCheck, nil, nil, trie.ErrMismatchProof
	}
	// if !exist {
	// 	return hashOfCheck, nil, nil, trie.ErrNotExist
	// }
	hashOfTrie, err = c.CCCProofs.ExistenceHash()
	if err != nil {
		return hashOfCheck, nil, nil, err
	}
	if len(c.Proofs) < 1 || c.Proofs[0] == nil {
		return hashOfCheck, hashOfTrie, nil, errors.New("at least 1 NodeProof needed when proof in header")
	}
	if c.Proofs[0].PType != trie.ProofHeaderCCCRoot {
		// not a proof of CashedTrie
		return hashOfCheck, hashOfTrie, nil, trie.ErrMismatchProof
	}
	if !c.Proofs[0].IsHeaderOf(c.Check.ToChain, c.AbsenceHeight) {
		return hashOfCheck, hashOfTrie, nil,
			fmt.Errorf("invalid CashedRootProof of ToChain:%d Height:%d", c.Check.ToChain, c.AbsenceHeight)
	}
	hashOfProof, err = c.Proofs.Proof(common.BytesToHash(hashOfTrie))
	if err != nil {
		return
	}
	if !bytes.Equal(hashOfProof, c.AbsenceHeaderHash[:]) {
		return hashOfCheck, hashOfTrie, hashOfProof, trie.ErrMismatchProof
	}
	return
}
