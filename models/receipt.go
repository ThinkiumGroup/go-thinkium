// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	dataBase "github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

//go:generate gencodec -type Log -field-override logMarshaling -out gen_log_json.go
//go:generate gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

// var (
// 	receiptStatusFailed     = make([]byte, 0)
// 	receiptStatusSuccessful = []byte{0x01}
// )

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)
	// ReceiptPostStateFailed = "success"

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
	// ReceiptPostStateSuccessful = "error"
)

type Log struct {
	// Consensus fields:
	// address of the contract that generated the event
	Address common.Address `json:"address" gencodec:"required"`
	// list of topics provided by the contract.
	Topics []common.Hash `json:"topics" gencodec:"required"`
	// supplied by the contract, usually ABI-encoded
	Data []byte `json:"data" gencodec:"required"`

	// Derived fields. These fields are filled in by the node
	// but not secured by consensus.
	// block in which the transaction was included
	BlockNumber uint64 `json:"blockNumber" gencodec:"required"`
	// hash of the transaction
	TxHash common.Hash `json:"transactionHash" gencodec:"required"`
	// index of the transaction in the block
	TxIndex uint `json:"transactionIndex" gencodec:"required"`
	// index of the log in the receipt
	Index uint `json:"logIndex" gencodec:"required"`
	// hash of the block in which the transaction was included
	BlockHash *common.Hash `json:"blockHash"`
}

type logMarshaling struct {
	Data        hexutil.Bytes
	BlockNumber hexutil.Uint64
	TxIndex     hexutil.Uint
	Index       hexutil.Uint
}

// Receipt represents the results of a transaction.
type Receipt struct {
	// Consensus fields
	PostState         []byte `json:"root"` // It is used to record the information of transaction execution in JSON format, such as gas, cost "gas", and world state "root" after execution.
	Status            uint64 `json:"status"`
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"`
	Logs              []*Log `json:"logs" gencodec:"required"`
	// Bloom             Bloom  `json:"logsBloom"         gencodec:"required"`

	// Implementation fields (don't reorder!)
	TxHash          common.Hash     `json:"transactionHash" gencodec:"required"`
	ContractAddress *common.Address `json:"contractAddress"`
	GasUsed         uint64          `json:"gasUsed" gencodec:"required"`
	Out             []byte          `json:"out" gencodec:"required"`
	Error           string          `json:"error"`
}

type receiptMarshaling struct {
	PostState         hexutil.Bytes
	Status            hexutil.Uint64
	CumulativeGasUsed hexutil.Uint64
	GasUsed           hexutil.Uint64
	Out               hexutil.Bytes
}

type Receipts []*Receipt

func (r *Receipt) GasFeeString() string {
	ps := ParsePostState(r.PostState)
	if ps == nil {
		return ""
	}
	return ps.GasFee
}

func (r *Receipt) GetPostRoot() []byte {
	ps := ParsePostState(r.PostState)
	if ps == nil {
		return r.PostState
	}
	return ps.Root
}

func (r *Receipt) String() string {
	return fmt.Sprintf("Receipt{TxHash:%x Contract:%x Status:%d Gas:%d Fee:%s PostRoot:%x len(Logs):%d len(Out):%d}",
		r.TxHash[:], r.ContractAddress[:], r.Status, r.GasUsed, r.GasFeeString(), r.GetPostRoot(), len(r.Logs), len(r.Out))
}

// Len returns the number of receipts in this list.
func (r Receipts) Len() int { return len(r) }

// NewReceipt creates a barebone transaction receipt, copying the init fields.
func NewReceipt(gasFee *big.Int, root []byte, err error, cumulativeGasUsed uint64) *Receipt {
	ps := NewPostState(gasFee, root)
	psbytes, _ := ps.Bytes()
	r := &Receipt{PostState: psbytes, CumulativeGasUsed: cumulativeGasUsed}
	if err != nil {
		r.Status = ReceiptStatusFailed
		r.Error = err.Error()
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

// ReadReceipts retrieves all the transaction receipts belonging to a block.
func ReadReceipts(db dataBase.Database, hash common.Hash) Receipts {

	// Retrieve the flattened receipt slice
	data, _ := db.Get(dataBase.ToBlockReceiptsKey(hash[:]))
	if len(data) == 0 {
		return nil
	}
	// Convert the revceipts from their storage form to their internal representation
	dataBuf := bytes.NewBuffer(data)
	receipts := make([]*Receipt, 0)
	if err := rtl.Decode(dataBuf, &receipts); err != nil {
		log.Error("Invalid receipt array", "hash", hash, "err", err)
		return nil
	}
	//
	// if len(receipts) > 0 {
	// 	log.Warnf("read receipts %v: %x", receipts, data)
	// }
	return receipts
}

// WriteReceipts stores all the transaction receipts belonging to a block.
func WriteReceipts(db dataBase.Database, receipts Receipts) ([]byte, error) {
	dataBuf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(dataBuf)
	dataBuf.Reset()

	err := rtl.Encode(receipts, dataBuf)
	if err != nil {
		log.Error("Failed to encode block receipts", "err", err)
		return nil, err
	}
	bs := dataBuf.Bytes()
	receiptHash, err := common.Hash256s(bs)
	if err != nil {
		return nil, err
	}
	// if len(receipts) > 0 {
	// 	log.Warnf("Write Receipts %s: %x", receipts, bs)
	// }
	// Store the flattened receipt slice
	if err := db.Put(dataBase.ToBlockReceiptsKey(receiptHash), bs); err != nil {
		log.Error("Failed to store block receipts", "err", err)
		return nil, err
	}
	return receiptHash, nil
}

// DeleteReceipts removes all receipt data associated with a block hash.
func DeleteReceipts(db dataBase.Database, hash common.Hash, number uint64) {
	if err := db.Delete(dataBase.ToBlockReceiptsKey(hash[:])); err != nil {
		log.Error("Failed to delete block receipts", "err", err)
	}
}

// ReadReceipt retrieves a specific transaction receipt from the database, along with
// its added positional metadata.
func ReadReceipt(receipts Receipts, index int) (*Receipt, error) {

	if len(receipts) <= index {
		return nil, common.ErrIllegalParams
	}

	return receipts[index], nil
}

// record the transaction process result
type PostState struct {
	GasFee string `json:"fee"`
	Root   []byte `json:"root"`
}

func NewPostState(gasFee *big.Int, root []byte) *PostState {
	feestr := "0"
	if gasFee != nil && gasFee.Sign() > 0 {
		feestr = gasFee.String()
	}
	return &PostState{
		GasFee: feestr,
		Root:   root,
	}
}

func (s *PostState) Bytes() ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

func ParsePostState(bs []byte) *PostState {
	if len(bs) == 0 || bs[0] != '{' {
		return nil
	}
	ps := new(PostState)
	if err := json.Unmarshal(bs, ps); err != nil {
		return nil
	}
	return ps
}
