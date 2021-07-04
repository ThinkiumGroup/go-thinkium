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

package rpcserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type (
	AccountChange struct {
		ChainID   common.ChainID  `json:"chainid"`   // Chain ID of from. When from is empty, it is the chain ID of delta.
		Height    common.Height   `json:"height"`    // Block height of the chain in which the transaction is executed
		From      *common.Address `json:"from"`      // When the account change is delta, from is empty. Otherwise, it is the transfer out account address
		To        *common.Address `json:"to"`        // Transfer in account address
		Nonce     uint64          `json:"nonce"`     // Nonce when a transfer out account performs a transaction. This value is meaningless when the account changes to delta.
		Val       *big.Int        `json:"value"`     // Account change amount
		Input     hexutil.Bytes   `json:"input"`     // Transaction input information
		UseLocal  bool            `json:"uselocal"`  // Is it a second currency transaction? False: base currency, true: second currency
		Extra     hexutil.Bytes   `json:"extra"`     // It is currently used to save transaction types. If it does not exist, it is a normal transaction. Otherwise, it will correspond to special operations
		TimeStamp uint64          `json:"timestamp"` // The timestamp of the block in which it is located
	}

	AccountWithCode struct {
		Addr            common.Address `json:"address"`         // Address of account
		Nonce           uint64         `json:"nonce"`           // Nonce of account
		Balance         *big.Int       `json:"balance"`         // Base currency，can't be nil
		LocalCurrency   *big.Int       `json:"localCurrency"`   // Second currency（if exists），could be nil
		StorageRoot     []byte         `json:"storageRoot"`     // Storage root of contract，Trie(key: Hash, value: Hash)
		CodeHash        []byte         `json:"codeHash"`        // Hash of contract code
		LongStorageRoot []byte         `json:"longStorageRoot"` // System contracts are used to hold more flexible data structures, Trie(key: Hash, value: []byte)
		Code            []byte         `json:"code"`
	}

	AccountHeight struct {
		Height          common.Height  `json:"height"`          // Current height of chain
		Addr            common.Address `json:"address"`         // Address of account
		Nonce           uint64         `json:"nonce"`           // Nonce of account
		Balance         *big.Int       `json:"balance"`         // Base currency，can't be nil
		LocalCurrency   *big.Int       `json:"localCurrency"`   // Second currency（if exists），could be nil
		StorageRoot     []byte         `json:"storageRoot"`     // Storage root of contract，Trie(key: Hash, value: Hash)
		CodeHash        []byte         `json:"codeHash"`        // Hash of contract code
		LongStorageRoot []byte         `json:"longStorageRoot"` // System contracts are used to hold more flexible data structures, Trie(key: Hash, value: []byte)
		Code            []byte         `json:"code"`
	}

	BlockMessage struct {
		Elections      []*models.ElectMessage `json:"elections"`      // start election msg
		AccountChanges []*AccountChange       `json:"accountchanges"` // transaction
	}

	TransactionReceipt struct {
		Transaction     *models.Transaction `json:"tx"`                                  // Transaction data object
		PostState       []byte              `json:"root"`                                // It is used to record the information of transaction execution in JSON format, such as gas, cost "gas", and world state "root" after execution.
		Status          uint64              `json:"status"`                              // Transaction execution status, 0: failed, 1: successful. (refers to whether the execution is abnormal)
		Logs            []*models.Log       `json:"logs" gencodec:"required"`            // The log written by the contract during execution
		TxHash          common.Hash         `json:"transactionHash" gencodec:"required"` // Transaction Hash
		ContractAddress common.Address      `json:"contractAddress"`                     // If you are creating a contract, save the address of the created contract here
		Out             hexutil.Bytes       `json:"out"`                                 // Return value of contract execution
		Height          common.Height       `json:"blockHeight"`                         // The block where the transaction is packaged is high and will not be returned when calling
		GasUsed         uint64              `json:"gasUsed"`                             // The gas value consumed by transaction execution is not returned in call
		GasFee          string              `json:"gasFee"`                              // The gas cost of transaction execution is not returned in call
		PostRoot        []byte              `json:"postroot"`                            // World state root after transaction execution (never return, always empty)
		Error           string              `json:"errorMsg"`                            // Error message in case of transaction execution failure
	}

	BlockInfo struct {
		Hash             common.Hash    `json:"hash"`          // Big hash, that is, big hash
		PreviousHash     common.Hash    `json:"previoushash"`  // Hash of last block
		ChainID          common.ChainID `json:"chainid"`       // Current chain ID
		Height           common.Height  `json:"height"`        // Block height
		Empty            bool           `json:"empty"`         // Whether it is an empty block, that is, whether it is a skipped block
		RewardAddress    common.Address `json:"rewardaddress"` // The reward address bound to the packing node (it can be any value, and the basis for issuing rewards is in the reward chain pledge contract, not depending on this value)
		MergedDeltaRoot  *common.Hash   `json:"mergeroot"`     // Root hash of delta merged from other partitions
		BalanceDeltaRoot *common.Hash   `json:"deltaroot"`     // The root hash of the delta tree generated by the current block transaction of the current partition needs to be sent to other partitions
		StateRoot        common.Hash    `json:"stateroot"`     // Hash root of the chain account
		RREra            *common.EraNum `json:"rrera"`         // Charging cycle of current block (main chain and reward chain)
		RRCurrent        *common.Hash   `json:"rrcurrent"`     // Pledge tree root hash (main chain and reward chain) when the current block is located
		RRNext           *common.Hash   `json:"rrnext"`        // Pledge tree root hash (main chain and reward chain) in the next billing cycle
		TxCount          int            `json:"txcount"`       // Transaction count in block
		TimeStamp        uint64         `json:"timestamp"`     // The time stamp of Proposer proposal can not be used as a basis
	}

	NodeInfo struct {
		NodeId        common.NodeID                    `json:"nodeId"`
		Version       string                           `json:"version"`
		IsDataNode    bool                             `json:"isDataNode"`
		DataNodeOf    common.ChainID                   `json:"dataNodeOf"`
		LastMsgTime   int64                            `json:"lastMsgTime"`
		LastEventTime int64                            `json:"lastEventTime"`
		LastBlockTime int64                            `json:"lastBlockTime"`
		Overflow      bool                             `json:"overflow"`
		LastBlocks    map[common.ChainID]common.Height `json:"lastBlocks"`
		OpTypes       map[common.ChainID][]string      `json:"opTypes"`
	}

	// information of a chain
	ChainInfo struct {
		ChainId   common.ChainID   `json:"chainId"`   // Chain ID
		Mode      common.ChainMode `json:"mode"`      // Root？Branch？Shard？
		ParentId  common.ChainID   `json:"parent"`    // Parent chain
		DataNodes []DataNodeInfo   `json:"datanodes"` // Data node list
	}

	DataNodeInfo struct {
		DataNodeId   common.NodeID `json:"dataNodeId"`   // Node ID
		DataNodeIp   string        `json:"dataNodeIp"`   // IP
		DataNodePort uint16        `json:"dataNodePort"` // RPC port
	}

	CashedCheckExistence struct {
		Existence bool   `json:"existence"` // Check exists in cashed tree and can be cancelled if it does not exist (other conditions must be met)
		Input     string `json:"input"`     // The data to be provided when canceling a check is the serialization of cancelcashcheckrequest
	}
)

func (r *TransactionReceipt) Reset() {
	if r == nil {
		return
	}
	r.Transaction = nil
	r.PostState = nil
	r.Status = 0
	r.Logs = nil
	r.TxHash = common.Hash{}
	r.ContractAddress = common.Address{}
	r.Out = nil
	r.Height = 0
	r.GasUsed = 0
	r.GasFee = ""
	r.PostRoot = nil
	r.Error = ""
}

func (r *TransactionReceipt) PartReceipt(tx *models.Transaction, rpt *models.Receipt) *TransactionReceipt {
	tr := r
	if r == nil {
		tr = new(TransactionReceipt)
	} else {
		r.Reset()
	}
	tr.Transaction = tx
	if rpt == nil {
		return tr
	}
	tr.PostState = rpt.PostState
	tr.Status = rpt.Status
	tr.Logs = rpt.Logs
	tr.TxHash = rpt.TxHash
	if rpt.ContractAddress != nil {
		tr.ContractAddress = *(rpt.ContractAddress)
	}
	tr.Out = rpt.Out
	tr.Error = rpt.Error
	return tr
}

func (r *TransactionReceipt) FullReceipt(tx *models.Transaction, blockHeight common.Height,
	rpt *models.Receipt) *TransactionReceipt {
	tr := r
	if r == nil {
		tr = new(TransactionReceipt)
	} else {
		r.Reset()
	}
	tr.Transaction = tx
	tr.Height = blockHeight
	if rpt == nil {
		return tr
	}
	tr.PostState = rpt.PostState
	tr.Status = rpt.Status
	tr.Logs = rpt.Logs
	tr.TxHash = rpt.TxHash
	if rpt.ContractAddress != nil {
		tr.ContractAddress = *(rpt.ContractAddress)
	}
	tr.Out = rpt.Out
	tr.GasUsed = rpt.GasUsed
	tr.GasFee = rpt.GasFeeString()
	tr.PostRoot = rpt.GetPostRoot()
	tr.Error = rpt.Error
	return tr
}

func (r *TransactionReceipt) Successed() bool {
	return r.Status == models.ReceiptStatusSuccessful
}

func (r *TransactionReceipt) String() string {
	if r == nil {
		return "RPT<nil>"
	}
	return fmt.Sprintf("RPT{"+
		"\n\t%s\n\tPostState:%s"+
		"\n\tStatus:%d"+
		"\n\tLogs:%v"+
		"\n\tTxHash:%x"+
		"\n\tContractAddress:%x"+
		"\n\tOut:%x"+
		"\n\tHeight:%s"+
		"\n\tGasUsed:%d"+
		"\n\tGasFee:%s"+
		"\n\tError:%s"+
		"\n}", r.Transaction.FullString(), string(r.PostState), r.Status, r.Logs, r.TxHash[:], r.ContractAddress[:],
		[]byte(r.Out), r.Height, r.GasUsed, r.GasFee, r.Error)
}

func (m *RpcAddress) PrintString() string {
	if m == nil {
		return "RpcAddress{nil}"
	}
	return fmt.Sprintf("RpcAddress{%d:%x}", m.Chainid, m.Address)
}

func (m *RpcAddress) MarshalJSON() ([]byte, error) {
	type ra struct {
		Cid  uint32 `json:"chainid"`
		Addr string `json:"address"`
	}
	r := ra{
		Cid:  m.Chainid,
		Addr: hexutil.Encode(m.Address),
	}
	return json.Marshal(r)
}

func (m *RpcTx) PrintString() string {
	return fmt.Sprintf("RpcTx{Chainid:%d From:%s To:%s Nonce:%d Val:%s len(Input):%d Local:%t len(Extra):%d}",
		m.Chainid, m.From.PrintString(), m.To.PrintString(), m.Nonce, m.Val, len(m.Input), m.Uselocal, len(m.Extra))
}

func (m *RpcTx) HashValue() ([]byte, error) {
	hasher := common.RealCipher.Hasher()
	if _, err := m.HashSerialize(hasher); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// see models.Transaction.HashSerialize
func (m *RpcTx) HashSerialize(w io.Writer) (int, error) {
	if len(m.From.Address) != 20 {
		return 0, errors.New("from address length must be 20")
	}
	from := common.BytesToAddressP(m.From.Address)
	var to *common.Address
	if m.To != nil && len(m.To.Address) > 0 {
		if len(m.To.Address) != 20 {
			return 0, errors.New("to address length must be 20")
		}
		to = common.BytesToAddressP(m.To.Address)
	}
	val, _ := math.ParseBig256(m.Val)

	p := models.TransactionStringForHash(common.ChainID(m.Chainid), from, to, m.Nonce,
		m.Uselocal, val, m.Input, m.Extra)

	log.Infof("%s -> %s", m.PrintString(), p)
	return w.Write([]byte(p))
}

func (m *RpcCashCheck) ToCashCheck() (*models.CashCheck, error) {
	if m == nil {
		return nil, nil
	}
	if m.From == nil || m.To == nil {
		return nil, common.ErrNil
	}
	amount := new(big.Int)
	amount, ok := big.NewInt(0).SetString(m.Amount, 10)
	if !ok {
		return nil, errors.New("illegal amount")
	}
	return &models.CashCheck{
		ParentChain:  common.ChainID(m.ParentChain),
		IsShard:      m.IsShard,
		FromChain:    common.ChainID(m.From.Chainid),
		FromAddress:  common.BytesToAddress(m.From.Address),
		Nonce:        m.Nonce,
		ToChain:      common.ChainID(m.To.Chainid),
		ToAddress:    common.BytesToAddress(m.To.Address),
		ExpireHeight: common.Height(m.ExpireHeight),
		Amount:       amount,
		UserLocal:    m.Uselocal,
		CurrencyID:   common.CoinID(m.CurrencyId),
	}, nil
}

func (m *RpcCashCheck) FromCashCheck(vcc *models.CashCheck) error {
	if vcc == nil {
		return common.ErrNil
	}
	m.ParentChain = uint32(vcc.ParentChain)
	m.IsShard = vcc.IsShard
	m.From = &RpcAddress{Chainid: uint32(vcc.FromChain), Address: vcc.FromAddress[:]}
	m.To = &RpcAddress{Chainid: uint32(vcc.ToChain), Address: vcc.ToAddress[:]}
	m.Nonce = vcc.Nonce
	m.ExpireHeight = uint64(vcc.ExpireHeight)
	m.Amount = "0"
	if vcc.Amount != nil {
		m.Amount = vcc.Amount.String()
	}
	m.Uselocal = vcc.UserLocal
	m.CurrencyId = int32(vcc.CurrencyID)
	return nil
}

func (b *BlockInfo) String() string {
	if jsons, err := json.Marshal(b); err != nil {
		return "!!!json marshal failed!!!"
	} else {
		return string(jsons)
	}
}

func (m *RpcRRProofReq) HashValue() ([]byte, error) {
	hasher := common.RealCipher.Hasher()
	if _, err := m.HashSerialize(hasher); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (m *RpcRRProofReq) HashSerialize(w io.Writer) (int, error) {
	str := []string{
		common.ChainID(m.ChainId).String(),
		hex.EncodeToString(m.RootHash),
		hex.EncodeToString(m.NodeHash),
	}
	// Multiple non fixed length bytes links must have a separator, otherwise the combination of different chains + era will have the same serialization
	p := strings.Join(str, ",")
	return w.Write([]byte(p))
}

func (m *RpcRRProofReq) Verify() error {
	nid, err := common.PubToNodeID(m.Pub)
	if err != nil {
		return err
	}
	nidh := nid.Hash()
	if !bytes.Equal(nidh[:], m.NodeHash) {
		return fmt.Errorf("public key and NodeIDHash not match")
	}
	objectHash, err := common.HashObject(m)
	if err != nil {
		return fmt.Errorf("hash object failed: %v", err)
	}
	if !common.VerifyHash(objectHash, m.Pub, m.Sig) {
		return fmt.Errorf("signature verfiy failed")
	}
	return nil
}
