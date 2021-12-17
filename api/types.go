package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

const (
	PendingBlockNumber  = BlockNumber(-2)
	LatestBlockNumber   = BlockNumber(-1)
	EarliestBlockNumber = BlockNumber(0)
)

type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

type BlockNumber int64

func (bn *BlockNumber) UnmarshalJSON(data []byte) error {
	input := strings.TrimSpace(string(data))
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' {
		input = input[1 : len(input)-1]
	}

	switch input {
	case "earliest":
		*bn = EarliestBlockNumber
		return nil
	case "latest":
		*bn = LatestBlockNumber
		return nil
	case "pending":
		*bn = PendingBlockNumber
		return nil
	}

	blckNum, err := hexutil.DecodeUint64(input)
	if err != nil {
		return err
	}
	if blckNum > math.MaxInt64 {
		return fmt.Errorf("block number larger than int64")
	}
	*bn = BlockNumber(blckNum)
	return nil
}

func (bn BlockNumber) MarshalText() ([]byte, error) {
	switch bn {
	case EarliestBlockNumber:
		return []byte("earliest"), nil
	case LatestBlockNumber:
		return []byte("latest"), nil
	case PendingBlockNumber:
		return []byte("pending"), nil
	default:
		return hexutil.Uint64(bn).MarshalText()
	}
}

func (bn BlockNumber) Int64() int64 {
	return (int64)(bn)
}

type BlockNumberOrHash struct {
	BlockNumber      *BlockNumber `json:"blockNumber,omitempty"`
	BlockHash        *common.Hash `json:"blockHash,omitempty"`
	RequireCanonical bool         `json:"requireCanonical,omitempty"`
}

func (bnh *BlockNumberOrHash) UnmarshalJSON(data []byte) error {
	type erased BlockNumberOrHash
	e := erased{}
	err := json.Unmarshal(data, &e)
	if err == nil {
		if e.BlockNumber != nil && e.BlockHash != nil {
			return fmt.Errorf("cannot specify both BlockHash and BlockNumber, choose one or the other")
		}
		bnh.BlockNumber = e.BlockNumber
		bnh.BlockHash = e.BlockHash
		bnh.RequireCanonical = e.RequireCanonical
		return nil
	}
	var input string
	err = json.Unmarshal(data, &input)
	if err != nil {
		return err
	}
	switch input {
	case "earliest":
		bn := EarliestBlockNumber
		bnh.BlockNumber = &bn
		return nil
	case "latest":
		bn := LatestBlockNumber
		bnh.BlockNumber = &bn
		return nil
	case "pending":
		bn := PendingBlockNumber
		bnh.BlockNumber = &bn
		return nil
	default:
		if len(input) == 66 {
			hash := common.Hash{}
			err := hash.UnmarshalText([]byte(input))
			if err != nil {
				return err
			}
			bnh.BlockHash = &hash
			return nil
		} else {
			blckNum, err := hexutil.DecodeUint64(input)
			if err != nil {
				return err
			}
			if blckNum > math.MaxInt64 {
				return fmt.Errorf("blocknumber too high")
			}
			bn := BlockNumber(blckNum)
			bnh.BlockNumber = &bn
			return nil
		}
	}
}

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
type RPCTransaction struct {
	BlockHash        *common.Hash       `json:"blockHash"`
	BlockNumber      *hexutil.Big       `json:"blockNumber"`
	From             common.Address     `json:"from"`
	Gas              hexutil.Uint64     `json:"gas"`
	GasPrice         *hexutil.Big       `json:"gasPrice"`
	GasFeeCap        *hexutil.Big       `json:"maxFeePerGas,omitempty"`
	GasTipCap        *hexutil.Big       `json:"maxPriorityFeePerGas,omitempty"`
	Hash             common.Hash        `json:"hash"`
	Input            hexutil.Bytes      `json:"input"`
	Nonce            hexutil.Uint64     `json:"nonce"`
	To               *common.Address    `json:"to"`
	TransactionIndex *hexutil.Uint64    `json:"transactionIndex"`
	Value            *hexutil.Big       `json:"value"`
	Type             hexutil.Uint64     `json:"type"`
	Accesses         *models.AccessList `json:"accessList,omitempty"`
	ChainID          *hexutil.Big       `json:"chainId,omitempty"`
	V                *hexutil.Big       `json:"v"`
	R                *hexutil.Big       `json:"r"`
	S                *hexutil.Big       `json:"s"`
}

func GenRpcTxRes(tx *models.Transaction, txI *models.TXIndex, recepit *models.Receipt) (*RPCTransaction, error) {
	accl := tx.AccessList()
	index := uint64(txI.Index)
	res := &RPCTransaction{
		BlockHash:        &txI.BlockHash,
		BlockNumber:      (*hexutil.Big)(big.NewInt(int64(txI.BlockHeight))),
		From:             *tx.From,
		Gas:              (hexutil.Uint64)(tx.Gas()),
		GasPrice:         (*hexutil.Big)(tx.GasPrice()),
		GasFeeCap:        (*hexutil.Big)(tx.GasFeeCap()),
		GasTipCap:        (*hexutil.Big)(tx.GasTipCap()),
		Hash:             recepit.TxHash,
		Input:            tx.Input,
		Nonce:            (hexutil.Uint64)(tx.Nonce),
		To:               tx.To,
		TransactionIndex: (*hexutil.Uint64)(&index),
		Value:            (*hexutil.Big)(tx.Val),
		Type:             (hexutil.Uint64)(tx.Type()),
		Accesses:         &accl,
		ChainID:          (*hexutil.Big)(tx.ETHChainID()),
		V:                nil,
		R:                nil,
		S:                nil,
	}
	return res, nil
}

// newRPCTransactionFromBlockHash returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockHash(b *models.BlockEMessage, hash common.Hash) *RPCTransaction {
	for idx, tx := range b.BlockBody.Txs {
		if tx.Hash() == hash {
			return newRPCTransactionFromBlockIndex(b, uint64(idx))
		}
	}
	return nil
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(b *models.BlockEMessage, index uint64) *RPCTransaction {
	txs := b.BlockBody.Txs
	if index >= uint64(len(txs)) {
		return nil
	}
	return newRPCTransaction(txs[index], b.Hash(), b.GetHeight(), index, nil)
}

// newRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
func newRPCTransaction(tx *models.Transaction, blockHash common.Hash, blockNumber common.Height, index uint64, baseFee *big.Int) *RPCTransaction {
	// Determine the signer. For replay-protected transactions, use the most permissive
	// signer, because we assume that signers are backwards-compatible with old
	// transactions. For non-protected transactions, the homestead signer is used
	// because the return value of ChainId is zero for those transactions.
	result := &RPCTransaction{
		Type:     hexutil.Uint64(tx.Type()),
		From:     *tx.From,
		Gas:      hexutil.Uint64(tx.Gas()),
		GasPrice: (*hexutil.Big)(tx.GasPrice()),
		Hash:     tx.Hash(),
		Input:    tx.Input,
		Nonce:    hexutil.Uint64(tx.Nonce),
		To:       tx.To,
		Value:    (*hexutil.Big)(tx.Val),
		V:        (*hexutil.Big)(big.NewInt(0)),
		R:        (*hexutil.Big)(big.NewInt(0)),
		S:        (*hexutil.Big)(big.NewInt(0)),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = &blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(uint64(blockNumber)))
		result.TransactionIndex = (*hexutil.Uint64)(&index)
	}
	switch tx.Type() {
	case models.AccessListTxType:
		al := tx.AccessList()
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ETHChainID())
	case models.DynamicFeeTxType:
		al := tx.AccessList()
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ETHChainID())
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		if baseFee != nil && blockHash != (common.Hash{}) {
			// price = min(tip, gasFeeCap - baseFee) + baseFee
			price := math.BigMin(new(big.Int).Add(tx.GasTipCap(), baseFee), tx.GasFeeCap())
			result.GasPrice = (*hexutil.Big)(price)
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}
	}
	return result
}

// OverrideAccount indicates the overriding fields of account during the execution
// of a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if statDiff is set, all diff will be applied first and then execute the call
// message.
type OverrideAccount struct {
	Nonce     *hexutil.Uint64              `json:"nonce"`
	Code      *hexutil.Bytes               `json:"code"`
	Balance   **hexutil.Big                `json:"balance"`
	State     *map[common.Hash]common.Hash `json:"state"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff"`
}

// StateOverride is the collection of overridden accounts.
type StateOverride map[common.Address]OverrideAccount

// FilterQuery contains options for contract log filtering.
type FilterQuery struct {
	BlockHash *common.Hash     // used by eth_getLogs, return logs only from block with this hash
	FromBlock *big.Int         // beginning of the queried range, nil means genesis block
	ToBlock   *big.Int         // end of the range, nil means latest block
	Addresses []common.Address // restricts matches to events created by specific contracts
	Topics    [][]common.Hash
}

// UnmarshalJSON sets *args fields with given data.
func (args *FilterQuery) UnmarshalJSON(data []byte) error {
	type input struct {
		BlockHash *common.Hash  `json:"blockHash"`
		FromBlock *BlockNumber  `json:"fromBlock"`
		ToBlock   *BlockNumber  `json:"toBlock"`
		Addresses interface{}   `json:"address"`
		Topics    []interface{} `json:"topics"`
	}

	var raw input
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.BlockHash != nil {
		if raw.FromBlock != nil || raw.ToBlock != nil {
			// BlockHash is mutually exclusive with FromBlock/ToBlock criteria
			return fmt.Errorf("cannot specify both BlockHash and FromBlock/ToBlock, choose one or the other")
		}
		args.BlockHash = raw.BlockHash
	} else {
		if raw.FromBlock != nil {
			args.FromBlock = big.NewInt(raw.FromBlock.Int64())
		}

		if raw.ToBlock != nil {
			args.ToBlock = big.NewInt(raw.ToBlock.Int64())
		}
	}

	args.Addresses = []common.Address{}

	if raw.Addresses != nil {
		// raw.Address can contain a single address or an array of addresses
		switch rawAddr := raw.Addresses.(type) {
		case []interface{}:
			for i, addr := range rawAddr {
				if strAddr, ok := addr.(string); ok {
					b, err := hexutil.Decode(strAddr)
					if err != nil || len(b) != common.AddressLength {
						return fmt.Errorf("hex has invalid length %d after decoding; expected %d for address", len(b), common.HashLength)
					}
					addr := common.BytesToAddress(b)
					args.Addresses = append(args.Addresses, addr)
				} else {
					return fmt.Errorf("non-string address at index %d", i)
				}
			}
		case string:
			b, err := hexutil.Decode(rawAddr)
			if err != nil || len(b) != common.AddressLength {
				return fmt.Errorf("hex has invalid length %d after decoding; expected %d for address", len(b), common.HashLength)
			}
			addr := common.BytesToAddress(b)
			args.Addresses = []common.Address{addr}
		default:
			return errors.New("invalid addresses in query")
		}
	}

	// topics is an array consisting of strings and/or arrays of strings.
	// JSON null values are converted to common.Hash{} and ignored by the filter manager.
	if len(raw.Topics) > 0 {
		args.Topics = make([][]common.Hash, len(raw.Topics))
		for i, t := range raw.Topics {
			switch topic := t.(type) {
			case nil:
				// ignore topic when matching logs

			case string:
				// match specific topic
				b, err := hexutil.Decode(topic)
				if err != nil || len(b) != common.AddressLength {
					return fmt.Errorf("hex has invalid length %d after decoding; expected %d for topic", len(b), common.HashLength)
				}
				top := common.BytesToHash(b)
				args.Topics[i] = []common.Hash{top}

			case []interface{}:
				// or case e.g. [null, "topic0", "topic1"]
				for _, rawTopic := range topic {
					if rawTopic == nil {
						// null component, match all
						args.Topics[i] = nil
						break
					}
					if topic, ok := rawTopic.(string); ok {
						b, err := hexutil.Decode(topic)
						if err != nil || len(b) != common.AddressLength {
							return fmt.Errorf("hex has invalid length %d after decoding; expected %d for topic", len(b), common.HashLength)
						}
						parsed := common.BytesToHash(b)
						args.Topics[i] = append(args.Topics[i], parsed)
					} else {
						return fmt.Errorf("invalid topic(s)")
					}
				}
			default:
				return fmt.Errorf("invalid topic(s)")
			}
		}
	}

	return nil
}

// TransactionArgs represents the arguments to construct a new transaction
// or a message call.
type TransactionArgs struct {
	From                 *common.Address    `json:"from"`
	To                   *common.Address    `json:"to"`
	Gas                  *hexutil.Uint64    `json:"gas"`
	GasPrice             *hexutil.Big       `json:"gasPrice"`
	MaxFeePerGas         *hexutil.Big       `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big       `json:"maxPriorityFeePerGas"`
	Value                *hexutil.Big       `json:"value"`
	Nonce                *hexutil.Uint64    `json:"nonce"`
	Data                 *hexutil.Bytes     `json:"data"` // data include R, S, V and orther filed
	Input                *hexutil.Bytes     `json:"input"`
	AccessList           *models.AccessList `json:"accessList,omitempty"`
	ChainID              *hexutil.Big       `json:"chainId,omitempty"`
}
