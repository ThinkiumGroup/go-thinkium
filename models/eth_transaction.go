package models

import (
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/rlp"
)

type StorageSize float64

var ETHSigner Signer = NewLondonSigner()

// ETHTransaction is an Ethereum transaction.
type ETHTransaction struct {
	inner TxData    // Consensus contents of a transaction
	time  time.Time // Time first seen locally (spam avoidance)

	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

// NewTx creates a new transaction.
func NewTx(inner TxData) *ETHTransaction {
	tx := new(ETHTransaction)
	tx.setDecoded(inner.copy(), 0)
	return tx
}

func (tx *ETHTransaction) SigAndPub() {
}

func (tx *ETHTransaction) ToTransaction() (*Transaction, error) {
	cid, err := FromETHChainID(tx.ChainId())
	if err != nil {
		return nil, err
	}
	var extrakeys = new(Extra)
	v, r, s := tx.inner.rawSignatureValues()
	switch tx.Type() {
	case LegacyTxType:
		extrakeys = &Extra{
			Type:     LegacyTxType,
			GasPrice: tx.GasPrice(),
			V:        v,
			R:        r,
			S:        s,
		}
	case AccessListTxType:
		extrakeys = &Extra{
			Type:       AccessListTxType,
			GasPrice:   tx.GasPrice(),
			AccessList: tx.AccessList(),
			V:          v,
			R:          r,
			S:          s,
		}
	case DynamicFeeTxType:
		extrakeys = &Extra{
			Type:       DynamicFeeTxType,
			GasTipCap:  tx.GasTipCap(),
			GasFeeCap:  tx.GasFeeCap(),
			AccessList: tx.AccessList(),
			V:          v,
			R:          r,
			S:          s,
		}
	}
	extrakeys.Gas = tx.Gas()
	gtkmtx := &Transaction{
		ChainID:   cid,
		From:      tx.From(),
		To:        tx.To(),
		Nonce:     tx.Nonce(),
		UseLocal:  false,
		Val:       tx.Value(),
		Input:     tx.inner.data(),
		Version:   TxVersion,
		MultiSigs: nil,
	}
	if err := gtkmtx.SetExtraKeys(extrakeys); err != nil {
		return nil, err
	}
	return gtkmtx, nil
}

//
// // WithSignature returns a new transaction with the given signature.
// // This signature needs to be in the [R || S || V] format where V is 0 or 1.
// func (tx *ETHTransaction) WithSignature(signer Signer, sig []byte) (*ETHTransaction, error) {
// 	r, s, v, err := signer.SignatureValues(tx, sig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	cpy := tx.inner.copy()
// 	cpy.setSignatureValues(signer.ChainID(), v, r, s)
// 	return &ETHTransaction{inner: cpy, time: tx.time}, nil
// }

func (tx *ETHTransaction) MarshalBinary() ([]byte, error) {
	return rlp.EncodeToBytes(tx.inner)
}

func (tx *ETHTransaction) GetSigner() Signer {
	// return NewEIP2930Signer(tx.ChainId())
	return NewEIP2930Signer()
}

func (tx *ETHTransaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// Protected says whether the transaction is replay-protected.
func (tx *ETHTransaction) Protected() bool {
	switch tx := tx.inner.(type) {
	case *LegacyTx:
		return tx.V != nil && isProtectedV(tx.V)
	default:
		return true
	}
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28 && v != 1 && v != 0
	}
	// anything not 27 or 28 is considered protected
	return true
}

func (tx *ETHTransaction) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f {
		// It's a legacy transaction.
		var data LegacyTx
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		tx.setDecoded(&data, len(b))
		return nil
	}
	// It's an EIP2718 typed transaction envelope.
	inner, err := tx.decodeTyped(b)
	if err != nil {
		return err
	}
	tx.setDecoded(inner, len(b))
	return nil
}

// Type returns the transaction type.
func (tx *ETHTransaction) Type() uint8 {
	return tx.inner.TxType()
}

// decodeTyped decodes a typed transaction from the canonical format.
func (tx *ETHTransaction) decodeTyped(b []byte) (TxData, error) {
	if len(b) == 0 {
		return nil, errEmptyTypedTx
	}
	switch b[0] {
	case AccessListTxType:
		var inner AccessListTx
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	case DynamicFeeTxType:
		var inner DynamicFeeTx
		err := rlp.DecodeBytes(b[1:], &inner)
		return &inner, err
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// setDecoded sets the inner transaction and size after decoding.
func (tx *ETHTransaction) setDecoded(inner TxData, size int) {
	tx.inner = inner
	tx.time = time.Now()
	if size > 0 {
		tx.size.Store(StorageSize(size))
	}
}

// ChainId returns the EIP155 chain ID of the transaction. The return value will always be
// non-nil. For legacy transactions which are not replay-protected, the return value is
// zero.
func (tx *ETHTransaction) ChainId() *big.Int {
	// return tx.inner.chainID()
	chainid := tx.inner.chainID()
	if chainid == nil {
		return big.NewInt(1)
	}
	return chainid
}

// Data returns the input data of the transaction.
func (tx *ETHTransaction) Data() []byte { return tx.inner.data() }

func (tx *ETHTransaction) From() *common.Address {

	from, err := ETHSigner.Sender(tx)
	if err != nil {
		return nil
	}
	return &from
}

// AccessList returns the access list of the transaction.
func (tx *ETHTransaction) AccessList() AccessList { return tx.inner.accessList() }

// Gas returns the gas limit of the transaction.
func (tx *ETHTransaction) Gas() uint64 { return tx.inner.gas() }

// GasPrice returns the gas price of the transaction.
func (tx *ETHTransaction) GasPrice() *big.Int { return new(big.Int).Set(tx.inner.gasPrice()) }

// GasTipCap returns the gasTipCap per gas of the transaction.
func (tx *ETHTransaction) GasTipCap() *big.Int { return new(big.Int).Set(tx.inner.gasTipCap()) }

// GasFeeCap returns the fee cap per gas of the transaction.
func (tx *ETHTransaction) GasFeeCap() *big.Int { return new(big.Int).Set(tx.inner.gasFeeCap()) }

// Value returns the ether amount of the transaction.
func (tx *ETHTransaction) Value() *big.Int { return new(big.Int).Set(tx.inner.value()) }

// Nonce returns the sender account nonce of the transaction.
func (tx *ETHTransaction) Nonce() uint64 { return tx.inner.nonce() }

// To returns the recipient address of the transaction.
// For contract-creation transactions, To returns nil.
func (tx *ETHTransaction) To() *common.Address {
	// Copy the pointed-to address.
	ito := tx.inner.to()
	if ito == nil {
		return nil
	}
	cpy := *ito
	return &cpy
}

func (tx *ETHTransaction) Hash() common.Hash {
	var h common.Hash
	if tx.Type() == LegacyTxType {
		h = common.RlpHash(tx.inner)
	} else {
		h = common.PrefixedRlpHash(tx.Type(), tx.inner)
	}
	return h
}

func (tx *ETHTransaction) HashValue() ([]byte, error) {
	signer := tx.GetSigner()
	hash := signer.Hash(tx)
	return hash.Slice(), nil
}
