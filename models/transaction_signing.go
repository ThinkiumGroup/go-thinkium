package models

import (
	"encoding/hex"
	"errors"
	"math/big"

	c1 "github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-ecrypto/sha3"
)

var (
	ErrInvalidSig         = errors.New("invalid transaction v, r, s values")
	ErrTxTypeNotSupported = errors.New("transaction type not supported")
	errEmptyTypedTx       = errors.New("empty typed transaction bytes")
)

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *ETHTransaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *ETHTransaction, sig []byte) (r, s, v *big.Int, err error)
	// ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	Hash(tx *ETHTransaction) common.Hash
	HashGtkm(tx *Transaction) common.Hash
	HashGtkmWithSig(tx *Transaction) common.Hash
	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool
	RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error)
}

type londonSigner struct{ eip2930Signer }

// NewLondonSigner returns a signer that accepts
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
// func NewLondonSigner(chainId *big.Int) Signer {
// 	return londonSigner{eip2930Signer{NewEIP155Signer(chainId)}}
func NewLondonSigner() Signer {
	return londonSigner{eip2930Signer{NewEIP155Signer()}}
}

func (s londonSigner) Sender(tx *ETHTransaction) (common.Address, error) {
	if tx.Type() != DynamicFeeTxType {
		return s.eip2930Signer.Sender(tx)
	}
	V, R, S := tx.RawSignatureValues()

	// DynamicFee txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	V = new(big.Int).Add(V, big.NewInt(27))
	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return common.Address{}, ErrInvalidChainId
	// }
	_, _, addr, err := recoverPlain(s.Hash(tx), R, S, V, true)
	return addr, err
}

func (s londonSigner) Equal(s2 Signer) bool {
	// x, ok := s2.(londonSigner)
	// return ok && x.chainId == s.chainId
	_, ok := s2.(londonSigner)
	return ok
}

func (s londonSigner) SignatureValues(tx *ETHTransaction, sig []byte) (R, S, V *big.Int, err error) {
	// txdata, ok := tx.inner.(*DynamicFeeTx)
	_, ok := tx.inner.(*DynamicFeeTx)
	if !ok {
		return s.eip2930Signer.SignatureValues(tx, sig)
	}
	// // Check that chain ID of tx matches the signer. We also accept ID zero here,
	// // because it indicates that the chain ID was not specified in the tx.
	// if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
	// 	return nil, nil, nil, ErrInvalidChainId
	// }
	R, S, _ = DecodeSignature(sig)
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

func (s londonSigner) RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error) {
	if tx.Type() != DynamicFeeTxType {
		return s.eip2930Signer.RecoverSigAndPub(tx)
	}
	V, R, S := tx.RawSignatureValues()
	V = new(big.Int).Add(V, big.NewInt(27))

	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return nil, nil, ErrInvalidChainId
	// }
	sig, pub, _, err = recoverPlain(s.Hash(tx), R, S, V, true)
	return sig, pub, err
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s londonSigner) Hash(tx *ETHTransaction) common.Hash {
	if tx.Type() != DynamicFeeTxType {
		return s.eip2930Signer.Hash(tx)
	}
	return common.PrefixedRlpHash(
		tx.Type(),
		[]interface{}{
			// s.chainId,
			tx.ChainId(),
			tx.Nonce(),
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
		})
}

// HashGtkmWithSig returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s londonSigner) HashGtkmWithSig(tx *Transaction) common.Hash {
	if tx.Type() != DynamicFeeTxType {
		return s.eip2930Signer.HashGtkmWithSig(tx)
	}
	V, R, S := tx.RawSignatureValues()
	return common.PrefixedRlpHash(
		tx.Type(),
		[]interface{}{
			tx.ETHChainID(),
			tx.Nonce,
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To,
			tx.Val,
			tx.Input,
			tx.AccessList(),
			V, R, S,
		})
}

// HashGtkm returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s londonSigner) HashGtkm(tx *Transaction) common.Hash {
	if tx.Type() != DynamicFeeTxType {
		return s.eip2930Signer.HashGtkm(tx)
	}
	return common.PrefixedRlpHash(
		tx.Type(),
		[]interface{}{
			tx.ETHChainID(),
			tx.Nonce,
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To,
			tx.Val,
			tx.Input,
			tx.AccessList(),
		})
}

type eip2930Signer struct{ EIP155Signer }

// NewEIP2930Signer returns a signer that accepts EIP-2930 access list transactions,
// EIP-155 replay protected transactions, and legacy Homestead transactions.
// func NewEIP2930Signer(chainId *big.Int) Signer {
// 	return eip2930Signer{NewEIP155Signer(chainId)}
func NewEIP2930Signer() Signer {
	return eip2930Signer{NewEIP155Signer()}
}

// func (s eip2930Signer) ChainID() *big.Int {
// 	return s.chainId
// }

func (s eip2930Signer) Equal(s2 Signer) bool {
	// x, ok := s2.(eip2930Signer)
	// return ok && x.chainId == s.chainId
	_, ok := s2.(eip2930Signer)
	return ok
}

func (s eip2930Signer) Sender(tx *ETHTransaction) (common.Address, error) {
	V, R, S := tx.RawSignatureValues()
	switch tx.Type() {
	case LegacyTxType:
		if !tx.Protected() {
			return HomesteadSigner{}.Sender(tx)
		}
		V = recoverV(V, tx.ChainId())
		// V = new(big.Int).Sub(V, s.chainIdMul)
		// V.Sub(V, big8)
	case AccessListTxType:
		// AL txs are defined to use 0 and 1 as their recovery
		// id, add 27 to become equivalent to unprotected Homestead signatures.
		V = new(big.Int).Add(V, big.NewInt(27))
	default:
		return common.Address{}, ErrTxTypeNotSupported
	}
	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return common.Address{}, ErrInvalidChainId
	// }
	_, _, addr, err := recoverPlain(s.Hash(tx), R, S, V, true)
	return addr, err
}

func (s eip2930Signer) RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error) {
	V, R, S := tx.RawSignatureValues()
	switch tx.Type() {
	case LegacyTxType:
		if !tx.Protected() {
			return HomesteadSigner{}.RecoverSigAndPub(tx)
		}
		V = recoverV(V, tx.ChainId())
		// V = new(big.Int).Sub(V, s.chainIdMul)
		// V.Sub(V, big8)
	case AccessListTxType:
		// AL txs are defined to use 0 and 1 as their recovery
		// id, add 27 to become equivalent to unprotected Homestead signatures.
		V = new(big.Int).Add(V, big.NewInt(27))
	default:
		return nil, nil, ErrTxTypeNotSupported
	}
	// if tx.ChainId().Cmp(s.chainId) != 0 {
	// 	return nil, nil, ErrInvalidChainId
	// }
	sig, pub, _, err = recoverPlain(s.Hash(tx), R, S, V, true)
	return sig, pub, err
}

func (s eip2930Signer) SignatureValues(tx *ETHTransaction, sig []byte) (R, S, V *big.Int, err error) {

	// switch txdata := tx.inner.(type) {
	switch tx.inner.(type) {
	case *LegacyTx:
		return s.EIP155Signer.SignatureValues(tx, sig)
	case *AccessListTx:
		// // Check that chain ID of tx matches the signer. We also accept ID zero here,
		// // because it indicates that the chain ID was not specified in the tx.
		// if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
		// 	return nil, nil, nil, ErrInvalidChainId
		// }
		R, S, _ = DecodeSignature(sig)
		V = big.NewInt(int64(sig[64]))
	default:
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip2930Signer) Hash(tx *ETHTransaction) common.Hash {
	switch tx.Type() {
	case LegacyTxType:
		return common.RlpHash([]interface{}{
			tx.Nonce(),
			tx.GasPrice(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.ChainId(), uint(0), uint(0),
		})
	case AccessListTxType:
		return common.PrefixedRlpHash(
			tx.Type(),
			[]interface{}{
				tx.ChainId(),
				tx.Nonce(),
				tx.GasPrice(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(),
			})
	default:
		// This _should_ not happen, but in case someone sends in a bad
		// json struct via RPC, it's probably more prudent to return an
		// empty hash instead of killing the node with a panic
		// panic("Unsupported transaction type: %d", tx.typ)
		return common.Hash{}
	}
}

// HashGtkm returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip2930Signer) HashGtkm(tx *Transaction) common.Hash {
	switch tx.Type() {
	case LegacyTxType:
		var objs []interface{}
		if tx.UseLocal {
			objs = []interface{}{
				tx.Nonce,
				tx.GasPrice(),
				tx.Gas(),
				tx.To,
				tx.Val,
				tx.UseLocal,
				tx.Input,
				tx.ETHChainID(), uint(0), uint(0),
			}
		} else {
			objs = []interface{}{
				tx.Nonce,
				tx.GasPrice(),
				tx.Gas(),
				tx.To,
				tx.Val,
				tx.Input,
				tx.ETHChainID(), uint(0), uint(0),
			}
		}
		keys := tx.ExtraKeys()
		if len(keys.TkmExtra) > 0 {
			// processing the unique fields of thinkium tx
			objs = append(objs, keys.TkmExtra)
		}
		return common.RlpHash(objs)
	case AccessListTxType:
		return common.PrefixedRlpHash(
			tx.Type(),
			[]interface{}{
				tx.ETHChainID(),
				tx.Nonce,
				tx.GasPrice(),
				tx.Gas(),
				tx.To,
				tx.Val,
				tx.Input,
				tx.AccessList(),
			})
	default:
		// This _should_ not happen, but in case someone sends in a bad
		// json struct via RPC, it's probably more prudent to return an
		// empty hash instead of killing the node with a panic
		// panic("Unsupported transaction type: %d", tx.typ)
		return common.Hash{}
	}
}

// HashGtkmWithSig returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s eip2930Signer) HashGtkmWithSig(tx *Transaction) common.Hash {
	V, R, S := tx.RawSignatureValues()
	switch tx.Type() {
	case LegacyTxType:
		var objs []interface{}
		if tx.UseLocal {
			objs = []interface{}{
				tx.Nonce,
				tx.GasPrice(),
				tx.Gas(),
				tx.To,
				tx.Val,
				tx.UseLocal,
				tx.Input,
				V, R, S,
			}
			// return common.RlpHash()
		} else {
			objs = []interface{}{
				tx.Nonce,
				tx.GasPrice(),
				tx.Gas(),
				tx.To,
				tx.Val,
				tx.Input,
				V, R, S,
			}
		}
		keys := tx.ExtraKeys()
		if len(keys.TkmExtra) > 0 || len(tx.MultiSigs) > 0 {
			// processing the unique fields of thinkium tx
			objs = append(objs, keys.TkmExtra)
			if len(tx.MultiSigs) > 0 {
				for _, pas := range tx.MultiSigs {
					if pas == nil {
						continue
					}
					objs = append(objs, pas.Signature)
				}
			}
		}
		return common.RlpHash(objs)
	case AccessListTxType:
		return common.PrefixedRlpHash(
			tx.Type(),
			[]interface{}{
				tx.ETHChainID(),
				tx.Nonce,
				tx.GasPrice(),
				tx.Gas(),
				tx.To,
				tx.Val,
				tx.Input,
				tx.AccessList(),
				V, R, S,
			})
	default:
		// This _should_ not happen, but in case someone sends in a bad
		// json struct via RPC, it's probably more prudent to return an
		// empty hash instead of killing the node with a panic
		// panic("Unsupported transaction type: %d", tx.typ)
		return common.Hash{}
	}
}

// EIP155Signer implements Signer using the EIP-155 rules. This accepts transactions which
// are replay-protected as well as unprotected homestead transactions.
type EIP155Signer struct {
	// chainId, chainIdMul *big.Int
}

// func NewEIP155Signer(chainId *big.Int) EIP155Signer {
func NewEIP155Signer() EIP155Signer {
	// if chainId == nil {
	// 	chainId = new(big.Int)
	// }
	// return EIP155Signer{
	// 	chainId:    chainId,
	// 	chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	// }
	return EIP155Signer{}
}

//
// func (s EIP155Signer) ChainID() *big.Int {
// 	return s.chainId
// }

func (s EIP155Signer) Equal(s2 Signer) bool {
	// eip155, ok := s2.(EIP155Signer)
	// return ok && eip155.chainId == (s.chainId)
	_, ok := s2.(EIP155Signer)
	return ok
}

var big8 = big.NewInt(8)

func (s EIP155Signer) Sender(tx *ETHTransaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	if !tx.Protected() {
		return HomesteadSigner{}.Sender(tx)
	}
	// if tx.ChainId() != s.chainId {
	// 	return common.Address{}, ErrInvalidChainId
	// }
	V, R, S := tx.RawSignatureValues()
	V = recoverV(V, tx.ChainId())
	// V = new(big.Int).Sub(V, s.chainIdMul)
	// V.Sub(V, big8)
	_, _, addr, err := recoverPlain(s.Hash(tx), R, S, V, true)
	return addr, err
}

func (s EIP155Signer) RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, ErrTxTypeNotSupported
	}
	if !tx.Protected() {
		return HomesteadSigner{}.RecoverSigAndPub(tx)
	}
	// if tx.ChainId() != s.chainId {
	// 	return nil, nil, ErrInvalidChainId
	// }
	V, R, S := tx.RawSignatureValues()
	V = recoverV(V, tx.ChainId())
	// V = new(big.Int).Sub(V, s.chainIdMul)
	// V.Sub(V, big8)
	sig, pub, _, err = recoverPlain(s.Hash(tx), R, S, V, true)
	return sig, pub, err
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s EIP155Signer) SignatureValues(tx *ETHTransaction, sig []byte) (R, S, V *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	R, S, V = DecodeSignature(sig)
	// if s.chainId.Sign() != 0 {
	txchainid := tx.ChainId()
	if txchainid != nil && txchainid.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, new(big.Int).Mul(txchainid, big.NewInt(2)))
		// V.Add(V, s.chainIdMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) Hash(tx *ETHTransaction) common.Hash {
	chainid := tx.ChainId()
	return common.RlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		chainid, uint(0), uint(0),
	})
}

// HashGtkm returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) HashGtkm(tx *Transaction) common.Hash {
	return common.RlpHash([]interface{}{
		tx.Nonce,
		tx.GasPrice(),
		tx.Gas(),
		tx.To,
		tx.Val,
		tx.Input,
		big.NewInt(int64(tx.ChainID)), uint(0), uint(0),
	})
}

// HashGtkmWithSig returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155Signer) HashGtkmWithSig(tx *Transaction) common.Hash {
	V, R, S := tx.RawSignatureValues()
	return common.RlpHash([]interface{}{
		tx.Nonce,
		tx.GasPrice(),
		tx.Gas(),
		tx.To,
		tx.Val,
		tx.Input,
		V, R, S,
	})
}

// HomesteadSigner HomesteadTransaction implements TransactionInterface using the
// homestead rules.
type HomesteadSigner struct{ FrontierSigner }

func (h HomesteadSigner) ChainID() *big.Int {
	return nil
}

func (h HomesteadSigner) Equal(s2 Signer) bool {
	_, ok := s2.(HomesteadSigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (h HomesteadSigner) SignatureValues(tx *ETHTransaction, sig []byte) (r, s, v *big.Int, err error) {
	return h.FrontierSigner.SignatureValues(tx, sig)
}

func (h HomesteadSigner) Sender(tx *ETHTransaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	_, _, addr, err := recoverPlain(h.Hash(tx), r, s, v, true)
	return addr, err
}

func (h HomesteadSigner) RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	sig, pub, _, err = recoverPlain(h.Hash(tx), r, s, v, true)
	return sig, pub, err
}

type FrontierSigner struct{}

func (f FrontierSigner) ChainID() *big.Int {
	return nil
}

func (f FrontierSigner) Equal(s2 Signer) bool {
	_, ok := s2.(FrontierSigner)
	return ok
}

func (f FrontierSigner) Sender(tx *ETHTransaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	_, _, addr, err := recoverPlain(f.Hash(tx), r, s, v, false)
	return addr, err
}

func (f FrontierSigner) RecoverSigAndPub(tx *ETHTransaction) (sig, pub []byte, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	sig, pub, _, err = recoverPlain(f.Hash(tx), r, s, v, false)
	return sig, pub, err
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (f FrontierSigner) SignatureValues(tx *ETHTransaction, sig []byte) (r, s, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	r, s, v = DecodeSignature(sig)
	return r, s, v, nil
}

func (f FrontierSigner) RecoverSig(tx *ETHTransaction) (sig []byte) {
	if tx.Type() != LegacyTxType {
		return nil
	}
	v, r, s := tx.inner.rawSignatureValues()
	sig = append(sig, r.Bytes()...)
	sig = append(sig, s.Bytes()...)
	sig = append(sig, v.Bytes()...)
	return sig
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (f FrontierSigner) Hash(tx *ETHTransaction) common.Hash {
	return common.RlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
	})
}

// HashGtkm returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (f FrontierSigner) HashGtkm(tx *Transaction) common.Hash {
	return common.RlpHash([]interface{}{
		tx.Nonce,
		tx.GasPrice(),
		tx.Gas(),
		tx.To,
		tx.Val,
		tx.Input,
	})
}

// HashGtkm returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (f FrontierSigner) HashGtkmWithSig(tx *Transaction) common.Hash {
	V, R, S := tx.RawSignatureValues()
	return common.RlpHash([]interface{}{
		tx.Nonce,
		tx.GasPrice(),
		tx.Gas(),
		tx.To,
		tx.Val,
		tx.Input,
		V, R, S,
	})
}

func DecodeSignature(sig []byte) (r, s, v *big.Int) {
	if len(sig) != common.RealCipher.LengthOfSignature() {
		log.Errorf("wrong size for signature: got %d, want %d", len(sig), common.RealCipher.LengthOfSignature())
		return nil, nil, nil
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (sig, pub []byte, addr common.Address, err error) {
	hex.EncodeToString(sighash.Bytes())
	if Vb.BitLen() > 8 {
		return nil, nil, common.Address{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !sha3.ValidateSignatureValues(V, R, S, homestead) {
		return nil, nil, common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig = make([]byte, common.RealCipher.LengthOfSignature())
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err = c1.Ecrecover(sighash[:], sig)
	if err != nil {
		return nil, nil, common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, nil, common.Address{}, errors.New("invalid public key")
	}
	copy(addr[:], common.SystemHash256(pub[1:])[12:])
	return sig, pub, addr, nil
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}

func recoverV(v *big.Int, chainId *big.Int) *big.Int {
	chainIdMul := new(big.Int).Mul(chainId, big.NewInt(2))
	vv := new(big.Int).Sub(v, chainIdMul)
	vv.Sub(vv, big8)
	return vv
}
