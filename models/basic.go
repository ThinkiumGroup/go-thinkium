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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/stephenfire/go-rtl"
)

type BlockHeighter interface {
	GetHeight() common.Height
	Hash() common.Hash
}

var TypeOfTransactionPtr = reflect.TypeOf((*Transaction)(nil))

type Transaction struct {
	ChainID   common.ChainID  `json:"chainID"`   // The chain ID that needs to process this transaction
	From      *common.Address `json:"from"`      // Address of transaction transmitter
	To        *common.Address `json:"to"`        // Address of transaction receiver
	Nonce     uint64          `json:"nonce"`     // Nonce of sender account
	UseLocal  bool            `json:"uselocal"`  // true: local currency，false: basic currency; default false
	Val       *big.Int        `json:"value"`     // Amount of the transaction
	Input     hexutil.Bytes   `json:"input"`     // Contract code/initial parameters when creating a contract, or input parameters when calling a contract
	Extra     hexutil.Bytes   `json:"extra"`     // Store transaction additional information
	Version   uint16          `json:"version"`   // Version number used to distinguish different execution methods when the transaction execution is incompatible due to upgrade
	MultiSigs PubAndSigs      `json:"multiSigs"` // The signatures used to sign this transaction will only be used when there are multiple signatures. The signature of the transaction sender is not here. Not included in Hash
	_cache    *Extra
}

type Extra struct {
	Type       byte     `json:"type"`
	Gas        uint64   `json:"gas"`
	GasPrice   *big.Int `json:"gasPrice"` // wei per gas
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	AccessList AccessList
	V, R, S    *big.Int
	TkmExtra   []byte
}

func (x *Extra) SetTkmExtra(extra []byte) error {
	if len(extra) == 0 {
		x.TkmExtra = nil
		return nil
	}
	var inputExtra map[string]interface{}
	if err := json.Unmarshal(extra, &inputExtra); err != nil {
		return fmt.Errorf("unmarshal extra failed: %v", err)
	}
	if gas, ok := inputExtra["gas"]; ok {
		x.Gas = uint64(gas.(float64))
		if len(inputExtra) == 1 {
			// "gas" only
			x.TkmExtra = nil
			return nil
		}
	}
	x.TkmExtra = extra
	return nil
}

func (x *Extra) String() string {
	if x == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{type:%d gas:%d gasPrice:%s GasTipCap:%s GasFeeCap:%s AccessList:%v V:%s R:%s S:%s TkmExtra:%s}",
		x.Type, x.Gas, math.BigIntForPrint(x.GasPrice), math.BigIntForPrint(x.GasTipCap), math.BigIntForPrint(x.GasFeeCap),
		x.AccessList, math.BigIntForPrint(x.V), math.BigIntForPrint(x.R), math.BigIntForPrint(x.S), string(x.TkmExtra))
}

// EthKeys Type returns the ethtransaction type.
func (tx *Transaction) ExtraKeys() (extra *Extra) {
	if tx._cache != nil {
		return tx._cache
	}
	defer func() {
		tx._cache = extra
	}()
	extra = &Extra{Type: LegacyTxType}
	if len(tx.Extra) == 0 {
		return extra
	}
	if tx.Version < ETHHashTxVersion {
		extra.SetTkmExtra(tx.Extra)
		return extra
	}
	_ = json.Unmarshal(tx.Extra, extra)
	return extra
}

func (tx *Transaction) SetExtraKeys(extras *Extra) error {
	if extrabs, err := json.Marshal(extras); err != nil {
		return fmt.Errorf("marshal extraKeys failed: %v", err)
	} else {
		tx.Extra = extrabs
		tx._cache = nil
	}
	return nil
}

func (tx *Transaction) SetTkmExtra(extra []byte) error {
	if len(extra) == 0 {
		return nil
	}
	extras := tx.ExtraKeys()
	extras.SetTkmExtra(extra)
	return tx.SetExtraKeys(extras)
}

func (tx *Transaction) GetTkmExtra() []byte {
	if tx.Version < ETHHashTxVersion {
		return tx.Extra
	}
	if len(tx.Extra) == 0 {
		return nil
	}
	return tx.ExtraKeys().TkmExtra
}

func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	ethkeys := tx.ExtraKeys()
	return ethkeys.V, ethkeys.R, ethkeys.S
}

// Type returns the ethtransaction type of tx.
func (tx *Transaction) Type() byte {
	return tx.ExtraKeys().Type
}

func (tx *Transaction) GasPrice() *big.Int {
	return tx.ExtraKeys().GasPrice
}

func (tx *Transaction) GasTipCap() *big.Int {
	return tx.ExtraKeys().GasTipCap
}

func (tx *Transaction) GasFeeCap() *big.Int {
	return tx.ExtraKeys().GasFeeCap
}

func (tx *Transaction) Gas() uint64 {
	return tx.ExtraKeys().Gas
}

func (tx *Transaction) AccessList() AccessList {
	return tx.ExtraKeys().AccessList
}

func (tx *Transaction) Clone() *Transaction {
	return &Transaction{
		ChainID:   tx.ChainID,
		From:      tx.From.Clone(),
		To:        tx.To.Clone(),
		Nonce:     tx.Nonce,
		UseLocal:  tx.UseLocal,
		Val:       math.CopyBigInt(tx.Val),
		Input:     common.CopyBytes(tx.Input),
		Extra:     common.CopyBytes(tx.Extra),
		Version:   tx.Version,
		MultiSigs: tx.MultiSigs.Clone(),
	}
}

func (tx Transaction) String() string {
	return fmt.Sprintf("Tx.%d{ChainID:%d From:%v To:%v Nonce:%d UseLocal:%t Val:%s len(Input):%d "+
		"len(Extra):%d MSigs:%d}", tx.Version, tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal,
		math.BigIntForPrint(tx.Val), len(tx.Input), len(tx.Extra), len(tx.MultiSigs))
}

func (tx Transaction) FullString() string {
	var input string
	var extra string
	if tx.Input != nil {
		input = hex.EncodeToString(tx.Input)
	}
	if tx.Extra != nil {
		extra = string(tx.Extra)
	}
	return fmt.Sprintf("Tx.%d{ChainID:%d From:%v To:%v Nonce:%d UseLocal:%t Val:%s Input:%s ExtraStr:%s Extras:%s MSigs:%s}",
		tx.Version, tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, math.BigIntForPrint(tx.Val), input, extra, tx.ExtraKeys(), tx.MultiSigs)
}

func (tx Transaction) GetChainID() common.ChainID {
	return tx.ChainID
}

func _uint2bigint(ui64 uint64) *big.Int {
	bs := rtl.Numeric.UintToBytes(ui64)
	return new(big.Int).SetBytes(bs)
}

func ETHChainID(tkmChainID common.ChainID, txVersion uint16) uint64 {
	if tkmChainID.IsNil() {
		return uint64(tkmChainID)
	}
	if txVersion > ETHHashTxVersion {
		return uint64(tkmChainID) + common.BigChainIDBase
	} else if txVersion == ETHHashTxVersion {
		return uint64(tkmChainID) + common.BigChainIDBaseV2
	} else {
		return uint64(tkmChainID)
	}
}

func ETHChainIDBig(tkmChainID common.ChainID, txVersion uint16) *big.Int {
	if tkmChainID.IsNil() {
		return nil
	}
	return _uint2bigint(ETHChainID(tkmChainID, txVersion))
}

func FromETHChainID(ethChainId *big.Int) (common.ChainID, error) {
	if ethChainId == nil {
		return common.NilChainID, errors.New("nil chain id")
	}
	if !ethChainId.IsUint64() {
		return common.NilChainID, errors.New("chain id not available")
	}
	ethcid := ethChainId.Uint64()
	maxChainID := uint64(math.MaxUint32) + common.BigChainIDBase
	if ethcid > maxChainID || ethcid < common.BigChainIDBase {
		return common.NilChainID, errors.New("chain id out of range")
	}
	cid := ethcid - common.BigChainIDBase
	return common.ChainID(cid), nil
}

func (tx *Transaction) ETHChainID() *big.Int {
	if tx == nil {
		return nil
	}
	return _uint2bigint(ETHChainID(tx.ChainID, tx.Version))
}

func (tx *Transaction) Hash() common.Hash {
	if tx.Version >= ETHHashTxVersion {
		return ETHSigner.HashGtkmWithSig(tx)
	}

	hasher := common.RealCipher.Hasher()
	p := TransactionStringForHash(tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, tx.Val, tx.Input, tx.Extra)
	if _, err := hasher.Write([]byte(p)); err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(hasher.Sum(nil))
}

func (tx Transaction) HashValue() ([]byte, error) {
	if tx.Version >= ETHHashTxVersion {
		hoe := ETHSigner.HashGtkm(&tx)
		return hoe.Slice(), nil
	}

	hasher := common.RealCipher.Hasher()
	p := TransactionStringForHash(tx.ChainID, tx.From, tx.To, tx.Nonce, tx.UseLocal, tx.Val, tx.Input, tx.Extra)
	if _, err := hasher.Write([]byte(p)); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// DeprecatedHash TODO delete compatible when restart the chain with new version
// Deprecated
func (tx Transaction) DeprecatedHash() ([]byte, error) {
	var t string
	if tx.To == nil {
		t = ""
	} else {
		t = tx.To.String()
	}
	var str []string
	if tx.UseLocal {
		// In order to ensure the consistency with the previous version Tx.Hash In this way,
		// the transactionroot in the previous header will remain unchanged when the object changes
		str = append(str, "L")
	}
	// To avoid different input/extra combinations to form the same hash source, a separator not
	// included in hex code is used in the middle. In order to maintain hash compatibility with
	// the old version of TX, only len (extra) >0 has this separator
	extraTag := ""
	if len(tx.Extra) > 0 {
		extraTag = "-"
	}
	str = append(str, []string{
		tx.ChainID.String(),
		tx.From.String(),
		t,
		strconv.FormatUint(tx.Nonce, 10),
		tx.Val.String(),
		hex.EncodeToString(tx.Input),
		extraTag,
		hex.EncodeToString(tx.Extra),
	}...)
	p := strings.Join(str, "")
	return common.Hash256s([]byte(p))
}

func TransactionStringForHash(chainid common.ChainID, from *common.Address, to *common.Address, nonce uint64,
	uselocal bool, val *big.Int, input []byte, extra []byte) string {
	t := ""
	if to != nil {
		t = to.String()
	}
	u := "0"
	if uselocal {
		u = "1"
	}
	var str []string
	str = append(str, []string{
		chainid.String(),
		from.String(),
		t,
		strconv.FormatUint(nonce, 10),
		u,
		val.String(),
		hex.EncodeToString(input),
		hex.EncodeToString(extra),
	}...)
	p := strings.Join(str, "-")
	return p
}

type CommReport struct {
	ChainId   common.ChainID
	ToChainId common.ChainID
	EpochNum  common.EpochNum
	Comm      *Committee
}

func (r *CommReport) GetChainID() common.ChainID {
	return r.ToChainId
}

func (r *CommReport) Hash() common.Hash {
	if r == nil {
		return common.Hash{}
	}
	return common.EncodeHash(r)
}

// BlockReport report of Block
type BlockReport struct {
	ToChainId   common.ChainID
	BlockHeader *BlockHeader    // the header of the reporting block
	NextComm    *EpochCommittee // next committee when election finished
	BlockPass   []*PubAndSig    // signatures of committee members who comfirmed reporting block. can be changed to aggregate signature in the future
}

func (r *BlockReport) GetChainID() common.ChainID {
	if r == nil || r.BlockHeader == nil {
		return common.NilChainID
	}
	return r.ToChainId
}

func (r *BlockReport) DestChainID() common.ChainID {
	if r == nil || r.BlockHeader == nil {
		return common.NilChainID
	}
	return r.ToChainId
}

func (r *BlockReport) Hash() common.Hash {
	if r.BlockHeader == nil {
		return common.Hash{}
	}
	bp := r.BlockPass
	r.BlockPass = nil
	hash := common.EncodeHash(r)
	r.BlockPass = bp
	return hash
}

func (r *BlockReport) Verify() error {
	if r == nil || r.BlockHeader == nil || len(r.BlockPass) == 0 {
		return errors.New("report and report.header and report.pass should not be nil")
	}
	if r.NextComm != nil {
		ncroot := r.NextComm.Hash()
		if !common.HashEquals(&ncroot, r.BlockHeader.ElectedNextRoot) {
			return fmt.Errorf("NextComm:%s Root:%x not match Root:%x in header", r.NextComm, ncroot[:5],
				common.ForPrint(r.BlockHeader.ElectedNextRoot))
		}
	}
	return nil
}

func (r *BlockReport) String() string {
	if r == nil {
		return "BlockReport<nil>"
	}
	return fmt.Sprintf("BlockReport{From:%d To:%d Height:%d Comm:%s Pass:%d}",
		r.BlockHeader.ChainID, r.ToChainId, r.BlockHeader.Height, r.NextComm, len(r.BlockPass))
}

type BlockSummary struct {
	ChainId   common.ChainID
	Height    common.Height
	BlockHash common.Hash
	// since v1.5.0, the election result of the next committee whill be packaged together.
	// Because only the data and comm node will receive the report and record the next committee
	// of the sub chain. Since the new elected node has already been synchronizing the main chain,
	// it will not synchronize the data again, then it will not be able to synchronize all the sub
	// chain committee information, resulting in the nodes missing the corresponding information
	// when the new epoch begins.
	NextComm *EpochCommittee
	// V0's BlockSummary.Hash is same with blockhash, which can't reflect the location information
	// of the block, and can't complete the proof of cross chain. V1 adds chainid and height to hash
	Version uint16
}

func (s *BlockSummary) GetChainID() common.ChainID {
	return s.ChainId
}

func (s *BlockSummary) Hash() common.Hash {
	switch s.Version {
	case 1:
		// since v2.0.3, incompatible with previous version
		h, _ := s.HashValue()
		return common.BytesToHash(h)
	default:
		return s.BlockHash
	}
}

func (s *BlockSummary) String() string {
	if s == nil {
		return "Summary<nil>"
	}
	if s.NextComm == nil {
		return fmt.Sprintf("Summary.%d{ChainId:%d Height:%d BlockHash:%x}",
			s.Version, s.ChainId, s.Height, s.BlockHash[:5])
	} else {
		return fmt.Sprintf("Summary.%d{ChainId:%d Height:%d BlockHash:%x NextComm:%s}",
			s.Version, s.ChainId, s.Height, s.BlockHash[:5], s.NextComm.String())
	}
}

func (s *BlockSummary) SummaryHash() ([]byte, error) {
	if s.Version != SummaryVersion {
		return nil, errors.New("miss match summary version")
	}
	buf := common.ToHeaderPosHashBuffer(s.ChainId, s.Height)
	return common.Hash256s(buf[:12])
}

func (s *BlockSummary) HashValue() ([]byte, error) {
	switch s.Version {
	case 1:
		// since v2.0.3，In order to prove that the data really belongs to the claimed block
		// height when the delta is transmitted, the chain ID and block height information are
		// added to the hash of the summary. As a result, the data will not be compatible with
		// the previous version
		shash, err := s.SummaryHash()
		if err != nil {
			return nil, err
		}
		return common.HashPair(shash, s.BlockHash[:]), nil
	default:
		return s.BlockHash.Bytes(), nil
	}
}

type HeaderSummary struct {
	Header    *BlockHeader
	Summaries []*BlockSummary
}

func (s *HeaderSummary) GetChainID() common.ChainID {
	return s.Header.ChainID
}

func (s *HeaderSummary) Hash() common.Hash {
	return s.Header.Hash()
}

func (s *HeaderSummary) String() string {
	return fmt.Sprintf("HeaderSummary{ChainId:%d, Height:%d, BlockHash:%s}", s.Header.ChainID, s.Header.Height, s.Header.Hash())
}

func (s *HeaderSummary) Find(chainId common.ChainID, height common.Height) (index int, summary *BlockSummary) {
	index = -1
	if s == nil {
		return
	}
	for i, su := range s.Summaries {
		if su != nil && su.ChainId == chainId && su.Height == height {
			index = i
			return
		}
	}
	return
}

// HeaderProof Get the proof from a packaged HeaderSummary in the current block to the hash of this block
func (s *HeaderSummary) HeaderProof(hashOfHeader []byte, proofChain *trie.ProofChain) ([]byte, error) {
	if len(s.Summaries) == 0 {
		return nil, errors.New("no summary found")
	}
	if len(s.Summaries) > 0 {
		toBeProof := -1
		for idx, sm := range s.Summaries {
			if bytes.Equal(sm.BlockHash[:], hashOfHeader) {
				toBeProof = idx
				break
			}
		}
		if toBeProof >= 0 {
			mProofs := common.NewMerkleProofs()
			hdsRoot, err := common.ValuesMerkleTreeHash(s.Summaries, toBeProof, mProofs)
			if !bytes.Equal(hdsRoot, s.Header.HdsRoot.Bytes()) {
				return nil, fmt.Errorf("HeaderProof hds root miss match %s", s.Header)
			}
			summaryHash, err := s.Summaries[toBeProof].SummaryHash()
			if err != nil {
				return nil, err
			}
			nProof := trie.NewHdsSummaryProof(common.BytesToHashP(summaryHash), mProofs)
			// nProof := trie.NewMerkleOnlyProof(trie.ProofMerkleOnly, mProofs)
			*proofChain = append(*proofChain, nProof)

			hs, err := s.Header.MakeProof(trie.ProofHeaderHdsRoot, proofChain)
			if err != nil {
				return nil, err
			}
			return hs, nil
		}
	}
	return nil, errors.New("header not included by summaries")
}

type BlockRequest struct {
	ChainId common.ChainID
	Height  common.Height
	NodeId  common.NodeID
}

func (b *BlockRequest) GetChainID() common.ChainID {
	return b.ChainId
}

func (b *BlockRequest) GetHeight() common.Height {
	return b.Height
}

func (b *BlockRequest) String() string {
	return fmt.Sprintf("BlockRequest{ChainID:%d Height:%d NodeId %s}",
		b.ChainId, b.Height, b.NodeId)
}

type BlockEMessage struct {
	BlockHeader *BlockHeader
	BlockBody   *BlockBody
	BlockPass   PubAndSigs
}

func (b *BlockEMessage) BlockNum() common.BlockNum {
	return b.BlockHeader.Height.BlockNum()
}

func (b *BlockEMessage) EpochNum() common.EpochNum {
	return b.BlockHeader.Height.EpochNum()
}

func (b *BlockEMessage) GetChainID() common.ChainID {
	return b.BlockHeader.ChainID
}

func (b *BlockEMessage) GetHeight() common.Height {
	if b.BlockHeader == nil {
		return 0
	}
	return b.BlockHeader.GetHeight()
}

func (b *BlockEMessage) GetHistoryRoot() []byte {
	if b == nil {
		return nil
	}
	return b.BlockHeader.GetHistoryRoot()
}

func (b *BlockEMessage) Hash() common.Hash {
	if b.BlockHeader == nil {
		return common.Hash{}
	}
	return b.BlockHeader.Hash()
}

func (b *BlockEMessage) InfoString() string {
	if b == nil || b.BlockHeader == nil {
		return ""
	}
	return b.BlockHeader.InfoString()
}

func (b *BlockEMessage) String() string {
	if b == nil || b.BlockHeader == nil {
		return "{}"
	}
	if b.BlockHeader.Empty {
		return fmt.Sprintf("{ChainID:%d EpochNum:%d BlockNum:%d Empty}",
			b.GetChainID(), b.EpochNum(), b.BlockNum())
	}
	return fmt.Sprintf("{ChainID:%d EpochNum:%d BlockNum:%d}",
		b.GetChainID(), b.EpochNum(), b.BlockNum())
}

func (b *BlockEMessage) EraString() string {
	if b == nil || b.BlockHeader == nil {
		return "{}"
	}
	if b.BlockHeader.Empty {
		return fmt.Sprintf("{ChainID:%d EpochNum:%d BlockNum:%d Empty} RREra:%s RR:%x RRN:%x RRC:%x",
			b.GetChainID(), b.EpochNum(), b.BlockNum(), b.BlockHeader.RREra,
			common.ForPrint(b.BlockHeader.RRRoot), common.ForPrint(b.BlockHeader.RRNextRoot),
			common.ForPrint(b.BlockHeader.RRChangingRoot))
	} else {
		return fmt.Sprintf("{ChainID:%d EpochNum:%d BlockNum:%d} RREra:%s RR:%x RRN:%x RRC:%x",
			b.GetChainID(), b.EpochNum(), b.BlockNum(), b.BlockHeader.RREra,
			common.ForPrint(b.BlockHeader.RRRoot), common.ForPrint(b.BlockHeader.RRNextRoot),
			common.ForPrint(b.BlockHeader.RRChangingRoot))
	}
}

func (b *BlockEMessage) Formalize() {
	if b == nil {
		return
	}
	if b.BlockBody != nil {
		b.BlockBody.Formalize()
	}
	if len(b.BlockPass) > 1 {
		sort.Sort(b.BlockPass)
	}
}

func checkBlockHashs(name string, fromHeader *common.Hash, fromBody func() (*common.Hash, error)) error {
	root, err := fromBody()
	if err != nil {
		return fmt.Errorf("%s check error: %v", name, err)
	}
	if !common.HashEquals(fromHeader, root) {
		return fmt.Errorf("%s check failed: fromBody:%x fromHeader:%x",
			name, common.ForPrint(root), common.ForPrint(fromHeader))
	}
	return nil
}

// CheckHashs Recalculate and verify the data in the header according to the body data, and return the
// corresponding error if it fails
func (b *BlockEMessage) CheckHashs() error {
	// AttendanceHash
	if err := checkBlockHashs("attendance", b.BlockHeader.AttendanceHash, b.BlockBody.AttendanceRoot); err != nil {
		return err
	}
	// ElectedNextRoot
	if err := checkBlockHashs("NextComm", b.BlockHeader.ElectedNextRoot, b.BlockBody.NextCommitteeRoot); err != nil {
		return err
	}
	// BalanceDeltaRoot: database needed when check this, It can only verify when the data is received and put into storage

	// TransactionRoot
	if err := checkBlockHashs("transactions", b.BlockHeader.TransactionRoot, b.BlockBody.TransactionsRoot); err != nil {
		return err
	}
	// HdsRoot
	if err := checkBlockHashs("hds", b.BlockHeader.HdsRoot, b.BlockBody.HdsRoot); err != nil {
		return err
	}
	// ElectResultRoot
	if err := checkBlockHashs("ElectResults", b.BlockHeader.ElectResultRoot, b.BlockBody.ElectResultRoot); err != nil {
		return err
	}
	// PreElectRoot
	if err := checkBlockHashs("preelects", b.BlockHeader.PreElectRoot, b.BlockBody.PreElectRoot); err != nil {
		return err
	}

	// since 2.0.0 SeedFactorRoot
	if err := checkBlockHashs("seedFactor", b.BlockHeader.FactorRoot, b.BlockBody.SeedFactorRoot); err != nil {
		return err
	}
	return nil
}

type BlockHeader struct {
	PreviousHash   common.Hash    `json:"previoushash"` // the hash of the previous block header on current chain
	HashHistory    common.Hash    `json:"history"`      // hash of the history tree of hash for each block recorded in height order
	ChainID        common.ChainID `json:"chainid"`      // current chain id
	Height         common.Height  `json:"height"`       // height of current block
	Empty          bool           `json:"empty"`        // empty block
	ParentHeight   common.Height  `json:"-"`            // height of parent height, is 0 if current is main chain
	ParentHash     *common.Hash   `json:"-"`            // block hash of main chain block at ParentHeight, nil if current is main chain
	RewardAddress  common.Address `json:"-"`            // reward to
	AttendanceHash *common.Hash   `json:"-"`            // The current epoch attendance record hash
	RewardedCursor *common.Height `json:"-"`            // If the current chain is the reward chain, record start height of main chain when next reward issues

	CommitteeHash    *common.Hash   `json:"-"`    // current epoch Committee member trie root hash
	ElectedNextRoot  *common.Hash   `json:"-"`    // root hash of the election result of next epoch committee members
	NewCommitteeSeed *common.Seed   `json:"seed"` // Current election seeds, only in the main chain
	RREra            *common.EraNum `json:"-"`    // the era corresponding to the root of the current Required Reserve tree. When this value is inconsistent with the height of main chain, it indicates that a new RR tree needs to be calculated
	RRRoot           *common.Hash   `json:"-"`    // root hash of the Required Reserve tree in current era. Only in the reward chain and the main chain
	RRNextRoot       *common.Hash   `json:"-"`    // root hash of the Required Reserve tree in next era. Only in the reward chain and the main chain
	RRChangingRoot   *common.Hash   `json:"-"`    // changes waiting to be processed in current era

	MergedDeltaRoot  *common.Hash `json:"mergeroot"` // Root hash of the merged delta sent from other shards
	BalanceDeltaRoot *common.Hash `json:"deltaroot"` // Root hash of the generated deltas by this block which needs to be sent to the other shards
	StateRoot        common.Hash  `json:"stateroot"` // account on current chain state trie root hash
	ChainInfoRoot    *common.Hash `json:"-"`         // for main chain only: all chain info trie root hash
	WaterlinesRoot   *common.Hash `json:"-"`         // since v2.3.0, the waterlines of other shards to current chain after the execution of this block. nil represent all zeros. Because the value of the previous block needs to be inherited when the block is empty, values after block execution recorded.
	VCCRoot          *common.Hash `json:"-"`         // Root hash of transfer out check tree in business chain
	CashedRoot       *common.Hash `json:"-"`         // Root hash of transfer in check tree in business chain
	TransactionRoot  *common.Hash `json:"-"`         // transactions in current block trie root hash
	ReceiptRoot      *common.Hash `json:"-"`         // receipts for transactions in current block trie root hash
	HdsRoot          *common.Hash `json:"-"`         // if there's any child chain of current chain, this is the Merkle trie root hash generated by the reported block header information of the child chain in order

	TimeStamp uint64 `json:"timestamp"`

	ElectResultRoot *common.Hash `json:"-"` // Since v1.5.0, Election result hash root (including pre election and ordinary election, ordinary one has not been provided yet)
	PreElectRoot    *common.Hash `json:"-"` // Since v1.5.0, the root hash of current preelecting list sorted by (Expire, ChainID), only in the main chain
	FactorRoot      *common.Hash `json:"-"` // since v2.0.0, seed random factor hash
}

func (h BlockHeader) GetHeight() common.Height {
	return h.Height
}

func (h *BlockHeader) GetHistoryRoot() []byte {
	if h == nil {
		return nil
	}
	return h.HashHistory[:]
}

func (h *BlockHeader) Era() common.EraNum {
	if !h.ChainID.IsMain() {
		return h.ParentHeight.EraNum()
	}
	return h.Height.EraNum()
}

func hashPointerHash(h *common.Hash) []byte {
	if h == nil {
		return common.NilHashSlice
	} else {
		return h[:]
	}
}

// Hash value and its corresponding position are generated together to generate hash, which can
// prove that this value is the value in this position
func hashIndexProperty(posBuffer [13]byte, index byte, h []byte) []byte {
	indexHash := common.HeaderIndexHash(posBuffer, index)
	return common.HashPair(indexHash, h)
}

// The hash values, generated by all the fields in block header, which are the leafs of merkle
// tree used to calculate the hash of block.
//
// Proof of existence: To prove that a certain value really exists in the certain field of a
// certain height block of a certain chain. A fixed sequence number is added to each field. All
// the hash value of (ChainID + block height + sequence number) and the hash value of the field
// are used to generate the merkle hash of block header.
//
// When calculating block hash, each block field is first related to the chain and height of
// the block, as well as the location of the field in the block header. And then merkle root is
// generated. It can not only prove the validity of data, but also prove that a hash (e.g. StateRoot)
// is the value of a specific field of a specific chain and height. It can also be used for proving
// non-existence (i.e. the location is not a certain value)
//
// Hash(field): Hash{Hash[ChainID(4bytes)+Height(8bytes)+location(1bytes)],Hash(field value)}
// 按Header的字段顺序，列出所有字段的Hash值，作为生成merkle tree的原料。
//     为了能够在证明存在性时 证明某个值确实是存在于某链某高度块某个字段代表
// 的树中，为每一个字段都增加了一个固定的序列号，并用这个(链ID+块高+序列号)的
// Hash值与该字段的Hash值进行Hash，得到生成Heder.Hash的原料
// 在计算块头Hash时，每一个块头属性先与块所在链和高度，以及该属性所在位置一起生成hash，之后再生成merkleroot。
// 不仅可以证明数据的有效性，同时证明某Hash(如stateroot)确实是特定链、特定高度的特定属性的值，同样也可用来不存在性（即该位置不是某个值）
// 每个位置的hash：Hash{Hash[ChainID(4字节)+高度(8字节)+位置(1字节)],Hash(对应属性hash)}
func (h *BlockHeader) hashList() ([][]byte, error) {
	if h == nil {
		return nil, common.ErrNil
	}
	posBuffer := common.ToHeaderPosHashBuffer(h.ChainID, h.Height)

	hashlist := make([][]byte, 0, 30)
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 0, h.PreviousHash[:]))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 1, h.HashHistory[:]))

	hh, err := h.ChainID.HashValue()
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 2, hh))

	hh, err = h.Height.HashValue()
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 3, hh))

	var b byte = 0
	if h.Empty {
		b = 1
	}
	hh, err = common.Hash256s([]byte{b})
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 4, hh))

	hh, err = h.ParentHeight.HashValue()
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 5, hh))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 6, hashPointerHash(h.ParentHash)))

	hh, err = common.Hash256s(h.RewardAddress[:])
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 7, hh))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 8, hashPointerHash(h.CommitteeHash)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 9, hashPointerHash(h.ElectedNextRoot)))

	if h.NewCommitteeSeed == nil {
		hh = common.NilHashSlice
	} else {
		hh = h.NewCommitteeSeed[:]
	}
	hh, err = common.Hash256s(hh)
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 10, hh))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 11, hashPointerHash(h.MergedDeltaRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 12, hashPointerHash(h.BalanceDeltaRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 13, h.StateRoot[:]))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 14, hashPointerHash(h.ChainInfoRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 15, hashPointerHash(h.WaterlinesRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 16, hashPointerHash(h.VCCRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 17, hashPointerHash(h.CashedRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 18, hashPointerHash(h.TransactionRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 19, hashPointerHash(h.ReceiptRoot)))

	hashlist = append(hashlist, hashIndexProperty(posBuffer, 20, hashPointerHash(h.HdsRoot)))

	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, h.TimeStamp)
	hh, err = common.Hash256s(bs)
	if err != nil {
		return nil, err
	}
	hashlist = append(hashlist, hashIndexProperty(posBuffer, 21, hh))

	// TODO: should remove conditions when restart the chain with new version
	// v1.5.0: Because each leaf of merkle tree is not the field value of the block header, nil data is not NilHash
	if h.AttendanceHash != nil || h.RewardedCursor != nil ||
		h.RREra != nil || h.RRRoot != nil || h.RRNextRoot != nil || h.RRChangingRoot != nil {
		hashlist = append(hashlist, hashIndexProperty(posBuffer, 22, hashPointerHash(h.AttendanceHash)))

		if h.RewardedCursor == nil {
			hh = common.NilHashSlice
		} else {
			hh, err = common.HashObject(h.RewardedCursor)
			if err != nil {
				return nil, err
			}
		}
		hashlist = append(hashlist, hashIndexProperty(posBuffer, 23, hh))

		if h.RREra == nil {
			hh = common.NilHashSlice
		} else {
			hh, err = common.HashObject(h.RREra)
			if err != nil {
				return nil, err
			}
		}
		hashlist = append(hashlist, hashIndexProperty(posBuffer, 24, hh))

		hashlist = append(hashlist, hashIndexProperty(posBuffer, 25, hashPointerHash(h.RRRoot)))

		hashlist = append(hashlist, hashIndexProperty(posBuffer, 26, hashPointerHash(h.RRNextRoot)))

		hashlist = append(hashlist, hashIndexProperty(posBuffer, 27, hashPointerHash(h.RRChangingRoot)))

		// add by v1.5.0
		if h.ElectResultRoot != nil || h.PreElectRoot != nil {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, 28, hashPointerHash(h.ElectResultRoot)))

			hashlist = append(hashlist, hashIndexProperty(posBuffer, 29, hashPointerHash(h.PreElectRoot)))
		}
		// add by v2.0.0 newSeed
		if h.FactorRoot != nil {
			hashlist = append(hashlist, hashIndexProperty(posBuffer, 30, hashPointerHash(h.FactorRoot)))
		}
	}

	return hashlist, err
}

func (h *BlockHeader) Hash() common.Hash {
	hashOfHeader, err := h.HashValue()
	if err != nil {
		panic(fmt.Sprintf("BlockHeader %s merkle tree hash failed: %v", h, err))
	}
	return common.BytesToHash(hashOfHeader)
}

func (h *BlockHeader) HashValue() ([]byte, error) {
	hashList, err := h.hashList()
	if err != nil {
		return nil, fmt.Errorf("BlockHeader %s hash failed: %v", h, err)
	}
	ret, err := common.MerkleHashComplete(hashList, 0, nil)
	// log.Debugf("ChainID:%d Height:%d Hash:%x List:%s",
	// 	h.ChainID, h.Height, common.ForPrint(ret), common.PrintBytesSlice(hashList, 5))
	return ret, err
}

// Proof generate proof from a specified field to block hash
func (h *BlockHeader) Proof(typ trie.ProofType) (hashOfHeader []byte, indexHash *common.Hash, proof *common.MerkleProofs, err error) {
	if h == nil {
		return nil, nil, nil, common.ErrNil
	}
	index, ok := trie.ProofableMap(typ)
	if !ok {
		panic("unsupport BlockHeader ProofType")
	}
	// posBuffer := toPosBuffer(h.ChainID, h.Height)
	// posBuffer[12] = byte(index)
	// indexHash = common.Hash256p(posBuffer[:])
	indexHash = common.BytesToHashP(common.HeaderIndexHash(common.ToHeaderPosHashBuffer(h.ChainID, h.Height), byte(index)))
	var hashList [][]byte
	hashList, err = h.hashList()
	if err != nil {
		panic(fmt.Sprintf("BlockHeader.Proof(%d) failed: %v", typ, err))
	}
	proof = common.NewMerkleProofs()
	hashOfHeader, err = common.MerkleHashComplete(hashList, index, proof)
	if err != nil {
		return nil, nil, nil, err
	}
	return
}

func (h *BlockHeader) MakeProof(typ trie.ProofType, proofChain *trie.ProofChain) (hashOfHeader []byte, err error) {
	if h == nil || proofChain == nil {
		return nil, common.ErrNil
	}
	var merkleProof *common.MerkleProofs
	var indexHash *common.Hash
	hashOfHeader, indexHash, merkleProof, err = h.Proof(typ)
	if err != nil {
		return nil, err
	}
	nodeProof := trie.NewHeaderPropertyProof(typ, indexHash, merkleProof)
	*proofChain = append(*proofChain, nodeProof)
	return hashOfHeader, nil
}

func (h *BlockHeader) Summary() string {
	if h == nil {
		return "Header<nil>"
	}
	return fmt.Sprintf("Header{ChainID:%d Height:%d Parent:%d}", h.ChainID, h.Height, h.ParentHeight)
}

func (h *BlockHeader) InfoString() string {
	if h == nil {
		return ""
	}
	vccroot := ""
	if h.VCCRoot != nil {
		vccroot = fmt.Sprintf(" VCC:%x", h.VCCRoot[:5])
	}
	cashedroot := ""
	if h.CashedRoot != nil {
		cashedroot = fmt.Sprintf(" Cashed:%x", h.CashedRoot[:5])
	}
	hdsroot := ""
	if h.HdsRoot != nil {
		hdsroot = fmt.Sprintf(" Hds:%x", h.HdsRoot[:5])
	}
	rrera := ""
	if h.RREra != nil {
		rrera = fmt.Sprintf(" RREra:%d RRR:%x RRN:%x RRC:%x", *h.RREra,
			common.ForPrint(h.RRRoot),
			common.ForPrint(h.RRNextRoot),
			common.ForPrint(h.RRChangingRoot),
		)
	}
	if h.Empty {
		return fmt.Sprintf("Prev:%x Parent:%d History:%x Root:%x Receipts:%x%s%s%s%s Empty",
			h.PreviousHash[:5], h.ParentHeight, h.HashHistory[:5], h.StateRoot[:5], common.ForPrint(h.ReceiptRoot),
			vccroot, cashedroot, hdsroot, rrera)
	}
	return fmt.Sprintf("Prev:%x Parent:%d History:%x Root:%x Receipts:%x%s%s%s%s",
		h.PreviousHash[:5], h.ParentHeight, h.HashHistory[:5], h.StateRoot[:5], common.ForPrint(h.ReceiptRoot),
		vccroot, cashedroot, hdsroot, rrera)
}

func (h *BlockHeader) String() string {
	if h == nil {
		return "{}"
	}
	return fmt.Sprintf("{ChainID:%d EpochNum:%d BlockNum:%d Empty:%t %s}",
		h.ChainID, h.Height.EpochNum(), h.Height.BlockNum(), h.Empty, h.InfoString())
}

func GenesisHeader(id common.ChainID, holder DataHolder) *BlockHeader {
	header := &BlockHeader{
		PreviousHash:     common.NilHash,
		HashHistory:      common.NilHash,
		ChainID:          id,
		Height:           common.NilHeight,
		Empty:            false,
		ParentHeight:     common.NilHeight,
		ParentHash:       common.BytesToHashP(common.NilHash.Bytes()),
		RewardAddress:    common.Address{},
		AttendanceHash:   nil, // In order to be compatible with historical data, genesis block has no attendance record
		RewardedCursor:   nil,
		CommitteeHash:    common.BytesToHashP(common.NilHashSlice), // TODO: the genesis committee should be recorded in the genesis block
		ElectedNextRoot:  nil,
		NewCommitteeSeed: nil,
		RREra:            nil,
		RRRoot:           nil,
		RRNextRoot:       nil,
		RRChangingRoot:   nil,
		MergedDeltaRoot:  nil,
		BalanceDeltaRoot: nil,
		StateRoot:        common.NilHash,
		ChainInfoRoot:    nil,
		WaterlinesRoot:   nil,
		VCCRoot:          nil,
		CashedRoot:       nil,
		TransactionRoot:  nil,
		ReceiptRoot:      nil,
		HdsRoot:          nil,
		ElectResultRoot:  nil,
		PreElectRoot:     nil,
		TimeStamp:        0,
	}
	if err := holder.SetGenesisHeader(header); err != nil {
		panic(fmt.Sprintf("set genesis header failed: %v", err))
	}
	return header
}

func GetHistoryRoot(holder DataHolder, height common.Height) ([]byte, error) {
	historyRoot, err := holder.GetHistoryRoot(height)
	if err != nil {
		return nil, err
	}
	if len(historyRoot) == 0 {
		historyRoot = common.NilHashSlice
	}
	return historyRoot, nil
}

func NewEmptyHeader(holder DataHolder, lastHeader *BlockHeader, committeeHash *common.Hash) (*BlockHeader, error) {
	historyRoot, err := GetHistoryRoot(holder, lastHeader.Height+1)
	if err != nil {
		return nil, err
	}
	return &BlockHeader{
		PreviousHash:     lastHeader.Hash(),
		HashHistory:      common.BytesToHash(historyRoot),
		ChainID:          lastHeader.ChainID,
		Height:           lastHeader.Height + 1,
		Empty:            true,
		ParentHeight:     lastHeader.ParentHeight,
		ParentHash:       lastHeader.ParentHash,
		RewardedCursor:   lastHeader.RewardedCursor,
		RewardAddress:    common.Address{},
		AttendanceHash:   lastHeader.AttendanceHash,
		CommitteeHash:    committeeHash,
		ElectedNextRoot:  nil,
		NewCommitteeSeed: nil,
		RREra:            lastHeader.RREra,
		RRRoot:           lastHeader.RRRoot,
		RRNextRoot:       lastHeader.RRNextRoot,
		RRChangingRoot:   lastHeader.RRChangingRoot,
		MergedDeltaRoot:  nil,
		BalanceDeltaRoot: nil,
		StateRoot:        lastHeader.StateRoot,     // all business chains must exist
		ChainInfoRoot:    lastHeader.ChainInfoRoot, // must exist in the main chain
		WaterlinesRoot:   lastHeader.WaterlinesRoot,
		VCCRoot:          lastHeader.VCCRoot,
		CashedRoot:       lastHeader.CashedRoot,
		TransactionRoot:  nil,
		ReceiptRoot:      nil,
		HdsRoot:          nil,
		TimeStamp:        0, // 0 for empty block (Empty is true)
	}, nil
}

func GenesisBlock(id common.ChainID, holder DataHolder) *BlockEMessage {
	return &BlockEMessage{
		BlockHeader: GenesisHeader(id, holder),
		BlockBody:   &BlockBody{}, // In order to be compatible with historical data, genesis block has no attendance record
	}
}

func NewEmptyBlock(holder DataHolder, lastBlock *BlockEMessage, committeeHash *common.Hash) (*BlockEMessage, error) {
	emptyHeader, err := NewEmptyHeader(holder, lastBlock.BlockHeader, committeeHash)
	if err != nil {
		return nil, err
	}
	attendance := lastBlock.BlockBody.Attendance

	height := lastBlock.GetHeight() + 1
	epochNum, blockNum := height.Split()
	//  1. create when there's no attendance record
	if attendance == nil {
		attendance = NewAttendanceRecord(epochNum, holder.GetDataNodeList()...)
	}
	//  2. set absence in attendance record for current height
	attendance.SetAbsentness(epochNum, blockNum)
	emptyBody := &BlockBody{
		Attendance: attendance,
	}
	//  3. calculate the hash value of the new attendance record
	// attendanceHash := attendance.Hash()
	if emptyHeader.AttendanceHash, err = emptyBody.AttendanceRoot(); err != nil {
		return nil, err
	}

	// emptyHeader.AttendanceHash = &attendanceHash
	return &BlockEMessage{
		BlockHeader: emptyHeader,
		BlockBody:   emptyBody,
	}, nil
}

type SeedFactor []byte

type BlockBody struct {
	NextCommittee     *Committee        // election results of the next committee
	NCMsg             []*ElectMessage   // election requests for chains (in main chain)
	DeltaFroms        DeltaFroms        // deltas merged to current shard
	Txs               []*Transaction    // transactions
	TxsPas            []*PubAndSig      // signatures corresponding to packaged transactions
	Deltas            []*AccountDelta   // the delta generated by packaged transactions on current shard needs to be sent to other shards
	Hds               []*BlockSummary   // block summary reported by children chains
	Attendance        *AttendanceRecord // attendance table of the current epoch
	RewardReqs        RewardRequests    // self-proving reward request of each chain received on the main chain
	ElectingResults   ChainElectResults // Since v1.5.0, a list of election results, it's a preelection when Epoch.IsNil()==true, others are local election (not provided at present)
	PreElectings      PreElectings      // Since v1.5.0, the list of preselections in progress, sorted by (expire, chainid)
	NextRealCommittee *Committee        // Since v1.5.0, when election finished, the result will be put into NextCommittee. If the election is failed, the current committee will continue to be used in the next epoch. At this time, the current committee needs to be written into this field, which can be brought with it when reporting.
	SeedFactor        SeedFactor        // Since v2.0.0, random factor of seed
}

func (bb *BlockBody) Formalize() {
	if bb == nil {
		return
	}
	if bb.Attendance != nil {
		bb.Attendance.Formalize()
	}
	if len(bb.RewardReqs) > 1 {
		sort.Sort(bb.RewardReqs)
	}
}

func (bb *BlockBody) AttendanceRoot() (*common.Hash, error) {
	if bb == nil || bb.Attendance == nil {
		return nil, nil
	}
	return bb.Attendance.Hash()
}

func (bb *BlockBody) NextCommitteeRoot() (*common.Hash, error) {
	if bb == nil || (bb.NextCommittee == nil && bb.NextRealCommittee == nil) {
		return nil, nil
	}
	h1 := bb.NextCommittee.Hash()
	h2 := bb.NextRealCommittee.Hash()
	h := common.HashPair(h1[:], h2[:])
	return common.BytesToHashP(h), nil
}

func sliceToHashRoot(root []byte, err error) (*common.Hash, error) {
	if err != nil {
		return nil, err
	}
	if common.IsNilHash(root) {
		return nil, nil
	}
	return common.BytesToHashP(root), nil
}

func (bb *BlockBody) TransactionsRoot() (*common.Hash, error) {
	if bb == nil || (len(bb.Txs) == 0 && len(bb.RewardReqs) == 0) {
		return nil, nil
	}
	var root []byte
	var err error
	if len(bb.RewardReqs) == 0 {
		root, err = common.ValuesMerkleTreeHash(bb.Txs, -1, nil)
	} else if len(bb.Txs) == 0 {
		root, err = common.ValuesMerkleTreeHash(bb.RewardReqs, -1, nil)
	} else {
		var mklValues []interface{}
		mklValues = append(mklValues, bb.Txs)
		mklValues = append(mklValues, bb.RewardReqs)
		root, err = common.ValuesMerkleTreeHash(mklValues, -1, nil)
	}
	return sliceToHashRoot(root, err)
}

func (bb *BlockBody) HdsRoot() (*common.Hash, error) {
	if bb == nil || len(bb.Hds) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(common.ValuesMerkleTreeHash(bb.Hds, -1, nil))
}

func (bb *BlockBody) ElectResultRoot() (*common.Hash, error) {
	if bb == nil || len(bb.ElectingResults) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(bb.ElectingResults.HashValue())
}

func (bb *BlockBody) PreElectRoot() (*common.Hash, error) {
	if bb == nil || len(bb.PreElectings) == 0 {
		return nil, nil
	}
	return sliceToHashRoot(bb.PreElectings.HashValue())
}

func (bb *BlockBody) SeedFactorRoot() (*common.Hash, error) {
	if bb == nil || bb.SeedFactor == nil {
		return nil, nil
	}
	factorHash, err := common.HashObject(bb.SeedFactor)
	return sliceToHashRoot(factorHash, err)
}

const maxCommSizeForPrint = 100

type Committee struct {
	Members   []common.NodeID
	indexMap  map[common.NodeID]common.CommID
	indexLock sync.Mutex
}

func NewCommittee() *Committee {
	return &Committee{
		Members: make([]common.NodeID, 0),
	}
}

func (c *Committee) checkIndex() {
	c.indexLock.Lock()
	defer c.indexLock.Unlock()
	if c.indexMap == nil {
		c.indexMap = make(map[common.NodeID]common.CommID)
		for i, nid := range c.Members {
			c.indexMap[nid] = common.CommID(i)
		}
	}
}

func (c *Committee) clrIndex() {
	c.indexLock.Lock()
	defer c.indexLock.Unlock()
	c.indexMap = nil
}

func (c *Committee) Hash() common.Hash {
	if c == nil || len(c.Members) == 0 {
		return common.NilHash
	}
	nodeHashs := make([][]byte, len(c.Members), len(c.Members))
	for i := 0; i < len(c.Members); i++ {
		nodeHashs[i] = c.Members[i].Hash().Bytes()
	}

	rootHash, err := common.MerkleHashComplete(nodeHashs, -1, nil)
	if err != nil {
		return common.Hash{}
	}
	return common.BytesToHash(rootHash)
}

func (c *Committee) Equals(o *Committee) bool {
	if c == o {
		return true
	}
	if c == nil || o == nil {
		return false
	}
	return common.NodeIDs(c.Members).Equals(o.Members)
}

func (c *Committee) Clone() *Committee {
	if c == nil {
		return nil
	}
	comm := &Committee{}
	comm.CopyMembers(c)
	return comm
}

func (c *Committee) Index(id common.NodeID) common.CommID {
	c.checkIndex()
	i, exist := c.indexMap[id]
	if !exist {
		return -1
	}
	return i
}

func (c *Committee) ReachRequires(ok int) bool {
	// return ok > c.Size()*2/3
	return ReachConfirm(c.Size(), ok)
}

func (c *Committee) Size() int {
	if c == nil {
		return 0
	}
	return len(c.Members)
}

func (c *Committee) Add(id common.NodeID) {
	c.Members = append(c.Members, id)
	c.clrIndex()
}

func (c *Committee) SetMembers(ids common.NodeIDs) *Committee {
	c.Members = ids.Clone()
	c.clrIndex()
	return c
}

func (c *Committee) IsAvailable() bool {
	if c != nil && len(c.Members) >= consts.MinimumCommSize {
		return true
	}
	return false
}

func (c *Committee) IsProposor(id common.NodeID, num common.BlockNum) bool {
	return c.Index(id) == common.CommID(num)%common.CommID(c.Size())
}

func (c *Committee) IsIn(id common.NodeID) bool {
	if c == nil {
		return false
	}
	if c.Index(id) == -1 {
		return false
	}
	return true
}

func (c *Committee) Reset() {
	c.Members = make([]common.NodeID, 0)
	c.clrIndex()
}

func (c *Committee) CopyMembers(committee *Committee) {
	if committee == nil {
		c.Reset()
		return
	}
	members := make([]common.NodeID, len(committee.Members))
	if len(committee.Members) > 0 {
		copy(members, committee.Members)
	}
	c.Members = members
	c.clrIndex()
}

func (c *Committee) FullString() string {
	if c == nil {
		return "COMM<nil>"
	}
	return fmt.Sprintf("COMM{%s}", c.Members)
}

func (c *Committee) String() string {
	if c == nil {
		return "COMM<nil>"
	}
	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		common.BytesBufferPool.Put(buf)
	}()
	buf.Reset()
	buf.WriteString("COMM{")
	if len(c.Members) <= maxCommSizeForPrint {
		buf.WriteString(fmt.Sprintf("%s", c.Members))
	} else {
		buf.WriteString(fmt.Sprintf("%s", c.Members[:maxCommSizeForPrint]))
		buf.WriteString(fmt.Sprintf("...(%d)", len(c.Members)))
	}
	buf.WriteString("}")
	return buf.String()
}

type EpochCommittee struct {
	Result *Committee // actual election results
	Real   *Committee // the final result, if Result.IsAvailable()==false, then Real is the actual Committee. Otherwise, it is nil
}

func NewEpochComm(result *Committee, current *Committee) *EpochCommittee {
	if result.IsAvailable() {
		return &EpochCommittee{Result: result.Clone(), Real: nil}
	} else {
		return &EpochCommittee{Result: result.Clone(), Real: current}
	}
}

func (c *EpochCommittee) Clone() *EpochCommittee {
	if c == nil {
		return nil
	}
	return &EpochCommittee{Result: c.Result.Clone(), Real: c.Real.Clone()}
}

func (c *EpochCommittee) IsAvailable() bool {
	if c == nil || (c.Result == nil && c.Real == nil) {
		return false
	}
	if !c.Result.IsAvailable() {
		if c.Real.IsAvailable() {
			return true
		} else {
			return false
		}
	}
	return true
}

func (c *EpochCommittee) Comm() *Committee {
	if c == nil {
		return nil
	}
	if c.Real != nil {
		return c.Real
	} else {
		return c.Result
	}
}

func (c *EpochCommittee) Hash() common.Hash {
	if c == nil || (c.Result == nil && c.Real == nil) {
		return common.NilHash
	}
	h1 := c.Result.Hash()
	h2 := c.Real.Hash()
	h := common.HashPair(h1[:], h2[:])
	return common.BytesToHash(h)
}

func (c *EpochCommittee) String() string {
	if c == nil {
		return "EpochComm<nil>"
	}

	if c.Real == nil {
		return fmt.Sprintf("EpochComm{Result:%s}", c.Result)
	} else {
		return fmt.Sprintf("EpochComm{Result:%s Real:%s}", c.Result, c.Real)
	}
}

type ChainEpochCommittee struct {
	ChainID common.ChainID
	Epoch   common.EpochNum
	Comm    *EpochCommittee
}

func (c *ChainEpochCommittee) String() string {
	if c == nil {
		return "CEComm<nil>"
	}
	return fmt.Sprintf("CEComm{ChainID:%d Epoch:%d Comm:%s}", c.ChainID, c.Epoch, c.Comm)
}

// TXIndex Transaction index
type TXIndex struct {
	BlockHeight uint64
	BlockHash   common.Hash
	Index       uint32
}

func NewTXIndex(blockHeight uint64, blockHash common.Hash, index uint32) *TXIndex {
	return &TXIndex{
		BlockHeight: blockHeight,
		BlockHash:   blockHash,
		Index:       index,
	}
}

func (i *TXIndex) String() string {
	if i == nil {
		return "TXIndex<nil>"
	}
	return fmt.Sprintf("TXIndex{Height:%d Hash:%s Index:%d}", i.BlockHeight, i.BlockHash, i.Index)
}

// Message EVM message
type Message struct {
	to         *common.Address
	from       common.Address
	nonce      uint64
	useLocal   bool
	amount     *big.Int
	gasLimit   uint64
	gasPrice   *big.Int
	data       []byte
	checkNonce bool
	bodyhash   common.Hash
	txhash     common.Hash
	senderSig  *PubAndSig
	multiSigs  PubAndSigs
	version    uint16
}

func NewMessage(bodyhash common.Hash, txhash common.Hash, from common.Address, to *common.Address, nonce uint64, useLocal bool,
	amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, checkNonce bool, senderSig *PubAndSig,
	multiSigs PubAndSigs, version uint16) Message {
	return Message{
		from:       from,
		to:         to,
		nonce:      nonce,
		useLocal:   useLocal,
		amount:     amount,
		gasLimit:   gasLimit,
		gasPrice:   gasPrice,
		data:       data,
		checkNonce: checkNonce,
		bodyhash:   bodyhash,
		txhash:     txhash,
		senderSig:  senderSig,
		multiSigs:  multiSigs,
		version:    version,
	}
}

func (m Message) From() common.Address  { return m.from }
func (m Message) To() *common.Address   { return m.to }
func (m Message) GasPrice() *big.Int    { return m.gasPrice }
func (m Message) UseLocal() bool        { return m.useLocal }
func (m Message) Value() *big.Int       { return m.amount }
func (m Message) Gas() uint64           { return m.gasLimit }
func (m Message) Nonce() uint64         { return m.nonce }
func (m Message) Data() []byte          { return m.data }
func (m Message) CheckNonce() bool      { return m.checkNonce }
func (m Message) TxHash() common.Hash   { return m.txhash }
func (m Message) Sig() *PubAndSig       { return m.senderSig }
func (m Message) MultiSigs() PubAndSigs { return m.multiSigs }
func (m Message) Version() uint16       { return m.version }

// AllValidSigns Traverse all the valid signatures without repetition, call the callback method, and return
// the map with the key as the public key of the valid signature
func (m Message) AllValidSigns(callback func(pas *PubAndSig)) map[string]struct{} {
	r := make(map[string]struct{}, len(m.multiSigs)+1)
	r[string(m.senderSig.PublicKey)] = struct{}{}
	if callback != nil {
		callback(m.senderSig)
	}
	if len(m.multiSigs) == 0 {
		return r
	}
	for _, sig := range m.multiSigs {
		if sig == nil {
			continue
		}
		_, exist := r[string(sig.PublicKey)]
		if exist {
			continue
		}
		if common.VerifyHash(m.bodyhash[:], sig.PublicKey, sig.Signature) {
			r[string(sig.PublicKey)] = struct{}{}
			if callback != nil {
				callback(sig)
			}
		}
	}
	return r
}

// SignedPubs Returns an unordered list of all correctly signed public keys
func (m Message) SignedPubs() map[string]struct{} {
	return m.AllValidSigns(nil)
}

// SignedAddresses Returns the unordered list of addresses corresponding to all correctly signed public keys
func (m Message) SignedAddresses() map[common.Address]struct{} {
	r := make(map[common.Address]struct{}, len(m.multiSigs)+1)
	m.AllValidSigns(func(pas *PubAndSig) {
		addr, err := common.AddressFromPubSlice(pas.PublicKey)
		if err != nil {
			return
		}
		r[addr] = struct{}{}
	})
	return r
}

// BlockCursor Cursor information used to record blocks, including block height and block hash
type BlockCursor struct {
	Height common.Height
	Hash   []byte
}

type HistoryBlock struct {
	Block *BlockEMessage
}

func (b *HistoryBlock) BlockNum() common.BlockNum {
	if b.Block == nil {
		return 0
	}
	return b.Block.BlockNum()
}

func (b *HistoryBlock) EpochNum() common.EpochNum {
	if b.Block == nil {
		return 0
	}
	return b.Block.EpochNum()
}

func (b *HistoryBlock) GetChainID() common.ChainID {
	return b.Block.GetChainID()
}

func (b *HistoryBlock) GetHeight() common.Height {
	if b.Block == nil {
		return 0
	}
	return b.Block.GetHeight()
}

func (b *HistoryBlock) Hash() common.Hash {
	if b.Block == nil {
		return common.Hash{}
	}
	return b.Block.Hash()
}

func (b *HistoryBlock) String() string {
	if b == nil {
		return "HistoryBlock<nil>"
	}
	return fmt.Sprintf("HistoryBlock%s", b.Block.String())
}

type NodeState struct {
	NodeId    common.NodeID
	ChainId   common.ChainID
	Height    common.Height
	BlockSig  []byte
	Ip        string
	BasicPort uint16
	DataPort  uint16
	ConPort0  uint16
	ConPort1  uint16
}

func (b *NodeState) GetChainID() common.ChainID {
	return b.ChainId
}

func (b *NodeState) Hash() common.Hash {
	return common.EncodeHash(b)
}

func (b *NodeState) String() string {
	if b == nil {
		return "BootState{}"
	}
	return fmt.Sprintf("BootState{NodeId:%s, Chain:%d, Height:%d, BlockSig:%x, Ip:%s, "+
		"BasicPort:%d, DataPort:%d, ConPort0:%d, ConPort1:%d}",
		b.NodeId, b.ChainId, b.Height, b.BlockSig[:5], b.Ip, b.BasicPort, b.DataPort, b.ConPort0, b.ConPort1)
}
