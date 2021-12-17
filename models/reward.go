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
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

const (
	MaxPenalizedTime  = 3     // After the penalty exceeds this number of times, the pledge percentage is cleared to 0
	WithdrawDelayEras = 2     // Withdraw lags 2 eras
	MinConsensusRR    = 10000 // Lower limit of consensus node pledges, (202012: from 50000->10000）
	MaxConsensusRR    = 10000 // The consensus node pledges is calculated at most according to this，(202012: from 50000->10000)
	ConsensusRRUnit   = 1000  // each rr unit a consensus node pledge has, get a unit reward. Consensus.(Node.RR/RRUnit*UnitReward)
	MinDataRR         = 50000 // Lower limit of data node pledges, (202012: from 200000->50000）
	MaxDataRR         = 50000 // The data node pledges is calculated at most according to this, (202012: from 200000->50000）
	DataRRUnit        = 50000 // each rr unit a data node pledge has, get a unit reward. DataNode.(Node.RR/RRUnit*UnitReward)

	MinRewardBalance = 100000 // A balance limit of reward account to stop process reward request
)

var (
	MinConsensusRRBig  = new(big.Int).Mul(big.NewInt(MinConsensusRR), BigTKM) // Pledge threshold for consensus nodes
	MaxConsensusRRBig  = new(big.Int).Mul(big.NewInt(MaxConsensusRR), BigTKM)
	ConsensusRRUnitBig = new(big.Int).Mul(big.NewInt(ConsensusRRUnit), BigTKM)
	MinDataRRBig       = new(big.Int).Mul(big.NewInt(MinDataRR), BigTKM) // Pledge threshold for data node
	MaxDataRRBig       = new(big.Int).Mul(big.NewInt(MaxDataRR), BigTKM)
	DataRRUnitBig      = new(big.Int).Mul(big.NewInt(DataRRUnit), BigTKM)

	MinRewardBalanceBig = new(big.Int).Mul(big.NewInt(MinRewardBalance), BigTKM)

	ErrLittleEra     = errors.New("era lesser than trie era")
	ErrMuchBigEra    = errors.New("era much bigger than trie era")
	ErrNeedSwitchEra = errors.New("need to switch era")
)

type RRProofs struct {
	Info  *RRInfo
	Proof trie.ProofChain
}

func (p *RRProofs) Clone() *RRProofs {
	if p == nil {
		return nil
	}
	ret := new(RRProofs)
	ret.Info = p.Info.Clone()
	ret.Proof = p.Proof.Clone()
	return ret
}

func (p *RRProofs) PrintString() string {
	if p == nil {
		return "RRProof<nil>"
	}
	return fmt.Sprintf("RRProof{Info:%s}", p.Info)
}

func (p *RRProofs) String() string {
	if p == nil {
		return "RRProof<nil>"
	}
	return fmt.Sprintf("RRProof{%s, %s}", p.Info, p.Proof)
}

func (p *RRProofs) VerifyProof(nodeIdHash common.Hash, root common.Hash) error {
	if p.Info == nil || p.Info.NodeIDHash != nodeIdHash || !p.Info.Available() {
		return errors.New("check RRNextProofs info failed")
	}

	if p.Proof == nil {
		return errors.New("check RRNextProofs missing proof")
	}

	infoHash, err := common.HashObject(p.Info)
	if err != nil {
		return common.NewDvppError("get RRNextProofs info hash failed:", err)
	}
	pr, err := p.Proof.Proof(common.BytesToHash(infoHash))
	if err != nil {
		return common.NewDvppError("culculate proof failed:", err)
	}
	if !bytes.Equal(pr, root.Bytes()) {
		return fmt.Errorf("check proof failed, expecting:%x but:%x", root.Bytes(), pr)
	}
	return nil
}

type (
	Withdrawing struct {
		Demand common.EraNum // Withdraw execution era (WithdrawDelayEras lagging after the application execution Era)
		Amount *big.Int      // Withdraw amount, if it is nil, it means all withdrawing
	}

	Withdrawings []*Withdrawing
)

func (w *Withdrawing) Expired(era common.EraNum) bool {
	if era.IsNil() {
		return false
	}
	return era >= w.Demand
}

func (w *Withdrawing) Equals(o *Withdrawing) bool {
	if w == o {
		return true
	}
	if w == nil || o == nil {
		return false
	}
	return w.Demand == o.Demand && math.CompareBigInt(w.Amount, o.Amount) == 0
}

func (w *Withdrawing) String() string {
	if w == nil {
		return "W/D<nil>"
	}
	return fmt.Sprintf("W/D{Demand:%d Amount:%s}", w.Demand, math.BigIntForPrint(w.Amount))
}

func (ws Withdrawings) String() string {
	if ws == nil {
		return "W/Ds<nil>"
	}
	if len(ws) == 0 {
		return "W/Ds[]"
	}
	buf := new(bytes.Buffer)
	for i, w := range ws {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(w.String())
	}
	return fmt.Sprintf("W/Ds[%s]", buf.String())
}

func (ws Withdrawings) Len() int {
	return len(ws)
}

func (ws Withdrawings) Swap(i, j int) {
	ws[i], ws[j] = ws[j], ws[i]
}

func (ws Withdrawings) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(ws, i, j); !needCompare {
		return less
	}
	return ws[i].Demand < ws[j].Demand
}

func (ws Withdrawings) Equals(os Withdrawings) bool {
	if len(ws) != len(os) {
		return false
	}
	for i := 0; i < len(ws); i++ {
		if !ws[i].Equals(os[i]) {
			return false
		}
	}
	return true
}

func (ws Withdrawings) Clone() Withdrawings {
	if ws == nil {
		return nil
	}
	rs := make(Withdrawings, len(ws))
	copy(rs, ws)
	return rs
}

// The total amount withdrawing to be withdrawed in the current withdrawing list. If all
// withdrawing are made, withdrawingAll is true, and the withdrawing value is meaningless
func (ws Withdrawings) All() (withdrawing *big.Int, withdrawingAll bool) {
	var all *big.Int
	for _, w := range ws {
		if w.Amount == nil {
			return nil, true
		} else {
			if all == nil {
				all = big.NewInt(0)
			}
			all.Add(all, w.Amount)
		}
	}
	return all, false
}

func (ws Withdrawings) GetWithdrawing(expireEra common.EraNum) *Withdrawing {
	for i := 0; i < len(ws); i++ {
		if ws[i] != nil && ws[i].Demand == expireEra {
			return ws[i]
		}
	}
	return nil
}

// Required Reserve Information of the node
type (
	RRInfo struct {
		// The hash value of the NodeID of the node is used to store information in a more
		// private way. It can also reduce storage capacity
		NodeIDHash common.Hash
		// The main chain block height at the time of the last deposit
		Height common.Height
		// Which type of node, supports common.Consensus/common.Data
		Type common.NodeType
		// If it is not nil, it means that this deposit has been applied for withdrawing and
		// will no longer participate in the calculation. When the value >= the cycle currently
		// being calculated, execute the withdrawing
		WithdrawDemand *common.EraNum
		// Record the number of penalties, initially 0, +1 after each Penalty execution
		PenalizedTimes int
		// Pledge amount (the total pledge amount of this node, >= effective pledge amount)
		Amount *big.Int
		// The percentage of the effective pledge amount of the current node in the total
		// effective pledge. If it is nil, it indicates that the current pledge does not
		// account for the proportion. It may be waiting for withdrawing at this time.
		Ratio *big.Rat
		// Reward binding address
		RewardAddr common.Address
		// Since v1.3.4. When WithdrawDemand!=nil, record all pending withdrawing records. If it
		// exists, the withdrawing due in the list will be executed every era.
		Withdrawings Withdrawings
		// since v1.5.0. Version number, used for compatible
		Version uint16
		// since v1.5.0。Used to record a total of valid pledged consensus nodes, only valid
		// when Type==common.Consensus, others are 0
		NodeCount uint32
		// node status
		Status uint16
	}

	// To be compatible with the old Hash value
	rrInfoMapperV0 struct {
		NodeIDHash     common.Hash
		Height         common.Height
		Type           common.NodeType
		WithdrawDemand *common.EraNum
		PenalizedTimes int
		Amount         *big.Int
		Ratio          *big.Rat
		RewardAddr     common.Address
	}

	rrInfoMapperV1 struct {
		NodeIDHash     common.Hash
		Height         common.Height
		Type           common.NodeType
		WithdrawDemand *common.EraNum
		PenalizedTimes int
		Amount         *big.Int
		Ratio          *big.Rat
		RewardAddr     common.Address
		Withdrawings   Withdrawings
		Version        uint16
		NodeCount      uint32
	}
)

// RRInfoVersion:1: NodeCount, 2: statue
const RRInfoVersion = 2

func CreateGenesisRRInfo(nodeIdHash common.Hash, nodeType common.NodeType) (*RRInfo, error) {
	amount := MinConsensusRRBig
	if nodeType == common.Consensus {
		// nothing
	} else if nodeType == common.Data {
		amount = MinDataRRBig
	} else {
		return nil, errors.New("node type error")
	}
	return &RRInfo{
		NodeIDHash:     nodeIdHash,
		Height:         0,
		Type:           nodeType,
		WithdrawDemand: nil,
		PenalizedTimes: 0,
		Amount:         new(big.Int).Set(amount),
		Ratio:          nil,
		RewardAddr:     AddressOfRewardForGenesis,
		Withdrawings:   nil,
		Version:        RRInfoVersion,
		NodeCount:      0,
		Status:         0x1,
	}, nil
}

// Compare the immutable information except Ratio and NodeCount
func (r *RRInfo) InfoEquals(v *RRInfo) bool {
	if r == v {
		return true
	}
	if r == nil || v == nil {
		return false
	}
	if r.NodeIDHash != v.NodeIDHash ||
		r.Height != v.Height ||
		r.Type != v.Type ||
		r.PenalizedTimes != v.PenalizedTimes ||
		// r.RewardAddr != v.RewardAddr {
		r.RewardAddr != v.RewardAddr ||
		r.Version != v.Version ||
		r.Status != v.Status {
		return false
	}

	if r.WithdrawDemand == v.WithdrawDemand ||
		(r.WithdrawDemand != nil && v.WithdrawDemand != nil && *r.WithdrawDemand == *v.WithdrawDemand) {
		if math.CompareBigInt(r.Amount, v.Amount) == 0 &&
			r.Withdrawings.Equals(v.Withdrawings) {
			return true
		}
	}
	return false
}

// Return the pledge amount after subtracting the amount to be redeemed, and whether the return
// value is a newly created object (the caller can decide whether to create an object when returning)
// When amount==nil is the same as 0, it means there is no available pledge
func (r *RRInfo) depositing() (amount *big.Int, created bool) {
	if r.WithdrawDemand == nil {
		// no withdrawing
		return r.Amount, false
	}
	w, wall := r.Withdrawings.All()
	if wall {
		// all withdrawing
		return nil, false
	}
	if w == nil {
		return r.Amount, false
	}
	return new(big.Int).Sub(r.Amount, w), true
}

func returnCreatedBigInt(v *big.Int, created bool) *big.Int {
	if created {
		return v
	}
	if v == nil {
		return big.NewInt(0)
	} else {
		return new(big.Int).Set(v)
	}
}

// Return the pledge amount after subtracting the amount to be redeemed
func (r *RRInfo) Depositing() *big.Int {
	return returnCreatedBigInt(r.depositing())
}

// Internal method, returns the current effective pledge amount. If the amount is nil, it means
// there is no effective pledge. If the amount is created, created returns true.
func (r *RRInfo) validAmount() (amount *big.Int, created bool) {
	if r.PenalizedTimes > MaxPenalizedTime {
		// If the number of penalties exceeds the limit, it is considered that there is no pledge
		return nil, false
	}
	return r.depositing()
}

// The current effective pledge amount (minus the part being redeemed)
func (r *RRInfo) ValidAmount() *big.Int {
	return returnCreatedBigInt(r.validAmount())
}

func (r *RRInfo) isAvaliable(amount *big.Int) bool {
	switch r.Type {
	case common.Consensus:
		if amount == nil || amount.Cmp(MinConsensusRRBig) < 0 || r.Ratio == nil || r.Ratio.Sign() <= 0 {
			return false
		}
	case common.Data:
		if amount == nil || amount.Cmp(MinDataRRBig) < 0 {
			return false
		}
	default:
		return false
	}
	return true
}

func (r *RRInfo) Available() bool {
	if r == nil {
		return false
	}
	value, _ := r.validAmount()
	return r.isAvaliable(value)
}

// Returns the share of the current node in Consensus
// 0：has not, did not participate in the election
// N：Indicates that N deposits have been paid, and there is a N times chance of being selected
func (r *RRInfo) Shares() uint64 {
	if r.Type == common.Data {
		return 0
	}
	va, _ := r.validAmount()
	if r.isAvaliable(va) == false {
		return 0
	}
	// if r == nil || r.Amount == nil || r.Amount.Sign() <= 0 || r.Ratio == nil || r.Ratio.Sign() <= 0 {
	// 	return 0
	// }
	amount := va
	if amount != nil && amount.Cmp(MaxConsensusRRBig) > 0 {
		amount = MaxConsensusRRBig
	}
	shares := big.NewInt(0)
	if amount != nil {
		shares = shares.Div(amount, MinConsensusRRBig)
	}
	return shares.Uint64()
}

func (r *RRInfo) String() string {
	if r == nil {
		return "RR<nil>"
	}
	return fmt.Sprintf("RR.%d{NIDH:%x LastHeight:%d Type:%s Withdraw:%s(%s) Penalized:%d "+
		"Amount:%s Addr:%x Ratio:%s NC:%d Status:%d}",
		r.Version, r.NodeIDHash[:5], r.Height, r.Type, r.WithdrawDemand, r.Withdrawings,
		r.PenalizedTimes, math.BigIntForPrint(r.Amount), r.RewardAddr[:5], r.Ratio, r.NodeCount, r.Status)
}

func (r *RRInfo) Key() []byte {
	return r.NodeIDHash[:]
}

// Compatibility check
func (r *RRInfo) Compatible(nodeIdHash common.Hash, typ common.NodeType, addr common.Address) bool {
	if typ == common.NoneNodeType {
		return nodeIdHash == r.NodeIDHash && addr == r.RewardAddr
	}
	return nodeIdHash == r.NodeIDHash && typ == r.Type && addr == r.RewardAddr
}

func (r *RRInfo) Clone() *RRInfo {
	if r == nil {
		return nil
	}
	var ratio *big.Rat
	if r.Ratio != nil {
		ratio = new(big.Rat).Set(r.Ratio)
	}
	var demand *common.EraNum
	if r.WithdrawDemand != nil {
		wd := *r.WithdrawDemand
		demand = &wd
	}
	return &RRInfo{
		NodeIDHash:     r.NodeIDHash,
		Height:         r.Height,
		Type:           r.Type,
		WithdrawDemand: demand,
		PenalizedTimes: r.PenalizedTimes,
		Amount:         math.CopyBigInt(r.Amount),
		Ratio:          ratio,
		RewardAddr:     r.RewardAddr,
		Withdrawings:   r.Withdrawings.Clone(),
		Version:        r.Version,
		NodeCount:      r.NodeCount,
		Status:         r.Status,
	}
}

func (r *RRInfo) Expired(eraNum common.EraNum) bool {
	if eraNum.IsNil() || r.WithdrawDemand == nil {
		return false
	}
	return eraNum >= *r.WithdrawDemand
}

// Returns the pledge amount of the specified type of nodeType of the current node
func (r *RRInfo) AvailableAmount(nodeType common.NodeType) *big.Int {
	if r.Type != nodeType {
		return nil
	}

	va, created := r.validAmount()
	if va != nil && va.Sign() > 0 {
		switch nodeType {
		case common.Consensus:
			if va.Cmp(MinConsensusRRBig) < 0 {
				return nil
			}
			if va.Cmp(MaxConsensusRRBig) > 0 {
				return new(big.Int).Set(MaxConsensusRRBig)
			}
		case common.Data:
			if va.Cmp(MinDataRRBig) < 0 {
				return nil
			}
			if va.Cmp(MaxDataRRBig) > 0 {
				return new(big.Int).Set(MaxDataRRBig)
			}
		default:
			return nil
		}
		if created {
			return va
		}
		return new(big.Int).Set(va)
	}
	return nil
}

func (r *RRInfo) HashValue() ([]byte, error) {
	if config.SystemConf.IsCompatible() == false || // specify incompatible old data
		r == nil ||
		r.Version == RRInfoVersion {
		return common.EncodeAndHash(r)
	}
	// compatible with old data
	switch r.Version {
	case 0:
		m := &rrInfoMapperV0{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
		}
		return common.EncodeAndHash(m)
	case 1:
		m := &rrInfoMapperV1{
			NodeIDHash:     r.NodeIDHash,
			Height:         r.Height,
			Type:           r.Type,
			WithdrawDemand: r.WithdrawDemand,
			PenalizedTimes: r.PenalizedTimes,
			Amount:         r.Amount,
			Ratio:          r.Ratio,
			RewardAddr:     r.RewardAddr,
			Withdrawings:   r.Withdrawings,
			Version:        r.Version,
			NodeCount:      r.NodeCount,
		}
		return common.EncodeAndHash(m)
	}
	return common.EncodeAndHash(r)
}

type RRStatusAct big.Int

var (
	maxRRStatusAct = big.NewInt(math.MaxUint16)
	minRRStatusAct = big.NewInt(-math.MaxUint16)
)

func (a *RRStatusAct) Ignored() bool {
	if a == nil || (*big.Int)(a).Sign() == 0 {
		return true
	}
	if (*big.Int)(a).Cmp(minRRStatusAct) < 0 || (*big.Int)(a).Cmp(maxRRStatusAct) > 0 {
		return true
	}
	return false
}

func (a *RRStatusAct) Todo() (act uint16, setOrClr bool) {
	if a.Ignored() {
		return 0, true
	}
	bi := (*big.Int)(a)
	if bi.Sign() > 0 {
		return uint16(bi.Uint64()), true
	}
	return uint16(-bi.Int64()), false
}

func (a *RRStatusAct) Merge(b *RRStatusAct) error {
	if a.Ignored() || b.Ignored() {
		return errors.New("ignored action could not be merged")
	}
	aact, asc := a.Todo()
	bact, bsc := b.Todo()
	if asc != bsc {
		return errors.New("different action could not be merged")
	}
	n := int64(aact | bact)
	if !asc {
		n = -n
	}
	(*big.Int)(a).SetInt64(n)
	return nil
}

type RRStatus uint16

func (s RRStatus) Change(value *big.Int) (newStatus RRStatus, msg string, changed bool) {
	act := (*RRStatusAct)(value)
	if act.Ignored() {
		return s, "", false
	}

	actValue, setOrClr := act.Todo()
	if setOrClr {
		msg = "SET"
		newValue := uint16(s) | actValue
		return RRStatus(newValue), msg, newValue != uint16(s)
	} else {
		msg = "CLR"
		newValue := uint16(s) & ^actValue
		return RRStatus(newValue), msg, newValue != uint16(s)
	}
}

func (s RRStatus) Match(bits uint16) bool {
	if bits == 0 {
		return false
	}
	return uint16(s)&bits == bits
}

// Required Reserve Act Type
type RRAType byte

const (
	RRADeposit  RRAType = iota // Deposit
	RRAPenalty                 // Confiscation deposit
	RRAWithdraw                // Withdraw
	RRAStatus                  // NewStatus>0: RRInfo.Status |= uint16(NewStatus), NewStatus<0:RRInfo.Status &= (^uint16(-NewStatus))
	RRAMax                     // The valid value must be less than this value
)

var AllRRATypes = []RRAType{RRADeposit, RRAPenalty, RRAWithdraw, RRAStatus}

func (t RRAType) String() string {
	switch t {
	case RRADeposit:
		return "DEP"
	case RRAPenalty:
		return "PEN"
	case RRAWithdraw:
		return "W/D"
	case RRAStatus:
		return "STATUS"
	default:
		return "NA"
	}
}

func (t RRAType) Valid() bool {
	return t < RRAMax
}

//
// func (t RRAType) Compatible(typ RRAType) bool {
// 	if typ >= RRAMax {
// 		return false
// 	}
// 	switch t {
// 	case RRADeposit:
// 		return true
// 	case RRAWithdraw:
// 		if typ == RRAPenalty || typ == RRAWithdraw {
// 			// A withdrawing request has been initiated, and punishment and withdrawing can be
// 			// executed in the same era (withdrawings are combineda into one).
// 			// In actual processing, the deposit is executed first, followed by punishment, and
// 			// finally withdrawing
// 			return true
// 		}
// 		return false
// 	case RRAPenalty:
// 		// No additional actions are allowed in the same era after a penalty
// 		return false
// 	default:
// 		return false
// 	}
// }

// Compare the priority of the two types, the higher the priority of the execution order, the
// smaller the Compare, the higher the execution priority
func (t RRAType) Compare(typ RRAType) int {
	if t >= RRAMax && typ >= RRAMax {
		return 0
	}
	if t >= RRAMax {
		return 1
	}
	if typ >= RRAMax {
		return -1
	}
	if t < typ {
		return -1
	}
	if t == typ {
		return 0
	}
	return 1
}

// Record changes for the same node, because all changes must be compatible, that is, NodeID/Addr
// must be equal, and effective Typ must also be equal, so these three pieces of information can
// only be recorded in RRC.
type RRAct struct {
	Typ             RRAType        // Current operation type: deposit, withdraw, penalty
	Height          common.Height  // Block height at the time of request
	Amount          *big.Int       // Nil when withdrawing all, other positive numbers
	RelatingChainID common.ChainID // The chain id of the transaction executed that generated this action
	RelatingTxHash  common.Hash    // The transaction that caused this action (Deposit/Withdraw
	//                             // refers to the transaction submitted by the user, and the
	//                             // penalty refers to the report transaction, etc.)
}

func (a *RRAct) Clone() *RRAct {
	if a == nil {
		return nil
	}
	return &RRAct{
		Typ:             a.Typ,
		Height:          a.Height,
		Amount:          math.CopyBigInt(a.Amount),
		RelatingChainID: a.RelatingChainID,
		RelatingTxHash:  a.RelatingTxHash,
	}
}

func (a *RRAct) String() string {
	if a == nil {
		return "Act<nil>"
	}
	return fmt.Sprintf("Act{%s Height:%d Amount:%s}", a.Typ, a.Height, math.BigIntForPrint(a.Amount))
}

func NewRRAct(typ RRAType, height common.Height, amount *big.Int, id common.ChainID, txHash common.Hash) (*RRAct, error) {
	if typ >= RRAMax {
		return nil, errors.New("wrong RRAType")
	}
	var a *big.Int
	// if typ != RRAWithdraw {
	if amount != nil {
		a = new(big.Int).Set(amount)
	}
	act := &RRAct{
		Typ:             typ,
		Height:          height,
		Amount:          a,
		RelatingChainID: id,
		RelatingTxHash:  txHash,
	}
	// if config.IsLogOn(config.DataDebugLog) {
	// 	log.Debugf("[RR] %s created", act)
	// }
	return act, nil
}

// Required Reserve Change
type RRC struct {
	NodeIDHash common.Hash     // NodeID hash of the changing node
	Addr       common.Address  // Binding address
	Typ        common.NodeType // Node type
	Acts       []*RRAct        // Changing list according to the order of transaction execution, execute in the order of priority during execution
}

func (rr *RRC) String() string {
	if rr == nil {
		return "RRC<nil>"
	}
	return fmt.Sprintf("RRC{NIH:%x Addr:%x Typ:%s Acts:%s}",
		rr.NodeIDHash[:5], rr.Addr[:5], rr.Typ, rr.Acts)
}

func (rr *RRC) Key() []byte {
	return rr.NodeIDHash[:]
}

// Check the modification to the same node, whether its nodeid/bindaddr and nodeType are the same
func (rr *RRC) Compatible(nodeIdHash common.Hash, typ common.NodeType, addr common.Address, actType RRAType) bool {
	if actType == RRAStatus {
		if rr.Typ == common.NoneNodeType || typ == common.NoneNodeType {
			return nodeIdHash == rr.NodeIDHash
		}
		return nodeIdHash == rr.NodeIDHash && typ == rr.Typ
	} else {
		if rr.Typ == common.NoneNodeType || typ == common.NoneNodeType {
			return nodeIdHash == rr.NodeIDHash && addr == rr.Addr
		}
		return nodeIdHash == rr.NodeIDHash && typ == rr.Typ && addr == rr.Addr
	}
}

// Calculate the change value of the node pledge in Changing, which can be a negative number. If
// withdrawing all exist, withdrawAll returns true, and delta is meaningless
func (rr *RRC) amountDelta() (delta *big.Int, withdrawAll bool) {
	if len(rr.Acts) == 0 {
		return nil, false
	}
	delta = big.NewInt(0)
	for _, act := range rr.Acts {
		if act == nil {
			continue
		}
		switch act.Typ {
		case RRADeposit:
			if act.Amount != nil && act.Amount.Sign() > 0 {
				delta.Add(delta, act.Amount)
			}
		case RRAPenalty:
			if act.Amount != nil && act.Amount.Sign() > 0 {
				delta.Sub(delta, act.Amount)
			}
		case RRAWithdraw:
			if act.Amount == nil {
				return nil, true
			} else {
				if act.Amount.Sign() > 0 {
					delta.Sub(delta, act.Amount)
				}
			}
		default:
			continue
		}
	}
	return delta, false
}

// Determine whether the withdrawing can be executed according to the Delta generated by the
// Act queue in the existing Changing and the amount of pledge to be redeemed reduced
func (rr *RRC) CheckWithdraw(depositing *big.Int, amount *big.Int) error {
	if depositing == nil && amount == nil {
		return errors.New("could not full withdraw without any deposit")
	}
	delta, withdrawAll := rr.amountDelta()
	if withdrawAll {
		return errors.New("could not withdraw any more after a full withdraw")
	}
	balance := big.NewInt(0)
	if depositing != nil {
		balance.Add(balance, depositing)
	}
	if delta != nil {
		balance.Add(balance, delta)
	}
	if balance.Sign() <= 0 {
		return fmt.Errorf("could not withdraw any more when depositing=%s delta=%s balance=%s",
			math.BigIntForPrint(depositing), math.BigIntForPrint(delta), math.BigIntForPrint(balance))
	}
	if amount != nil && balance.Cmp(amount) < 0 {
		return fmt.Errorf("withdraw %s not allowed cause of depositing=%s delta=%s balance=%s",
			math.BigIntForPrint(amount), math.BigIntForPrint(depositing),
			math.BigIntForPrint(delta), math.BigIntForPrint(balance))
	}
	return nil
}

// Combine existing Act queues to avoid excessively long queues occupying resources
func (rr *RRC) MergeActs() {
	if len(rr.Acts) == 0 {
		return
	}
	newacts := make([]*RRAct, 0, len(rr.Acts))
	m := make(map[RRAType]*RRAct)
	for _, act := range rr.Acts {
		if act == nil {
			continue
		}

		if act.Typ == RRAStatus {
			// status change actions are not merged
			newacts = append(newacts, act.Clone())
			continue
		}

		old, exist := m[act.Typ]
		if exist && old != nil {
			// Already exists, merge
			// You can record logs at this time, or send EVENT
			old.Height = act.Height
			if act.Typ == RRAWithdraw && (old.Amount == nil || act.Amount == nil) {
				// If there is a all withdrawing, then still all withdrawing
				old.Amount = nil
			} else {
				old.Amount = math.MustBigInt(old.Amount)
				old.Amount.Add(old.Amount, math.MustBigInt(act.Amount))
			}
			old.RelatingChainID = act.RelatingChainID
			old.RelatingTxHash = act.RelatingTxHash
		} else {
			m[act.Typ] = act.Clone()
		}
	}

	setter := func(typ RRAType) {
		act, exist := m[typ]
		if !exist || act == nil {
			return
		}
		newacts = append(newacts, act)
	}
	for _, typ := range AllRRATypes {
		setter(typ)
	}

	if config.IsLogOn(config.DataDebugLog) {
		log.Debugf("[RR] MergeActs(NIH:%x Addr:%x Typ:%s): %s -> %s", rr.NodeIDHash[:5], rr.Addr[:5], rr.Typ,
			rr.Acts, newacts)
	}
	rr.Acts = newacts
}

// Apply the pledge change request to the corresponding required reserve information and return it.
// If the info parameter is nil, create a new info apply changes and return it
func (rr *RRC) ApplyTo(info *RRInfo, stateDB StateDB) (
	changed bool, shouldRemove bool, newinfo *RRInfo, err error) {
	if rr == nil || len(rr.Acts) == 0 {
		// nop
		return false, false, info, nil
	}

	if info != nil && !info.Compatible(rr.NodeIDHash, rr.Typ, rr.Addr) {
		return false, false, nil, common.ErrMissMatch
	}

	if info != nil {
		newinfo = info.Clone()
	}

	defer func() {
		if config.IsLogOn(config.DataDebugLog) {
			log.Debugf("[RR] %s applied: changed:%t shouldRemove:%t newinfo:%s err:%v",
				rr, changed, shouldRemove, newinfo, err)
		}
	}()

	acts := make([]*RRAct, 0, len(rr.Acts))
	for i := 0; i < len(rr.Acts); i++ {
		// TODO: could check again if the act is compatible
		if rr.Acts[i] != nil {
			acts = append(acts, rr.Acts[i])
		}
	}
	// sort
	sort.Slice(acts, func(i, j int) bool {
		if acts[i].Typ.Compare(acts[j].Typ) == 0 {
			return acts[i].Height.Compare(acts[j].Height) < 0
		}
		return acts[i].Typ.Compare(acts[j].Typ) < 0
	})
	for _, act := range acts {
		// TODO: When processing an action, you can write the chain and Tx information contained
		//  in Act to receipt.Log, for an explanation
		switch act.Typ {
		case RRADeposit:
			if newinfo == nil {
				newinfo = &RRInfo{
					NodeIDHash:     rr.NodeIDHash,
					Height:         act.Height,
					Type:           rr.Typ,
					WithdrawDemand: nil,
					PenalizedTimes: 0,
					Amount:         new(big.Int).Set(act.Amount),
					Ratio:          nil,
					RewardAddr:     rr.Addr,
					Withdrawings:   nil,
				}
				if config.IsLogOn(config.DataDebugLog) {
					log.Debugf("[RR] %s created by depositing %s", newinfo, act)
				}
			} else {
				newinfo.Amount.Add(newinfo.Amount, act.Amount)
				if config.IsLogOn(config.DataDebugLog) {
					log.Debugf("[RR] depositing %s applied, %s", act, newinfo)
				}
			}
			changed = true
			shouldRemove = false
		case RRAPenalty:
			if newinfo == nil {
				return false, false, nil, common.ErrNil
			}
			// Used to record the fines actually deducted from the pledge account
			amount := new(big.Int).Set(act.Amount)
			if newinfo.Amount.Cmp(act.Amount) <= 0 {
				// The node's pledge account is insufficient to pay the penalty
				amount.Set(newinfo.Amount)
				newinfo.Amount = big.NewInt(0)
				shouldRemove = true
				newinfo = nil
			} else {
				newinfo.Amount.Sub(newinfo.Amount, act.Amount)
			}
			if stateDB.GetBalance(AddressOfRequiredReserve).Cmp(amount) < 0 {
				// The pledge account is insufficient to pay the penalty
				// TODO: The pledge account is unbalanced. In order not to report an error, you
				//  can deduct as much as you can
				return false, false, nil, common.ErrInsufficientBalance
			}
			stateDB.SubBalance(AddressOfRequiredReserve, amount)
			stateDB.AddBalance(AddressOfPenalty, amount)
			changed = true
			if config.IsLogOn(config.DataDebugLog) {
				log.Debugf("[RR] penalty %s applied, %s", act, newinfo)
			}
		case RRAWithdraw:
			// If newinfo == nil, it will not be processed. It may be a penalty for confiscating
			// the money and failing to withdraw cash.
			if newinfo == nil {
				log.Warnf("[RR] %s ignored cause of no RRInfo found", act)
			} else {
				// if newinfo != nil {
				withdrawEra := act.Height.EraNum() + WithdrawDelayEras
				wd := newinfo.Withdrawings.GetWithdrawing(withdrawEra)
				if wd == nil {
					wd = &Withdrawing{
						Demand: withdrawEra,
						Amount: math.CopyBigInt(act.Amount),
					}
					newinfo.Withdrawings = append(newinfo.Withdrawings, wd)
					sort.Sort(newinfo.Withdrawings)
					nextEra := newinfo.Withdrawings[0].Demand
					newinfo.WithdrawDemand = &nextEra
				} else {
					if wd.Amount == nil {
						// All withdrawd, no more modification
					} else {
						if act.Amount == nil {
							// All withdrawing added
							wd.Amount = nil
						} else {
							// Part withdrawing added
							wd.Amount.Add(wd.Amount, act.Amount)
						}
					}
					// There are already pending withdrawing records, do not modify the value
					// of WithdrawDemand, modify it when the execution expires
				}
				if act.Amount == nil {
					newinfo.Ratio = nil
				}
				changed = true
				if config.IsLogOn(config.DataDebugLog) {
					log.Debugf("[RR] withdrawing %s applied, %s", act, newinfo)
				}
			}
		case RRAStatus:
			if newinfo == nil {
				log.Warnf("[RR] %s ignored cause of no RRInfo found", act)
			} else {
				shouldRemove = false
				var newStatus, oldStatus RRStatus
				var msg string
				oldStatus = RRStatus(newinfo.Status)
				newStatus, msg, changed = oldStatus.Change(act.Amount)

				if msg == "" {
					if config.IsLogOn(config.DataDebugLog) {
						log.Debugf("[RR] NewStatus==%s, ignored", act.Amount)
					}
				} else {
					if changed {
						newinfo.Status = uint16(newStatus)
					}
					if config.IsLogOn(config.DataDebugLog) {
						log.Debugf("[RR] oldStatus(%d) %s newStatus(%s) -> %s", oldStatus, msg, act.Amount, newinfo)
					}
				}
			}
		default:
			return false, false, nil, errors.New("unknown act type")
		}
	}
	if newinfo.Amount.Sign() <= 0 {
		shouldRemove = true
		newinfo = nil
	}
	return
}

type RRTries interface {
	Commit() error
	Rollback()
	MatchEra(era common.EraNum) error
	NextEra(toEra common.EraNum) (err error)
	PreCommitStatus() (era common.EraNum, rrRoot, nextRoot, changingRoot []byte, err error)
	Era() common.EraNum
	Deposit(fromChain common.ChainID, fromTxHash common.Hash, height common.Height, typ common.NodeType,
		nodeIdHash common.Hash, addr common.Address, amount *big.Int) error
	Withdraw(fromChain common.ChainID, fromTxHash common.Hash, height common.Height,
		nodeIdHash common.Hash, addr common.Address) error
	Penalty(fromChain common.ChainID, fromTxHash common.Hash, nodeIdHash common.Hash, amount *big.Int) error
	PreHashValue() (rrRoot, rrNextRoot, rrChangingRoot []byte, err error)
	PreCommit() (currentRoot, nextRoot, changingRoot []byte, err error)
}

func RRDepositRequestHash(nodeId common.NodeID, nodeType common.NodeType,
	bindAddr common.Address, nonce uint64, amount *big.Int) []byte {
	s := fmt.Sprintf("%x,%d,%x,%d,%s", nodeId[:], nodeType, bindAddr[:], nonce, amount)
	return common.SystemHash256([]byte(s))
}

type RRProofsRequest struct {
	ToChainId common.ChainID
	NodeId    common.NodeID
	Era       common.EraNum
	RootHash  common.Hash
}

func (rr *RRProofsRequest) GetChainID() common.ChainID {
	return rr.ToChainId
}

func (rr *RRProofsRequest) String() string {
	if rr == nil {
		return fmt.Sprintf("RRProofsRequest{}")
	}
	return fmt.Sprintf("RRProofsRequest {ToChainId: %d, NodeId:%s, Era: %d, RootHash:%s }", rr.ToChainId, rr.NodeId, rr.Era, rr.RootHash)
}

type RRProofsMessage struct {
	NodeId   common.NodeID
	Era      common.EraNum
	RootHash common.Hash
	Proofs   *RRProofs
}

func (rm *RRProofsMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (rm *RRProofsMessage) String() string {
	if rm == nil {
		return fmt.Sprintf("RRProofsMessage<nil>")
	}
	return fmt.Sprintf("RRProofsMessage{NodeId:%s, Era: %d, RootHash:%s, Proofs:%s }",
		rm.NodeId, rm.Era, rm.RootHash, rm.Proofs)
}
