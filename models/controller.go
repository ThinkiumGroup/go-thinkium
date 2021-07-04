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
	"fmt"
	"reflect"
	"strconv"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/sirupsen/logrus"
)

type (
	OperatorType byte

	OpSet struct {
		onlyOne bool
		one     OperatorType
		ots     map[OperatorType]struct{}
	}

	Operator struct {
		Type       OperatorType
		Operations []interface{}
	}

	RawData interface {
		GetFrom() Location
		GetFromNodeID() *common.NodeID
		GetFromChainID() common.ChainID
		GetFromNetType() common.NetType
		GetEventType() EventType
		GetData() []byte
		GetObject() interface{}
		GetHash() *common.Hash
		GetPublicKey() []byte
		GetSignature() []byte
	}

	ChainEvent interface {
		GetChainID() common.ChainID
	}

	DirectiveMsg interface {
		DestChainID() common.ChainID
	}

	ThresholdEvent interface {
		ChainEvent
		// Whether the current message can join the queue according to the threshold value, threshold can be nil
		Pass(threshold interface{}) bool
	}

	PubAndSig struct {
		PublicKey []byte
		Signature []byte
	}

	PubAndSigs []*PubAndSig

	Context struct {
		Op        *OpSet
		Eventer   Eventer
		ChainInfo *common.ChainInfos
		ShardInfo common.ShardInfo
		Networker Networker
		Holder    DataHolder
		Engine    Engine

		// source of message
		Source Location
		// FromNodeID *common.nodeid
		// FromChainID common.ChainID
		// FromNetType common.NetType

		// for test adapter
		// cengine   consensus.Engine
		// mainChain *consensus.MainChain
		Dmanager DataManager
		Nmanager NetworkManager

		WorkerName string
		Logger     logrus.FieldLogger
		PAS        *PubAndSig
	}

	Eventer interface {
		common.Service
		PrintCounts()
		SetEngine(engine Engine)
		SetDataManager(manager DataManager)
		SetNetworkManager(manager NetworkManager)
		Shutdown()
		HasChainOpType(chainid common.ChainID, opType OperatorType) bool
		GetChainOpTypes(chainid common.ChainID) []OperatorType
		GetNodeOpTypes() map[common.ChainID][]string
		AddChainOpType(id common.ChainID, opType OperatorType)
		AppendChainOpType(id common.ChainID, opType OperatorType)
		RemoveChainOpType(id common.ChainID, opType OperatorType)
		ReplaceChainOpTypes(id common.ChainID, fromType OperatorType, toType OperatorType) bool
		ClearChainOpType(chainid common.ChainID)
		ResetToFailureOpType(chainid common.ChainID)
		RebuildContext(ctx *Context, newChainID common.ChainID) *Context
		SetEventThreshold(chainId common.ChainID, threshold interface{})
		PostMain(RawData)
		SyncPost(event interface{})
		Post(interface{})
		PostEvent(event interface{}, pub, sig []byte) error
		ExitChain(id common.ChainID) // exit from chain
		// check access permission
		CheckPermission(chainId common.ChainID, nodeId common.NodeID, netType common.NetType, proof []byte) error
	}

	Location struct {
		nodeID  *common.NodeID
		chainID common.ChainID
		netType common.NetType
	}

	RawDataObj struct {
		from      Location     // source of event
		eventType EventType    // event type
		h         *common.Hash // payload hash, hash(event body serialization, event type)
		data      []byte       // event body serialization
		pub       []byte       // public key
		sig       []byte       // signature of hash of the event: Sign(HashObject(EventObject))
		v         interface{}  // object deserialized from data
	}

	QueueObj struct {
		From      Location     // source of event
		EventType EventType    // event type
		H         *common.Hash // payload hash, hash(event body serialization, event type)
		V         interface{}  // event object
		P         []byte       // public key
		S         []byte       // signature of hash of the event: Sign(HashObject(V))
	}
)

var (
	RawDataPool = sync.Pool{
		New: func() interface{} {
			return new(RawDataObj)
		},
	}

	QueueObjPool = sync.Pool{
		New: func() interface{} {
			return new(QueueObj)
		},
	}

	operatorTypeNames = map[OperatorType]string{
		CtrlOp:      "CTRL",
		DataOp:      "DATA",
		CommitteeOp: "COMM",
		SpectatorOp: "SPEC",
		MemoOp:      "MEMO",
		InitialOp:   "INIT",
		StartOp:     "START",
		FailureOp:   "FAIL",
		PreelectOp:  "PELT",
	}

	TypeOfContextPtr = reflect.TypeOf((*Context)(nil))
)

func (o OperatorType) String() string {
	if n, ok := operatorTypeNames[o]; ok {
		return n
	}
	return "OperatorType-" + strconv.Itoa(int(o))
}

func NewOpSet(ots []OperatorType) *OpSet {
	if len(ots) == 0 {
		return &OpSet{
			onlyOne: false,
			one:     0,
			ots:     nil,
		}
	}
	m := make(map[OperatorType]struct{})
	for _, ot := range ots {
		m[ot] = struct{}{}
	}
	if len(m) == 1 {
		set := new(OpSet)
		set.onlyOne = true
		for k, _ := range m {
			set.one = k
		}
		return set
	} else {
		return &OpSet{
			onlyOne: false,
			one:     0,
			ots:     m,
		}
	}
}

func (s *OpSet) Has(opType OperatorType) bool {
	if s == nil || (s.onlyOne == false && len(s.ots) == 0) {
		return false
	}
	if s.onlyOne {
		return opType == s.one
	} else {
		_, exist := s.ots[opType]
		return exist
	}
}

// any one or more
func (s *OpSet) HasAny(opTypes ...OperatorType) bool {
	if s == nil || (s.onlyOne == false && len(s.ots) == 0) {
		return false
	}
	if s.onlyOne {
		for _, opt := range opTypes {
			if opt == s.one {
				return true
			}
		}
		return false
	} else {
		for _, opt := range opTypes {
			_, exist := s.ots[opt]
			if exist {
				return true
			}
		}
		return false
	}
}

func (l Location) NodeID() *common.NodeID {
	return l.nodeID
}

func (l Location) ChainID() common.ChainID {
	return l.chainID
}

func (l Location) NetType() common.NetType {
	return l.netType
}

func (l *Location) SetNodeID(nid *common.NodeID) {
	l.nodeID = nid
}

func (l *Location) SetChainID(chainID common.ChainID) {
	l.chainID = chainID
}

func (l *Location) SetNetType(netType common.NetType) {
	l.netType = netType
}

func (l Location) NoWhere() bool {
	return l.nodeID == nil
}

func (l Location) String() string {
	return fmt.Sprintf("Location{NID:%s, ChainID:%d, NetType:%s}", l.nodeID, l.chainID, l.netType)
}

func NewRawData(fromNodeID *common.NodeID, fromChainID common.ChainID,
	fromNetType common.NetType, eventType EventType, data, pub, sig []byte, dataHash *common.Hash, v interface{}) *RawDataObj {
	rawdata, _ := RawDataPool.Get().(*RawDataObj)
	rawdata.from.nodeID = fromNodeID
	rawdata.from.chainID = fromChainID
	rawdata.from.netType = fromNetType
	rawdata.eventType = eventType
	rawdata.data = data
	rawdata.v = v
	rawdata.pub = pub
	rawdata.sig = sig
	if dataHash == nil {
		msgLoad := append(data, eventType.Bytes()...)
		rawdata.h = common.Hash256p(msgLoad)
	} else {
		rawdata.h = dataHash
	}
	return rawdata
}

func ReleaseRawData(rawData *RawDataObj) {
	RawDataPool.Put(rawData)
}

func (r *RawDataObj) GetFrom() Location {
	return r.from
}

func (r *RawDataObj) GetFromNodeID() *common.NodeID {
	return r.from.NodeID()
}

func (r *RawDataObj) GetFromChainID() common.ChainID {
	return r.from.ChainID()
}

func (r *RawDataObj) GetFromNetType() common.NetType {
	return r.from.NetType()
}

func (r *RawDataObj) GetEventType() EventType {
	return r.eventType
}

func (r *RawDataObj) GetData() []byte {
	return r.data
}

func (r *RawDataObj) GetObject() interface{} {
	return r.v
}

func (r *RawDataObj) GetHash() *common.Hash {
	return r.h
}

func (r *RawDataObj) GetPublicKey() []byte {
	return r.pub
}

func (r *RawDataObj) GetSignature() []byte {
	return r.sig
}

func (r *RawDataObj) String() string {
	return fmt.Sprintf("{eventType:%s, from:%s len(data)=%d, hash=%x, v==nil:%t}",
		r.eventType, r.from, len(r.data), r.h[:5], r.v == nil)
}

func NewQueueObj(fromNodeID *common.NodeID, fromChainID common.ChainID, fromNetType common.NetType,
	eventType EventType, hashOfPayLoad *common.Hash, event interface{}, pub, sig []byte) *QueueObj {
	o := QueueObjPool.Get().(*QueueObj)
	o.From.SetNodeID(fromNodeID)
	o.From.SetChainID(fromChainID)
	o.From.SetNetType(fromNetType)
	o.EventType = eventType
	o.H = hashOfPayLoad
	o.V = event
	o.P = pub
	o.S = sig
	return o
}

func ReleaseQueueObj(obj *QueueObj) {
	QueueObjPool.Put(obj)
}

func (r *QueueObj) String() string {
	if r == nil {
		return ""
	}
	var h []byte
	if r.H != nil {
		h = r.H[:5]
	}
	return fmt.Sprintf("QueueObj{%s, Hash:%x, %s}", r.EventType, h, r.From)
}

// return public key bytes slice and signature bytes slice
func (ctx *Context) GetPAS() ([]byte, []byte) {
	if ctx.PAS == nil {
		return nil, nil
	}
	return ctx.PAS.PublicKey, ctx.PAS.Signature
}

// clear public key and signature in context
func (ctx *Context) ClearPAS() {
	ctx.PAS = nil
}

// set public key and signature in context
func (ctx *Context) SetPAS(pub, sig []byte) {
	ctx.PAS = &PubAndSig{PublicKey: pub, Signature: sig}
}

func (ctx *Context) Clone() *Context {
	if ctx == nil {
		return nil
	}
	return &Context{
		ChainInfo:  ctx.ChainInfo,
		ShardInfo:  ctx.ShardInfo,
		Holder:     ctx.Holder,
		Engine:     ctx.Engine,
		Op:         ctx.Op,
		Source:     ctx.Source,
		Networker:  ctx.Networker,
		Eventer:    ctx.Eventer,
		Dmanager:   ctx.Dmanager,
		Nmanager:   ctx.Nmanager,
		WorkerName: ctx.WorkerName,
		Logger:     ctx.Logger,
	}
}

func nilName(name string, isNil bool) string {
	if isNil {
		return name + "<nil>"
	}
	return name
}

func (ctx *Context) String() string {
	if ctx == nil {
		return "Context<nil>"
	}
	shard := "ShardInfo<nil>"
	if ctx.ShardInfo != nil {
		shard = fmt.Sprintf("%s", ctx.ShardInfo)
	}
	return fmt.Sprintf("Context{%s %s %s %s %s %s %s %s %s %s %s}",
		nilName("Eventer", ctx.Eventer == nil),
		ctx.ChainInfo, shard, nilName("Networker", ctx.Networker == nil),
		nilName("Holder", ctx.Holder == nil), nilName("Engine", ctx.Engine == nil),
		nilName("DManager", ctx.Dmanager == nil), nilName("NManager", ctx.Nmanager == nil),
		ctx.Source, ctx.WorkerName, nilName("PaS", ctx.PAS == nil))
}

func (p *PubAndSig) Equals(v interface{}) bool {
	o, ok := v.(*PubAndSig)
	if !ok {
		return false
	}
	if p == o {
		return true
	}
	if p != nil && o != nil &&
		bytes.Equal(p.Signature, o.Signature) &&
		bytes.Equal(p.PublicKey, o.PublicKey) {
		return true
	}
	return false
}

func (p *PubAndSig) Clone() *PubAndSig {
	if p == nil {
		return nil
	}
	n := new(PubAndSig)
	n.PublicKey = common.CopyBytes(p.PublicKey)
	n.Signature = common.CopyBytes(p.Signature)
	return n
}

func (p *PubAndSig) String() string {
	if p == nil {
		return "PaS<nil>"
	}
	return fmt.Sprintf("PaS{P:%x S:%x}", common.ForPrint(p.PublicKey),
		common.ForPrint(p.Signature))
}

func (p *PubAndSig) FullString() string {
	if p == nil {
		return "PaS<nil>"
	}
	return fmt.Sprintf("PaS{P:%x S:%x}", p.PublicKey, p.Signature)
}

func (ps PubAndSigs) Len() int {
	return len(ps)
}

func (ps PubAndSigs) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// sort by (public key, signature)
func (ps PubAndSigs) Less(i, j int) bool {
	if less, needCom := common.PointerSliceLess(ps, i, j); !needCom {
		return less
	}
	switch bytes.Compare(ps[i].Signature, ps[j].Signature) {
	case 0:
		return bytes.Compare(ps[i].Signature, ps[j].Signature) < 0
	case -1:
		return true
	default:
		return false
	}
}

func (ps PubAndSigs) Clone() PubAndSigs {
	if ps == nil {
		return nil
	}
	ns := make(PubAndSigs, len(ps))
	for i := 0; i < len(ps); i++ {
		ns[i] = ps[i].Clone()
	}
	return ns
}
