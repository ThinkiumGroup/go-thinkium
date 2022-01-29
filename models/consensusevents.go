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
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/ThinkiumGroup/go-common"
)

type TextEMessage struct {
	Body string
}
type ReportNodeInfoEMessage struct {
	NodeID common.NodeID
}

func (m *ReportNodeInfoEMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (m *ReportNodeInfoEMessage) String() string {
	if m == nil {
		return "ReportNodeInfo<nil>"
	}
	return fmt.Sprintf("ReportNodeInfo{NodeID:%s}", m.NodeID)
}

type CommEntry struct {
	ChainID common.ChainID
	Comm    *Committee
}

func (e CommEntry) String() string {
	return fmt.Sprintf("Entry{ChainID:%d Comm:%s}", e.ChainID, e.Comm)
}

// When starting, each chain data node reports the last consensus committee to the main chain
// data node
type LastCommEMessage struct {
	Height common.Height
	Entry  CommEntry
}

func (l *LastCommEMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (l *LastCommEMessage) String() string {
	if l == nil {
		return "LastComm<nil>"
	}
	return fmt.Sprintf("LastComm{ChainID:%d Height:%d Comm:%s}", l.Entry.ChainID, l.Height, l.Entry.Comm)
}

type StartCommEMessage struct {
	Comms []CommEntry
}

func (m *StartCommEMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (m *StartCommEMessage) GetComm(id common.ChainID) *Committee {
	for _, item := range m.Comms {
		if item.ChainID == id {
			return item.Comm
		}
	}
	return nil
}

func (m *StartCommEMessage) Hash() common.Hash {
	return common.EncodeHash(m)
}

func (m *StartCommEMessage) String() string {
	if m == nil {
		return "StartComm<nil>"
	}
	return fmt.Sprintf("StartComm{%s}", m.Comms)
}

type StartConsEMessage struct {
	ChainID common.ChainID
	Height  common.Height
}

func (m *StartConsEMessage) GetChainID() common.ChainID {
	return m.ChainID
}

func (m *StartConsEMessage) String() string {
	if m == nil {
		return "StartCons<nil>"
	}
	return fmt.Sprintf("StartCons{ChainID:%d Height:%d}", m.ChainID, m.Height)
}

type ToOneEMessage struct {
	From        common.NodeID
	To          common.NodeID
	NeedRespond bool
	Type        EventType
	Body        []byte
}

func (m *ToOneEMessage) Source() common.NodeID {
	return m.From
}

//
// func (m *ToOneEMessage) SourcePAS() *PubAndSig {
// 	return nil
// }

type JustHashEMessage struct {
	Hash common.Hash // hash of eventLoad
}

type WantDetailEMessage struct {
	Hash common.Hash // hash of eventLoad
}

/*
type JustDetailEMessage struct {
	Type EventType
	Body []byte
}
*/

type ElectMessage struct {
	// EpochNum is the current epoch number
	// I.e., the elected committee is for epoch EpochNum+1
	EpochNum     common.EpochNum `json:"epoch"` // 选举时所在epoch
	ElectChainID common.ChainID  `json:"chainid"`
	// block     *block // use to verify NCmessage
}

func (p *ElectMessage) Hash() common.Hash {
	return common.EncodeHash(p)
}

func (p *ElectMessage) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *ElectMessage) String() string {
	return fmt.Sprintf("Electing{ChainID:%d EpochNum:%d}", p.ElectChainID, p.EpochNum)
}

// To broadcast last height of the chain the current node recorded. Used to select the data node
// with the lowest height in the same chain ast the leader of synchronous data. The leader
// broadcasts the synchronization data. If everyone is highly consistent, everyone will send the
// same synchronization data
// FIXME: should use the data node with the highest height of data to be the leader. missing data
//  should be resync by sync procedure
type BlockHeight struct {
	ChainID common.ChainID
	Height  common.Height
}

func (bh *BlockHeight) GetChainID() common.ChainID {
	return bh.ChainID
}

func (bh *BlockHeight) GetHeight() common.Height {
	return bh.Height
}

func (bh *BlockHeight) GetEpochNum() common.EpochNum {
	if bh.Height.IsNil() {
		return 0
	}
	return bh.Height.EpochNum()
}

func (bh *BlockHeight) GetBlockNum() common.BlockNum {
	if bh.Height.IsNil() {
		return 0
	}
	return bh.Height.BlockNum()
}

func (bh BlockHeight) String() string {
	return fmt.Sprintf("Height{ChainID:%d Height:%d}", bh.ChainID, bh.Height)
}

type LastReportMessage struct {
	ChainID common.ChainID
	Height  common.Height
}

func (m *LastReportMessage) GetChainID() common.ChainID {
	return m.ChainID
}

func (m *LastReportMessage) DestChainID() common.ChainID {
	return m.ChainID
}

func (m *LastReportMessage) GetHeight() common.Height {
	return m.Height
}

func (m *LastReportMessage) GetEpochNum() common.EpochNum {
	return m.Height.EpochNum()
}

func (m *LastReportMessage) GetBlockNum() common.BlockNum {
	return m.Height.BlockNum()
}

func (m *LastReportMessage) String() string {
	if m.Height.IsNil() {
		return fmt.Sprintf("LastReport{ChainID:%d NONE}", m.ChainID)
	} else {
		return fmt.Sprintf("LastReport{ChainID:%d Height:%d EpochNum:%d BlockNum:%d}",
			m.ChainID, m.Height, m.GetEpochNum(), m.GetBlockNum())
	}
}

// Even if it is an empty block, the attendance table must be filled in. Otherwise, when the
// last block of epoch is an empty block, the data node will not be able to report the attendance
// table (the previous block cannot prove the attendance of the following block). Therefore,
// the empty block should not only fill in the attendance table, but also fill in the attendance
// hash in the header. In this way, the attendance table of each block is locked in the header,
// so there is no need to record blocknum separately
type AttendanceRecord struct {
	Epoch      common.EpochNum // current epoch
	Attendance *big.Int        // Indicates by bit whether the corresponding data block is empty, Attendance.Bit(BlockNum)==1 is normal block and ==0 is empty block
	DataNodes  common.NodeIDs  // List of datanode nodeid in ascending order
	Stats      []int           // Stats of alive data nodes

	nodeIdxs map[common.NodeID]int // cache data node id -> index of Stats
}

func NewAttendanceRecord(epoch common.EpochNum, dataNodes ...common.NodeID) *AttendanceRecord {
	r := &AttendanceRecord{
		Epoch:      epoch,
		Attendance: big.NewInt(0),
		DataNodes:  nil,
	}
	r.setDataNodes(dataNodes...)
	return r
}

func (a *AttendanceRecord) check(epoch common.EpochNum, block common.BlockNum) {
	if block == 0 || a.Attendance == nil {
		a.Epoch = epoch
		a.Attendance = big.NewInt(0)
	}
}

func (a *AttendanceRecord) SetAttendance(epoch common.EpochNum, block common.BlockNum) {
	a.check(epoch, block)
	a.Attendance.SetBit(a.Attendance, int(block), 1)
}

func (a *AttendanceRecord) SetAbsentness(epoch common.EpochNum, block common.BlockNum) {
	a.check(epoch, block)
	a.Attendance.SetBit(a.Attendance, int(block), 0)
}

func (a *AttendanceRecord) Hash() (*common.Hash, error) {
	b, e := common.HashObject(a)
	if e != nil {
		return nil, e
	}
	return common.BytesToHashP(b), nil
}

func (a *AttendanceRecord) setDataNodes(nodeIds ...common.NodeID) {
	if len(nodeIds) == 0 {
		a.DataNodes = make(common.NodeIDs, 0)
		return
	}
	m := make(map[common.NodeID]struct{})
	for i := 0; i < len(nodeIds); i++ {
		m[nodeIds[i]] = common.EmptyPlaceHolder
	}
	nids := make(common.NodeIDs, 0, len(m))
	for nid, _ := range m {
		nids = append(nids, nid)
	}
	sort.Sort(nids)
	a.DataNodes = nids
	a.Stats = make([]int, len(nids))
}

func (a *AttendanceRecord) AddDataNodeStat(nodeId common.NodeID) {
	if len(a.Stats) == len(a.DataNodes) {
		// update stats count if and only if stats created by NewAttendanceRecord method
		idx := a.dataNodeIdx(nodeId)
		if idx < 0 {
			return
		}
		a.Stats[idx]++
	}
}

func (a *AttendanceRecord) IsLegalFirst(datanodes common.NodeIDs) error {
	if a == nil {
		return errors.New("nil attendance")
	}
	if len(a.DataNodes) != len(a.Stats) || len(a.DataNodes) != len(datanodes) {
		return errors.New("wrong size of data nodes or stats")
	}
	// check data node legality when starting an epoch
	for i := 0; i < len(datanodes); i++ {
		if datanodes[i] != a.DataNodes[i] {
			return errors.New("illegal data nodes")
		}
	}
	// check stats: values of new attendance stats can only be 1 or 0
	for _, stat := range a.Stats {
		if stat != 0 && stat != 1 {
			return errors.New("new stat should be 0 or 1")
		}
	}
	return nil
}

func (a *AttendanceRecord) IsLegalNext(next *AttendanceRecord) error {
	if next == nil {
		if a != nil {
			return errors.New("should not turn not nil to nil")
		}
		// always nil is ok, means no reward needed
		return nil
	}

	if a == nil {
		// basic check of next
		if len(next.DataNodes) != len(next.Stats) {
			return errors.New("new attendance with not equal sizes of DataNodes and Stats")
		}

		// values of new attendance stats can only be 1 or 0
		for _, stat := range next.Stats {
			if stat != 0 && stat != 1 {
				return errors.New("new stat should be 0 or 1")
			}
		}
		return nil
	}

	// a != nil && next != nil
	// datanodes list must be same except switching epoch. Because of DataNodes changes are begin
	// to take effect on the beginning of an epoch. Which means attendance of Epoch:N.Block:0 is
	// not a legal next to Epoch.(N-1).Block.(BlocksInEpoch-1).
	if len(next.DataNodes) != len(a.DataNodes) || len(next.Stats) != len(a.Stats) {
		return errors.New("size of data nodes and stats should not change in one epoch")
	}
	for i := 0; i < len(next.DataNodes); i++ {
		if next.DataNodes[i] != a.DataNodes[i] {
			return errors.New("data nodes should not change")
		}
	}
	for i := 0; i < len(next.Stats); i++ {
		if next.Stats[i] != a.Stats[i] && next.Stats[i] != a.Stats[i]+1 {
			return errors.New("illegal change of stats")
		}
	}

	return nil
}

func (a *AttendanceRecord) String() string {
	if a == nil {
		return fmt.Sprintf("AttendanceRecord<nil>")
	}
	return fmt.Sprintf("AttendanceRecord{Epoch:%d Attendance.BitLen:%d DataNodes:%s Stats：%v}",
		a.Epoch, a.Attendance.BitLen(), a.DataNodes, a.Stats)
}

func (a *AttendanceRecord) Formalize() {
	// if a != nil && len(a.DataNodes) > 1 {
	// 	sort.Sort(a.DataNodes)
	// }
}

func (a *AttendanceRecord) dataNodeIdx(nid common.NodeID) int {
	if a == nil {
		return -1
	}
	// cache
	if a.nodeIdxs == nil {
		a.nodeIdxs = make(map[common.NodeID]int)
		for i, id := range a.DataNodes {
			a.nodeIdxs[id] = i
		}
	}
	// for i, id := range a.DataNodes {
	// 	if id == nid {
	// 		return i
	// 	}
	// }
	if i, exist := a.nodeIdxs[nid]; exist {
		return i
	}
	return -1
}

type RewardRequest struct {
	ChainId      common.ChainID
	CommitteePks [][]byte          // The public key list of the members of the current committee in the order of proposing
	Epoch        common.EpochNum   // Epoch where the reward is declared
	LastHeader   *BlockHeader      // The block header of the last block of the epoch declared
	Attendance   *AttendanceRecord // The attendance table of the last block, which contains the attendance records of the entire epoch
	PASs         PubAndSigs        // Signature list for the last block
}

func (a *RewardRequest) HashValue() ([]byte, error) {
	// Without signature set, the block signature set received by each data node is not the same
	pas := a.PASs
	a.PASs = nil
	ret, err := common.EncodeAndHash(a)
	a.PASs = pas
	return ret, err
}

func (a *RewardRequest) GetChainID() common.ChainID {
	return common.MainChainID
}

func (a *RewardRequest) DestChainID() common.ChainID {
	return common.MainChainID
}

func (a *RewardRequest) Hash() common.Hash {
	b, e := common.HashObject(a)
	if e != nil {
		return common.NilHash
	}
	return common.BytesToHash(b)
}

func (a *RewardRequest) String() string {
	if a == nil {
		return fmt.Sprintf("RewardRequest<nil>")
	}
	return fmt.Sprintf("RewardRequest{ChainID:%d Epoch:%d Last:%s Pas:%d Pks:%d, attendance:%s}",
		a.ChainId, a.Epoch, a.LastHeader.Summary(), len(a.PASs), len(a.CommitteePks), a.Attendance)
}

func (a *RewardRequest) Formalize() {
	if a == nil {
		return
	}
	if len(a.PASs) > 1 {
		sort.Sort(a.PASs)
	}
}

type RewardRequests []*RewardRequest

func (rs RewardRequests) Len() int {
	return len(rs)
}

func (rs RewardRequests) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

func (rs RewardRequests) Less(i, j int) bool {
	if less, compare := common.PointerSliceLess(rs, i, j); compare == false {
		return less
	}
	if rs[i].ChainId == rs[j].ChainId {
		return rs[i].Epoch < rs[j].Epoch
	} else if rs[i].ChainId < rs[j].ChainId {
		return true
	}
	return false
}
