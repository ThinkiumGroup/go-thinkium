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
	"sort"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/consts"
)

type (
	// Node internal control event. When you need to start a preelection, just send a message
	// to the queue
	// Create at performing commitPreelects when executing StateDB.Commit.
	PreelectionStart struct {
		ChainID      common.ChainID // the chain starting preelection
		ParentHeight common.Height  // the main chain height when starting the preelection
	}

	// Node internal control event. When the pre-election enters the startup phase, and the node
	// is selected, this message is sent to connect to the network, and the corresponding identity
	// of the chain is set to PREELECT
	// Create at performing commitPreelects.checkElected when executing StateDB.Commit.
	PreelectionConnect struct {
		ChainID common.ChainID // The chain that needs to be connected after the pre-election
		Height  common.Height  // Record the height of the main chain generating the message, and to distinguish different events (to avoid Hash duplication)
		Comm    *Committee     // Committee after pre-election
	}

	// Node internal control event, the data node starts to broadcast synchronous data during
	// the pre-election startup phase
	// Create at preforming commitPreelects.checkElected when executing StateDB.Commit
	PreelectionSync struct {
		ChainID common.ChainID
		Height  common.Height
	}

	// Node internal control event, the consensus node checks whether the consensus is normal
	// during the pre-election startup phase
	// Create at preforming commitPreelects.checkElected when executing StateDB.Commit
	PreelectionExamine struct {
		ChainID common.ChainID
		Height  common.Height
	}

	// Node internal control event, consensus node found failure in the pre-election during the
	// startup phase, exit the network, and close consensus
	// Create at performing commitPreelects when executing StateDB.Commit.
	// (Fault tolerance mechanism) or create at preforming commitPreelects.checkElected when
	// executing StateDB.Commit
	PreelectionExit struct {
		ChainID common.ChainID
		Height  common.Height
	}
)

func (p *PreelectionStart) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *PreelectionStart) String() string {
	if p == nil {
		return "PEStart<nil>"
	}
	return fmt.Sprintf("PEStart{ChainID:%d ParentHeight:%d}", p.ChainID, p.ParentHeight)
}

func (p *PreelectionConnect) GetChainID() common.ChainID {
	return common.MainChainID
}

func (p *PreelectionConnect) String() string {
	if p == nil {
		return "PEConnect<nil>"
	}
	return fmt.Sprintf("PEConnect{ChainID:%d Height:%d Comm:%s}", p.ChainID, p.Height, p.Comm)
}

func (p PreelectionSync) GetChainID() common.ChainID {
	return p.ChainID
}

func (p *PreelectionSync) String() string {
	if p == nil {
		return "PESync<nil>"
	}
	return fmt.Sprintf("PESync{ChainID:%d Height:%d}", p.ChainID, p.Height)
}

func (p PreelectionExamine) GetChainID() common.ChainID {
	return p.ChainID
}

func (p *PreelectionExamine) String() string {
	if p == nil {
		return "PEExamine<nil>"
	}
	return fmt.Sprintf("PEExamine{ChainID:%d Height:%d}", p.ChainID, p.Height)
}

func (p PreelectionExit) GetChainID() common.ChainID {
	return p.ChainID
}

func (p *PreelectionExit) String() string {
	if p == nil {
		return "PEExit<nil>"
	}
	return fmt.Sprintf("PEExit{ChainID:%d Height:%d}", p.ChainID, p.Height)
}

type PreElectPhase byte

// Create pre-election stage: Create when the contract is successfully executed, enter the Creating
//    stage, broadcast and delete when proposing, there is no CachedHash at this time.
// Pre-election phase: In the commit block phase, use block.PreElectings to overwrite the electings
//    in the cache, and clear the corresponding creating/results/elected cache.
// For different stages:
//    Creating: Enter the Electing phase, add CachedHash, and generate a PreelectionStart control
//              event, which is responsible for sending out the election information of this node
//    Electing: Add CachedHash
//    Starting: No need to deal with
//    Exiting: When the Starting timeout, switch to Exiting package, when receiving Exiting in the
//             package, you need to send a control event to check whether the target chain is started,
//             if not you need to exit
// Pre-launch phase: When reaching Electing.Expire, if the election result is successful, enter the
//    Starting phase and pack
// 创建预选举阶段: 合约执行成功时创建，进入Creating阶段，打包时广播并删除，此时没有CachedHash。
// 预选举阶段: 在commit block阶段，使用block.PreElectings覆盖缓存中的electings, 并清除相应creating/results/elected缓存。针对不同阶段：
//    Creating: 进入Electing阶段，补CachedHash，并产生PreelectionStart控制消息，该消息负责向外发送本节点的参选信息
//    Electing: 补CachedHash
//    Starting: 无需处理
//    Exiting: 当Starting超时时，转为Exiting打包，接收到包中Exiting时，需要发送控制消息检查目标链是否启动了，没有启动需要退出
// 预启动阶段: 到达Electing.Expire时，如果选举结果成功，则进入Starting阶段并打包
const (
	PECreating PreElectPhase = 0x0 + iota // new pre-election
	PEElecting                            // pre-electing
	PEStarting                            // starting
	PEExiting                             // exiting
)

func (p PreElectPhase) String() string {
	switch p {
	case PECreating:
		return "Creating"
	case PEElecting:
		return "Electing"
	case PEStarting:
		return "Starting"
	case PEExiting:
		return "Exiting"
	default:
		return fmt.Sprintf("unknown-0x%x", byte(p))
	}
}

// The pre-election records, generated by the contract call of creation of the chain or the
// start of the pre-election, are put into the block after the main chain is generated. The
// consensused pre-election, which is generated from the Start block of the main chain and
// continues until the Expire block, has been kept in the main chain block until it is deleted.
// Makes the pre-election well documented.
// And it is necessary to synchronize the preElectCache in the main chain DataHolder when
// the new node synchronizes the main chain data, because the seed required by the VRF
// algorithm will be recorded in the cache.
// 由创建链或启动预选举合约产生的预选举记录，在主链生成后放入块中，以此
// 发布经过共识的预选举，从主链的第Start块生成，一直持续到Expire块之后
// 被主链共识删除为止一直保存在主链块中。使得预选举有据可查。
// 且需要在新节点同步主链数据时将主链DataHolder中的preElectCache一起
// 同步，因为在cache中会记录VRF算法需要的seed。
type PreElecting struct {
	// Chain of pre-election
	ChainID common.ChainID
	// Current execution stage
	Phase PreElectPhase
	// Seed of main chain when pre-electing
	Seed *common.Seed
	// Count the number of election retrys, because the election may not be successful, and the
	// election can be automatically started again (3 times in total)
	Count int
	// The height of the main chain when the pre-election starts. Because the Hash value of the
	// current block is required when creating PreElecting, it cannot be stored in the object and
	// needs to be obtained from the data node when synchronizing data
	Start common.Height
	// The Hash of the main chain height block at startup has a value in the cache and is nil in
	// the BlockBody
	CachedHash *common.Hash
	// When the new chain is a ManagedComm chain, NidHashes saves the hash values of all authorized
	// node IDs, which are the basis for the pre-election. The election type can also be judged
	// based on whether this field is empty
	NidHashes []common.Hash
	// Electing phase: the height of the main chain at which the pre-election ends;
	// Starting phase: the height of the main chain at which consensus is initiated
	Expire common.Height
}

func (pe *PreElecting) String() string {
	if pe == nil {
		return "Preelect<nil>"
	}
	return fmt.Sprintf("Preelect{ChainID:%d %s Seed:%x Count:%d Start:%d StartHash:%x NidHashes:%d Expire:%d}",
		pe.ChainID, pe.Phase, common.ForPrint(pe.Seed), pe.Count,
		pe.Start, common.ForPrint(pe.CachedHash), len(pe.NidHashes), pe.Expire)
}

func (pe *PreElecting) IsValidManagedComm() bool {
	if pe == nil {
		return false
	}
	return len(pe.NidHashes) >= consts.MinimumCommSize
}

func (pe *PreElecting) IsVrf() bool {
	return pe != nil && pe.Seed != nil && len(pe.NidHashes) == 0
}

func (pe *PreElecting) IsManagedComm() bool {
	return pe != nil && pe.Seed == nil && len(pe.NidHashes) > 0
}

func PreelectSeed(seed common.Seed, blockHash common.Hash) common.Seed {
	h := common.Hash256(seed[:], blockHash[:])
	return common.BytesToSeed(h[:])
}

func (pe *PreElecting) PreSeed() (*common.Seed, error) {
	if pe.Seed == nil || pe.CachedHash == nil {
		return nil, fmt.Errorf("vrf preelect seed (%x) or hash (%x) is nil",
			common.ForPrint(pe.Seed),
			common.ForPrint(pe.CachedHash))
	}
	preseed := PreelectSeed(*pe.Seed, *pe.CachedHash)
	return &preseed, nil
}

func (pe *PreElecting) Clone() *PreElecting {
	if pe == nil {
		return nil
	}
	return &PreElecting{
		ChainID:    pe.ChainID,
		Phase:      pe.Phase,
		Seed:       pe.Seed.Clone(),
		Count:      pe.Count,
		Start:      pe.Start,
		CachedHash: pe.CachedHash.Clone(),
		NidHashes:  common.CopyHashs(pe.NidHashes),
		Expire:     pe.Expire,
	}
}

// Generate objects for packaging, the pre-election information in the block does not include BlockHash
func (pe *PreElecting) ToPack() *PreElecting {
	if pe == nil {
		return nil
	}
	return &PreElecting{
		ChainID:   pe.ChainID,
		Phase:     pe.Phase,
		Seed:      pe.Seed.Clone(),
		Count:     pe.Count,
		Start:     pe.Start,
		Expire:    pe.Expire,
		NidHashes: common.CopyHashs(pe.NidHashes),
	}
}

func (pe *PreElecting) Equals(o *PreElecting) bool {
	if pe == o {
		return true
	}
	if pe == nil || o == nil {
		return false
	}
	if pe.ChainID != o.ChainID || pe.Phase != o.Phase || pe.Count != o.Count ||
		pe.Start != o.Start || pe.Expire != o.Expire {
		return false
	}
	if !pe.Seed.Equals(o.Seed) || !pe.CachedHash.Equals(o.CachedHash) {
		return false
	}
	if !common.HashsEquals(pe.NidHashes, o.NidHashes) {
		return false
	}
	return true
}

// Objects placed in the block, the ongoing pre-election list sorted by (Expire, ChainID),
// and generate MerkleTreeHash into the block header
type PreElectings []*PreElecting

func (p PreElectings) Len() int {
	return len(p)
}

func (p PreElectings) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p PreElectings) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(p, i, j); !needCompare {
		return less
	}
	if p[i].Expire == p[j].Expire {
		if p[i].ChainID == p[j].ChainID {
			return p[i].Phase < p[j].Phase
		}
		return p[i].ChainID < p[j].ChainID
	}
	return p[i].Expire < p[j].Expire
}

func (p PreElectings) Equals(o PreElectings) bool {
	if p == nil && o == nil {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	if len(p) != len(o) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !p[i].Equals(o[i]) {
			return false
		}
	}
	return true
}

// Calculate MerkelHash, need to sort before calling
func (p PreElectings) HashValue() ([]byte, error) {
	var hashlist [][]byte
	for _, electing := range p {
		if electing == nil {
			hashlist = append(hashlist, common.CopyBytes(common.NilHashSlice))
		} else {
			h, err := common.HashObject(electing)
			if err != nil {
				return nil, err
			}
			hashlist = append(hashlist, h)
		}
	}
	return common.MerkleHash(hashlist, -1, nil)
}

type (
	// Election type interface based on VRF algorithm
	VrfResulter interface {
		GetNodeID() common.NodeID
		GetVrfResult() (sortHash *common.Hash, proof []byte, factorHash *common.Hash)
		VrfVerify(seed common.Seed) error
	}

	// Election result interface
	ElectResulter interface {
		// The chain ID where the election occurs should be distinguished from the GetChainID()
		// method of the ChainEvent interface
		GetElectingChainID() common.ChainID
		// The Epoch where the election took place, the value of the pre-election is NilEpoch
		GetEpochNum() common.EpochNum
		VrfResulter
	}

	// Election results in a unified format, used when transmitting separately
	// In order to be compatible with VRFResultEMessage, the format is compatible
	ElectResult struct {
		NodeID   common.NodeID   // Node ID participating in the election
		ChainID  common.ChainID  // Election chain
		Epoch    common.EpochNum // Epoch of the election
		Sorthash *common.Hash    // The result of the VRF algorithm
		Proof    []byte          // Proof of VRF algorithm results
	}

	ElectResults []*ElectResult

	// Because the ChainID/Epoch information is missing, it cannot be used alone and needs to be
	// used in conjunction with ChainElectResult
	NodeResult struct {
		NodeID     common.NodeID // The ID of the node participating in the election. For ManagedComm, only this field is needed, and the other fields are empty
		Sorthash   *common.Hash  // The result of the VRF algorithm
		Proof      []byte        // Proof of VRF algorithm results
		FactorHash *common.Hash  // since2.0.0 The node declares the hash of the random factor participating in the seed calculation
	}

	NodeResults []*NodeResult

	// The compound data structure packed in the block, the memory and the form of the data set in the block
	ChainElectResult struct {
		ChainID common.ChainID  // Election chain
		Epoch   common.EpochNum // The Epoch where the election took place, the value of the pre-election is NilEpoch
		Results NodeResults
	}

	ChainElectResults []*ChainElectResult
)

func (r *ElectResult) FromResulter(resulter ElectResulter) *ElectResult {
	r.ChainID = resulter.GetElectingChainID()
	r.Epoch = resulter.GetEpochNum()
	r.NodeID = resulter.GetNodeID()
	r.Sorthash, r.Proof, _ = resulter.GetVrfResult()
	return r
}

func (r *ElectResult) GetChainID() common.ChainID {
	return r.ChainID
}

func (r *ElectResult) GetElectingChainID() common.ChainID {
	return r.ChainID
}

func (r *ElectResult) GetEpochNum() common.EpochNum {
	return r.Epoch
}

func (r *ElectResult) GetNodeID() common.NodeID {
	return r.NodeID
}

func (r *ElectResult) GetVrfResult() (*common.Hash, []byte, *common.Hash) {
	return r.Sorthash, r.Proof, nil
}

func (r *ElectResult) IsPreElecting() bool {
	return r.Epoch.IsNil()
}

func (r *ElectResult) VrfVerify(seed common.Seed) error {
	return VerifyVrfResult(r, seed)
}

func (r *ElectResult) String() string {
	if r == nil {
		return "EResult<nil>"
	}
	return fmt.Sprintf("EResult{NID:%s ChainID:%d Epoch:%s Sorthash:%x Proof:%x}", r.NodeID, r.ChainID, r.Epoch,
		common.ForPrint(r.Sorthash), common.ForPrint(r.Proof))
}

func VerifyVrfResult(event VrfResulter, seed common.Seed) error {
	if event == nil {
		return common.ErrNil
	}
	sortHash, proof, _ := event.GetVrfResult()
	if sortHash == nil || len(proof) == 0 {
		return errors.New("sortHash or proof is nil")
	}
	nid := event.GetNodeID()
	if len(proof) == 0 {
		return common.ErrNil
	}

	pubKey, err := common.RealCipher.BytesToPub(common.RealCipher.PubFromNodeId(nid[:]))
	if err != nil {
		return err
	}
	if !pubKey.VrfVerify(seed[:], proof, *sortHash) {
		return fmt.Errorf("VRF result verify failed: NodeID:%x Seed:%x Proof:%x SortHash:%x",
			nid[:5], seed[:5], proof[:5], sortHash[:5])
	}
	return nil
}

func (rs ElectResults) Len() int {
	return len(rs)
}

func (rs ElectResults) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

// sorted by (ChainID, EpochNum, Sorthash, NodeID)
func (rs ElectResults) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(rs, i, j); needCompare == false {
		return less
	}
	if rs[i].ChainID < rs[j].ChainID {
		return true
	} else if rs[i].ChainID > rs[j].ChainID {
		return false
	}
	if rs[i].Epoch == rs[j].Epoch {
		// For VRF, sort by SortHash
		p := bytes.Compare(rs[i].Sorthash.Slice(), rs[j].Sorthash.Slice())
		if p == 0 {
			// If SortHash is the same, or more likely ManagedCommittee, then sort by NodeID
			return bytes.Compare(rs[i].NodeID[:], rs[j].NodeID[:]) < 0
		}
		return p < 0
	} else {
		if rs[i].Epoch.IsNil() || rs[i].Epoch < rs[j].Epoch {
			return true
		} else {
			return false
		}
	}
}

func (rs ElectResults) HashValue() ([]byte, error) {
	hashList := make([][]byte, len(rs))
	var err error
	for i := 0; i < len(rs); i++ {
		hashList[i], err = common.HashObject(rs[i])
		if err != nil {
			return nil, fmt.Errorf("hash (%d) result with error: %v", i, err)
		}
	}
	return common.MerkleHash(hashList, -1, nil)
}

func (rs ElectResults) ToPreElectMap() map[common.ChainID]map[common.NodeID]*ElectResult {
	mm := make(map[common.ChainID]map[common.NodeID]*ElectResult)
	for _, one := range rs {
		if one == nil || one.Epoch.IsNil() {
			// If it is not a pre-election result, skip it
			continue
		}
		m, ok := mm[one.ChainID]
		if !ok {
			m = make(map[common.NodeID]*ElectResult)
			mm[one.ChainID] = m
		}
		m[one.NodeID] = one
	}
	return mm
}

func (n *NodeResult) FromVrfResulter(resulter VrfResulter) *NodeResult {
	n.NodeID = resulter.GetNodeID()
	n.Sorthash, n.Proof, n.FactorHash = resulter.GetVrfResult()
	return n
}

func (n *NodeResult) GetNodeID() common.NodeID {
	return n.NodeID
}

func (n *NodeResult) GetVrfResult() (sorthash *common.Hash, proof []byte, factorHash *common.Hash) {
	return n.Sorthash, n.Proof, n.FactorHash
}

func (n *NodeResult) VrfVerify(seed common.Seed) error {
	return VerifyVrfResult(n, seed)
}

func (n *NodeResult) String() string {
	if n == nil {
		return "NodeResult<nil>"
	}
	return fmt.Sprintf("NR{NID:%s Proof:%x Sorthash:%x}", n.NodeID,
		common.ForPrint(n.Proof), common.ForPrint(n.Sorthash))
}

func (ns NodeResults) Len() int {
	return len(ns)
}

func (ns NodeResults) Swap(i, j int) {
	ns[i], ns[j] = ns[j], ns[i]
}

func (ns NodeResults) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(ns, i, j); !needCompare {
		return less
	}
	// For VRF, sort by SortHash
	p := bytes.Compare(ns[i].Sorthash.Slice(), ns[i].Sorthash.Slice())
	if p == 0 {
		// If SortHash is the same, or more likely ManagedCommittee, then sorthash is nil, sorted by NodeID
		return bytes.Compare(ns[i].NodeID[:], ns[j].NodeID[:]) < 0
	}
	return p < 0
}

func (ns NodeResults) VrfVerifyAll(seed common.Seed) error {
	for i, nr := range ns {
		if err := nr.VrfVerify(seed); err != nil {
			return fmt.Errorf("index %d, %s verify failed: %v", i, nr, err)
		}
	}
	return nil
}

func (ns NodeResults) ManagedCommVerifyAll(nidHashes []common.Hash) error {
	if len(ns) < 20 {
		for _, nr := range ns {
			if nr == nil {
				return errors.New("nil result found")
			}
			if common.IsNodeIDIn(nidHashes, nr.NodeID) == false {
				return fmt.Errorf("%s is not a authorized node", nr.NodeID)
			}
		}
	} else {
		m := make(map[common.Hash]struct{}, len(nidHashes))
		for _, nidh := range nidHashes {
			m[nidh] = struct{}{}
		}
		for _, nr := range ns {
			if nr == nil {
				return errors.New("nil result found")
			}
			h := nr.NodeID.Hash()
			if _, exist := m[h]; !exist {
				return fmt.Errorf("%s is not a authorized node", nr.NodeID)
			}
		}
	}
	return nil
}

func (ns NodeResults) ToMap() map[common.NodeID]*NodeResult {
	m := make(map[common.NodeID]*NodeResult, len(ns))
	for _, nr := range ns {
		if nr != nil {
			m[nr.NodeID] = nr
		}
	}
	return m
}

// the difference of ns - os
func (ns NodeResults) Remove(os NodeResults) NodeResults {
	if len(ns) == 0 {
		return nil
	}
	if len(os) == 0 {
		return ns
	}
	var ret NodeResults
	osm := os.ToMap()
	for _, nr := range ns {
		if nr == nil {
			continue
		}
		if _, exist := osm[nr.NodeID]; !exist {
			ret = append(ret, nr)
		}
	}
	return ret
}

func (c *ChainElectResult) ResultLen() int {
	return len(c.Results)
}

func (c *ChainElectResult) Success() bool {
	if c == nil {
		return false
	}
	return len(c.Results) >= consts.MinimumCommSize
}

func (c *ChainElectResult) ToCommittee() *Committee {
	if len(c.Results) == 0 {
		return NewCommittee()
	}
	if len(c.Results) > 1 {
		sort.Sort(c.Results)
	}
	nids := make([]common.NodeID, len(c.Results))
	for i := 0; i < len(c.Results); i++ {
		nids[i] = c.Results[i].NodeID
	}
	return &Committee{Members: nids}
}

func (c *ChainElectResult) String() string {
	if c == nil {
		return "CEResult<nil>"
	}
	return fmt.Sprintf("CEResult{ChainID:%d Epoch:%s Len(Results):%d}", c.ChainID, c.Epoch, len(c.Results))
}

func (c *ChainElectResult) HashValue() ([]byte, error) {
	if c == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	hashList := make([][]byte, len(c.Results)+2)
	hashList[0], _ = common.HashObject(c.ChainID)
	hashList[1], _ = common.HashObject(c.Epoch)
	var err error
	for i := 0; i < len(c.Results); i++ {
		hashList[i+2], err = common.HashObject(c.Results[i])
		if err != nil {
			return nil, fmt.Errorf("hash (%d) NodeResult with error: %v", i, err)
		}
	}
	return common.MerkleHash(hashList, -1, nil)
}

func (cs ChainElectResults) Len() int {
	return len(cs)
}

func (cs ChainElectResults) Swap(i, j int) {
	cs[i], cs[j] = cs[j], cs[i]
}

func (cs ChainElectResults) Less(i, j int) bool {
	if less, needCompare := common.PointerSliceLess(cs, i, j); !needCompare {
		return less
	}
	if cs[i].ChainID == cs[j].ChainID {
		if cs[i].Epoch == cs[j].Epoch {
			return false
		}
		return cs[i].Epoch.IsNil() || cs[i].Epoch < cs[j].Epoch
	}
	return cs[i].ChainID < cs[j].ChainID
}

// Whether there is a pre-election result
func (cs ChainElectResults) HavePreelects() bool {
	if len(cs) == 0 {
		return false
	}
	for _, rs := range cs {
		if rs == nil {
			continue
		}
		if rs.Epoch.IsNil() {
			return true
		}
	}
	return false
}

func (cs ChainElectResults) ToMap() map[common.ChainID]*ChainElectResult {
	if cs == nil {
		return nil
	}
	r := make(map[common.ChainID]*ChainElectResult, len(cs))
	for _, cer := range cs {
		if cer != nil {
			r[cer.ChainID] = cer
		}
	}
	return r
}

func (cs ChainElectResults) HashValue() ([]byte, error) {
	hashList := make([][]byte, len(cs))
	var err error
	for i := 0; i < len(cs); i++ {
		hashList[i], err = common.HashObject(cs[i])
		if err != nil {
			return nil, fmt.Errorf("hash (%d) ChainElectResult with error: %v", i, err)
		}
	}
	return common.MerkleHash(hashList, -1, nil)
}
