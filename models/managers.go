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
	"net"
	"reflect"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/trie"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/sirupsen/logrus"
)

var (
	ErrMainChainOnly = errors.New("supported by main chain only")
)

type (
	BlockChain interface {
		CurrentBlock() *BlockEMessage
		Append(block *BlockEMessage, validator func(*BlockEMessage) error) (int, []byte, error)
		GetCurrentHeight() common.Height
		GetBlockHash(height common.Height) (*common.Hash, bool)
		GetBlock(height common.Height) (*BlockEMessage, error)
		GetHeader(height common.Height) (*BlockHeader, error)
		GetBlockByHash(hashOfHeader []byte) (*BlockEMessage, error)
		GetBlockTxIndexs(txHash []byte) (*TXIndex, error)
	}

	BlockAppendSuccess func(block *BlockEMessage, hashOfHeader []byte) error

	// snapshot of chain status
	ChainSnapshot struct {
		Height     common.Height    // current height
		Block      *BlockEMessage   // block of current height
		Waterlines []ShardWaterline // waterlines of shards at current height
		CheckEpoch bool             // whether to check epoch matchness
	}

	ProposeResult struct {
		Processed      []*Transaction    // executed transactions
		ProcessedPas   []*PubAndSig      // the signatures corresponding to the executed transactions one by one
		StateRoot      []byte            // world state tree root hash after transaction execution
		DeltaTrie      *AccountDeltaTrie // DeltaTrie generated after transaction execution
		ReceiptsHash   []byte            // hash value of all executed transactions receipts
		VccRoot        []byte            // root hash of signed check tree
		CashedRoot     []byte            // root hash of cashed check tree
		RREra          common.EraNum     // current era of reward chain
		RRRoot         []byte            // root hash of required reserve tree at current era in reward chain
		RRNextRoot     []byte            // root hash of required reserve tree at next era in reward chain
		RRChangingRoot []byte            // root hash of modification request tree currently to be applied in reward chain
		ChainInfoRoot  []byte            // root hash of chain info tree in main chain
		WaterlinesRoot []byte            // merkle root hash of all waterline values of all shards after the completion of delta merge and transaction execution
	}

	WholeWorld struct {
		State        *trie.Trie
		Chains       *trie.Trie
		History      *trie.HistoryTree
		Waterlines   []ShardWaterline
		Vcc          *trie.Trie
		Cashed       *trie.Trie
		RREra        *common.EraNum
		RRCurrent    *trie.Trie
		RRNext       *trie.Trie
		RRChanging   *trie.Trie
		PreElectings PreElectings
	}

	DataHolder interface {
		// GetChainInfo() *common.ChainInfos
		// GetShardInfo returns ShardInfo only if current chain is a shard chain
		GetShardInfo() common.ShardInfo
		GetChainInfoRoot() (*common.Hash, error)
		SetGenesisHeader(header *BlockHeader) error
		GetChainInfo() (*common.ChainInfos, bool)
		// ChainList() common.ChainIDs
		GetDataNodeList() common.NodeIDs
		IsDataNode() bool // is it the data node of current chain
		IsMemoNode() bool // is it the full node of current chain
		IncCount(height common.Height, timestamp uint64, count uint64)
		// FIXME: should not reture database to other layer
		GetDb() db.Database

		// GetBlockChain get BlockChain of current Chain
		GetBlockChain() BlockChain
		GetBlock(height common.Height) (*BlockEMessage, error)
		GetBlockByHash(hashOfHeader []byte) (*BlockEMessage, error)
		GetBlockWithUnverified(height common.Height) (*BlockEMessage, error)
		SaveUnverifiedBlock(block *BlockEMessage) error
		GetBlockHash(height common.Height) (*common.Hash, bool)
		GetHeader(height common.Height) (*BlockHeader, error)
		GetHistoryRoot(expectingHeight common.Height) ([]byte, error)
		// SaveRewardRequests(block *BlockEMessage, hashOfBlock []byte) error
		PutBlock(block *BlockEMessage, appendSuccessFunc BlockAppendSuccess) error

		CreateEmptyAccountTrie() *trie.Trie
		CreateAccountTrie(rootHash []byte) *trie.Trie
		RestoreHistoryTreeFromProofs(lastHeight common.Height, lastHeightHash []byte,
			proofs trie.ProofChain) (*trie.HistoryTree, error)
		CreateHistoryTree(root []byte, checkPrecedingNil bool) (*trie.HistoryTree, error)
		CreateEmptyVccOrigin() *trie.Trie
		CreateEmptyCashedOrigin() *trie.Trie
		SyncState(height common.Height, block *BlockEMessage, states *WholeWorld, logger logrus.FieldLogger) error
		SyncChains(chains *trie.Trie) error
		SyncAccTrie(height common.Height, accStates *trie.Trie) error
		SyncBlock(block *BlockEMessage) error
		// IsSynced returns 0 if the chain is not yet synced, and returns 1 if synced
		IsSynced() bool
		SetSynced()
		IsFull() bool
		StopSyncing()
		IsEmpty() bool
		IsExpectingEpoch(epoch common.EpochNum) error
		GetCurrentHeight() common.Height
		SetCurrentHeight(height common.Height)
		SetCurrentToHeight(height common.Height, hob common.Hash) error

		GetWorldStateRoot() ([]byte, error)
		SnapshotRoots() (snapshot *ChainSnapshot, err error)
		GetWorldStateStream(snapshot *ChainSnapshot) (accStream [][]byte,
			stoStream [][]byte, codeStream [][]byte, longStream [][]byte, deltaStream [][]byte, chainsStream []byte, err error)
		GetCashCheckState(vccRoot, cashedRoot []byte) (vccs, casheds [][]byte, err error)
		// UnmarshalSyncData(r io.Reader) (*trie.Trie, *trie.Trie, error)

		// GetTransactions returns transaction trie in specific block
		GetTransactions(height common.Height) (trie.ITrie, error)
		// GetReceipts returns receipt list in specific block by its receiptsHash
		GetReceiptsByRoot(receiptHash common.Hash) Receipts

		CallProcessTx(tx *Transaction, senderSig *PubAndSig, blockHeader *BlockHeader) (interface{}, error)

		ProposeData(froms DeltaFroms, header *BlockHeader, txs []*Transaction, pas []*PubAndSig) (result *ProposeResult, err error)

		CanBeAccept(reportChainID common.ChainID, height common.Height, hob []byte) error
		PrepareBlock(block *BlockEMessage) error
		ForceCommit() (err error)

		CreateRootDeltaTrie() *AccountDeltaTrie
		// RestoreDeltaTrieFromBlock recover complete AccountDeltaTrie from block。
		RestoreDeltaTrieFromBlock(block *BlockEMessage) (*AccountDeltaTrie, error)

		SaveReceivedDelta(fromID common.ChainID, height common.Height, deltas []*AccountDelta) (
			overflow bool, waterline common.Height, overflowed []*DeltaFrom, missing bool, missingLength int, err error)
		SaveDeltasGroup(fromID common.ChainID, group DeltasGroup) (overflow bool,
			waterline common.Height, overflowed []*DeltaFrom, missing bool, missingLength int, err error)

		CheckReceivedDelta(fromID common.ChainID, height common.Height) bool

		CreateAccountDeltaTrie() trie.ITrie
		PopDeltaFroms() DeltaFroms
		PutDeltaFroms(deltaFroms DeltaFroms)
		CreateDeltaFromTrie() *AccountDeltaFromTrie
		ShouldSendDelta() (A, B common.Height, confirmed common.Height, mainBlockSummary *HeaderSummary, err error)
		SetDeltaToBeSent(height common.Height)
		VerifyDeltasPack(pack *DeltasPack) error

		// Verifiable Cash Check Trie
		AddVCC(vcc *CashCheck) (hashOfVcc []byte, err error)
		DeleteVCC(vcc *CashCheck) (ok bool, hashOfVcc []byte, err error)
		VccProof(vcc *CashCheck) (height common.Height, proofChain trie.ProofChain, hashOfHeader []byte, err error)
		AddCCC(vcc *CashCheck, txHash *common.Hash) (hashOfVcc []byte, err error)
		CCCExsitenceProof(ccc *CashCheck) (height common.Height, existence bool, existProof trie.ProofChain,
			cashedRootProof trie.ProofChain, hashOfHeader []byte, err error)
		GetCCCRelativeTx(hashOfVcc []byte) (hashOfTx []byte, err error)

		CreateVCCTrie(root []byte) *trie.Trie
		CreateCCCTrie(root []byte) *trie.Trie

		GetAccount(addr *common.Address) (*Account, bool)
		GetCodeByHash(codeHash common.Hash) []byte
		GetGasSettings() (gasPrice *big.Int, gasLimit uint64)

		SwitchEpoch()
		HasChild() bool

		// Record the committee election result comm of chainid chain in epoch num. if comm is
		// not available, prev is the last effective committee.
		// Because the parent chain needs to keep the consensus committee information of the
		// sub chain, chainId is necessary.
		PutCommittee(chainId common.ChainID, num common.EpochNum, comm *Committee, prev *Committee) error
		GetCommittee(chainId common.ChainID, num common.EpochNum) (*Committee, error)
		GetEpochComm(chainId common.ChainID, num common.EpochNum) (*EpochCommittee, error)
		SyncCommittees(currentHeight common.Height) ([]*ChainEpochCommittee, error)

		PutHeaderSummaries(bock *BlockEMessage) error
		GetHeaderSummary(chainId common.ChainID, height common.Height) (*HeaderSummary, error)

		// Interfaces used to record whether messages have been processed
		Process(hash common.Hash) bool
		Processed(hash common.Hash) bool
		RemoveProcessed(hash common.Hash)
		ClearProcessed()

		AppendHistory(height common.Height, hash []byte) (newRoot []byte, err error)
		SetSyncFinish(height common.Height)
		GetSyncFinish() common.Height
		SetCursorManually(to common.Height) error
		GetStateDB() StateDB

		GetConsistantLong(addr common.Address, key common.Hash) []byte
		SetLongState(addr common.Address, key common.Hash, value []byte)

		// interfaces for chain management
		MCHAddBootNode(id common.ChainID, bootNode common.Dataserver) (errr error)
		MCHRemoveBootNode(id common.ChainID, nodeId common.NodeID) error
		MCHAddDataNode(id common.ChainID, nodeId common.NodeID) error
		MCHRemoveDataNode(id common.ChainID, nodeId common.NodeID) error
		MCHAddAdmin(id common.ChainID, adminPub []byte) error
		MCHDelAdmin(id common.ChainID, adminPub []byte) error
		MCHAttributes(id common.ChainID, isSet bool, attrs ...common.ChainAttr) error

		// interfaces for election
		GetPreElecting(id common.ChainID) *PreElecting
		PutPreElectResult(resulter ElectResulter)
		ProposePreElecting(height common.Height) (PreElectings, ChainElectResults)
		SetPreelectExamineResult(chainId common.ChainID, success bool) error
		SyncPreElection(electings PreElectings)
		MergeProof(key uint64, value []byte, proofs trie.ProofChain) error

		// interface for check nodes
		CacheAliveDataNode(id common.NodeID, height common.Height)
		LoadAliveDataNodes() common.NodeIDs
		ClearAliveDataNodes(height common.Height)
	}

	DataManager interface {
		common.Service
		Eventer() Eventer
		SetChainStructs(chains *config.Config)
		InitOneChain(chainid common.ChainID) error
		CreateGenesisData(chainId common.ChainID) error
		CreateChainInfosOrigin(rootHash []byte) *trie.Trie
		GetChainInfos(id common.ChainID) (*common.ChainInfos, bool)
		IsInUsingDataNode(dataNodeId common.NodeID) (common.ChainID, bool)
		IsNoGasChain(chainId common.ChainID) (bool, common.ChainID)
		GetChainStats(id common.ChainID) (*ChainStats, error)
		DataNodeOf() common.ChainID
		IsDataNode() bool
		IsMemoNode() bool
		// Deprecated
		IsDataMemoNode() bool
		GetShardInfo(chainid common.ChainID) common.ShardInfo
		IsDataNodeOf(id common.ChainID) bool
		IsShard(id common.ChainID) bool
		HasAttribute(id common.ChainID, attr common.ChainAttr) bool
		IsLeaf(id common.ChainID) bool
		GetChainChildren(chainid common.ChainID) common.ChainIDs
		GetChainChildrenAndSelfInfos(chainid common.ChainID) []*common.ChainInfos
		GetDataNodes(id common.ChainID) map[common.NodeID]struct{}
		GetGenesisDataNodeList(id common.ChainID) common.NodeIDs
		GetDataNodeList(id common.ChainID) common.NodeIDs
		GetDataNodeIDs(chainId common.ChainID) common.NodeIDs // Return if there is a list of Genesis data nodes, otherwise return to the list of data nodes
		GetChainList() common.ChainIDs
		GetVrfChainList() common.ChainIDs
		GetAllChainInfos() []*common.ChainInfos
		GetGenesisNodes() map[common.NodeID]common.NodeType
		CreateTestAccount(chainid common.ChainID, addr common.Address, balance *big.Int, local *big.Int) error
		ForceCommit(chainid common.ChainID) error
		// GetAccount(addr *common.Address, chainID common.ChainID) (Account, bool)
		GetChainData(chainid common.ChainID) (DataHolder, error)
		GetMainChainLong(addr common.Address, key common.Hash) []byte
		GetChainLong(chainid common.ChainID, addr common.Address, key common.Hash) []byte
		RemoveChain(chainid common.ChainID)
		GetHeaderSummaries(chainid common.ChainID, height common.Height) ([]*HeaderSummary, error)

		SetCursorManually(to common.Height) error

		ReadOnly() DataManager
		GetStartNodes() common.NodeIDs
		AddStartNode(id common.NodeID)
		StartNodesSize() int
		AddLastComm(lastComm *LastCommEMessage) error
		ToStartComm(chainIds common.ChainIDs) (*StartCommEMessage, error)
		// cache seed
		SetSeed(epoch common.EpochNum, newseed *common.Seed) bool
		GetSeed() *common.Seed
		LastSeedUpdatedAt() common.EpochNum
		SaveCommitteeAt(at common.ChainID, commChain common.ChainID,
			epoch common.EpochNum, comm, prev *Committee) error
		GetCommitteeAt(at common.ChainID, commChain common.ChainID, epoch common.EpochNum) (*EpochCommittee, error)
	}

	P2PServer interface {
		// get boot chain id
		BootChain() common.ChainID
		// discovery type is sort
		DiscoverTypeIsSRT() bool
		// set chains dataNodes to discovery table tmpNodes
		SetTmpDataNodes(infos []*common.ChainInfos)
		// replace discovery dataNodes with tmpNodes
		ReplaceDataNodes()
		// abandon useless peers in ChainToPeers
		AbandonUselessPeers()
		// start server
		Start() error
		// stop server
		Stop()
		// get the local nodeId
		NodeID() *common.NodeID
		// get the server local port
		LocalPort() uint16
		// broadcast message use goroutine
		BroadcastAsync(info string, msgv interface{}, pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error)
		// send a message to oriented nodes
		SendToNode(info string, toNodes common.NodeIDs, pb interface{}, pub, sig []byte) ([]byte, []byte, error)
		// send a message to my peer
		SendToPeer(info string, toNodes common.NodeIDs, pb interface{}, pub, sig []byte) ([]byte, []byte, error)
		// send a message to another chain
		SendToChain(info string, chainid common.ChainID, pb interface{}, pub, sig []byte) ([]byte, []byte, error)
		// randomly select size peers to send messsages
		RandBroadcast(size int, info string, msgv interface{}, pub, sig []byte,
			skips ...*common.NodeID) ([]byte, []byte, error)
		// synchronous broadcast, others not specified are sent asynchronously
		BroadcastSync(info string, msgv interface{}, pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error)
	}

	ConnectedCallBackFunc func(id common.ChainID, netType common.NetType, server P2PServer)

	Networker interface {
		// Create start a boot node
		Create(typ common.NetType, addr net.Addr, boots map[common.NodeID]net.Addr, infos []*common.ChainInfos, callback ConnectedCallBackFunc) error
		// Connect connect to p2p network with a boot node
		Connect(typ common.NetType, bootId common.ChainID, boots map[common.NodeID]net.Addr, infos []*common.ChainInfos, permission []byte, callback ConnectedCallBackFunc) error
		// Reset reset a boot node
		Reset(typ common.NetType, addr net.Addr, callback ConnectedCallBackFunc) error
		// Exit exit from current p2p network
		Exit(typ common.NetType) (int, error)
		// Check whether a certain net type exists
		IsIn(typ common.NetType) bool
		// Get chain id that the net worker belongs to
		GetChainID() common.ChainID
		// Set data net discovery table's tmpNodes
		SetTmpDataNodes(nt common.NetType)
		// Replace discovery table's dataNodes with tmpNodes
		ReplaceDataNodes(nt common.NetType)
		// Abandon useless peers
		AbandonUselessPeers(nt common.NetType)
		// broadcast asynchronized
		Broadcast(info string, typ common.NetType, msg interface{},
			pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error)
		// SendToNode send a message to a specific node in p2p network
		SendToNode(info string, typ common.NetType, nodeids common.NodeIDs,
			msg interface{}, pub, sig []byte) ([]byte, []byte, error)
		SendToPeer(info string, typ common.NetType, nodeids common.NodeIDs,
			msg interface{}, pub, sig []byte) ([]byte, []byte, error)
		SendToChain(info string, typ common.NetType, chainid common.ChainID,
			msg interface{}, pub, sig []byte) ([]byte, []byte, error)
		Rand(size int, info string, typ common.NetType, msg interface{}, pub, sig []byte,
			skips ...*common.NodeID) ([]byte, []byte, error)
		// broadcast synchronized
		BroadcastSync(info string, typ common.NetType, msg interface{},
			pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error)
	}

	NetworkManager interface {
		common.Service
		InitChain(id common.ChainID) error
		GetDataServer(chainId common.ChainID) *[]common.Dataserver
		GetNetworker(id common.ChainID) Networker
		BroadcastFull(info string, skip *common.NodeID, cid common.ChainID, ntp common.NetType,
			pb interface{}, pub, sig []byte) error
		BroadcastFullSync(info string, skip *common.NodeID, cid common.ChainID, ntp common.NetType,
			pb interface{}, pub, sig []byte) error
		SendToNode(info string, ntp common.NetType, chainId common.ChainID, to common.NodeIDs,
			pb interface{}, pub, sig []byte) error
		SendToPeer(info string, ntp common.NetType, chainId common.ChainID, toNodes common.NodeIDs,
			pb interface{}, pub, sig []byte) error
		SendToChain(info string, ntp common.NetType, fromChain common.ChainID, toChain common.ChainID,
			pb interface{}, pub, sig []byte) error
		Rand(size int, info string, chainId common.ChainID, ntp common.NetType, msg interface{}, pub, sig []byte,
			skips ...*common.NodeID) error
		GetChainNet(id common.ChainID, netType common.NetType) (map[common.NodeID]net.Addr, bool)
		StartConNet(networker Networker, chainid common.ChainID, netType common.NetType) (common.NodeID, error)
		CreateOrConnectNet(ntp common.NetType, bootChainID, localChandID common.ChainID) error
		IsBootNode(id common.ChainID) bool
		ClearNetWorker(id common.ChainID)
		InitNet(chaininfo *common.ChainInfos) error
		StopOneNet(cid common.ChainID, ntp common.NetType) (int, error)
		ResetNet(chainid common.ChainID, ntp common.NetType) error
		ConnectNet(chaininfo *common.ChainInfos) error
		Status()
	}

	Noticer interface {
		common.Service
		CanPublish(block *BlockEMessage) bool
		Publish(block *BlockEMessage, receipts []*Receipt) error
	}
)

func (ss *ChainSnapshot) String() string {
	return fmt.Sprintf("Snapshot{Height:%d Waterlines:%s Block:{%s} CheckEpoch:%t}",
		ss.Height, ss.Waterlines, ss.Block.InfoString(), ss.CheckEpoch)
}

func (ww *WholeWorld) String() string {
	t := func(v interface{}) string {
		val := reflect.ValueOf(v)
		if val.Kind() == reflect.Ptr {
			if val.IsNil() {
				return "<nil>"
			} else {
				return "[not nil]"
			}
		}
		return ""
	}
	return fmt.Sprintf("{State:%s Chains:%s History:%s Waterlines:%d Vcc:%s Cashed:%s RR:%s RRN:%s RRC:%s}",
		t(ww.State), t(ww.Chains), t(ww.History), len(ww.Waterlines), t(ww.Vcc),
		t(ww.Cashed), t(ww.RRCurrent), t(ww.RRNext), t(ww.RRChanging))
}
