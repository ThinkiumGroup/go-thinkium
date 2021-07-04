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

package discover

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
)

const MaxPeersPerChain = 10
const benchSize = 128

type bench struct {
	seats []*Node
	ips   DistinctNetSet
}

// bump moves the given node to the front of the bench entry list
// if it is contained in that list.
func (b *bench) bump(n *Node) bool {
	if b.seats == nil {
		n.addedAt = time.Now()
		b.seats = []*Node{n}
		return true
	}
	for i := range b.seats {
		if b.seats[i].ID == n.ID {
			// move it to the front
			copy(b.seats[1:], b.seats[:i])
			b.seats[0] = n
			return true
		}
	}
	return false
}

type STable struct {
	mutex      sync.Mutex // protects benches, bench content, nursery, rand
	chainId    common.ChainID
	bootId     common.ChainID
	netType    common.NetType
	dataNodes  []*ChainDataNodes
	tmpNodes   []*ChainDataNodes // for the changing chains
	benches    sync.Map          // chainId => *bench
	nursery    []*Node           // bootstrap nodes
	rand       *mrand.Rand       // source of randomness, periodically reseeded
	ips        DistinctNetSet
	db         *nodeDB // database of known nodes
	refreshReq chan chan struct{}
	initDone   chan struct{}
	closeReq   chan struct{}
	closed     chan struct{}

	discv Discovery
	self  *Node // metadata of the local node
}

func newSTable(d Discovery, self *Node, cfg UDPConfig) (*STable, error) {
	// If no node database was given, use an in-memory one
	db, err := newNodeDB(cfg.NodeDBPath, nodeDBVersion, self.ID)
	if err != nil {
		return nil, err
	}
	tab := &STable{
		chainId:    cfg.ChainID,
		bootId:     cfg.BootId,
		netType:    cfg.NetType,
		dataNodes:  cfg.ChainDataNodes,
		discv:      d,
		self:       self,
		db:         db,
		refreshReq: make(chan chan struct{}),
		initDone:   make(chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
		rand:       mrand.New(mrand.NewSource(0)),
		ips:        DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
	}
	if err := tab.setFallbackNodes(cfg.Bootnodes); err != nil {
		return nil, err
	}
	tab.seedRand()
	tab.loadSeedNodes()
	return tab, nil
}

func (tab *STable) seedRand() {
	var b [8]byte
	crand.Read(b[:])

	tab.mutex.Lock()
	tab.rand.Seed(int64(binary.BigEndian.Uint64(b[:])))
	tab.mutex.Unlock()
}

// Self returns the local node.
// The returned node should not be modified by the caller.
func (tab *STable) Self() *Node {
	return tab.self
}

// ReadRandomNodes fills the given slice with random nodes from the
// table. It will not write the same node more than once. The nodes in
// the slice are copies and can be modified by the caller.
func (tab *STable) ReadRandomNodes(buf []*Node) (n int) {
	if !tab.isInitDone() {
		return 0
	}
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	cids := GetVisitChainIds(tab.dataNodes, tab.chainId)
	if cids == nil {
		return 0
	}
	// Find all non-empty benches and get a fresh slice of their entries.
	var buckets [][]*Node
	for _, cid := range cids {
		val, ok := tab.benches.Load(cid)
		if !ok {
			continue
		}
		bench := val.(*bench)
		if len(bench.seats) > 0 {
			buckets = append(buckets, bench.seats)
		}
	}

	if len(buckets) == 0 {
		return 0
	}
	// Shuffle the buckets.
	for i := len(buckets) - 1; i > 0; i-- {
		j := tab.rand.Intn(len(buckets))
		buckets[i], buckets[j] = buckets[j], buckets[i]
	}
	// Move head of each bucket into buf, removing buckets that become empty.
	var i, j int
	for ; i < len(buf); i, j = i+1, (j+1)%len(buckets) {
		b := buckets[j]
		buf[i] = &(*b[0])
		buckets[j] = b[1:]
		if len(b) == 1 {
			buckets = append(buckets[:j], buckets[j+1:]...)
		}
		if len(buckets) == 0 {
			break
		}
	}
	return i + 1
}

// Close terminates the network listener and flushes the node database.
func (tab *STable) Close() {
	select {
	case <-tab.closed:
		// already closed.
	case tab.closeReq <- struct{}{}:
		<-tab.closed // wait for refreshLoop to end.
	}
}

// setFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
func (tab *STable) setFallbackNodes(nodes []*Node) error {
	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}
	}
	tab.nursery = make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		cpy := *n
		// Recompute cpy.sha because the node might not have been
		// created by NewNode or ParseNode.
		cpy.Hash = common.Hash256(n.ID[:])
		tab.nursery = append(tab.nursery, &cpy)
	}
	return nil
}

// isInitDone returns whether the table's initial seeding procedure has completed.
func (tab *STable) isInitDone() bool {
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

// Resolve searches for a specific node with the given ID.
// It returns nil if the node could not be found.
func (tab *STable) Resolve(targetID common.NodeID) *Node {
	// If the node is present in the local table, no
	// network interaction is required.
	var node *Node
	tab.benches.Range(func(key, value interface{}) bool {
		b := value.(*bench)
		for _, n := range b.seats {
			if bytes.Equal(n.ID[:], targetID[:]) {
				node = n
				return false
			}
		}
		return true
	})
	// Otherwise, do a network lookup.
	if node == nil {
		node = tab.Find(targetID)
	}
	return node
}

func (tab *STable) Find(target common.NodeID) *Node {
	var (
		// target         = common.Keccak256Hash(targetID[:])
		asked          = make(map[common.NodeID]bool)
		reply          = make(chan map[common.ChainID][]*Node, MaxPeersPerChain)
		pendingQueries = 0
		result         map[common.ChainID][]*Node
	)
	// don't query further if we hit ourself.
	// unlikely to happen often in practice.
	asked[tab.self.ID] = true

	// generate initial result set
	result = tab.benchRow(MaxPeersPerChain)

	for {
		// ask the alpha closest nodes that we haven't asked yet
		for _, ns := range result {
			pendingQueries = 0
			for i := 0; i < len(ns) && pendingQueries < MaxPeersPerChain; i++ {
				if ns[i] == nil {
					continue
				}
				if !asked[ns[i].ID] {
					asked[ns[i].ID] = true
					pendingQueries++
					go tab.findnode(ns[i], reply)
				}
			}
			if pendingQueries == MaxPeersPerChain {
				break
			}

		}
		if pendingQueries == 0 {
			// we have asked all closest nodes, stop the search
			break
		}

		// wait for the next reply
		for _, ns := range <-reply {
			for _, n := range ns {
				if bytes.Equal(n.ID[:], target[:]) {
					return n
				}
			}
		}
		pendingQueries--
	}
	return nil
}

// Lookup performs a network search for nodes close
// to the given target. It approaches the target by querying
// nodes that are closer to it on each iteration.
// The given target does not need to be an actual node
// identifier.
func (tab *STable) Lookup(target interface{}) []*Node {
	return tab.lookup(true)
}

//Get data nodes
func (tab *STable) GetDataNodes() []*ChainDataNodes {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	return tab.dataNodes
}

// Server uses this to filter the keys of ChainToPeers,close the peers in value if the key is not in return list
func (tab *STable) GetAccessChains() common.ChainIDs {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	return GetConnectedChains(tab.dataNodes, tab.chainId)
}

// Update the tmp nodes when chain structure was changed
func (tab *STable) SetTmpNodes(dataNodes []*ChainDataNodes) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	if dataNodes == nil || tab.tmpNodes != nil {
		return
	}
	h1, err := common.HashObject(tab.dataNodes)
	if err != nil {
		log.Errorf("P2P chain %d net %s hash DataNodes error %v", tab.chainId, tab.netType, err)
		return
	}
	h2, err := common.HashObject(dataNodes)
	if err != nil {
		log.Errorf("P2P chain %d net %s hash tmpNodes error %v", tab.chainId, tab.netType, err)
		return
	}
	if bytes.Equal(h1, h2) {
		if config.IsLogOn(config.NetDebugLog) {
			log.Debugf("P2P chain %d net %s ignore unchanged chains", tab.chainId, tab.netType)
		}
		return
	}
	tab.tmpNodes = dataNodes
}

// switch to changed chains
func (tab *STable) SwitchToTmpNodes() {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	if tab.tmpNodes == nil {
		return
	}
	tab.dataNodes = tab.tmpNodes
	tab.tmpNodes = nil
}

func (tab *STable) lookup(refreshIfEmpty bool) []*Node {
	var (
		// target         = common.Keccak256Hash(targetID[:])
		asked          = make(map[common.NodeID]bool)
		seen           = make(map[common.NodeID]bool)
		reply          = make(chan map[common.ChainID][]*Node, MaxPeersPerChain)
		pendingQueries = 0
		result         map[common.ChainID][]*Node
		ret            []*Node
	)
	// don't query further if we hit ourself.
	// unlikely to happen often in practice.
	asked[tab.self.ID] = true
	for {
		// generate initial result set
		result = tab.benchRow(MaxPeersPerChain)
		if len(result) > 0 || !refreshIfEmpty {
			break
		}
		// The result set is empty, all nodes were dropped, refresh.
		// We actually wait for the refresh to complete here. The very
		// first query will hit this case and run the bootstrapping
		// logic.
		<-tab.refresh()
		refreshIfEmpty = false
	}
	// filter lookup result with sort rule for dial out
	chains := GetVisitChainIds(tab.dataNodes, tab.chainId)
	tmpChains := GetVisitChainIds(tab.tmpNodes, tab.chainId)
	if config.IsLogOn(config.NetDebugLog) {
		log.Debugf("P2P SORT GetVisitChainIds for chain %d net %s return chains %s tmpChains %s", tab.chainId, tab.netType, chains, tmpChains)
	}

	for {
		// ask the alpha closest nodes that we haven't asked yet
		for _, ns := range result {
			for i := 0; i < len(ns) && pendingQueries < MaxPeersPerChain; i++ {
				n := ns[i]
				if n == nil {
					continue
				}
				if !asked[n.ID] {
					asked[n.ID] = true
					pendingQueries++
					go tab.findnode(n, reply)
				}
			}
			if pendingQueries == MaxPeersPerChain {
				break
			}
		}
		if pendingQueries == 0 {
			// we have asked all closest nodes, stop the search
			break
		}

		// wait for the next reply
		for cid, ns := range <-reply {
			for _, n := range ns {
				if n != nil && !seen[n.ID] {
					seen[n.ID] = true
					if IsIn(chains, cid) || IsIn(tmpChains, cid) {
						ret = append(ret, n)
					}
				}
			}
		}
		pendingQueries--
	}
	return ret
}

func (tab *STable) findnode(n *Node, reply chan<- map[common.ChainID][]*Node) {
	if tab == nil || n == nil {
		return
	}
	fails := tab.db.findFails(n.ID)
	r, err := tab.discv.FindNode(n.ID, n.UdpAddr(), nil)
	if err == errEmptyTable {
		tab.Close()
		return
	}
	if err != nil || len(r) == 0 {
		fails++
		tab.db.updateFindFails(n.ID, fails)

		if fails >= maxFindnodeFailures {
			tab.delete(tab.chainId, n)
		}
	} else if fails > 0 {
		tab.db.updateFindFails(n.ID, fails-1)
	}

	// Grab as many nodes as possible. Some of them might not be alive anymore, but we'll
	// just remove those again during revalidation.
	for c, ns := range r {
		for _, nd := range ns {
			tab.add(c, nd)
		}
	}
	reply <- r
}

func (tab *STable) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	case tab.refreshReq <- done:
	case <-tab.closed:
		close(done)
	}
	return done
}

// loop schedules refresh, revalidate runs and coordinates shutdown.
func (tab *STable) loop() {
	var (
		revalidate     = time.NewTimer(tab.nextRevalidateTime())
		refresh        = time.NewTicker(refreshInterval)
		copyNodes      = time.NewTicker(copyNodesInterval)
		revalidateDone = make(chan struct{})
		refreshDone    = make(chan struct{})           // where doRefresh reports completion
		waiting        = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
	)
	defer refresh.Stop()
	defer revalidate.Stop()
	defer copyNodes.Stop()

	// Start initial refresh.
	go tab.doRefresh(refreshDone)

loop:
	for {
		select {
		case <-refresh.C:
			tab.seedRand()
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		case req := <-tab.refreshReq:
			waiting = append(waiting, req)
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		case <-refreshDone:
			for _, ch := range waiting {
				close(ch)
			}
			waiting, refreshDone = nil, nil
		case <-revalidate.C:
			go tab.doRevalidate(revalidateDone)
		case <-revalidateDone:
			revalidate.Reset(tab.nextRevalidateTime())
		case <-copyNodes.C:
			go tab.copyLiveNodes()
		case <-tab.closeReq:
			break loop
		}
	}

	if refreshDone != nil {
		<-refreshDone
	}
	for _, ch := range waiting {
		close(ch)
	}
	tab.db.close()
	close(tab.closed)
}

// doRefresh performs a lookup for a random target to keep benches
// full. seed nodes are inserted if the table is empty (initial
// bootstrap or discarded faulty peers).
func (tab *STable) doRefresh(done chan struct{}) {
	defer close(done)

	// Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.
	tab.loadSeedNodes()

	// Run lookup to discover new neighbor nodes.
	tab.lookup(false)

}

func (tab *STable) loadSeedNodes() {
	// seeds := tab.db.querySeeds(seedCount, seedMaxAge)
	var seeds []*Node
	seeds = append(seeds, tab.nursery...)
	for i := range seeds {
		seed := seeds[i]
		tab.add(tab.bootId, seed)
	}
	if config.IsLogOn(config.NetDebugLog) {
		log.Debugf("P2P SORT UDP ChainId %d bootId %d loadSeedNodes %s", tab.chainId, tab.bootId, seeds)
	}
}

// doRevalidate checks that the last node in a random benches is still live
// and replaces or deletes the node if it isn't.
func (tab *STable) doRevalidate(done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	lasts := tab.nodeToRevalidate()
	if len(lasts) == 0 {
		return
	}

	for c, last := range lasts {
		// Ping the selected node and wait for a pong.
		err := tab.discv.Ping(last.ID, last.UdpAddr())
		tab.mutex.Lock()
		b := tab.bench(c)
		if b == nil {
			tab.mutex.Unlock()
			continue
		}
		if err == nil {
			b.bump(last)
			tab.mutex.Unlock()
			continue
		}
		// No reply received, pick a replacement or delete the node if there aren't
		// any replacements.
		if r := tab.replace(b, last); r != nil {
			if config.IsLogOn(config.NetDebugLog) {
				log.Debugf("P2P Removed dead node chain %d id %s ip %s r %s rip %s", c, last.ID, last.IP, r.ID, r.IP)
			}
		} else {
			if config.IsLogOn(config.NetDebugLog) {
				log.Debugf("P2P Replaced dead node chain %d id %s ip %s", c, last.ID, last.IP)
			}
		}
		tab.mutex.Unlock()
	}

}

// nodeToRevalidate returns the last node in a random, non-empty bench.
func (tab *STable) nodeToRevalidate() map[common.ChainID]*Node {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	ret := make(map[common.ChainID]*Node)
	tab.benches.Range(func(key, value interface{}) bool {
		cid := key.(common.ChainID)
		bench := value.(*bench)
		if bench == nil || len(bench.seats) == 0 {
			return true
		}
		ret[cid] = bench.seats[len(bench.seats)-1]
		return true
	})
	return ret
}

func (tab *STable) nextRevalidateTime() time.Duration {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return time.Duration(tab.rand.Int63n(int64(revalidateInterval)))
}

// copyLiveNodes adds nodes from the table to the database if they have been in the table
// longer then minTableTime.
func (tab *STable) copyLiveNodes() {
	// tab.mutex.Lock()
	// defer tab.mutex.Unlock()
	//
	// now := time.Now()
	// tab.benches.Range(func(key, value interface{}) bool {
	// 	for _, n := range value.(*bench).seats {
	// 		if now.Sub(n.addedAt) >= seedMinTableTime {
	// 			tab.db.updateNode(n)
	// 		}
	// 	}
	// 	return true
	// })
}

// benchRow returns the front n nodes in the table each bench
// The caller must hold tab.mutex.
func (tab *STable) benchRow(n int) map[common.ChainID][]*Node {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	ret := make(map[common.ChainID][]*Node)
	tab.benches.Range(func(key, value interface{}) bool {
		b := value.(*bench)
		if len(b.seats) > 0 {
			c := key.(common.ChainID)
			if n > len(b.seats) {
				ret[c] = b.seats
			} else {
				ret[c] = b.seats[:n]
			}
		}
		return true
	})
	return ret
}

// modify by gy
func (tab *STable) Len() (n int) {
	return tab.len()
}

func (tab *STable) len() (n int) {
	tab.benches.Range(func(key, value interface{}) bool {
		b := value.(*bench)
		n += len(b.seats)
		return true
	})
	return n
}

// bench returns the bench for the given node ID hash.
func (tab *STable) bench(chainId common.ChainID) *bench {
	if b, ok := tab.benches.Load(chainId); ok {
		return b.(*bench)
	}
	return nil
}

// add attempts to add the given node to its corresponding bench. If the bench has space
// available, adding the node succeeds immediately. Otherwise, the node is added if the
// least recently active node in the bench does not respond to a ping packetSort.
//
// The caller must not hold tab.mutex.
func (tab *STable) add(chainid common.ChainID, n *Node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	b := tab.bench(chainid)
	if b == nil {
		b = new(bench)
		tab.benches.Store(chainid, b)
	}
	tab.bumpOrAdd(b, n)
}

// addThroughPing adds the given node to the table. Compared to plain
// 'add' there is an additional safety measure: if the table is still
// initializing the node is not added. This prevents an attack where the
// table could be filled by just sending ping repeatedly.
//
// The caller must not hold tab.mutex.
func (tab *STable) addThroughPing(cid common.ChainID, n *Node) {
	if !tab.isInitDone() {
		return
	}
	tab.add(cid, n)
}

// delete removes an entry from the node table. It is used to evacuate dead nodes.
func (tab *STable) delete(cid common.ChainID, node *Node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	tab.deleteInBench(tab.bench(cid), node)
}

func (tab *STable) addIP(b *bench, ip net.IP) bool {
	if IsLAN(ip) {
		return true
	}
	if !tab.ips.Add(ip) {
		// if config.IsLogOn(config.NetDebugLog) {
		// 	log.Debugf("IP exceeds table limit, ip %s", ip)
		// }
		return false
	}
	if !b.ips.Add(ip) {
		tab.ips.Remove(ip)
		return false
	}
	return true
}

func (tab *STable) removeIP(b *bench, ip net.IP) {
	if IsLAN(ip) {
		return
	}
	tab.ips.Remove(ip)
	b.ips.Remove(ip)
}

// replace removes n from the replacement list and replaces 'last' with it if it is the
// last entry in the bench. If 'last' isn't the last entry, it has either been replaced
// with someone else or became active.
func (tab *STable) replace(b *bench, last *Node) *Node {
	if len(b.seats) == 0 || b.seats[len(b.seats)-1].ID != last.ID {
		// Entry has moved, don't replace it.
		return nil
	}
	tab.deleteInBench(b, last)
	return last
}

// bumpOrAdd moves n to the front of the bench entry list or adds it if the list isn't
// full. The return value is true if n is in the bench.
func (tab *STable) bumpOrAdd(b *bench, n *Node) bool {
	if b.bump(n) {
		return true
	}
	if len(b.seats) >= benchSize {
		return false
	}
	b.seats, _ = pushNode(b.seats, n, benchSize)
	n.addedAt = time.Now()
	return true
}

func (tab *STable) deleteInBench(b *bench, n *Node) {
	if b == nil {
		return
	}
	b.seats = deleteNode(b.seats, n)
}
