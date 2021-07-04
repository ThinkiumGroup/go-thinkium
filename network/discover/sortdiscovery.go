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
	"container/list"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/network/nat"
	"github.com/stephenfire/go-rtl"
)

func init() {
	p := neighborsSort{Version: srtVersion, ChainID: common.NilChainID, NetType: common.BranchDataNet, Expiration: ^uint64(0)}
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0), RPC: ^uint16(0), ID: nodeDBNilNodeID}
	for n := 0; ; n++ {
		p.Nodes = append(p.Nodes, maxSizeNode)
		bs, err := rtl.Marshal(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		if headSize+len(bs)+1 >= 1280 {
			maxNeighbors = n
			break
		}
	}
}

const (
	// sort discovery version
	srtVersion = 1

	// visit neighbourChain count
	visitNeighourChainCount = 2

	// all neighbourChain count (dial out + in)
	neighbourChainCount = visitNeighourChainCount * 2

	// connect chain step
	friendChainDistance = neighbourChainCount + 1

	// sort tab size
	SortTableSize = 64
)

// Get the chainId list which needs to dial out
func GetVisitChainIds(boots []*ChainDataNodes, centre common.ChainID) common.ChainIDs {
	if len(boots) == 0 {
		return nil
	}
	selfIdx := getChainIndex(boots, centre)
	if selfIdx == -1 {
		return nil
	}
	chainCount := len(boots)
	var chainIds common.ChainIDs
	// return all chains when chain count less than friendChainDistance
	if chainCount < friendChainDistance {
		for i := 0; i < chainCount; i++ {
			chainIds = append(chainIds, boots[i].ChainId)
		}
		return chainIds
	}

	visitChainCount := (chainCount/friendChainDistance + neighbourChainCount) / 2

	chainIds = append(chainIds, centre)
	for i := 0; i < visitChainCount; i++ {
		if i < visitNeighourChainCount {
			idx := selfIdx + i + 1
			if idx >= chainCount {
				idx = idx - chainCount
			}
			chainIds = append(chainIds, boots[idx].ChainId)
			continue
		}
		idx := selfIdx + visitNeighourChainCount + (i-visitNeighourChainCount+1)*friendChainDistance
		if idx >= chainCount {
			idx = idx % chainCount
		}
		chainIds = append(chainIds, boots[idx].ChainId)
	}

	sort.SliceStable(chainIds, func(i, j int) bool {
		return chainIds[i] < chainIds[j]
	})
	return chainIds
}

// find a chain who was closet to the target chain
func GetTargetChain(boots []*ChainDataNodes, selfChain common.ChainID, targetChain common.ChainID) common.ChainID {
	connectedIndexes := getConnectedIndexes(boots, selfChain)
	if len(connectedIndexes) == 0 {
		return common.NilChainID
	}
	targetIdx := getChainIndex(boots, targetChain)
	if targetIdx == -1 {
		return common.NilChainID
	}
	// when the target chain's index was less than the connected min index
	if targetIdx < connectedIndexes[0] {
		if connectedIndexes[0]-targetIdx <= len(boots)+targetIdx-connectedIndexes[len(connectedIndexes)-1] {
			return boots[connectedIndexes[0]].ChainId
		}
		return boots[connectedIndexes[len(connectedIndexes)-1]].ChainId
	}

	// when the target chain's index was bigger than the connected max index
	if targetIdx >= connectedIndexes[len(connectedIndexes)-1] {
		if len(boots)+connectedIndexes[0]-targetIdx <= targetIdx-connectedIndexes[len(connectedIndexes)-1] {
			return boots[connectedIndexes[0]].ChainId
		}
		return boots[connectedIndexes[len(connectedIndexes)-1]].ChainId
	}

	// when the target chain's index was between the connected indexes
	idx := sort.Search(len(connectedIndexes), func(i int) bool {
		return connectedIndexes[i] > targetIdx
	})
	if connectedIndexes[idx]-targetIdx < targetIdx-connectedIndexes[idx-1] {
		return boots[connectedIndexes[idx]].ChainId
	}
	return boots[connectedIndexes[idx-1]].ChainId

}

// get all the connected chains
func GetConnectedChains(boots []*ChainDataNodes, centre common.ChainID) common.ChainIDs {
	idxes := getConnectedIndexes(boots, centre)
	var ret common.ChainIDs
	for _, idx := range idxes {
		ret = append(ret, boots[idx].ChainId)
	}
	return ret
}

func getConnectedIndexes(boots []*ChainDataNodes, centre common.ChainID) []int {
	selfIdx := getChainIndex(boots, centre)
	if selfIdx == -1 {
		return nil
	}
	chainCount := len(boots)
	visitChainCount := (chainCount/friendChainDistance + neighbourChainCount) / 2

	var indexes []int
	if chainCount < friendChainDistance {
		for i := 0; i < chainCount; i++ {
			indexes = append(indexes, i)
		}
		return indexes
	}

	indexes = append(indexes, selfIdx)
	for i := 0; i < visitChainCount; i++ {
		if i < visitNeighourChainCount {
			vidx := selfIdx + i + 1
			if vidx >= chainCount {
				vidx = vidx - chainCount
			}
			indexes = append(indexes, vidx)
			cidx := selfIdx - i - 1
			if cidx < 0 {
				cidx = chainCount + cidx
			}
			indexes = append(indexes, cidx)
			continue
		}
		vidx := selfIdx + visitNeighourChainCount + (i-visitNeighourChainCount+1)*friendChainDistance
		if vidx >= chainCount {
			vidx = vidx - chainCount
		}
		indexes = append(indexes, vidx)

		cidx := selfIdx - visitNeighourChainCount - (i-visitNeighourChainCount+1)*friendChainDistance
		if cidx < 0 {
			cidx = cidx + chainCount
		}
		indexes = append(indexes, cidx)
	}
	sort.SliceStable(indexes, func(i, j int) bool {
		return indexes[i] < indexes[j]
	})
	return indexes
}

// find the chain's index in the list
func getChainIndex(boots []*ChainDataNodes, cid common.ChainID) int {
	for i, b := range boots {
		if b.ChainId == cid {
			return i
		}
	}
	return -1
}

func IsIn(cids common.ChainIDs, cid common.ChainID) bool {
	for _, id := range cids {
		if id == cid {
			return true
		}
	}
	return false
}

// udp implements the RPC protocol.
type udp_srt struct {
	conn        *net.UDPConn
	netrestrict *Netlist

	ourEndpoint rpcEndpoint

	addpending chan *pending
	gotreply   chan reply

	closing chan struct{}
	nat     nat.Nat

	*STable
}

// ListenUDP returns a new table that listens for UDP packets on laddr.
func SetupDiscoverySRT(self *Node, c *net.UDPConn, cfg UDPConfig) (Discovery, error) {
	tab, udp, err := setupSORTUDP(self, c, cfg)
	if err != nil {
		return nil, err
	}
	log.Infof("P2P SORT UDP setup %s", tab.self)
	return udp, nil
}

func setupSORTUDP(self *Node, c *net.UDPConn, cfg UDPConfig) (*STable, *udp_srt, error) {
	udp := &udp_srt{
		conn:       c,
		closing:    make(chan struct{}),
		gotreply:   make(chan reply),
		addpending: make(chan *pending),
	}
	realaddr := c.LocalAddr().(*net.UDPAddr)
	if cfg.AnnounceAddr != nil {
		realaddr = cfg.AnnounceAddr
	}
	// TODO: separate TCP port
	udp.ourEndpoint = makeEndpoint(realaddr, self.TCP)
	tab, err := newSTable(udp, self, cfg)
	if err != nil {
		return nil, nil, err
	}
	udp.STable = tab
	go tab.loop()

	go udp.loop()
	go udp.readLoop(nil)
	return udp.STable, udp, nil
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *udp_srt) loop() {
	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *pending // head of plist when timeout was last reset
		contTimeouts = 0      // number of continuous timeouts to do NTP checks
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*pending)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closing:
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*pending).errc <- errClosed
			}
			return

		case p := <-t.addpending:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if p.from == r.from && p.ptype == r.ptype {
					matched = true
					// Remove the matcher if its callback indicates
					// that all replies have been received. This is
					// required for packet types that expect multiple
					// reply packets.
					if p.callback(r.data) {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

func (t *udp_srt) write(toaddr *net.UDPAddr, packet []byte) error {
	_, err := t.conn.WriteToUDP(packet, toaddr)
	return err
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *udp_srt) readLoop(unhandled chan<- ReadPacket) {
	if unhandled != nil {
		defer close(unhandled)
	}
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	buf := make([]byte, 1280)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if IsTemporaryError(err) {
			// Ignore temporary read errors.
			if config.IsLogOn(config.NetDebugLog) {
				log.Debugf("P2P SORT UDP read Temporary error %v", err)
			}
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			if config.IsLogOn(config.NetDebugLog) {
				log.Warnf("P2P SORT UDP read error %v", err)
			}
			return
		}
		if t.HandlePacket(from, buf[:nbytes]) != nil && unhandled != nil {
			select {
			case unhandled <- ReadPacket{buf[:nbytes], from}:
			default:
			}
		}
	}
}

func (t *udp_srt) HandlePacket(from *net.UDPAddr, buf []byte) error {
	packet, fromID, hash, err := decodePacketSort(buf)
	if err != nil {
		log.Errorf("P2P Bad discover packet addr %s err %v", from, err)
		return err
	}
	return packet.handleSort(t, from, fromID, hash)
}

/**
 *  implements interface <Discovery>
 */
func (t *udp_srt) Type() DiscoveryType {
	return SRT
}

func (t *udp_srt) Version() uint32 {
	return srtVersion
}

func (t *udp_srt) NodeTable() DiscoverTable {
	return t.STable
}

func (t *udp_srt) GetChainID(id common.NodeID) (common.ChainID, error) {
	ChainDataNodes := t.GetDataNodes()
	for _, chaindatanode := range ChainDataNodes {
		for _, datanode := range chaindatanode.DataNodes {
			if id == datanode.ID {
				return chaindatanode.ChainId, nil
			}
		}
	}
	return 0, errors.New("P2P nodeId is not in the DataNodes")
}

// ping sends a ping message to the given node and waits for a reply.
func (t *udp_srt) Ping(toid common.NodeID, toaddr *net.UDPAddr) error {
	return <-t.SendPing(toid, toaddr, nil)
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
func (t *udp_srt) FindNode(toid common.NodeID, toaddr *net.UDPAddr, target interface{}) (map[common.ChainID][]*Node, error) {
	if t.STable == nil {
		return nil, errEmptyTable
	}
	if time.Since(t.db.lastPingReceived(toid)) > nodeDBNodeExpiration {
		t.Ping(toid, toaddr)
		t.waitping(toid)
	}

	return t.SendFindNode(toid, toaddr)
}

func (t *udp_srt) Close() error {
	t.STable.Close()
	close(t.closing)
	return t.conn.Close()
}

func (t *udp_srt) Send(toaddr *net.UDPAddr, ptype byte, req packetSort) ([]byte, error) {
	packet, hash, err := encodePacketSort(ptype, req)
	if err != nil {
		log.Errorf("P2P SORT UDP encodePacketSort error %v", err)
		return hash, err
	}
	return hash, t.write(toaddr, packet)
}

// sendPing sends a ping message to the given node and invokes the callback
// when the reply arrives.
func (t *udp_srt) SendPing(toid common.NodeID, toaddr *net.UDPAddr, callback func()) <-chan error {
	req := &pingSort{
		Version:    srtVersion,
		ChainID:    t.chainId,
		NetType:    t.netType,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, 0), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	packet, hash, err := encodePacketSort(pingPacket, req)
	if err != nil {
		errc := make(chan error, 1)
		errc <- err
		return errc
	}
	errc := t.pending(toid, pongPacket, func(p interface{}) bool {
		ok := bytes.Equal(p.(*pongSort).ReplyTok, hash)
		if ok && callback != nil {
			callback()
		}
		return ok
	})
	t.write(toaddr, packet)
	return errc
}

// TODO remove no response nodes
func (t *udp_srt) SendFindNode(toid common.NodeID, toaddr *net.UDPAddr) (map[common.ChainID][]*Node, error) {
	ret := make(map[common.ChainID][]*Node)
	nreceived := 0
	errc := t.pending(toid, neighborsPacket, func(r interface{}) bool {
		reply := r.(*neighborsSort)
		// log.Debug("SORT UDP neighbors.ChainID,NetType,Nodes", reply.ChainID, reply.NetType, reply.Nodes)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
			if err != nil {
				// log.Warnf("P2P SORT UDP Invalid neighbor node received ip %s TCP[%d],UDP[%d], addr %s error %v", rn.IP, rn.TCP, rn.UDP, toaddr, err)
				continue
			}
			//log.Debug("SORT UDP reply.ChainID,reply.node", reply.ChainID, n)
			ret[reply.ChainID] = append(ret[reply.ChainID], n)
		}
		return nreceived >= SortTableSize
	})
	t.Send(toaddr, findnodePacket, &findnodeSort{
		Version:    srtVersion,
		ChainID:    t.chainId,
		NetType:    t.netType,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	return ret, <-errc
}

func (t *udp_srt) waitping(from common.NodeID) error {
	return <-t.pending(from, pingPacket, func(interface{}) bool { return true })
}

// pending adds a reply callback to the pending reply queue.
// see the documentation of type pending for a detailed explanation.
func (t *udp_srt) pending(id common.NodeID, ptype byte, callback func(interface{}) bool) <-chan error {
	ch := make(chan error, 1)
	p := &pending{from: id, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addpending <- p:
		// loop will handle it
	case <-t.closing:
		ch <- errClosed
	}
	return ch
}

func (t *udp_srt) handleReply(from common.NodeID, ptype byte, req packetSort) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, ptype, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closing:
		return false
	}
}

func (t *udp_srt) nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*Node, error) {
	if rn.UDP <= 1024 {
		return nil, errors.New("low port")
	}
	if err := CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict whitelist")
	}
	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP, rn.RPC)
	err := n.validateComplete()
	return n, err
}

func encodePacketSort(ptype byte, req interface{}) (packet, hash []byte, err error) {
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	if err := rtl.Encode(req, b); err != nil {
		log.Error("P2P Can't encode packet", "err", err)
		return nil, nil, err
	}
	packet = b.Bytes()
	pub, sig, err := common.SignHash(common.SystemHash256(packet[headSize:]))
	if err != nil {
		log.Errorf("P2P SORT UDP sign packet ptype %v err %v", ptype, err)
		return nil, nil, err
	}
	copy(packet[macSize:], pub)
	copy(packet[macSize+pubSize:], sig)
	// add the hash to the front. Note: this doesn't protect the
	// packet in any way. Our public key will be part of this hash in
	// The future.
	hash = common.SystemHash256(packet[macSize:])
	copy(packet, hash)
	return packet, hash, nil
}

func decodePacketSort(buf []byte) (packetSort, common.NodeID, []byte, error) {
	if len(buf) < headSize+1 {
		return nil, common.NodeID{}, nil, errPacketTooSmall
	}
	hash, pub, sig, sigdata := buf[:macSize], buf[macSize:macSize+pubSize], buf[headSize-sigSize:headSize], buf[headSize:]
	shouldhash := common.SystemHash256(buf[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, common.NodeID{}, nil, errBadHash
	}
	if !common.VerifyHash(common.SystemHash256(buf[headSize:]), pub, sig) {
		return nil, common.NodeID{}, hash, errors.New("hash signature verify failed")
	}
	pubkey, err := common.RealCipher.BytesToPub(pub)
	if err != nil {
		return nil, common.NodeID{}, nil, err
	}
	fromID := common.BytesToNodeID(common.RealCipher.PubToBytes(pubkey))
	var req packetSort
	switch ptype := sigdata[0]; ptype {
	case pingPacket:
		req = new(pingSort)
	case pongPacket:
		req = new(pongSort)
	case findnodePacket:
		req = new(findnodeSort)
	case neighborsPacket:
		req = new(neighborsSort)
	default:
		return nil, fromID, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	err = rtl.Decode(bytes.NewReader(sigdata[1:]), req)
	return req, fromID, hash, err
}
