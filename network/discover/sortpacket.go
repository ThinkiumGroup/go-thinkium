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
	"net"
	"time"

	"github.com/ThinkiumGroup/go-common"
)

type (
	packetSort interface {
		handleSort(t *udp_srt, from *net.UDPAddr, fromID common.NodeID, mac []byte) error
		nameSort() string
	}

	pingSort struct {
		Version    uint
		ChainID    common.ChainID
		NetType    common.NetType
		From, To   rpcEndpoint
		Expiration uint64
	}

	// pongSort is the reply to pingSort.
	pongSort struct {
		Version uint
		ChainID common.ChainID
		NetType common.NetType
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint

		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
	}

	// findnodeSort is a query for nodes close to the given target.
	findnodeSort struct {
		Version    uint
		ChainID    common.ChainID
		NetType    common.NetType
		Expiration uint64
	}

	// reply to findnodeSort
	neighborsSort struct {
		Version        uint
		ChainID        common.ChainID
		NetType        common.NetType
		IsInvalidchain bool
		Nodes          []rpcNode
		Expiration     uint64
	}
)

func (req *pingSort) handleSort(t *udp_srt, from *net.UDPAddr, fromID common.NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if req.Version != srtVersion {
		return errVersion
	}
	if req.NetType != t.netType {
		return errNetType
	}

	t.Send(from, pongPacket, &pongSort{
		Version:    srtVersion,
		ChainID:    t.chainId,
		NetType:    t.netType,
		To:         makeEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	t.handleReply(fromID, pingPacket, req)

	// Add the node to the table. Before doing so, ensure that we have a recent enough pong
	// recorded in the database so their findnode requests will be accepted later.
	n := NewNode(fromID, from.IP, uint16(from.Port), req.From.TCP, req.From.RPC)
	if time.Since(t.db.lastPongReceived(fromID)) > nodeDBNodeExpiration {
		t.SendPing(fromID, from, func() { t.addThroughPing(req.ChainID, n) })
	} else {
		t.addThroughPing(req.ChainID, n)
	}
	t.db.updateLastPingReceived(fromID, time.Now())
	return nil
}

func (req *pingSort) nameSort() string { return "SORTPING" }

func (req *pongSort) handleSort(t *udp_srt, from *net.UDPAddr, fromID common.NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if req.Version != srtVersion {
		return errVersion
	}
	if req.NetType != t.netType {
		return errNetType
	}

	if !t.handleReply(fromID, pongPacket, req) {
		return errUnsolicitedReply
	}
	t.db.updateLastPongReceived(fromID, time.Now())
	return nil
}

func (req *pongSort) nameSort() string { return "SORTPONG" }

func (req *findnodeSort) handleSort(t *udp_srt, from *net.UDPAddr, fromID common.NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if req.Version != srtVersion {
		return errVersion
	}
	if req.NetType != t.netType {
		return errNetType
	}

	if !t.db.hasBond(fromID) {
		// No endpoint proof pong exists, we don't process the packet. This prevents an
		// attack vector where the discovery protocol could be used to amplify traffic in a
		// DDOS attack. A malicious actor would send a findnode request with the IP address
		// and UDP port of the target as the source address. The recipient of the findnode
		// packet would then send a neighbors packet (which is a much bigger packet than
		// findnode) to the victim.
		return errUnknownNode
	}

	closest := t.benchRow(MaxPeersPerChain)
	for c, cl := range closest {
		p := neighborsSort{Version: srtVersion, ChainID: c, NetType: t.netType, Expiration: uint64(time.Now().Add(expiration).Unix())}
		var sent bool
		// Send neighbors in chunks with at most maxNeighbors per packet
		// to stay below the 1280 byte limit.
		for _, n := range cl {
			if n == nil {
				continue
			}
			//log.Debug("SORT UDP closest chianid,node,maxNeighbors", c, n.String(), maxNeighbors)
			if n.UDP <= 1024 {
				continue
			}
			if CheckRelayIP(from.IP, n.IP) == nil {
				p.Nodes = append(p.Nodes, nodeToRPC(n))
			}
			if len(p.Nodes) == maxNeighbors {
				t.Send(from, neighborsPacket, &p)
				p.Nodes = p.Nodes[:0]
				sent = true
			}
		}
		if len(p.Nodes) > 0 || !sent {
			t.Send(from, neighborsPacket, &p)
		}
	}

	return nil
}

func (req *findnodeSort) nameSort() string { return "SORTFINDNODE" }

func (req *neighborsSort) handleSort(t *udp_srt, from *net.UDPAddr, fromID common.NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if req.Version != srtVersion {
		return errVersion
	}
	if req.NetType != t.netType {
		return errNetType
	}

	if !t.handleReply(fromID, neighborsPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func (req *neighborsSort) nameSort() string { return "SORTNEIGHBORS" }
