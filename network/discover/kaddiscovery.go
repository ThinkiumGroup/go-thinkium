package discover

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/network/nat"
	"github.com/stephenfire/go-rtl"
)

// Errors
var (
	errPacketTooSmall   = errors.New("too small")
	errBadHash          = errors.New("bad hash")
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")
	errEmptyTable       = errors.New("empty table")
	errChainID          = errors.New("chain miss match")
	errNetType          = errors.New("net miss match")
	errVersion          = errors.New("version miss match")
)

// RPC packet types
const (
	pingPacket = iota + 1 // zero is 'reserved'
	pongPacket
	findnodePacket
	neighborsPacket
)

// Timeouts
const (
	kadVersion = 2000000 // nopos

	respTimeout = 500 * time.Millisecond
	expiration  = 20 * time.Second

	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user
)

const (
	macSize  = 256 / 8
	pubSize  = 520 / 8
	sigSize  = 520 / 8
	headSize = macSize + pubSize + sigSize // space of packet frame data
)

var (
	headSpace = make([]byte, headSize)

	// Neighbors replies are sent across multiple packets to
	// stay below the 1280 byte limit. We compute the maximum number
	// of entries by stuffing a packet until it grows too large.
	maxNeighbors int
)

func init() {
	p := neighbors{Version: kadVersion, ChainID: common.NilChainID, NetType: common.BranchDataNet, Expiration: ^uint64(0)}
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

// RPC request structures
type (
	rpcNode struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		RPC uint16
		ID  common.NodeID
	}

	rpcEndpoint struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		RPC uint16
	}
)

// udp implements the RPC protocol.
type udp_kad struct {
	conn        *net.UDPConn
	netrestrict *Netlist

	ourEndpoint rpcEndpoint

	addpending chan *pending
	gotreply   chan reply

	closing chan struct{}
	nat     nat.Nat

	*Table
}

// pending represents a pending reply.
//
// some implementations of the protocol wish to send more than one
// reply packet to findnode. in general, any neighbors packet cannot
// be matched up with a specific findnode packet.
//
// our implementation handles this by storing a callback function for
// each pending reply. incoming packets from a node are dispatched
// to all the callback functions for that node.
type pending struct {
	// these fields must match in the reply.
	from  common.NodeID
	ptype byte

	// time when the request must complete
	deadline time.Time

	// callback is called when a matching reply arrives. if it returns
	// true, the callback is removed from the pending reply queue.
	// if it returns false, the reply is considered incomplete and
	// the callback will be invoked again for the next matching reply.
	callback func(resp interface{}) (done bool)

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	errc chan<- error
}

type reply struct {
	from  common.NodeID
	ptype byte
	data  interface{}
	// loop indicates whether there was
	// a matching request by sending on this channel.
	matched chan<- bool
}

// ReadPacket is sent to the unhandled channel when it could not be processed
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

// Config holds Table-related settings.
type UDPConfig struct {
	ChainID common.ChainID
	BootId  common.ChainID
	NetType common.NetType
	// These settings are optional:
	AnnounceAddr   *net.UDPAddr // local address announced in the DHT
	NodeDBPath     string       // if set, the node database is stored at this filesystem location
	Bootnodes      []*Node      // list of bootstrap nodes
	ChainDataNodes []*ChainDataNodes
}

// ListenUDP returns a new table that listens for UDP packets on laddr.
func SetupDiscoveryKAD(self *Node, c *net.UDPConn, cfg UDPConfig) (Discovery, error) {
	tab, udp, err := setupKADUDP(self, c, cfg)
	if err != nil {
		return nil, err
	}
	log.Infof("KAD UDP setup %s", tab.self)
	return udp, nil
}

func setupKADUDP(self *Node, c *net.UDPConn, cfg UDPConfig) (*Table, *udp_kad, error) {
	udp := &udp_kad{
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
	tab, err := newTable(udp, self, cfg)
	if err != nil {
		return nil, nil, err
	}
	udp.Table = tab
	go tab.loop()

	go udp.loop()
	go udp.readLoop(nil)
	return udp.Table, udp, nil
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *udp_kad) loop() {
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

func (t *udp_kad) write(toaddr *net.UDPAddr, packet []byte) error {
	_, err := t.conn.WriteToUDP(packet, toaddr)
	return err
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *udp_kad) readLoop(unhandled chan<- ReadPacket) {
	if unhandled != nil {
		defer close(unhandled)
	}
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	buf := make([]byte, 1280)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			if IsTemporaryError(err) {
				// Ignore temporary read errors.
				if config.IsLogOn(config.NetDebugLog) {
					log.Debugf("Temporary UDP read error %v", err)
				}
				continue
			}
			// Shut down the loop for permament errors.
			if config.IsLogOn(config.NetDebugLog) {
				log.Warnf("UDP read error %v", err)
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

func (t *udp_kad) HandlePacket(from *net.UDPAddr, buf []byte) error {
	packet, fromID, hash, err := decodePacket(buf)
	if err != nil {
		log.Errorf("Bad discover packet addr %s err %v", from, err)
		return err
	}
	return packet.handle(t, from, fromID, hash)
}

/**
 *  implements interface <Discovery>
 */
func (t *udp_kad) Type() DiscoveryType {
	return KAD
}

func (t *udp_kad) Version() uint32 {
	return kadVersion
}

func (t *udp_kad) NodeTable() DiscoverTable {
	return t.Table
}

func (t *udp_kad) GetChainID(id common.NodeID) (common.ChainID, error) {
	ChainDataNodes := t.GetDataNodes()
	for _, chaindatanode := range ChainDataNodes {
		for _, datanode := range chaindatanode.DataNodes {
			if id == datanode.ID {
				return chaindatanode.ChainId, nil
			}
		}
	}
	return 0, errors.New("The nodeid is not in the datanodes")
}

// ping sends a ping message to the given node and waits for a reply.
func (t *udp_kad) Ping(toid common.NodeID, toaddr *net.UDPAddr) error {
	return <-t.SendPing(toid, toaddr, nil)
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
func (t *udp_kad) FindNode(toid common.NodeID, toaddr *net.UDPAddr, target interface{}) (map[common.ChainID][]*Node, error) {
	if t.Table == nil {
		return nil, errEmptyTable
	}
	if time.Since(t.db.lastPingReceived(toid)) > nodeDBNodeExpiration {
		t.Ping(toid, toaddr)
		t.waitping(toid)
	}

	return t.SendFindNode(toid, toaddr, target.(common.NodeID))
}

func (t *udp_kad) Close() error {
	t.Table.Close()
	close(t.closing)
	return t.conn.Close()
}

func (t *udp_kad) Send(toaddr *net.UDPAddr, ptype byte, req packet) ([]byte, error) {
	packet, hash, err := encodePacket(ptype, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, packet)
}

// sendPing sends a ping message to the given node and invokes the callback
// when the reply arrives.
func (t *udp_kad) SendPing(toid common.NodeID, toaddr *net.UDPAddr, callback func()) <-chan error {
	req := &ping{
		Version:    kadVersion,
		ChainID:    t.bootId,
		NetType:    t.netType,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, 0), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	packet, hash, err := encodePacket(pingPacket, req)
	if err != nil {
		errc := make(chan error, 1)
		errc <- err
		return errc
	}
	errc := t.pending(toid, pongPacket, func(p interface{}) bool {
		ok := bytes.Equal(p.(*pong).ReplyTok, hash)
		if ok && callback != nil {
			callback()
		}
		return ok
	})
	t.write(toaddr, packet)
	return errc
}

// TODO remove no response nodes
func (t *udp_kad) SendFindNode(toid common.NodeID, toaddr *net.UDPAddr, target common.NodeID) (map[common.ChainID][]*Node, error) {
	ret := make(map[common.ChainID][]*Node)
	nreceived := 0
	errc := t.pending(toid, neighborsPacket, func(r interface{}) bool {
		reply := r.(*neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
			if err != nil {
				// log.Errorf("Invalid neighbor node received ip %s addr %s error %v", rn.IP, toaddr, err)
				continue
			}
			ret[t.bootId] = append(ret[t.bootId], n)
		}
		return nreceived >= bucketSize
	})
	_, err := t.Send(toaddr, findnodePacket, &findnode{
		Version:    kadVersion,
		ChainID:    t.bootId,
		NetType:    t.netType,
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	if err != nil {
		return ret, err
	}
	return ret, <-errc
}

func (t *udp_kad) waitping(from common.NodeID) error {
	return <-t.pending(from, pingPacket, func(interface{}) bool { return true })
}

// pending adds a reply callback to the pending reply queue.
// see the documentation of type pending for a detailed explanation.
func (t *udp_kad) pending(id common.NodeID, ptype byte, callback func(interface{}) bool) <-chan error {
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

func (t *udp_kad) handleReply(from common.NodeID, ptype byte, req packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, ptype, req, matched}:
		// loop will handle it
		return <-matched
	case <-t.closing:
		return false
	}
}

func encodePacket(ptype byte, req interface{}) (packet, hash []byte, err error) {
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(ptype)
	if err := rtl.Encode(req, b); err != nil {
		log.Error("Can't encode packet", "err", err)
		return nil, nil, err
	}
	packet = b.Bytes()
	pub, sig, err := common.SignHash(common.SystemHash256(packet[headSize:]))
	if err != nil {
		log.Error("Can't sign packet", "err", err)
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

func decodePacket(buf []byte) (packet, common.NodeID, []byte, error) {
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
	var req packet
	switch ptype := sigdata[0]; ptype {
	case pingPacket:
		req = new(ping)
	case pongPacket:
		req = new(pong)
	case findnodePacket:
		req = new(findnode)
	case neighborsPacket:
		req = new(neighbors)
	default:
		return nil, fromID, hash, fmt.Errorf("unknown type: %d", ptype)
	}

	err = rtl.Decode(bytes.NewReader(sigdata[1:]), req)

	return req, fromID, hash, err
}

// TODO use real tpc port
func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: uint16(addr.Port)}
}

func (t *udp_kad) nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*Node, error) {
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
