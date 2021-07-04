package network

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/ThinkiumGroup/go-thinkium/network/discover"
	"github.com/ThinkiumGroup/go-thinkium/network/nat"
	"github.com/sirupsen/logrus"
	"github.com/stephenfire/go-rtl"
)

const (
	// max peer count
	MaxPeerCount = 21
	// max count for dialing in nodes
	MaxPendCount = 21
	// default max count for dialing in nodes
	defaultMaxPendingPeers = 50
	// Tcp ping interval
	pingInterval = 25 * time.Second
	// remote ip dial in interval
	inboundThrottleTime = 30 * time.Second
	// max dial task count
	maxActiveDialTasks = 16
	// for calculate dail out count
	defaultDialRatio = 3
	// Tcp handshake version
	TcpHandShakerVersion = 2000000 // nopos
	addPeerFlag          = 1
	delPeerFlag          = 2
)

var (
	sequenceLock sync.Mutex
	sequence     uint64 = 0
)

type Server struct {
	SID uint64

	discover.Node
	discover.P2PConfig

	isRunning bool

	lock sync.Mutex

	Peers sync.Map

	ChainToPeers sync.Map

	listener Listener

	handShaker HandShaker

	discv discover.Discovery

	lastLookup time.Time

	wg sync.WaitGroup

	addpeer chan *Peer
	delpeer chan *Peer
	quit    chan struct{}

	inboundHistory expHeap

	Eventer        models.Eventer
	recentMsgPool  *RecentMsgPool  // recent broadcastpart cache，(Hash(eventLoad)) -> (msgLoad)
	wantDetailLock *WantDetailLock // lock for process wantdetailevent
	localPort      uint16
	chainID        common.ChainID
	bootID         common.ChainID
	netType        common.NetType
	callbackOnce   sync.Once
	callbackFun    models.ConnectedCallBackFunc

	logger logrus.FieldLogger
}

func nextSequenceID() uint64 {
	sequenceLock.Lock()
	defer sequenceLock.Unlock()
	sequence = sequence + 1
	return sequence
}

func NewP2PServer(con map[string]common.NodeID, bootport uint16, localport uint16, eventer models.Eventer,
	chainId common.ChainID, bootId common.ChainID, netType common.NetType, infos []*common.ChainInfos,
	pms []byte, callback models.ConnectedCallBackFunc) (models.P2PServer, error) {
	var bootNodes []*discover.Node
	for k, v := range con {
		ip, port := parseAddr(k)
		bootNodes = append(bootNodes, discover.NewNode(v, ip, port, port, 0))
	}
	//if bootport > 0 {
	//	localport = 0
	//}
	lnport := bootport
	if bootport == 0 && localport > 0 {
		lnport = localport
	}
	conf := &discover.P2PConfig{
		MaxPeersCount:  MaxPeerCount,
		MaxPendCount:   MaxPendCount,
		ListenAddr:     fmt.Sprintf(":%d", lnport),
		BootstrapNodes: bootNodes,
		TrustedNodes:   bootNodes,
		DiscoveryType:  discover.KAD,
	}
	// discovery for data net
	if netType == common.RootDataNet || netType == common.BranchDataNet {
		conf.DiscoveryType = discover.SRT
		conf.DialRatio = 2
		conf.ChainDataNodes = discover.ToChainDataNodes(netType, bootId, infos)
	}

	if bootport > 0 || (netType == common.BasicNet && !chainId.IsMain()) {
		conf.StaticNodes = bootNodes
	}

	// FIXME: initialize ip
	node := discover.NewNode(common.SystemNodeID, nil, lnport, lnport, 0)

	sid := nextSequenceID()
	svr := Server{
		SID:            sid,
		Node:           *node,
		P2PConfig:      *conf,
		Eventer:        eventer,
		localPort:      lnport,
		chainID:        chainId,
		bootID:         bootId,
		netType:        netType,
		addpeer:        make(chan *Peer),
		delpeer:        make(chan *Peer),
		quit:           make(chan struct{}),
		callbackFun:    callback,
		recentMsgPool:  NewRecentMsgPool(RecentMsgPoolSize),
		wantDetailLock: NewWantDetailLock(NewWantDetailLockSize),
		logger: log.WithFields(logrus.Fields{
			"W":     "P2P",
			"CHAIN": chainId,
			"NET":   netType,
			"SID":   sid,
		}),
	}

	svr.handShaker = &TcpHandShaker{
		self:       node,
		version:    TcpHandShakerVersion,
		dialer:     NewTcpDialer(),
		chainId:    chainId,
		bootId:     bootId,
		netType:    netType,
		permission: pms,
		logger:     svr.logger,
		checkFunc:  eventer.CheckPermission,
	}
	svr.listener = &TcpListener{}

	if config.IsLogOn(config.NetLog) {
		svr.logger.Infof("[NETWORK] NewP2PServer: nodeid:%s bootport:%d localport:%d ChainID:%d NT:%s",
			common.SystemNodeID, bootport, localport, chainId, netType)
	}

	return &svr, nil
}

func (s *Server) Start() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.isRunning {
		return errors.New("Server is running!")
	}

	if s.Clock == nil {
		s.Clock = discover.System{}
	}

	s.startListenTcp()

	s.startListenUdp()

	s.wg.Add(1)
	go s.startTaskScheduler()

	if s.callbackFun != nil {
		s.callbackOnce.Do(func() {
			s.callbackFun(s.chainID, s.netType, s)
		})
	}

	return nil
}

func (s *Server) startListenTcp() {
	err := s.listener.Listen("tcp", s.ListenAddr)
	if err != nil {
		if s.listener != nil {
			s.listener.Close()
		}
		s.logger.Errorf("node %s listen tcp error %v", s.Node.String(), err)
		return
	}

	s.logger.Infof("[P2P] listen tcp on %s", s.ListenAddr)

	laddr := s.listener.Addr().(*net.TCPAddr)
	s.ListenAddr = laddr.String()

	s.wg.Add(1)
	go s.readLoop()

	// nat
	if !laddr.IP.IsLoopback() && s.Nat != nil {
		go nat.Map(s.Nat, s.quit, "tcp", laddr.Port, laddr.Port, "tcp p2p")
	}
}

func (s *Server) startListenUdp() {
	var (
		conn     *net.UDPConn
		realaddr *net.UDPAddr
	)
	s.logger.Infof("[P2P] listen udp on %s discoveryType %s", s.ListenAddr, s.DiscoveryType)
	addr, err := net.ResolveUDPAddr("udp", s.ListenAddr)
	if err != nil {
		panic("resolve udp addr fail")
	}
	conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		s.logger.Errorf("listen %s error %v", addr, err)
		panic("listen udp addr error")
	}
	realaddr = conn.LocalAddr().(*net.UDPAddr)
	if s.Nat != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(s.Nat, s.quit, "udp", realaddr.Port, realaddr.Port, "udp discovery")
		}
		// TODO: react to external IP changes over time.
		if ext, err := s.Nat.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}

	cfg := discover.UDPConfig{
		ChainID:        s.chainID,
		BootId:         s.bootID,
		NetType:        s.netType,
		AnnounceAddr:   realaddr,
		NodeDBPath:     s.DatabasePath,
		Bootnodes:      s.BootstrapNodes,
		ChainDataNodes: s.ChainDataNodes,
	}
	if s.DiscoveryType.IsSRT() {
		s.discv, err = discover.SetupDiscoverySRT(&s.Node, conn, cfg)
	} else {
		s.discv, err = discover.SetupDiscoveryKAD(&s.Node, conn, cfg)
	}
	if err != nil {
		s.logger.Errorf("SetupDiscovery error %v", err)
	}

}

func (s *Server) readLoop() {
	tokens := defaultMaxPendingPeers
	if s.MaxPendCount > 0 {
		tokens = s.MaxPendCount
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	defer func() {
		s.wg.Done()
		for i := 0; i < len(slots); i++ {
			<-slots
		}
		if config.IsLogOn(config.NetDebugLog) {
			s.logger.Debugf("P2P server readLoop out %v", s)
		}
	}()

	for {
		<-slots

		var con net.Conn
		var err error

		for {
			con, err = s.listener.Accept()
			if err == nil {
				break
			}
			if discover.IsTemporaryError(err) {
				if config.IsLogOn(config.NetDebugLog) {
					s.logger.Debugf("Temporary read error %v", err)
				}
				continue
			}
			if config.IsLogOn(config.NetDebugLog) {
				s.logger.Warnf("accept inbound tcp connection error %v", err)
			}
			slots <- struct{}{}
			return
		}

		remoteIP := AddrIP(con.RemoteAddr())
		if err := s.checkInboundConn(con, remoteIP); err != nil {
			s.logger.Errorf("rejected inbound connection addr %s error %v", con.RemoteAddr(), err)
			SendReasonAndClose(con, nil, err)
			slots <- struct{}{}
			continue
		}

		// verify the inbound connection's proof and keep ping the remote peer
		if n, chainid, sec, err := s.handShaker.VerifyPeerProof(con); err != nil {
			if err != io.EOF {
				s.logger.Errorf("verify inbound peer proof error addr %s error %v", con.RemoteAddr(), err)
			}
			SendReasonAndClose(con, nil, err)
			slots <- struct{}{}
		} else {
			peer := NewPeer(*n, chainid, con, inboundConn, sec, s.NewPeerLogger(n.ID), s.HandleMsg, s.HandPeerInfo)
			peer.IP = remoteIP
			select {
			case s.addpeer <- peer:
			case <-s.quit:
				peer.close(DiscQuitting)
			}
			slots <- struct{}{}
		}
	}
}

func (s *Server) startTaskScheduler() {
	defer func() {
		s.wg.Done()
		if config.IsLogOn(config.NetDebugLog) {
			s.logger.Debug("P2P startTaskScheduler loop out")
		}
	}()
	s.isRunning = true
	dynPeersCount := s.maxDialedConns()
	taskScheduler := newTaskScheduler(s.StaticNodes, s.BootstrapNodes, s.discv.NodeTable(), dynPeersCount, s.NetRestrict)
	var (
		peers        = make(map[common.NodeID]*Peer)
		trusted      = make(map[common.NodeID]bool, len(s.TrustedNodes))
		taskdone     = make(chan task, maxActiveDialTasks)
		runningTasks []task
		queuedTasks  []task // tasks that can't run yet
		inboundCount = 0
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	for _, n := range s.TrustedNodes {
		trusted[n.ID] = true
	}

	// starts until max number of active tasks is satisfied
	startTasks := func(ts []task) (rest []task) {
		i := 0
		for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
			t := ts[i]
			go func() { t.Do(s); taskdone <- t }()
			runningTasks = append(runningTasks, t)
		}
		return ts[i:]
	}
	delTask := func(t task) {
		for i := range runningTasks {
			if runningTasks[i] == t {
				runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
				break
			}
		}
	}
	scheduleTasks := func() {
		// Start from queue first.
		queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
		// Query dialer for new tasks and start as many as possible now.
		if len(runningTasks) < maxActiveDialTasks {
			nt := taskScheduler.newTasks(s.DiscoveryType, len(runningTasks)+len(queuedTasks), peers, time.Now())
			queuedTasks = append(queuedTasks, startTasks(nt)...)
		}
	}

running:
	for {
		scheduleTasks()

		select {
		case <-s.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case t := <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			taskScheduler.taskDone(t, time.Now())
			delTask(t)
		case p := <-s.addpeer:
			if trusted[p.ID] {
				p.flag |= trustedConn
			}
			// check limit
			if err := s.connectPeerChecks(peers, inboundCount, p); err != nil {
				if config.IsLogOn(config.NetDebugLog) {
					s.logger.Debugf("P2P ignore peer %s %s reason %v", p, p.flag, err)
				}
				if r, ok := err.(DiscReason); ok {
					p.close(r)
				}
				continue
			}

			s.wg.Add(1)
			go s.runPeer(p)

			peers[p.ID] = p
			s.addPeerToChainPeers(p)

			if p.is(inboundConn) {
				inboundCount++
			}

			// Peer information change callback
			if p.callbackFun != nil {
				p.callbackFun(p, addPeerFlag, len(peers), inboundCount)
			}

			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
		case p := <-s.delpeer:
			// A peer disconnected.
			in := peers[p.ID]
			// make sure delete a peer already in peers
			if in != nil && p.TCP == in.TCP {
				delete(peers, p.ID)
				s.delPeerFromChainPeers(p)

				if p.is(inboundConn) {
					inboundCount--
				}
			}

			// Peer information change callback
			if p.callbackFun != nil {
				p.callbackFun(p, delPeerFlag, len(peers), inboundCount)
			}
		}
	}

	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debug("P2P networking is spinning down")
	}

	if s.discv != nil {
		s.discv.Close()
	}

	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debug("P2P discovery closed")
	}

	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}

	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debug("P2P peers closing")
	}

	for len(peers) > 0 {
		p := <-s.delpeer
		delete(peers, p.ID)
		s.delPeerFromChainPeers(p)

		if p.is(inboundConn) {
			inboundCount--
		}
		// Peer information change callback
		if p.callbackFun != nil {
			p.callbackFun(p, delPeerFlag, len(peers), inboundCount)
		}
	}
	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debug("P2P peers closed")
	}
}

func (s *Server) PeerCount() int {
	var count int
	s.Peers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (s *Server) maxInboundConns() int {
	return s.MaxPeersCount - s.maxDialedConns()
}

func (s *Server) maxDialedConns() int {
	r := s.DialRatio
	if r == 0 {
		r = defaultDialRatio
	}
	return s.MaxPeersCount / r
}

func (s *Server) checkInboundConn(con net.Conn, remoteIP net.IP) error {
	if remoteIP == nil {
		return nil
	}
	// Reject connections that do not match NetRestrict.
	if s.NetRestrict != nil && !s.NetRestrict.Contains(remoteIP) {
		return DiscInvalidIP
	}
	// Reject Internet peers that try too often.
	now := s.Clock.Now()
	s.inboundHistory.expire(now, nil)
	if !discover.IsLAN(remoteIP) && s.inboundHistory.contains(remoteIP.String()) {
		return DiscTryTooOften
	}
	s.inboundHistory.add(remoteIP.String(), now.Add(inboundThrottleTime))

	return nil
}

func (srv *Server) connectPeerChecks(peers map[common.NodeID]*Peer, inboundCount int, p *Peer) error {
	switch {
	case !p.is(trustedConn) && len(peers) >= srv.MaxPeersCount:
		return DiscTooManyPeers
	case !p.is(trustedConn) && p.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyInboundPeers
	case peers[p.ID] != nil:
		return DiscAlreadyConnected
	case p.ID == srv.ID:
		return DiscSelf
	case srv.DiscoveryType.IsSRT() && p.flag == inboundConn:
		if val, ok := srv.ChainToPeers.Load(p.chainId); ok {
			if len(val.([]*Peer)) >= maxChildToChildAcceptConns {
				return DiscTooManyChildToChildPeers
			}
		}
		return nil
	default:
		return nil
	}
}

func (s *Server) runPeer(p *Peer) {
	defer func() {
		s.wg.Done()
		if config.IsLogOn(config.NetDebugLog) {
			s.logger.Debugf("P2P runPeer out %v", p)
		}
	}()
	p.Run()
	s.delpeer <- p
}

func SendReasonAndClose(conn net.Conn, enc cipher.Stream, erro error) {
	if conn == nil {
		return
	}
	var err error
	if r, ok := erro.(DiscReason); ok && r != DiscNetworkError && r != DiscRequested && r != DiscSubprotocolError {
		if err = conn.SetWriteDeadline(time.Now().Add(discTimeout)); err == nil {
			pl, _ := rtl.Marshal(&r)
			discMsg := &Msg{
				MsgType: &DiscMsgType,
				Payload: pl,
			}
			msgload := writeMsgload(discMsg, enc)
			_, err = conn.Write(msgload)
		}
	}
	if config.IsLogOn(config.NetDebugLog) {
		log.Debugf("P2P SendReasonAndClose %v, %v", erro, err)
	}
	conn.Close()
}

func AddrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	default:
		return nil
	}
}

func (s *Server) Stop() {
	s.lock.Lock()
	if !s.isRunning {
		s.lock.Unlock()
		s.logger.Error("Server not running!")
		return
	}

	s.isRunning = false

	s.listener.Close()

	close(s.quit)

	s.lock.Unlock()

	s.wg.Wait()

	s.recentMsgPool.Stop()
	s.wantDetailLock.UnlockAll()
}

func (s *Server) NodeID() *common.NodeID {
	return &s.ID
}

func (s *Server) LocalPort() uint16 {
	return s.localPort
}

func (s *Server) PeerIDs() []common.NodeID {
	nodeids := make([]common.NodeID, 0)
	s.Peers.Range(func(key, value interface{}) bool {
		nid, ok := key.(common.NodeID)
		if ok {
			nodeids = append(nodeids, nid)
		}
		return true
	})
	return nodeids
}

func (s *Server) BootChain() common.ChainID {
	return s.bootID
}

func (s *Server) DiscoverTypeIsSRT() bool {
	return s.DiscoveryType.IsSRT()
}

func needPart(payLoadLen int) bool {
	return payLoadLen >= MaxBytesCanBroadcast-common.RealCipher.LengthOfPublicKey()-common.RealCipher.LengthOfSignature()
}

func (s *Server) BroadcastAsync(info string, msgv interface{}, pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error) {
	var etype models.EventType
	var eventLoad []byte
	var err error
	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(msgv, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(msgv, false)
	}
	if err != nil {
		return nil, nil, common.NewDvppError("async broadcast invalid message error", err)
	}
	go func() {
		if !needPart(len(eventLoad)) {
			err = s.BroadcastFullPayLoad(info, etype, eventLoad, pub, sig, skips...)
		} else {
			err = s.BroadcastPartPayLoad(info, etype, eventLoad, pub, sig, skips...)
		}
		if err != nil {
			if !needPart(len(eventLoad)) {
				s.logger.Errorf("[NETWORK] async full broadcast %s, skips:%s error %v", msgv, skips, err)
			} else {
				s.logger.Errorf("[NETWORK] async part broadcast %s, skips:%s error %v", msgv, skips, err)
			}
		}
	}()
	return pub, sig, err
}

func (s *Server) BroadcastSync(info string, msgv interface{}, pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error) {
	var etype models.EventType
	var eventLoad []byte
	var err error
	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(msgv, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(msgv, false)
	}
	if err != nil {
		return nil, nil, common.NewDvppError("sync broadcast invalid message error", err)
	}

	if !needPart(len(eventLoad)) {
		err = s.BroadcastFullPayLoad(info, etype, eventLoad, pub, sig, skips...)
	} else {
		err = s.BroadcastPartPayLoad(info, etype, eventLoad, pub, sig, skips...)
	}
	if err != nil {
		if !needPart(len(eventLoad)) {
			s.logger.Errorf("[NETWORK] sync full broadcast %s, skips:%s error %v", msgv, skips, err)
		} else {
			s.logger.Errorf("[NETWORK] sync part broadcast %s, skips:%s error %v", msgv, skips, err)
		}
	}

	return pub, sig, err
}

func (s *Server) BroadcastFullPayLoad(info string, eventType models.EventType,
	eventLoad, pub, sig []byte, skips ...*common.NodeID) error {
	var nodes []*common.NodeID
	var err error

	if len(common.NetDelay) == 2 && common.NetDelay[1] > 0 {
		delay := common.NetDelay[0] + rand.Intn(common.NetDelay[1]-common.NetDelay[0])
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	eventHash := common.Hash256(eventLoad)
	msg := PackP2PMsg(eventLoad, pub, sig)
	msgLoad := writeMsgload(msg, nil)
	s.Peers.Range(func(key, value interface{}) bool {
		nid, ok := key.(common.NodeID)
		if ok {
			for _, sk := range skips {
				if sk != nil && nid == *sk {
					return true
				}
			}
			_, inNodes := SystemRecentRecPool.IsExist(eventHash, &nid)
			if inNodes {
				skips = append(skips, &nid)
				return true
			}
		}
		if v, ok := value.(*Peer); ok {
			if config.IsLogOn(config.NetDebugLog) {
				nodes = append(nodes, &nid)
			}
			// if err = v.WriteMsg(msg); err != nil {
			if err = v.WriteMsgLoad(msgLoad); err != nil {
				s.logger.Errorf("[NETWORK] BroadcastFullPayLoad  ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to Node:%s, %s, error: %v",
					s.chainID, s.netType, eventHash[:5], eventType, len(eventLoad), s.NodeID(), nid, info, err)
			} else {
				SystemRecentRecPool.Add(eventHash, &nid)
			}
		}
		return true
	})
	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debugf("[NETWORK] BroadcastFullPayLoad: ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to Nodes:%v, skips:%s, %s",
			s.chainID, s.netType, eventHash[:5], eventType, len(eventLoad), s.NodeID(), nodes, skips, info)
	}
	return err
}

func (s *Server) BroadcastFull(info string, msgv interface{}, pub, sig []byte, skips ...*common.NodeID) error {
	var etype models.EventType
	var eventLoad []byte
	var err error
	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(msgv, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(msgv, false)
	}
	if err != nil {
		s.logger.Errorf("[NETWORK] BroadcastFull.WritePayLoad %s message error: %v", etype, err)
		return err
	}
	go func() {
		err = s.BroadcastFullPayLoad(info, etype, eventLoad, pub, sig, skips...)
		if err != nil {
			s.logger.Errorf("[NETWORK] BroadcastFull.BroadcastFullPayLoad %s, skips:%s error %v", msgv, skips, err)
		}
	}()
	return err
}

func (s *Server) BroadcastPartPayLoad(info string, eventType models.EventType,
	eventLoad, pub, sig []byte, skips ...*common.NodeID) error {

	// cache Hash(eventLoad) -> msgLoad to avoid resend a msg
	eventHash := common.Hash256(eventLoad)
	msg := PackP2PMsg(eventLoad, pub, sig)
	msgLoad := writeMsgload(msg, nil)
	err := s.recentMsgPool.PutLoad(eventHash, msgLoad)
	if err != nil {
		s.logger.Errorf("[NETWORK] (%s) cache msgLoad %s, EventLoadHash:%x , error: %v",
			info, eventType, eventHash[:5], err)
		return err
	}

	jhm := models.JustHashEMessage{
		Hash: eventHash,
	}

	if len(common.NetDelay) == 2 && common.NetDelay[1] > 0 {
		delay := common.NetDelay[0] + rand.Intn(common.NetDelay[1]-common.NetDelay[0])
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	var partEventLoad []byte
	var partPub []byte
	var partSig []byte
	var partEventType = models.UNSETEVENT
	// var partMsg *Msg
	var partMsgLoad []byte
	var ph common.Hash

	var fullNodes, partNodes []*common.NodeID
	n := NumOfFullBroadcast
	// if n > 0 {
	// 	msg = PackP2PMsg(msgLoad, pub, sig)
	// }
	s.Peers.Range(func(key, value interface{}) bool {
		nid, ok := key.(common.NodeID)
		if ok {
			for _, sk := range skips {
				if sk != nil && nid == *sk {
					return true
				}
			}
			_, inNodes := SystemRecentRecPool.IsExist(eventHash, &nid)
			if inNodes {
				// 短时间内从该节点接收过同一条信息
				skips = append(skips, &nid)
				return true
			}
		}
		if v, ok := value.(*Peer); ok {
			if n > 0 {
				n--
				// send full message
				if err = v.WriteMsgLoad(msgLoad); err != nil {
					s.logger.Errorf("[NETWORK] BroadcastPart ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to Node:%s, %s, error: %v",
						s.chainID, s.netType, eventHash[:5], eventType, len(eventLoad), s.NodeID(), nid, info, err)
				} else {
					SystemRecentRecPool.Add(eventHash, &nid)
					if config.IsLogOn(config.NetDebugLog) {
						fullNodes = append(fullNodes, &nid)
					}
				}
			} else {
				// just send hash of the message
				if partEventLoad == nil {
					partEventType, partEventLoad, partPub, partSig, err = WriteEventLoad(jhm, true)
					if err != nil {
						partEventLoad = nil
						return true
					}
					partMsg := PackP2PMsg(partEventLoad, partPub, partSig)
					partMsgLoad = writeMsgload(partMsg, nil)
					ph, _ = common.Hash256WithError(partEventLoad)
				}
				if err = v.WriteMsgLoad(partMsgLoad); err != nil {
					s.logger.Errorf("[NETWORK] BroadcastPart ChainID:%d NT:%s H:%x Full:(%s,Len:%d) Part:(%s,Len:%d) NID:%s to Node:%s, %s, error: %v",
						s.chainID, s.netType, jhm.Hash[:5], eventType, len(eventLoad), partEventType, len(partEventLoad), s.NodeID(), nid, info, err)
				} else {
					SystemRecentRecPool.Add(eventHash, &nid)
					SystemRecentRecPool.Add(ph, &nid)
					if config.IsLogOn(config.NetDebugLog) {
						partNodes = append(partNodes, &nid)
					}
				}

			}
		}
		return true
	})
	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debugf("[NETWORK] BroadcastPart: ChainID:%d NT:%s H:%x NID:%s (%s,Len:%d) to %v, (%s,Len:%d) to %v, skips:%s, %s",
			s.chainID, s.netType, jhm.Hash[:5], s.NodeID(), eventType, len(eventLoad), fullNodes, partEventType, len(partEventLoad), partNodes, skips, info)
	}

	return nil
}

func (s *Server) sendToNode(info string, toNodes common.NodeIDs, pb interface{}, pub, sig []byte, sync bool) (outpub, outsig []byte, err error) {
	var etype models.EventType
	var eventLoad []byte
	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(pb, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(pb, false)
	}
	if err != nil {
		return pub, sig, common.NewDvppError("WriteEventLoad error", err)
	}
	eventHash, _ := common.Hash256WithError(eventLoad)
	msg := PackP2PMsg(eventLoad, pub, sig)
	for _, to := range toNodes {
		if to == *s.NodeID() {
			continue
		}
		if mp, ok := s.Peers.Load(to); ok {
			// the node is my neighbour!!
			if v, ok := mp.(*Peer); ok {
				go func() {
					if err = v.WriteMsg(msg); err != nil {
						s.logger.Errorf("[NETWORK] sendToNode ChainID:%d NT:%s H:%x (%s,Len:%d) to Node:%s, %s, error: %v",
							s.chainID, s.netType, eventHash[:5], etype, len(eventLoad), to, info, err)
					} else {
						SystemRecentRecPool.Add(eventHash, s.NodeID())
						if config.IsLogOn(config.NetDebugLog) {
							s.logger.Debugf("[NETWORK] sendToNode ChainID:%d NT:%s H:%x (%s,Len:%d) to NID:%s, %s success",
								s.chainID, s.netType, eventHash[:5], etype, len(eventLoad), to, info)
						}
					}
				}()
				return pub, sig, nil
			}
		}
	}

	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debugf("[NETWORK] sendToNode H:%x to %s need broadcast", eventHash[:5], toNodes)
	}

	if sync {
		if !needPart(len(eventLoad)) {
			err = s.BroadcastFullPayLoad(info, etype, eventLoad, pub, sig)
		} else {
			err = s.BroadcastPartPayLoad(info, etype, eventLoad, pub, sig)
		}
		if err != nil {
			s.logger.Errorf("[NETWORK] sync send broadcast %s error %v", pb, err)
		}
	} else {
		go func() {
			if !needPart(len(eventLoad)) {
				err = s.BroadcastFullPayLoad(info, etype, eventLoad, pub, sig)
			} else {
				err = s.BroadcastPartPayLoad(info, etype, eventLoad, pub, sig)
			}
			if err != nil {
				s.logger.Errorf("[NETWORK] async send broadcast %s error %v", pb, err)
			}
		}()
	}

	return pub, sig, nil
}

func (s *Server) sendToPeer(info string, toNodes common.NodeIDs, pb interface{}, pub, sig []byte, sync bool) (outpub, outsig []byte, err error) {
	var etype models.EventType
	var eventLoad []byte
	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(pb, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(pb, false)
	}
	if err != nil {
		return pub, sig, common.NewDvppError("WriteEventLoad error", err)
	}
	eventHash, _ := common.Hash256WithError(eventLoad)
	msg := PackP2PMsg(eventLoad, pub, sig)
	// shuffle the seeds
	var tos common.NodeIDs
	if len(toNodes) > 1 {
		copy(tos[:], toNodes[:])
		rand.Shuffle(len(tos), func(i, j int) {
			tos[i], tos[j] = tos[j], tos[i]
		})
	}

	for _, to := range tos {
		if to == *s.NodeID() {
			continue
		}
		if mp, ok := s.Peers.Load(to); ok {
			// the node is my neighbour!!
			if v, ok := mp.(*Peer); ok {
				go func() {
					if err = v.WriteMsg(msg); err != nil {
						s.logger.Errorf("[NETWORK] sendToPeer ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to Node:%s, %s, error: %v",
							s.chainID, s.netType, eventHash[:5], etype, len(eventLoad), s.NodeID(), to, info, err)
					} else {
						SystemRecentRecPool.Add(eventHash, s.NodeID())
						if config.IsLogOn(config.NetDebugLog) {
							s.logger.Debugf("[NETWORK] sendToPeer ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to NID:%s, %s success",
								s.chainID, s.netType, eventHash[:5], etype, len(eventLoad), s.NodeID(), to, info)
						}
					}
				}()
				return pub, sig, nil
			}
		}
	}

	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debugf("[NETWORK] sendToPeer H:%x to %s need broadcast", eventHash[:5], toNodes)
	}
	s.RandBroadcast(1, info, pb, pub, sig)

	return pub, sig, nil
}

func (s *Server) sendToChain(info string, chainId common.ChainID, pb interface{}, pub, sig []byte, sync bool) (outpub, outsig []byte, err error) {
	var etype models.EventType
	var eventLoad []byte
	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(pb, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(pb, false)
	}
	if err != nil {
		return pub, sig, common.NewDvppError("WriteEventLoad error", err)
	}
	eventHash, _ := common.Hash256WithError(eventLoad)
	msg := PackP2PMsg(eventLoad, pub, sig)
	msgLoad := writeMsgload(msg, nil)
	// find a closet chain to the target
	targetChainId := discover.GetTargetChain(s.discv.NodeTable().GetDataNodes(), s.chainID, chainId)
	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debugf("[NETWORK] sendToChain H:%x discoverGetTargetChain from %d to %d pass by %d", eventHash[:5], s.chainID, chainId, targetChainId)
	}
	if targetChainId == common.NilChainID {
		return pub, sig, errors.New("[NETWORK] sendToChain no target")
	}
	if peers, ok := s.ChainToPeers.Load(targetChainId); ok {
		go func() {
			for _, peer := range peers.([]*Peer) {
				// if err = peer.WriteMsg(msg); err != nil {
				if err = peer.WriteMsgLoad(msgLoad); err != nil {
					s.logger.Errorf("[NETWORK] sendToChain %d by targetChain %d %s NT:%s H:%x (%s,Len:%d) error: %v",
						chainId, targetChainId, peer.ID, s.netType, eventHash[:5], etype, len(eventLoad), err)
				} else {
					SystemRecentRecPool.Add(eventHash, s.NodeID())
					if config.IsLogOn(config.NetDebugLog) {
						s.logger.Debugf("[NETWORK] sendToChain %d by targetChain %d %s NT:%s H:%x (%s,Len:%d) success",
							chainId, targetChainId, peer.ID, s.netType, eventHash[:5], etype, len(eventLoad))
					}
				}
			}
		}()
	} else {
		s.logger.Errorf("[NETWORK] sendToChain H:%x from chain %d node %s to chain %d pass by targetChain %d error: targetChain not found", eventHash[:5], s.chainID, s.NodeID(), chainId, targetChainId)
	}
	return pub, sig, nil
}

func (s *Server) SendToNode(info string, toNodes common.NodeIDs, pb interface{}, pub, sig []byte) ([]byte, []byte, error) {
	return s.sendToNode(info, toNodes, pb, pub, sig, false)
}

func (s *Server) SendToPeer(info string, toNodes common.NodeIDs, pb interface{}, pub, sig []byte) ([]byte, []byte, error) {
	return s.sendToPeer(info, toNodes, pb, pub, sig, false)
}

func (s *Server) SendToChain(info string, chainid common.ChainID, pb interface{}, pub, sig []byte) ([]byte, []byte, error) {
	return s.sendToChain(info, chainid, pb, pub, sig, false)
}

func (s *Server) RandBroadcast(size int, info string, msgv interface{}, pub, sig []byte,
	skips ...*common.NodeID) ([]byte, []byte, error) {
	var etype models.EventType
	var eventLoad []byte
	var err error

	if sig == nil {
		etype, eventLoad, pub, sig, err = WriteEventLoad(msgv, true)
	} else {
		etype, eventLoad, _, _, err = WriteEventLoad(msgv, false)
	}
	if err != nil {
		return pub, sig, common.NewDvppError("RandBroadcast.WriteEventLoad error", err)
	}

	var nodes []*common.NodeID
	var peerIds []*common.NodeID

	eventHash := common.Hash256(eventLoad)

	// find peer's NodeID
	s.Peers.Range(func(key, value interface{}) bool {
		nid, ok := key.(common.NodeID)
		if ok {
			for _, sk := range skips {
				if sk != nil && nid == *sk {
					return true
				}
			}
			_, inNodes := SystemRecentRecPool.IsExist(eventHash, &nid)
			if inNodes {
				return true
			}
		}
		peerIds = append(peerIds, &nid)
		return true
	})
	// rand a peer
	if size <= 0 || size >= len(peerIds) {
		nodes = peerIds
	} else {
		r := rand.New(rand.NewSource(rand.Int63()))
		for i := 0; i < size && len(peerIds) > 0; i++ {
			n := r.Intn(len(peerIds))
			nodes = append(nodes, peerIds[n])
			peerIds = append(peerIds[:n], peerIds[n+1:]...)
		}
	}

	// send
	go func() {
		msg := PackP2PMsg(eventLoad, pub, sig)
		msgLoad := writeMsgload(msg, nil)
		for i := 0; i < len(nodes); i++ {
			if v, ok := s.Peers.Load(*(nodes[i])); ok {
				if rp, ok := v.(*Peer); ok {
					// if err = rp.WriteMsg(msg); err != nil {
					if err = rp.WriteMsgLoad(msgLoad); err != nil {
						s.logger.Errorf("[NETWORK] RandBroadcast ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to Node:%s, %s, error: %v",
							s.chainID, s.netType, eventHash[:5], etype, len(eventLoad), s.NodeID(), nodes[i], info, err)
					}

				}
			}
		}
	}()
	if config.IsLogOn(config.NetDebugLog) {
		s.logger.Debugf("[NETWORK] RandBroadcast: ChainID:%d NT:%s H:%x (%s,Len:%d) NID:%s to Nodes:%v, %s",
			s.chainID, s.netType, eventHash[:5], etype, len(eventLoad), s.NodeID(), nodes, info)
	}
	return pub, sig, nil
}

func (s *Server) HandleMsg(peer *Peer, msg *Msg) error {
	nodeID := &peer.ID
	common.Watch(common.P2P)
	eventLoad, t, body, pub, sig, err := UnpackP2PMsg(msg)
	if err != nil {
		s.logger.Errorf("[NETWORK] unpack %s message from %s error: %v", t, nodeID, err)
		return err
	}
	// verify signature
	m, err := models.UnmarshalEvent(t, body)
	if err != nil {
		s.logger.Errorf("[NETWORK] unmarshal %s message from %s error: %v", t, nodeID, err)
		return err
	}
	if valid := common.VerifyMsg(m, pub, sig); !valid {
		s.logger.Errorf("[NETWORK] verify %s message %s error: invalid signature pub %x %x", t, m, pub, sig)
		return err
	}
	hashOfEventLoad := common.Hash256(eventLoad)
	switch t {
	case models.JustHashEvent:
		if mm, ok := m.(*models.JustHashEMessage); ok {
			// if _, ok := s.recentMsgPool.GetLoad(mm.Hash); !ok {
			if !s.recentMsgPool.IsExist(mm.Hash) {
				// the current node haven't sent the msg
				exist, _ := SystemRecentRecPool.IsExist(mm.Hash, nil)
				if exist {
					// the current node have received the msg
					if config.IsLogOn(config.NetDebugLog) {
						s.logger.Debugf("[NETWORK] Received NID:%s ChainID:%d NT:%s ET:%s, "+
							"H:%x, message already received", nodeID, s.chainID, s.netType, t, mm.Hash[:5])
					}
				} else {
					// the current node haven't received the msg
					if !s.wantDetailLock.Lock(mm.Hash) {
						// already sent a wantdetail
						if config.IsLogOn(config.NetDebugLog) {
							s.logger.Debugf("[NETWORK] Received NID:%s ChainID:%d NT:%s ET:%s, "+
								"H:%x, waiting Detail", nodeID, s.chainID, s.netType, t, mm.Hash[:5])
						}
					} else {
						// send a wantdetail
						SystemRecentRecPool.Add(hashOfEventLoad, nodeID)
						msg := models.WantDetailEMessage{
							Hash: mm.Hash,
						}
						mt, p2pMsg, err := WriteP2PMsg(msg, true)
						if err != nil {
							s.wantDetailLock.Unlock(mm.Hash)
							s.logger.Errorf("[NETWORK] WriteP2PMsg error %v", err)
							return err
						}
						peer.WriteMsg(p2pMsg)
						if config.IsLogOn(config.NetDebugLog) {
							s.logger.Debugf("[NETWORK] Received NID:%s ChainID:%d NT:%s ET:%s, "+
								"H:%x, %s sent", nodeID, s.chainID, s.netType, t, mm.Hash[:5], mt)
						}
					}
				}
			} else {
				// the current node have sent the msg recently
				if config.IsLogOn(config.NetDebugLog) {
					s.logger.Debugf("[NETWORK] Received NID:%s ChainID:%d NT:%s ET:%s, "+
						"H:%x, pooled already, ignored", nodeID, s.chainID, s.netType, t, mm.Hash[:5])
				}
			}
		} else {
			s.logger.Error("[NETWORK] not a just hash message")
		}
	case models.WantDetailEvent:
		if mm, ok := m.(*models.WantDetailEMessage); ok {
			if msgLoad, ok := s.recentMsgPool.GetLoad(mm.Hash); ok {
				// the current node have sent JustHashEvent recently
				peer.WriteMsgLoad(msgLoad)
				// peer.WriteMsg(PackP2PMsg(payLoad, nil, nil))
				if config.IsLogOn(config.NetDebugLog) {
					mt, _ := GetEventTypeFromMsgLoad(msgLoad)
					s.logger.Debugf("[NETWORK] Received NID:%s ChainID:%d NT:%s ET:%s, "+
						"H:%x, %s sent", nodeID, s.chainID, s.netType, t, mm.Hash[:5], mt)
				}
			} else {
				s.logger.Errorf("[NETWORK] Received NID:%s ChainID:%d NT:%s ET:%s, "+
					"H:%x, message not found", nodeID, s.chainID, s.netType, t, mm.Hash[:5])
			}
		} else {
			s.logger.Error("[NETWORK] not a want detail message")
		}
	default:
		added := SystemRecentRecPool.Add(hashOfEventLoad, nodeID)
		alreadyHas := !added || s.recentMsgPool.IsExist(hashOfEventLoad)

		// unlock WantDetailLock
		s.wantDetailLock.Unlock(hashOfEventLoad)

		if config.IsLogOn(config.NetDebugLog) {
			s.logger.Debugf("[NETWORK] Receive: NID:%s ChainID:%d NT:%s H:%x (%s, Len:%d) hitCache:%t",
				nodeID, s.chainID, s.netType, hashOfEventLoad[:5], t, len(eventLoad), alreadyHas)
		}

		if !alreadyHas {
			raw := models.NewRawData(nodeID, s.chainID, s.netType, t, body, pub, sig, &hashOfEventLoad, m)
			s.Eventer.PostMain(raw)
			if t == models.TxEvent {
				s.logger.Debugf("[NETWORK] TxEvent to RawData sent: %s", raw)
			}
		}
	}
	// }
	return nil
}

func (s *Server) HandPeerInfo(p *Peer, flag int, peerCount int, inboundCount int) error {
	if config.IsLogOn(config.NetLog) {
		if flag == addPeerFlag {
			s.logger.Infof("[PEER] connected one node %s flag %s discv %s count %d, inbound count %d", p.Node.String(), p.flag, s.DiscoveryType, peerCount, inboundCount)
		} else if flag == delPeerFlag {
			s.logger.Infof("[PEER] disconnected one node %s flag %s discv %s count %d, inbound count %d", p.Node.String(), p.flag, s.DiscoveryType, peerCount, inboundCount)
		}
	}
	return nil
}

func (s *Server) addPeerToChainPeers(p *Peer) {
	s.Peers.Store(p.ID, p)
	if s.DiscoveryType.IsSRT() {
		if val, ok := s.ChainToPeers.Load(p.chainId); ok {
			peers := val.([]*Peer)
			var exist bool
			for i, peer := range peers {
				if bytes.Equal(peer.ID[:], p.ID[:]) {
					peers[i] = p
					exist = true
					break
				}
			}
			if !exist {
				peers = append(peers, p)
			}
			s.ChainToPeers.Store(p.chainId, peers)
			if config.IsLogOn(config.NetDebugLog) {
				s.logger.Debugf("SORT add chainId %d peer %s peers count %d", p.chainId, p, len(peers))
			}
		} else {
			peers := []*Peer{p}
			s.ChainToPeers.Store(p.chainId, peers)
			if config.IsLogOn(config.NetDebugLog) {
				s.logger.Debugf("SORT add chainId %d peer %s peers count 1", p.chainId, p)
			}
		}

	}
}

func (s *Server) delPeerFromChainPeers(p *Peer) {
	s.Peers.Delete(p.ID)
	if s.DiscoveryType.IsSRT() {
		if val, ok := s.ChainToPeers.Load(p.chainId); ok {
			peers := val.([]*Peer)
			var flag bool
			for i, peer := range peers {
				if bytes.Equal(peer.ID[:], p.ID[:]) {
					flag = true
					peers = append(peers[:i], peers[i+1:]...)
					break
				}
			}
			if config.IsLogOn(config.NetDebugLog) {
				s.logger.Debugf("SORT del chainId %d peer %s peers count %d", p.chainId, p, len(peers))
			}
			if len(peers) == 0 {
				s.ChainToPeers.Delete(p.chainId)
				return
			}
			if flag {
				s.ChainToPeers.Store(p.chainId, peers)
			}
		}
	}
}

// set the new chain structure to tmp
func (s *Server) SetTmpDataNodes(infos []*common.ChainInfos) {
	if len(infos) == 0 || s.DiscoveryType.IsKAD() {
		return
	}
	tmpNodes := discover.ToChainDataNodes(s.netType, s.bootID, infos)
	s.discv.NodeTable().SetTmpNodes(tmpNodes)
}

// change the current chain structure with tmp and clear tmp
func (s *Server) ReplaceDataNodes() {
	if s.DiscoveryType.IsKAD() {
		return
	}
	s.discv.NodeTable().SwitchToTmpNodes()
}

// abandon useless peers
func (s *Server) AbandonUselessPeers() {
	if s.DiscoveryType.IsKAD() {
		return
	}
	chains := s.discv.NodeTable().GetAccessChains()
	s.ChainToPeers.Range(func(key, value interface{}) bool {
		cid := key.(common.ChainID)
		if discover.IsIn(chains, cid) {
			return true
		}
		peers := value.([]*Peer)
		for _, p := range peers {
			p.Disconnect(DiscUselessPeer)
		}
		if config.IsLogOn(config.NetLog) {
			s.logger.Infof("[NETWORK] abandon chain %d peers %d", cid, len(peers))
		}
		return true
	})
}

func (s *Server) NewPeerLogger(nid common.NodeID) logrus.FieldLogger {
	return log.WithFields(
		logrus.Fields{
			"W":     "PEER",
			"CHAIN": s.chainID,
			"NET":   s.netType,
			"SID":   s.SID,
			"NID":   nid.String(),
		})
}
