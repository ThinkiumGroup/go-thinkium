package network

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/network/discover"
)

var (
	errSelf             = errors.New("is self")
	errAlreadyDialing   = errors.New("already dialing")
	errAlreadyConnected = errors.New("already connected")
	errRecentlyDialed   = errors.New("recently dialed")
	errNotWhitelisted   = errors.New("not contained in netrestrict whitelist")
)

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn

	// This is the amount of time spent waiting in between
	// redialing a certain node.
	dialHistoryExpiration = 30 * time.Second

	// If no peers are found for this amount of time, the initial bootnodes are
	// attempted to be connected.
	fallbackInterval = 20 * time.Second

	// Discovery lookups are throttled and can only run
	// once every few seconds.
	lookupInterval = 5 * time.Second

	// Endpoint resolution is throttled with bounded backoff.
	initialResolveDelay        = 60 * time.Second
	maxResolveDelay            = time.Hour
	maxChildToChildDailConns   = 4
	maxChildToChildAcceptConns = 32
)

type (
	connFlag int32

	task interface {
		Do(*Server)
	}

	dialTask struct {
		flags        connFlag
		dest         *discover.Node
		lastResolved time.Time
		resolveDelay time.Duration
	}

	// discoverTask runs discovery table operations.
	// Only one discoverTask is active at any time.
	// discoverTask.Do performs a random lookup.
	discoverTask struct {
		results []*discover.Node
	}

	// A waitExpireTask is generated if there are no other tasks
	// to keep the loop in Server.run ticking.
	waitExpireTask struct {
		time.Duration
	}

	taskScheduler struct {
		maxDynDials int
		ntab        discover.DiscoverTable
		netrestrict *discover.Netlist

		lookupRunning bool
		dialing       map[common.NodeID]connFlag
		lookupBuf     []*discover.Node // current discovery lookup results
		randomNodes   []*discover.Node // filled from Table
		static        map[common.NodeID]*dialTask
		hist          *dialHistory

		start     time.Time        // time when the dialer was first used
		bootnodes []*discover.Node // default dials when there are no peers
	}
)

func newTaskScheduler(static []*discover.Node, bootnodes []*discover.Node, ntab discover.DiscoverTable, maxdyn int, netrestrict *discover.Netlist) *taskScheduler {
	s := &taskScheduler{
		maxDynDials: maxdyn,
		ntab:        ntab,
		netrestrict: netrestrict,
		static:      make(map[common.NodeID]*dialTask),
		dialing:     make(map[common.NodeID]connFlag),
		bootnodes:   make([]*discover.Node, len(bootnodes)),
		randomNodes: make([]*discover.Node, maxdyn/2),
		hist:        new(dialHistory),
	}
	copy(s.bootnodes, bootnodes)
	for _, n := range static {
		s.addStatic(n)
	}
	return s
}

func (t *dialTask) Do(srv *Server) {
	if !srv.isRunning {
		return
	}
	if t.dest.Incomplete() {
		if !t.resolve(srv) {
			srv.logger.Errorf("[TASK] can not resolve server %s", srv)
			return
		}
	}
	err := t.dial(srv)
	if err != nil && err != DiscTooManyChildToChildPeers && err != DiscAlreadyConnected {
		// Try resolving the ID of static nodes if dialing failed.
		if _, ok := err.(*dialErr); ok && t.flags&staticDialedConn != 0 {
			if t.resolve(srv) {
				err = t.dial(srv)
			}
		} else {
			// retry
			time.Sleep(1 * time.Second)
			err = t.dial(srv)
		}
	}
	if err != nil && config.IsLogOn(config.NetDebugLog) {
		srv.logger.Debugf("[TASK] dial %s error %v", t, err)
	}
}

// resolve attempts to find the current endpoint for the destination
// using discovery.
//
// Resolve operations are throttled with backoff to avoid flooding the
// discovery network with useless queries for nodes that don't exist.
// The backoff delay resets when the node is found.
func (t *dialTask) resolve(srv *Server) bool {
	if srv.discv == nil {
		if config.IsLogOn(config.NetDebugLog) {
			srv.logger.Debugf("Can't resolve node %s discovery not initialized", t.dest.ID)
		}
		return false
	}
	if t.resolveDelay == 0 {
		t.resolveDelay = initialResolveDelay
	}
	if time.Since(t.lastResolved) < t.resolveDelay {
		return false
	}
	resolved := srv.discv.NodeTable().Resolve(t.dest.ID)
	t.lastResolved = time.Now()
	if resolved == nil {
		t.resolveDelay *= 2
		if t.resolveDelay > maxResolveDelay {
			t.resolveDelay = maxResolveDelay
		}
		if config.IsLogOn(config.NetDebugLog) {
			log.Debugf("Resolving node %s failed newdelay %v", t.dest.ID, t.resolveDelay)
		}
		return false
	}
	// The node was found.
	t.resolveDelay = initialResolveDelay
	t.dest = resolved
	if config.IsLogOn(config.NetDebugLog) {
		log.Debugf("Resolved node %s addr %v", t.dest.ID, net.TCPAddr{IP: t.dest.IP, Port: int(t.dest.TCP)})
	}
	return true
}

// dial performs the actual connection attempt.
func (t *dialTask) dial(s *Server) error {
	var err error
	var chainId common.ChainID
	if s.DiscoveryType.IsSRT() {
		chainId, err = s.discv.GetChainID(t.dest.ID)
		if err != nil {
			return err
		}
		if peers, ok := s.ChainToPeers.Load(chainId); ok {
			if len(peers.([]*Peer)) >= maxChildToChildDailConns {
				return DiscTooManyChildToChildPeers
			}
		}
	}
	_, ok := s.Peers.Load(t.dest.ID)
	if ok {
		return DiscAlreadyConnected
	}
	var conn net.Conn
	var sec *Secrets
	if conn, sec, err = s.handShaker.ShakeHandWith(t.dest); err != nil {
		return err
	}
	peer := NewPeer(*t.dest, chainId, conn, t.flags, sec, s.NewPeerLogger(t.dest.ID), s.HandleMsg, s.HandPeerInfo)
	select {
	case s.addpeer <- peer:
	case <-s.quit:
		peer.close(DiscQuitting)
	}
	return err
}

func (t *dialTask) String() string {
	return fmt.Sprintf("%s %s", t.flags, t.dest)
}

func (t *discoverTask) Do(srv *Server) {
	// newTasks generates a lookup task whenever dynamic dials are
	// necessary. Lookups need to take some time, otherwise the
	// event loop spins too fast.
	next := srv.lastLookup.Add(lookupInterval)
	if now := time.Now(); now.Before(next) {
		time.Sleep(next.Sub(now))
	}
	srv.lastLookup = time.Now()
	var target common.NodeID
	rand.Read(target[:])
	t.results = srv.discv.NodeTable().Lookup(target)
}

func (t *discoverTask) String() string {
	s := "discovery lookup"
	if len(t.results) > 0 {
		s += fmt.Sprintf(" (%d results)", len(t.results))
	}
	return s
}

func (t waitExpireTask) Do(*Server) {
	time.Sleep(t.Duration)
}
func (t waitExpireTask) String() string {
	return fmt.Sprintf("wait for dial hist expire (%v)", t.Duration)
}

func (s *taskScheduler) addStatic(n *discover.Node) {
	// This overwrites the task instead of updating an existing
	// entry, giving users the opportunity to force a resolve operation.
	s.static[n.ID] = &dialTask{flags: staticDialedConn, dest: n}
}

func (s *taskScheduler) removeStatic(n *discover.Node) {
	// This removes a task so future attempts to connect will not be made.
	delete(s.static, n.ID)
	// This removes a previous dial timestamp so that application
	// can force a server to reconnect with chosen peer immediately.
	s.hist.remove(n.ID)
}

func (s *taskScheduler) newTasks(discvertype discover.DiscoveryType, nRunning int, peers map[common.NodeID]*Peer, now time.Time) []task {
	if s.start.IsZero() {
		s.start = now
	}

	var newtasks []task
	addDial := func(flag connFlag, n *discover.Node) bool {
		if err := s.checkDial(n, peers); err != nil {
			return false
		}
		s.dialing[n.ID] = flag
		newtasks = append(newtasks, &dialTask{flags: flag, dest: n})
		return true
	}

	// Compute number of dynamic dials necessary at this point.
	needDynDials := s.maxDynDials
	/**
	if config.IsLogOn(config.NetLog) {
		log.Debug("newTasks dynamic dials needDynDials: ", "needDynDials", needDynDials, "discvertype", discvertype)
	}***/
	for _, p := range peers {
		if p.is(dynDialedConn) {
			needDynDials--
		}
	}
	for _, flag := range s.dialing {
		if flag&dynDialedConn != 0 {
			needDynDials--
		}
	}

	// Expire the dial history on every invocation.
	s.hist.expire(now)

	// Create dials for static nodes if they are not connected.
	for id, t := range s.static {
		err := s.checkDial(t.dest, peers)
		switch err {
		case errNotWhitelisted, errSelf:
			log.Warn("Removing static dial candidate", "id", t.dest.ID, "addr", &net.TCPAddr{IP: t.dest.IP, Port: int(t.dest.TCP)}, "err", err)
			delete(s.static, t.dest.ID)
		case nil:
			s.dialing[id] = t.flags
			newtasks = append(newtasks, t)
		}
	}

	// Use random nodes from the table for half of the necessary dynamic KAD dials.
	if discvertype.IsKAD() {
		// If we don't have any peers whatsoever, try to dial a random bootnode. This
		// scenario is useful for the testnet (and private networks) where the discovery
		// table might be full of mostly bad peers, making it hard to find good ones.
		if len(peers) == 0 && len(s.bootnodes) > 0 && needDynDials > 0 && now.Sub(s.start) > fallbackInterval {
			bootnode := s.bootnodes[0]
			s.bootnodes = append(s.bootnodes[:0], s.bootnodes[1:]...)
			s.bootnodes = append(s.bootnodes, bootnode)
			/**
			if config.IsLogOn(config.NetLog) {
				log.Debug("newTasks add a bootnode peer: ", "bootnode:", bootnode, "discvertype", discvertype)
			}**/
			if addDial(dynDialedConn, bootnode) {
				needDynDials--
			}
		}

		randomCandidates := needDynDials / 2
		if randomCandidates > 0 {
			n := s.ntab.ReadRandomNodes(s.randomNodes)
			for i := 0; i < randomCandidates && i < n; i++ {
				if addDial(dynDialedConn, s.randomNodes[i]) {
					needDynDials--
				}
			}
		}
	}
	// Create dynamic dials from random lookup results, removing tried
	// items from the result buffer.
	i := 0
	for ; i < len(s.lookupBuf) && needDynDials > 0; i++ {
		/***
		if config.IsLogOn(config.NetLog) {
			log.Debug("lookupBuf--: ", "i", i, "lookupBuf node:", s.lookupBuf[i], "discvertype", discvertype)
		}****/
		if addDial(dynDialedConn, s.lookupBuf[i]) {
			needDynDials--
		}
	}
	s.lookupBuf = s.lookupBuf[:copy(s.lookupBuf, s.lookupBuf[i:])]
	// Launch a discovery lookup if more candidates are needed.
	if len(s.lookupBuf) < needDynDials && !s.lookupRunning {
		s.lookupRunning = true
		newtasks = append(newtasks, &discoverTask{})
	}

	// Launch a timer to wait for the next node to expire if all
	// candidates have been tried and no task is currently active.
	// This should prevent cases where the dialer logic is not ticked
	// because there are no pending events.
	if nRunning == 0 && len(newtasks) == 0 && s.hist.Len() > 0 {
		t := &waitExpireTask{s.hist.min().exp.Sub(now)}
		newtasks = append(newtasks, t)
	}
	return newtasks
}

func (s *taskScheduler) checkDial(n *discover.Node, peers map[common.NodeID]*Peer) error {
	_, dialing := s.dialing[n.ID]
	switch {
	case dialing:
		return errAlreadyDialing
	case peers[n.ID] != nil:
		return errAlreadyConnected
	case s.ntab != nil && n.ID == s.ntab.Self().ID:
		return errSelf
	case s.netrestrict != nil && !s.netrestrict.Contains(n.IP):
		return errNotWhitelisted
	case s.hist.contains(n.ID):
		return errRecentlyDialed
	}
	return nil
}

func (s *taskScheduler) taskDone(t task, now time.Time) {
	switch t := t.(type) {
	case *dialTask:
		s.hist.add(t.dest.ID, now.Add(dialHistoryExpiration))
		delete(s.dialing, t.dest.ID)
	case *discoverTask:
		s.lookupRunning = false
		s.lookupBuf = append(s.lookupBuf, t.results...)
	}
}

func (f connFlag) match(flag connFlag) bool {
	return f&flag == flag
}

func (f connFlag) String() string {
	var names []string
	if f.match(inboundConn) {
		names = append(names, "inbound")
	}
	if f.match(dynDialedConn) {
		names = append(names, "dynDialedConn")
	}
	if f.match(staticDialedConn) {
		names = append(names, "staticDialedConn")
	}
	if f.match(trustedConn) {
		names = append(names, "trustedConn")
	}
	return strings.Join(names, "_")
}
