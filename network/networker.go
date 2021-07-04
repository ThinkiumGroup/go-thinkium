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

package network

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
)

type NetWorker struct {
	chainID     common.ChainID
	eventer     models.Eventer
	dmanager    models.DataManager
	bootservers map[string]common.NodeID
	portPool    *PortPool
	servers     map[common.NetType]models.P2PServer
	counter     int
	closing     sync.Once
	lock        sync.RWMutex
	logger      logrus.FieldLogger
}

func NewNetWorker(chainID common.ChainID, eventer models.Eventer, dmanager models.DataManager, bootservers map[string]common.NodeID,
	pool *PortPool) *NetWorker {
	return &NetWorker{
		chainID:     chainID,
		eventer:     eventer,
		dmanager:    dmanager,
		bootservers: bootservers,
		portPool:    pool,
		servers:     make(map[common.NetType]models.P2PServer),
		counter:     0,
		logger:      log.WithFields(logrus.Fields{"W": "Networker", "CHAINID": chainID}),
	}
}

// start a boot node
func (n *NetWorker) Create(typ common.NetType, address net.Addr, boots map[common.NodeID]net.Addr, infos []*common.ChainInfos, callback models.ConnectedCallBackFunc) error {
	n.lock.Lock()
	defer n.lock.Unlock()
	if typ == common.BasicNet {
		n.counter++
	}
	if _, ok := n.servers[typ]; ok {
		return ErrAlreadyConnected
	}
	v, ok := n.bootservers[address.String()]
	if !ok || v != common.SystemNodeID {
		return errors.New("addr not in bootnode addresses or node id not match")
	}
	boot := make(map[string]common.NodeID)
	for nid, addr := range boots {
		boot[addr.String()] = nid
	}
	_, lnport, _ := net.SplitHostPort(address.String())
	bootport, err := strconv.Atoi(lnport)
	if err != nil {
		return err
	}
	np, err := NewP2PServer(boot, uint16(bootport), 0, n.eventer, n.chainID, n.chainID, typ, infos, nil, callback)
	if err != nil {
		return errors.New("start boot node error")
	} else if err := np.Start(); err != nil {
		return err
	} else {
		n.servers[typ] = np
		return nil
	}
}

// connect to a boot node
func (n *NetWorker) Connect(typ common.NetType, bootId common.ChainID, boots map[common.NodeID]net.Addr, infos []*common.ChainInfos, permission []byte, callback models.ConnectedCallBackFunc) (err error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if typ == common.BasicNet {
		n.counter++
	}
	if _, ok := n.servers[typ]; ok {
		// log.Error("already connect to net", typ)
		return ErrAlreadyConnected
	}

	boot := make(map[string]common.NodeID)
	for nid, addr := range boots {
		boot[addr.String()] = nid
	}

	var usedPort []uint16
	defer func() {
		for _, port := range usedPort {
			n.portPool.Put(port)
		}
	}()

	for i := 0; i < TimesToRetryConnect; i++ {
		lnport, ok := n.portPool.Get()
		if !ok || lnport == 0 {
			return errors.New("no enough port to listen")
		}
		np, errr := NewP2PServer(boot, 0, lnport, n.eventer, n.chainID, bootId, typ, infos, permission, callback)
		if errr != nil {
			n.portPool.Put(lnport)
			return errr
		}
		if errr := np.Start(); errr != nil {
			n.logger.Warnf("reconnect! the port is %d, error: %s", lnport, errr)
			usedPort = append(usedPort, lnport)
			err = errr
		} else {
			n.servers[typ] = np
			return nil
		}
	}
	return err
}

func (n *NetWorker) Reset(typ common.NetType, addr net.Addr, callback models.ConnectedCallBackFunc) error {
	srv := n.servers[typ]
	if srv == nil {
		return errors.New("reset server does not exist")
	}
	if typ == common.BasicNet {
		n.counter = 1
	}
	var err error
	go func() {
		n.lock.Lock()
		defer n.lock.Unlock()
		if config.IsLogOn(config.NetDebugLog) {
			n.logger.Debugf("[CONNECTION] reset stopping Networker ChainID:%d, NetType:%s", n.chainID, typ)
		}
		srv.Stop()

		delete(n.servers, typ)
		if config.IsLogOn(config.NetDebugLog) {
			n.logger.Debugf("[CONNECTION] reset stopped Networker ChainID:%d, NetType:%s", n.chainID, typ)
		}

		v, ok := n.bootservers[addr.String()]
		if !ok || v != common.SystemNodeID {
			err = errors.New("reset addr not in bootnode addresses or node id not match")
			n.logger.Error("reset addr not in bootnode addresses or node id not match")
			return
		}
		boot := make(map[string]common.NodeID)
		boot[addr.String()] = v
		_, lnport, _ := net.SplitHostPort(addr.String())
		bootport, err1 := strconv.Atoi(lnport)
		if err1 != nil {
			err = err1
			n.logger.Errorf("reset boot port error: %v", err1)
			return
		}
		np, err2 := NewP2PServer(boot, uint16(bootport), 0, n.eventer, n.chainID, n.chainID, typ, nil, nil, callback)
		if err2 != nil {
			err = err2
			n.logger.Errorf("reset new boot node error: %v", err2)
			return
		}
		if err3 := np.Start(); err3 != nil {
			err = err3
			n.logger.Errorf("reset start boot node error: %v", err3)
			return
		}
		n.servers[typ] = np
		if config.IsLogOn(config.NetDebugLog) {
			n.logger.Debugf("[CONNECTION] reset success ChainID:%d, NetType:%s", n.chainID, typ)
		}
	}()
	return err
}

func (n *NetWorker) exitLocked(typ common.NetType) error {
	srv := n.servers[typ]
	if srv == nil {
		return errors.New("server does not exist")
	}
	go func() {
		if config.IsLogOn(config.NetDebugLog) {
			n.logger.Debugf("[CONNECTION] stopping Networker ChainID:%d, NetType:%s", n.chainID, typ)
		}
		srv.Stop()
		if srv.LocalPort() > 0 {
			if config.IsLogOn(config.NetDebugLog) {
				n.logger.Infof("[CONNECTION] exit from %s, recover port:%d", typ, srv.LocalPort())
			}
			n.portPool.Put(srv.LocalPort())
		}
		if config.IsLogOn(config.NetDebugLog) {
			n.logger.Debugf("[CONNECTION] stopped Networker ChainID:%d, NetType:%s", n.chainID, typ)
		}
	}()
	delete(n.servers, typ)
	return nil
}

// quit from current network
func (n *NetWorker) Exit(typ common.NetType) (int, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if typ == common.BasicNet {
		n.counter--
		if n.counter > 0 {
			if config.IsLogOn(config.NetDebugLog) {
				n.logger.Debugf("[CONNECTION] ChainID:%d, NetType:%s in use", n.chainID, typ)
			}
			return n.counter, errors.New("net still in use")
		}
	}

	return 0, n.exitLocked(typ)
}

func (n *NetWorker) IsIn(netType common.NetType) bool {
	return n.getP2P(netType) != nil
}

func (n *NetWorker) GetChainID() common.ChainID {
	return n.chainID
}

func (n *NetWorker) getP2P(netType common.NetType) models.P2PServer {
	n.lock.RLock()
	defer n.lock.RUnlock()

	p2p, ok := n.servers[netType]
	if !ok {
		return nil
	}
	return p2p
}

func (n *NetWorker) Broadcast(info string, typ common.NetType, msg interface{}, pub, sig []byte,
	skips ...*common.NodeID) ([]byte, []byte, error) {
	if n == nil {
		n.logger.Errorf("Broadcast(%s, %T) on nil Networker!!", typ, msg)
		return nil, nil, common.ErrNil
	}
	if p2p := n.getP2P(typ); p2p != nil {
		return p2p.BroadcastAsync(info, msg, pub, sig, skips...)
	}
	return nil, nil, errors.New(fmt.Sprintf("network @ chain=%d type=%s not found", n.chainID, typ))
}

func (n *NetWorker) BroadcastSync(info string, typ common.NetType, msg interface{}, pub, sig []byte,
	skips ...*common.NodeID) ([]byte, []byte, error) {
	if n == nil {
		n.logger.Errorf("Broadcast(%s, %T) on nil Networker!!", typ, msg)
		return nil, nil, common.ErrNil
	}
	if p2p := n.getP2P(typ); p2p != nil {
		return p2p.BroadcastSync(info, msg, pub, sig, skips...)
	}
	return nil, nil, errors.New(fmt.Sprintf("network @ chain=%d type=%s not found", n.chainID, typ))
}

func (n *NetWorker) SendToNode(info string, typ common.NetType, nodeids common.NodeIDs,
	msg interface{}, pub, sig []byte) ([]byte, []byte, error) {
	p2p := n.getP2P(typ)
	if p2p == nil {
		return nil, nil, fmt.Errorf("network ChainID:%d NT:%s not found", n.chainID, typ)
	}
	if config.IsLogOn(config.NetDebugLog) {
		n.logger.Debugf("SendToNode send Message route NetType[%v] nodes [%v]", typ, nodeids)
	}
	return p2p.SendToNode(info, nodeids, msg, pub, sig)

}

func (n *NetWorker) SendToPeer(info string, typ common.NetType, nodeids common.NodeIDs,
	msg interface{}, pub, sig []byte) ([]byte, []byte, error) {
	p2p := n.getP2P(typ)
	if p2p == nil {
		return nil, nil, fmt.Errorf("network ChainID:%d NT:%s not found", n.chainID, typ)
	}
	if config.IsLogOn(config.NetDebugLog) {
		n.logger.Debugf("SendToPeer send Message route NetType[%v] nodes [%v]", typ, nodeids)
	}
	return p2p.SendToPeer(info, nodeids, msg, pub, sig)
}

func (n *NetWorker) SendToChain(info string, typ common.NetType, chainid common.ChainID,
	msg interface{}, pub, sig []byte) ([]byte, []byte, error) {
	p2p := n.getP2P(typ)
	if p2p == nil {
		return nil, nil, fmt.Errorf("network ChainID:%d NT:%s not found", n.chainID, typ)
	}
	if p2p.DiscoverTypeIsSRT() {
		if config.IsLogOn(config.NetDebugLog) {
			n.logger.Debugf("SendToChain SORT send Message route NetType[%v],chainid[%d]", typ, chainid)
		}
		return p2p.SendToChain(info, chainid, msg, pub, sig)
	}

	return nil, nil, fmt.Errorf("Discovery KAD ChainID:%d NT:%s can't sendToChain", n.chainID, typ)
}

func (n *NetWorker) Rand(size int, info string, typ common.NetType, msg interface{},
	pub, sig []byte, skips ...*common.NodeID) ([]byte, []byte, error) {
	if p2p := n.getP2P(typ); p2p != nil {
		return p2p.RandBroadcast(size, info, msg, pub, sig, skips...)
	} else {
		return nil, nil, fmt.Errorf("network ChainID:%d NT:%s not found", n.chainID, typ)
	}
}

func (n *NetWorker) Close() error {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.closing.Do(func() {
		for k, v := range n.servers {
			n.counter = 0
			if v != nil {
				n.exitLocked(k)
			}
		}
	})
	return nil
}

func (n *NetWorker) NetTypes() (types []common.NetType) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	types = make([]common.NetType, 0, len(n.servers))
	for nty := range n.servers {
		types = append(types, nty)
	}
	return types
}

func (n *NetWorker) SetTmpDataNodes(nt common.NetType) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	if p2p := n.servers[nt]; p2p != nil {
		infos := n.dmanager.GetChainChildrenAndSelfInfos(p2p.BootChain())
		p2p.SetTmpDataNodes(infos)
	} else {
		n.logger.Errorf("ResetDataNodes for net %s server not found", nt)
	}
}

func (n *NetWorker) ReplaceDataNodes(nt common.NetType) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	if p2p := n.servers[nt]; p2p != nil {
		p2p.ReplaceDataNodes()
	} else {
		n.logger.Errorf("ReplaceDataNodes for net %s server not found", nt)
	}
}

func (n *NetWorker) AbandonUselessPeers(nt common.NetType) {
	n.lock.RLock()
	defer n.lock.RUnlock()
	if p2p := n.servers[nt]; p2p != nil {
		p2p.AbandonUselessPeers()
	} else {
		n.logger.Errorf("AbandonUselessPeers for net %s server not found", nt)
	}
}
