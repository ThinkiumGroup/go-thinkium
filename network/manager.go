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
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
)

type Manager struct {
	common.AbstractService
	portPool    *PortPool
	eventer     models.Eventer
	dmanager    models.DataManager
	networkers  sync.Map // ChainID -> *NetWorker
	networkLock sync.Mutex
	logger      logrus.FieldLogger
}

func NewManager(portrange *[2]uint16, eventer models.Eventer) (*Manager, error) {
	var portPool *PortPool
	if portrange == nil {
		portPool = NewPortPool(common.DefaultP2PPort1, common.DefaultP2pPort2)
	} else {
		portPool = NewPortPool(portrange[0], portrange[1])
	}
	manager := &Manager{
		portPool: portPool,
		eventer:  eventer,
		logger:   log.WithFields(logrus.Fields{"W": "NManager"}),
	}

	manager.SetChanger(manager)

	return manager, nil
}

func (m *Manager) GetBootMap() map[string]common.NodeID {
	bootmap := make(map[string]common.NodeID)
	chaininfos := m.dmanager.GetAllChainInfos()
	for _, info := range chaininfos {
		for _, ds := range info.BootNodes {
			id, _ := hex.DecodeString(ds.NodeIDString)
			nid, _ := common.ParseNodeIDBytes(id)
			oneBootMap(bootmap, *nid, ds.IP, ds.BasicPort)
			oneBootMap(bootmap, *nid, ds.IP, ds.ConsensusPort0)
			oneBootMap(bootmap, *nid, ds.IP, ds.ConsensusPort1)
			oneBootMap(bootmap, *nid, ds.IP, ds.DataPort0)
			oneBootMap(bootmap, *nid, ds.IP, ds.DataPort1)
		}
	}
	return bootmap
}

func oneBootMap(bootmap map[string]common.NodeID, nid common.NodeID, ip string, port uint16) {
	if port > 0 {
		key := ip + ":" + strconv.Itoa(int(port))
		bootmap[key] = nid
	}
}

func oneAddr(ip string, port uint16) string {
	if port == 0 {
		return ""
	}
	return ip + ":" + strconv.Itoa(int(port))
}

func (m *Manager) SetDataManager(dmanager models.DataManager) {
	m.dmanager = dmanager
}

func (m *Manager) GetAllNetInfomap() map[common.ChainID]map[common.NodeID]common.NetInfo {
	netinfos := make(map[common.ChainID]map[common.NodeID]common.NetInfo)

	chaininfos := m.dmanager.GetAllChainInfos()
	for _, info := range chaininfos {
		infomap := make(map[common.NodeID]common.NetInfo)
		for _, data := range info.BootNodes {
			nodeid, _ := data.GetNodeID()
			infomap[*nodeid] = common.NewNetInfo(nodeid,
				oneAddr(data.IP, data.BasicPort),
				oneAddr(data.IP, data.ConsensusPort0),
				oneAddr(data.IP, data.ConsensusPort1),
				oneAddr(data.IP, data.DataPort0),
				oneAddr(data.IP, data.DataPort1),
			)
		}
		netinfos[info.ID] = infomap
	}
	return netinfos
}

func (m *Manager) GetNetInfomap(chainid common.ChainID) (map[common.NodeID]common.NetInfo, bool) {
	netinfo := make(map[common.NodeID]common.NetInfo)
	chaininfo, ok := m.dmanager.GetChainInfos(chainid)
	if !ok {
		return nil, false
	}
	for _, data := range chaininfo.BootNodes {
		nodeid, _ := data.GetNodeID()
		netinfo[*nodeid] = common.NewNetInfo(nodeid,
			oneAddr(data.IP, data.BasicPort),
			oneAddr(data.IP, data.ConsensusPort0),
			oneAddr(data.IP, data.ConsensusPort1),
			oneAddr(data.IP, data.DataPort0),
			oneAddr(data.IP, data.DataPort1),
		)
	}
	return netinfo, true
}

func (m *Manager) GetDataServer(chainId common.ChainID) *[]common.Dataserver {
	if chaininfo, ok := m.dmanager.GetChainInfos(chainId); !ok {
		return nil
	} else {
		return &chaininfo.BootNodes
	}
}

func (m *Manager) Status() {
	m.logger.Infof("--------------------CONNECT STATUS %s-------------------------", consts.Version)
	var chainids []common.ChainID
	m.networkers.Range(func(key, value interface{}) bool {
		if chainid, ok := key.(common.ChainID); ok {
			if _, ok := value.(*NetWorker); ok {
				chainids = append(chainids, chainid)
			}
		}
		return true
	})
	sort.Slice(chainids, func(i, j int) bool {
		return chainids[i] < chainids[j]
	})
	for _, chainid := range chainids {
		value, ok := m.networkers.Load(chainid)
		if !ok {
			continue
		}
		if nw, ok := value.(*NetWorker); ok {
			netTypeSlice := nw.NetTypes()
			syncing := "N/A"
			if holder, err := m.dmanager.GetChainData(chainid); err == nil && holder != nil {
				if holder.IsSynced() {
					syncing = "SYNC"
				} else {
					syncing = "NOTSYNC"
				}
			}
			m.logger.Infof("ChainID:%d\tnetType:%v\tOP:%v\t%s",
				chainid, netTypeSlice, m.eventer.GetChainOpTypes(chainid), syncing)
		}
	}
	m.logger.Info("----------------------------------------------------------------------")

}

func (m *Manager) String() string {
	return fmt.Sprintf("network manager(%s)", common.SystemNodeID)
}

func (m *Manager) GetNetworker(id common.ChainID) models.Networker {
	n := m.getNetworker(id)
	if n == nil {
		return nil
	}
	return n
}

func (m *Manager) getNetworker(id common.ChainID) *NetWorker {
	w, exist := m.networkers.Load(id)
	if !exist || w == nil {
		return nil
	}
	n, ok := w.(*NetWorker)
	if !ok {
		panic("expecting a *network.NetWorker")
	}
	return n
}

func (m *Manager) InitChain(id common.ChainID) error {
	m.networkLock.Lock()
	defer m.networkLock.Unlock()
	n := m.GetNetworker(id)
	if n != nil {
		return nil
	}
	n = NewNetWorker(id, m.eventer, m.dmanager, m.GetBootMap(), m.portPool)
	m.logger.Infof("[NManager] join ChainID:%d create networker", id)
	m.networkers.Store(id, n)
	return nil
}

func (m *Manager) InitNet(chaininfo *common.ChainInfos) error {
	if m.IsBootNode(chaininfo.ID) {
		vvv := m.GetNetworker(chaininfo.ID)
		if _, err := m.StartConNet(vvv, chaininfo.ID, common.ConsensusNet1); err != nil {
			return err
		}
		if _, err := m.StartConNet(vvv, chaininfo.ID, common.ConsensusNet2); err != nil {
			return err
		}
		switch chaininfo.Mode {
		case common.Branch:
			// branch chain join root data net
			m.CreateOrConnectNet(common.RootDataNet, chaininfo.ParentID, chaininfo.ID)
			// shard chain's parent should join branch data net
			ids := m.dmanager.GetChainChildren(chaininfo.ID)
			if ids != nil && ids.Len() > 0 && chaininfo.ParentID.IsMain() {
				m.CreateOrConnectNet(common.BranchDataNet, chaininfo.ID, chaininfo.ID)
			}
			m.CreateOrConnectNet(common.BasicNet, chaininfo.ID, chaininfo.ID)
		case common.Shard:
			m.CreateOrConnectNet(common.RootDataNet, common.MainChainID, chaininfo.ID)
			m.CreateOrConnectNet(common.BranchDataNet, chaininfo.ParentID, chaininfo.ID)
			m.CreateOrConnectNet(common.BasicNet, chaininfo.ID, chaininfo.ID)
		}
	}
	return nil
}

func (m *Manager) ConnectNet(chaininfo *common.ChainInfos) error {
	m.CreateOrConnectNet(common.ConsensusNet1, chaininfo.ID, chaininfo.ID)
	m.CreateOrConnectNet(common.ConsensusNet2, chaininfo.ID, chaininfo.ID)
	switch chaininfo.Mode {
	case common.Root:
		m.CreateOrConnectNet(common.RootDataNet, chaininfo.ID, chaininfo.ID)
	case common.Branch:
		// branch chain join root data net
		m.CreateOrConnectNet(common.RootDataNet, chaininfo.ParentID, chaininfo.ID)
		// shard chain's parent should join branch data net
		ids := m.dmanager.GetChainChildren(chaininfo.ID)
		if ids != nil && ids.Len() > 0 && chaininfo.ParentID.IsMain() {
			m.CreateOrConnectNet(common.BranchDataNet, chaininfo.ID, chaininfo.ID)
		}
		m.CreateOrConnectNet(common.BasicNet, chaininfo.ID, chaininfo.ID)
	case common.Shard:
		m.CreateOrConnectNet(common.RootDataNet, common.MainChainID, chaininfo.ID)
		m.CreateOrConnectNet(common.BranchDataNet, chaininfo.ParentID, chaininfo.ID)
		m.CreateOrConnectNet(common.BasicNet, chaininfo.ID, chaininfo.ID)
	}
	return nil
}

func (m *Manager) ClearNetWorker(id common.ChainID) {
	// close networker before delete
	nw := m.getNetworker(id)
	if nw != nil {
		nw.Close()
	}
	m.networkers.Delete(id)
}

// create networker for main chain
func (m *Manager) Initializer() error {
	m.InitChain(common.MainChainID)
	m.logger.Info(m.String(), "main chain networker initialized")
	return nil
}

func (m *Manager) Starter() error {
	// start main chain, create or connect
	vv := m.GetNetworker(common.MainChainID)
	boots, ok := m.GetChainNet(common.MainChainID, common.BasicNet)
	if !ok {
		panic("no main chain basic boot node found")
	}
	addr := boots[common.SystemNodeID]
	if addr != nil {
		// i am the bootnode of main chain, create
		m.logger.Infof("[CONNECTION] start chain(%d) basicnet with %s @ %s", common.MainChainID, addr, common.SystemNodeID)
		if err := vv.Create(common.BasicNet, addr, boots, nil, nil); err != nil {
			return err
		}
		m.logger.Infof("[CONNECTION] start chain(%d) root datanet with %s @ %s", common.MainChainID, addr, common.SystemNodeID)
		// single chain ignore create data net
		if !common.StandAlone {
			m.CreateOrConnectNet(common.RootDataNet, common.MainChainID, common.MainChainID)
			// 主链创建共识网络
			if _, err := m.StartConNet(vv, common.MainChainID, common.ConsensusNet1); err != nil {
				return err
			}
			if _, err := m.StartConNet(vv, common.MainChainID, common.ConsensusNet2); err != nil {
				return err
			}
		}
	} else {
		// i am not the boot node of main chain, connect root basic net
		m.logger.Infof("[CONNECTION] connect chain(%d) basicnet @ %s -> %s", common.MainChainID, common.SystemNodeID, boots)
		if err := vv.Connect(common.BasicNet, common.MainChainID, boots, nil, nil, nil); err != nil {
			if err == ErrAlreadyConnected {
				m.logger.Warnf("[CONNECTION] connect chain(%d) basicnet @ %s -> %s warning: %v",
					common.MainChainID, common.SystemNodeID, boots, err)
			} else {
				return err
			}
		}
	}
	// initialize other net
	for k := range m.GetAllNetInfomap() {
		chaininfo, ok := m.dmanager.GetChainInfos(k)
		if !ok || chaininfo == nil || k == common.MainChainID || !m.IsBootNode(k) {
			continue
		}
		// initialize networker
		m.InitChain(k)
		// join net
		m.InitNet(chaininfo)
	}

	if m.dmanager.IsMemoNode() {
		m.InitChain(*common.ForChain)
	}

	// a new data node join net
	if m.dmanager.IsDataMemoNode() {
		chaininfo, ok := m.dmanager.GetChainInfos(*common.ForChain)
		if ok {
			m.InitChain(*common.ForChain)
			m.ConnectNet(chaininfo)
		}
	}

	m.logger.Info(m.String(), "net started")
	return nil
}

// stop manager's all networkers
func (m *Manager) Closer() error {
	// for _, client := range m.clients {
	// 	client.Close()
	// }
	// m.server.Close()
	// m.nctx.Close()

	m.networkers.Range(func(key, value interface{}) bool {
		networker, _ := value.(*NetWorker)
		networker.Close()
		return true
	})
	// m.p2psvr.Server.Stop()

	m.logger.Info(m.String(), "closed")
	return nil
}

func parseAddr(s string) (net.IP, uint16) {
	splitS := strings.Split(s, ":")
	if len(splitS) != 2 {
		return nil, 0
	}
	ip := net.ParseIP(splitS[0])
	port, err := strconv.ParseUint(splitS[1], 10, 16)
	if ip == nil || err != nil {
		return nil, 0
	}
	return ip, uint16(port)
}

func (m *Manager) IsBootNode(id common.ChainID) bool {
	mm, ok := m.GetNetInfomap(id)
	if !ok {
		return false
	}
	for id, _ := range mm {
		if common.SystemNodeID == id {
			return true
		}
	}
	return false
}

func (m *Manager) GetChainNet(id common.ChainID, netType common.NetType) (map[common.NodeID]net.Addr, bool) {
	// if m.GetAllNetInfomap() == nil {
	// 	return nil, false
	// }
	infomap, ok := m.GetNetInfomap(id)
	if !ok {
		return nil, false
	}
	ret := make(map[common.NodeID]net.Addr)
	for nid, info := range infomap {
		addr := info.GetAddr(netType)
		if addr != nil {
			ret[nid] = addr
		}
	}
	return ret, len(ret) > 0
}

func (m *Manager) StartConNet(networker models.Networker, chainid common.ChainID,
	netType common.NetType) (common.NodeID, error) {
	boots, ok := m.GetChainNet(chainid, netType)
	if !ok {
		panic(fmt.Sprintf("no boot node found: ChainID:%d NetType:%s", chainid, netType))
	}
	addr := boots[common.SystemNodeID]
	if addr != nil {
		m.logger.Infof("Starting ChainID:%d NetType:%s with %s @ %s", chainid, netType, addr, common.SystemNodeID)
		if err := networker.Create(netType, addr, boots, nil,
			func(id common.ChainID, netType common.NetType, server models.P2PServer) {
				m.logger.Infof("Started ChainID:%d NetType:%s with %s @ %s", chainid, netType, addr, common.SystemNodeID)
			}); err != nil {
			return common.SystemNodeID, err
		}
	}
	return common.SystemNodeID, nil
}

func (m *Manager) ResetConNet(networker models.Networker, chainid common.ChainID,
	netType common.NetType) (common.NodeID, error) {
	boots, ok := m.GetChainNet(chainid, netType)
	if !ok {
		panic(fmt.Sprintf("no boot node found: ChainID:%d NetType:%s", chainid, netType))
	}
	addr := boots[common.SystemNodeID]
	if addr != nil {
		m.logger.Infof("Starting ChainID:%d NetType:%s with %s @ %s", chainid, netType, addr, common.SystemNodeID)
		if err := networker.Create(netType, addr, boots, nil,
			func(id common.ChainID, netType common.NetType, server models.P2PServer) {
				m.logger.Infof("Started ChainID:%d NetType:%s with %s @ %s", chainid, netType, addr, common.SystemNodeID)
			}); err != nil {
			return common.SystemNodeID, err
		}
	}
	return common.SystemNodeID, nil
}

func (m *Manager) CreateOrConnectNet(ntp common.NetType, bootChainID, localChandID common.ChainID) error {
	if bootChainID.IsNil() || localChandID.IsNil() {
		return nil
	}
	infos := m.dmanager.GetChainChildrenAndSelfInfos(bootChainID)
	if boots, ok := m.GetChainNet(bootChainID, ntp); ok {
		addr := boots[common.SystemNodeID]
		if addr != nil {
			// the current node is BootNode for data net
			if config.IsLogOn(config.NetLog) {
				m.logger.Infof("data net boot node created, ChainID:%d Addr:%s", bootChainID, addr)
			}
			vt := m.GetNetworker(bootChainID)
			if err := vt.Create(ntp, addr, boots, infos, nil); err != nil {
				return err
			}
		} else {
			// the current node isn't BootNode for data net
			if config.IsLogOn(config.NetLog) {
				m.logger.Infof("connect to data net boot node, ChainID:%d -> ChainID:%d netType:%s",
					localChandID, bootChainID, ntp)
			}
			vt := m.GetNetworker(localChandID)
			if err := vt.Connect(ntp, bootChainID, boots, infos, nil, nil); err != nil {
				if err == ErrAlreadyConnected {
					m.logger.Warnf("connect to data net boot node, ChainID:%d -> ChainID:%d netType:%s warning %v",
						localChandID, bootChainID, ntp, err)
				} else {
					m.logger.Errorf("connect to data net boot node, ChainID:%d -> ChainID:%d netType:%s error %v",
						localChandID, bootChainID, ntp, err)
					return err
				}
			}
		}
	} else {
		if config.IsLogOn(config.NetLog) {
			m.logger.Infof("no data net found for ChainID:%d", bootChainID)
		}
	}
	return nil
}

func (m *Manager) ResetNet(chainid common.ChainID, ntp common.NetType) error {
	if m.IsBootNode(chainid) {
		m.ResetOneNet(chainid, ntp)
	}
	return nil
}

// stop manager's one networker
func (m *Manager) StopOneChain(id *common.ChainID) error {
	if v, ok := m.networkers.Load(*id); ok {
		nw, _ := v.(*NetWorker)
		nw.Close()
		m.logger.Info("chain ", id, "closed")
		return nil
	} else {
		m.logger.Error("error to close one chain")
		return errors.New("error to close one chain")
	}
}

// stop manager's one net of a networker
func (m *Manager) StopOneNet(cid common.ChainID, ntp common.NetType) (int, error) {
	if v, ok := m.networkers.Load(cid); ok {
		nw, _ := v.(*NetWorker)
		if uc, err := nw.Exit(ntp); err != nil {
			m.logger.Warnf("[NETWORK] fail to close one net: ChainID:%d NetType:%s error %v", cid, ntp, err)
			return uc, err
		}
		if config.IsLogOn(config.NetDebugLog) {
			m.logger.Debugf("[NETWORK] ChainID:%d NetType:%s closed", cid, ntp)
		}
	}
	return 0, nil
}

func (m *Manager) CreateOneNet(cid common.ChainID, ntp common.NetType) error {
	if v, ok := m.networkers.Load(cid); ok {
		nw, _ := v.(*NetWorker)
		boots, _ := m.GetChainNet(cid, ntp)
		for _, addr := range boots {
			if nw.IsIn(ntp) {
				return nil
			}
			if err := nw.Create(ntp, addr, boots, nil, nil); err == nil {
				return nil
			}
		}
	}
	m.logger.Errorf("[NETWORK] error to create net: ChainID:%d NetType:%s", cid, ntp)
	return errors.New("error to create one consensus net")
}

func (m *Manager) ResetOneNet(cid common.ChainID, ntp common.NetType) error {
	if v, ok := m.networkers.Load(cid); ok {
		nw, _ := v.(*NetWorker)
		boots, _ := m.GetChainNet(cid, ntp)
		addr := boots[common.SystemNodeID]
		if addr == nil {
			return errors.New("not a boot node")
		}
		if err := nw.Reset(ntp, addr, nil); err != nil {
			m.logger.Errorf("[NETWORK] error to reset net: ChainID:%d NetType:%s", cid, ntp)
			return errors.New("error to reset net")
		}
	}
	return nil
}

func (m *Manager) SendToNode(info string, ntp common.NetType, chainId common.ChainID, toNodes common.NodeIDs,
	pb interface{}, pub, sig []byte) error {
	if nt := m.GetNetworker(chainId); nt != nil {
		_, _, err := nt.SendToNode(info, ntp, toNodes, pb, pub, sig)
		return err
	}
	return errors.New("can't send msg on chain")
}

func (m *Manager) SendToPeer(info string, ntp common.NetType, chainId common.ChainID, toNodes common.NodeIDs,
	pb interface{}, pub, sig []byte) error {
	if nt := m.GetNetworker(chainId); nt != nil {
		_, _, err := nt.SendToPeer(info, ntp, toNodes, pb, pub, sig)
		return err
	}
	return errors.New("can't send msg on chain")
}

func (m *Manager) SendToChain(info string, ntp common.NetType, fromChain common.ChainID, toChain common.ChainID,
	pb interface{}, pub, sig []byte) error {
	if nt := m.GetNetworker(fromChain); nt != nil {
		_, _, err := nt.SendToChain(info, ntp, toChain, pb, pub, sig)
		return err
	}
	return errors.New("can't send msg on chain")
}

func (m *Manager) BroadcastFull(info string, skip *common.NodeID, cid common.ChainID, ntp common.NetType,
	pb interface{}, pub, sig []byte) error {
	var err error
	if nt := m.GetNetworker(cid); nt != nil {
		if skip != nil {
			_, _, err = nt.Broadcast(info, ntp, pb, pub, sig, skip)
		} else {
			_, _, err = nt.Broadcast(info, ntp, pb, pub, sig)
		}
	} else {
		m.logger.Errorf("ChainID:%d Networker not found", cid)
		err = errors.New("can't broadcast on chain: " + cid.String())
	}
	return err
}

func (m *Manager) BroadcastFullSync(info string, skip *common.NodeID, cid common.ChainID, ntp common.NetType,
	pb interface{}, pub, sig []byte) error {
	var err error
	if nt := m.GetNetworker(cid); nt != nil {
		if skip != nil {
			_, _, err = nt.BroadcastSync(info, ntp, pb, pub, sig, skip)
		} else {
			_, _, err = nt.BroadcastSync(info, ntp, pb, pub, sig)
		}
	} else {
		m.logger.Errorf("ChainID:%d Networker not found", cid)
		err = errors.New("can't broadcast on chain")
	}
	return err
}

func (m *Manager) Rand(size int, info string, chainId common.ChainID, ntp common.NetType, msg interface{},
	pub, sig []byte, skips ...*common.NodeID) error {
	if nt := m.GetNetworker(chainId); nt != nil {
		_, _, err := nt.Rand(size, info, ntp, msg, pub, sig, skips...)
		return err
	}
	m.logger.Errorf("ChainID:%d Networker not found", chainId)
	return errors.New("can't random broadcast on chain")
}
