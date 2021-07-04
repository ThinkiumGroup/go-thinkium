package discover

import (
	"net"

	"github.com/ThinkiumGroup/go-common"
)

type DiscoveryType string

const (
	KAD DiscoveryType = "KAD"
	SRT DiscoveryType = "SORT"
)

type Discovery interface {
	// discovery type
	Type() DiscoveryType
	// version
	Version() uint32
	// read msg from udp connection
	NodeTable() DiscoverTable
	//Get chainid from tab
	GetChainID(id common.NodeID) (common.ChainID, error)
	// ping
	Ping(common.NodeID, *net.UDPAddr) error
	// find node
	FindNode(toid common.NodeID, addr *net.UDPAddr, target interface{}) (map[common.ChainID][]*Node, error)
	// close
	Close() error
}

type DiscoverTable interface {
	Self() *Node
	Close()
	// modify by gy
	Len() int
	Resolve(target common.NodeID) *Node
	Lookup(target interface{}) []*Node
	ReadRandomNodes([]*Node) int

	// FOR SORT TABLE
	GetDataNodes() []*ChainDataNodes
	GetAccessChains() common.ChainIDs
	SetTmpNodes(dataNodes []*ChainDataNodes)
	SwitchToTmpNodes()
}

func IsTemporaryError(err error) bool {
	tempErr, ok := err.(interface {
		Temporary() bool
	})
	return ok && tempErr.Temporary()
}

func (d DiscoveryType) IsKAD() bool {
	return d == KAD
}

func (d DiscoveryType) IsSRT() bool {
	return d == SRT
}
