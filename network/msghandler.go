package network

type MsgHandler interface {
	// interface to handle the received p2p msg
	HandleMsg(peer *Peer, msg *Msg) error
}
