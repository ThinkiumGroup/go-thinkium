package network

import (
	"bytes"
	aes2 "crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/network/discover"
	"github.com/sirupsen/logrus"
	"github.com/stephenfire/go-rtl"
)

const (
	readTimeout      = 30 * time.Second
	writeTimeout     = 20 * time.Second
	handshakeTimeout = 5 * time.Second
	discTimeout      = 1 * time.Second
)

var pendZero = make([]byte, 16)

type HandleMsgFunc func(peer *Peer, msg *Msg) error
type CallbackFun func(peer *Peer, flag int, peerCount int, inboundCount int) error

type Peer struct {
	discover.Node
	chainId      common.ChainID
	logger       logrus.FieldLogger
	RW           net.Conn
	MC           chan *Msg
	handleFun    HandleMsgFunc
	callbackFun  CallbackFun
	flag         connFlag
	rlock, wlock sync.Mutex
	protoErr     chan error
	disc         chan DiscReason
	closed       chan struct{}
	wg           sync.WaitGroup

	enc cipher.Stream
	dec cipher.Stream
}

func NewPeer(n discover.Node, chainId common.ChainID, con net.Conn, flag connFlag, sec *Secrets, logger logrus.FieldLogger, handleFunc HandleMsgFunc, callbackFun CallbackFun) *Peer {
	peer := &Peer{
		Node:        n,
		chainId:     chainId,
		RW:          con,
		flag:        flag,
		logger:      logger,
		MC:          make(chan *Msg),
		handleFun:   handleFunc,
		callbackFun: callbackFun,
		protoErr:    make(chan error, 1),
		disc:        make(chan DiscReason, 1),
		closed:      make(chan struct{}),
	}
	aes, err := aes2.NewCipher(sec.AES)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize())
	peer.enc = cipher.NewCTR(aes, iv)
	peer.dec = cipher.NewCTR(aes, iv)
	return peer
}

// length（4 bytes） + type（2 bytes） +  msg body
func (p *Peer) ReadMsg() (*Msg, error) {
	p.rlock.Lock()
	defer p.rlock.Unlock()
	p.RW.SetReadDeadline(time.Now().Add(readTimeout))
	return readMsgLoad(p.RW, p.dec)
}

func (p *Peer) writeMsgLoadLocked(msgLoad []byte) error {
	err := p.RW.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err != nil {
		p.Disconnect(DiscNetworkError)
		return err
	}
	_, err = p.RW.Write(msgLoad)
	if err != nil {
		p.Disconnect(DiscNetworkError)
	}
	return err
}

func (p *Peer) WriteMsg(msg *Msg) error {
	p.wlock.Lock()
	defer p.wlock.Unlock()
	msgload := writeMsgload(msg, p.enc)
	return p.writeMsgLoadLocked(msgload)
}

func (p *Peer) WriteMsgLoad(msgLoad []byte) error {
	p.wlock.Lock()
	defer p.wlock.Unlock()
	load := make([]byte, len(msgLoad))
	copy(load, msgLoad)
	start := 4
	if consts.P2PNeedMAC {
		start += consts.P2PMacLen
	}
	if p.enc != nil {
		mod := (len(load) - start) % aes2.BlockSize
		if mod > 0 {
			load = append(load, pendZero[:aes2.BlockSize-mod]...)
		}
		p.enc.XORKeyStream(load[start:], load[start:])
	}

	return p.writeMsgLoadLocked(load)
}

func writeMsgload(msg *Msg, enc cipher.Stream) []byte {
	if msg == nil {
		return nil
	}

	var msgload []byte
	var hasher hash.Hash

	len := msg.LoadSize() + MsgTypeLength
	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len))

	mtb := msg.MsgType.Bytes()

	if consts.P2PNeedMAC {
		hasher = common.RealCipher.Hasher()
		msgload = make([]byte, consts.P2PMacLen)
		hasher.Write(msgLen)
		hasher.Write(mtb[:MsgTypeLength])
		hasher.Write(msg.Payload)
		h := hasher.Sum(nil)
		copy(msgload[:consts.P2PMacLen], h[:consts.P2PMacLen])
	}

	msgbuf := append(mtb[:MsgTypeLength], msg.Payload...)
	if enc != nil {
		mod := len % aes2.BlockSize
		if mod > 0 {
			msgbuf = append(msgbuf, pendZero[:aes2.BlockSize-mod]...)
		}
		enc.XORKeyStream(msgbuf, msgbuf)
	}

	msgload = append(msgload, msgLen...)
	msgload = append(msgload, msgbuf...)

	return msgload
}

func readMsgLoad(r io.Reader, dec cipher.Stream) (*Msg, error) {
	var mac, h []byte
	var hasher hash.Hash
	var err error
	if consts.P2PNeedMAC {
		mac = make([]byte, consts.P2PMacLen)
		_, err = io.ReadFull(r, mac)
		if err != nil {
			return nil, err
		}
		hasher = common.RealCipher.Hasher()
	}

	lenbytes := make([]byte, 4)
	_, err = io.ReadFull(r, lenbytes)
	if err != nil {
		// p.logger.Errorf("peer ReadMsgio.ReadFull lenbytes err %v,Peer Node[%s]", err, p.Node.String())
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenbytes)
	msgloadlen := msgLen
	if msgloadlen > 100000000 {
		return nil, DiscMsgTooLarge
	}
	if dec != nil {
		mod := msgloadlen % aes2.BlockSize
		if mod > 0 {
			msgloadlen = msgloadlen + aes2.BlockSize - mod
		}
	}

	msgload := make([]byte, msgloadlen)
	_, err = io.ReadFull(r, msgload)
	if err != nil {
		// p.logger.Errorf("peer ReadMsgio.ReadFull msgload err %v,Peer Node[%s]", err, p.Node.String())
		return nil, err
	}

	if len(msgload) < 3 {
		// p.logger.Errorf("peer ReadMsgio.ReadFull  DiscRequested err %v,Peer Node[%s]", err, p.Node.String())
		return nil, DiscRequested
	}
	if dec != nil {
		dec.XORKeyStream(msgload, msgload)
	}

	if consts.P2PNeedMAC {
		hasher.Write(lenbytes)
		hasher.Write(msgload[:MsgTypeLength])
		hasher.Write(msgload[MsgTypeLength:msgLen])
		h = hasher.Sum(nil)
		if !bytes.Equal(h[:consts.P2PMacLen], mac) {
			return nil, errors.New("bad MAC")
		}
	}

	msgType := toMsgType(msgload[:MsgTypeLength])
	msg := &Msg{
		MsgType:    msgType,
		Payload:    msgload[MsgTypeLength:msgLen],
		ReceivedAt: time.Now(),
	}
	return msg, nil
}

func (p *Peer) is(flag connFlag) bool {
	return p.flag&flag != 0
}

// 检查对端节点活性
func (p *Peer) PingLoop() {
	ping := time.NewTimer(pingInterval)
	defer func() {
		p.wg.Done()
		ping.Stop()
		if config.IsLogOn(config.NetDebugLog) {
			p.logger.Debugf("P2P peer PingLoop out %s", p)
		}
	}()
	for {
		select {
		case <-ping.C:
			if err := p.Ping(); err != nil {
				p.logger.Errorf("P2P ping peer %s error %v", p.ID, err)
				// p.protoErr <- err
				return
			}
			ping.Reset(pingInterval)
		case <-p.closed:
			return
		}
	}
}

func (p *Peer) Ping() error {
	return p.WriteMsg(PingMsg)
}

func (p *Peer) Pong() error {
	return p.WriteMsg(PongMsg)
}

func (p *Peer) Disconnect(reason DiscReason) {
	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

func (p *Peer) ReadLoop(readErrChan chan<- error) {
	defer func() {
		p.wg.Done()
		if config.IsLogOn(config.NetDebugLog) {
			p.logger.Debugf("P2P peer ReadLoop out %s", p)
		}
	}()
	for {
		select {
		case <-p.closed:
			return
		default:
			err := p.handleMsg()
			if err != nil {
				if r, ok := err.(DiscReason); ok {
					if r == DiscQuitting {
						return
					}
					if config.IsLogOn(config.NetDebugLog) {
						p.logger.Debugf("tcp DiscRequested err %v", r)
					}
					if r == DiscMsgTooLarge {
						readErrChan <- r
					} else {
						readErrChan <- DiscRequested
					}
				} else {
					if config.IsLogOn(config.NetDebugLog) {
						p.logger.Debugf("tcp readErrChan err %v", err)
					}
					readErrChan <- err
				}
				return
			}
		}
	}
}

func (p *Peer) handleMsg() error {
	msg, err := p.ReadMsg()
	if err != nil {
		return err
	}
	switch *msg.MsgType {
	case HandProofMsgType:
		// msg.Discard()
	case PingMsgType:
		// msg.Discard()
		go p.Pong()
	case PongMsgType:
		// msg.Discard()
	case DiscMsgType:
		var reason [1]DiscReason
		err = rtl.Unmarshal(msg.Payload, &reason)
		if err != nil {
			return DiscNetworkError
		}
		// msg.Discard()
		return reason[0]
	case EventMsgType:
		select {
		case p.MC <- msg:
		case <-p.closed:
			return DiscQuitting
		}
	default:
		p.logger.Errorf("handleMsg receive unknown msg type %v", msg.MsgType)
		// msg.Discard()
		return io.EOF
	}
	return nil
}

func (p *Peer) startProcessMsg(readErrChan chan<- error) {
	defer func() {
		p.wg.Done()
		if config.IsLogOn(config.NetDebugLog) {
			p.logger.Debugf("P2P startProcessMsg loop out peer %s", p)
		}
	}()
	for {
		select {
		case msg := <-p.MC:
			err := p.handleFun(p, msg)
			if err != nil {
				p.logger.Errorf("P2P handleFun msg error %v", err)
				readErrChan <- err
				return
			}
		case <-p.closed:
			return
		}
	}
}

func (p *Peer) Run() (err error) {
	var (
		readErrChan = make(chan error, 2)
		reason      DiscReason
	)

	p.wg.Add(3)
	go p.ReadLoop(readErrChan)
	go p.PingLoop()
	go p.startProcessMsg(readErrChan)

loop:
	for {
		select {
		case err = <-readErrChan:
			if r, ok := err.(DiscReason); ok {
				reason = r
			} else {
				reason = DiscNetworkError
			}
			break loop
		case err = <-p.protoErr:
			reason = discReasonForError(err)
			break loop
		case err = <-p.disc:
			reason = discReasonForError(err)
			break loop
		}
	}

	if config.IsLogOn(config.NetDebugLog) {
		p.logger.Debugf("stop run peer %s %v", p, reason)
	}

	close(p.closed)
	p.close(reason)
	p.wg.Wait()

	if config.IsLogOn(config.NetDebugLog) {
		p.logger.Debugf("stopped run peer %s %v", p, reason)
	}
	return
}

func (p *Peer) close(err error) {
	p.wlock.Lock()
	defer p.wlock.Unlock()
	SendReasonAndClose(p.RW, p.enc, err)
}
