package network

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/network/discover"
	log "github.com/sirupsen/logrus"
)

type CheckPermissionFunc func(cid common.ChainID, nid common.NodeID, ntt common.NetType, proof []byte) error

type dialErr struct {
	error
}

type Secrets struct {
	AES []byte
	MAC []byte
}

func (s *Secrets) String() string {
	if s == nil {
		return fmt.Sprint("Secrets{}")
	}
	return fmt.Sprintf("Secrets{AES:%x, MAC:%x}", s.AES[:5], s.MAC[:5])
}

type HandShakeReq struct {
	reqPub      []byte
	reqNonce    []byte
	reqRandPriv cipher.ECCPrivateKey
	reqRandPub  cipher.ECCPublicKey
	reqRandSig  []byte
}

type HandShakeRsp struct {
	respPub      []byte
	respNonce    []byte
	respRandPriv cipher.ECCPrivateKey
	respRandPub  cipher.ECCPublicKey
}

type HandShaker interface {
	//get handshake ChainID
	GetChainID() (common.ChainID, error)

	// hand shake with a node
	ShakeHandWith(node *discover.Node) (net.Conn, *Secrets, error)

	// verify the incoming node's proof
	VerifyPeerProof(net.Conn) (*discover.Node, common.ChainID, *Secrets, error)
}

type TcpHandShaker struct {
	self       *discover.Node
	version    uint64
	dialer     Dialer
	chainId    common.ChainID
	bootId     common.ChainID
	netType    common.NetType
	permission []byte
	logger     log.FieldLogger
	checkFunc  CheckPermissionFunc
}

func (s *TcpHandShaker) GetChainID() (common.ChainID, error) {
	return s.chainId, nil
}

func (s *TcpHandShaker) ShakeHandWith(node *discover.Node) (net.Conn, *Secrets, error) {
	proof, req, err := s.makeProof(node.PUB)
	if err != nil {
		return nil, nil, err
	}

	conn, err := s.dialer.Dial("tcp", node)
	if err != nil {
		return nil, nil, &dialErr{err}
	}

	msg := &Msg{MsgType: &HandProofMsgType, Payload: proof}
	proofload := writeMsgload(msg, nil)
	conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if _, err := conn.Write(proofload); err != nil {
		conn.Close()
		return nil, nil, err
	}

	resp, err := receiveHandShakeResponse(conn, node.ID)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	secret, err := makeSecrets(req, resp)

	return conn, secret, err
}

func (s *TcpHandShaker) VerifyPeerProof(con net.Conn) (*discover.Node, common.ChainID, *Secrets, error) {
	con.SetReadDeadline(time.Now().Add(handshakeTimeout))
	proofMsg, err := readMsgLoad(con, nil)
	if err != nil {
		return nil, common.NilChainID, nil, err
	}
	addr := con.RemoteAddr().(*net.TCPAddr)
	node, chainId, req, err := s.checkProof(proofMsg.Payload, addr)
	if err != nil {
		return nil, common.NilChainID, nil, err
	}

	resp, err := sendHandShakeResponse(con)
	if err != nil {
		return nil, common.NilChainID, nil, err
	}

	secret, err := makeSecrets(req, resp)

	return node, chainId, secret, err
}

// TODO Here abandon ingressMac and egressMac and remotePub
func makeSecrets(req *HandShakeReq, resp *HandShakeRsp) (*Secrets, error) {
	var err error
	var ecdheSecret []byte
	if req.reqRandPriv != nil {
		ecdheSecret, err = req.reqRandPriv.GenerateShared(resp.respRandPub, SECLen, MACLen)
	} else {
		ecdheSecret, err = resp.respRandPriv.GenerateShared(req.reqRandPub, SECLen, MACLen)
	}
	if err != nil {
		return nil, err
	}
	sharedSecret := common.SystemHash256(ecdheSecret, common.SystemHash256(resp.respNonce, req.reqNonce))
	aesSecret := common.SystemHash256(ecdheSecret, sharedSecret)
	macSecret := common.SystemHash256(ecdheSecret, aesSecret)

	sec := &Secrets{
		AES: aesSecret,
		MAC: macSecret,
	}
	return sec, nil
}

// send shake hand response
func sendHandShakeResponse(conn net.Conn) (*HandShakeRsp, error) {
	hashLen := SECLen + MACLen
	pubLen := common.RealCipher.LengthOfPublicKey()
	sigLen := common.RealCipher.LengthOfSignature()

	respNonce := make([]byte, hashLen)
	_, err := rand.Read(respNonce)
	if err != nil {
		return nil, err
	}
	randomPrivKey, err := common.RealCipher.GenerateKey()
	if err != nil {
		return nil, err
	}

	randPub := randomPrivKey.GetPublicKey()

	respData := make([]byte, hashLen+pubLen+sigLen)
	copy(respData[:hashLen], respNonce)
	copy(respData[hashLen:hashLen+pubLen], randPub.ToBytes())

	pub, sig, err := common.SignMsg(respData[:hashLen+pubLen])
	copy(respData[hashLen+pubLen:], sig)

	msg := &Msg{MsgType: &HandProofMsgType, Payload: respData}
	respload := writeMsgload(msg, nil)
	conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if _, err := conn.Write(respload); err != nil {
		return nil, err
	}

	resp := &HandShakeRsp{
		respPub:      pub,
		respNonce:    respNonce,
		respRandPriv: randomPrivKey,
		respRandPub:  randPub,
	}

	return resp, nil
}

func receiveHandShakeResponse(conn net.Conn, nid common.NodeID) (*HandShakeRsp, error) {
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	respMsg, err := readMsgLoad(conn, nil)
	if err != nil {
		return nil, err
	}
	pub := common.RealCipher.PubFromNodeId(nid[:])
	hashLen := SECLen + MACLen
	pubLen := common.RealCipher.LengthOfPublicKey()
	sigLen := common.RealCipher.LengthOfSignature()

	if *respMsg.MsgType != HandProofMsgType {
		return nil, dialErr{errors.New("invalid msg type received")}
	}
	if respMsg.LoadSize() != hashLen+pubLen+sigLen {
		return nil, dialErr{errors.New("invalid msg length received")}
	}
	sig := respMsg.Payload[hashLen+pubLen:]
	if !common.VerifyMsg(respMsg.Payload[:hashLen+pubLen], pub, sig) {
		return nil, dialErr{errors.New("invalid msg signature received")}
	}
	respNonce := respMsg.Payload[:hashLen]
	respRandPub, err := common.RealCipher.BytesToPub(respMsg.Payload[hashLen : hashLen+pubLen])
	if err != nil {
		return nil, dialErr{err}
	}

	resp := &HandShakeRsp{
		respPub:     pub,
		respNonce:   respNonce,
		respRandPub: respRandPub,
	}

	return resp, nil
}

func (s *TcpHandShaker) makeProof(remotePub []byte) ([]byte, *HandShakeReq, error) {
	pmsLen := len(s.permission)
	hasLen := SECLen + MACLen
	pubLen := common.RealCipher.LengthOfPublicKey()
	sigLen := common.RealCipher.LengthOfSignature()

	initNonce := make([]byte, hasLen)
	_, err := rand.Read(initNonce)
	if err != nil {
		return nil, nil, err
	}

	remote, err := common.RealCipher.BytesToPub(remotePub)
	if err != nil {
		return nil, nil, err
	}
	shared, err := common.SystemPrivKey.GenerateShared(remote, SECLen, MACLen)

	signed := xor(shared, initNonce)

	randPriv, err := common.RealCipher.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	randSig, err := common.RealCipher.Sign(randPriv.ToBytes(), signed)
	if err != nil {
		return nil, nil, err
	}
	randPub := randPriv.GetPublicKey()

	proof := make([]byte, common.NodeIDBytes+17+pmsLen+hasLen+pubLen+sigLen+sigLen)
	copy(proof[:common.NodeIDBytes], s.self.ID.Bytes())

	binary.BigEndian.PutUint32(proof[common.NodeIDBytes:common.NodeIDBytes+4], uint32(s.chainId))
	binary.BigEndian.PutUint32(proof[common.NodeIDBytes+4:common.NodeIDBytes+8], uint32(s.bootId))
	proof[common.NodeIDBytes+8] = byte(s.netType)
	binary.BigEndian.PutUint64(proof[common.NodeIDBytes+9:common.NodeIDBytes+17], s.version)
	if pmsLen > 0 {
		copy(proof[common.NodeIDBytes+17:common.NodeIDBytes+17+pmsLen], s.permission)
	}
	copy(proof[common.NodeIDBytes+17+pmsLen:common.NodeIDBytes+17+pmsLen+hasLen], initNonce)
	copy(proof[common.NodeIDBytes+17+pmsLen+hasLen:common.NodeIDBytes+17+pmsLen+hasLen+pubLen], randPub.ToBytes())
	copy(proof[common.NodeIDBytes+17+pmsLen+hasLen+pubLen:common.NodeIDBytes+17+pmsLen+hasLen+pubLen+sigLen], randSig)

	pub, sig, err := common.SignMsg(proof[:common.NodeIDBytes+17+pmsLen+hasLen+pubLen+sigLen])
	if err != nil {
		return nil, nil, errors.New("sign proof error")
	}
	copy(proof[common.NodeIDBytes+17+pmsLen+hasLen+pubLen+sigLen:], sig)

	req := &HandShakeReq{
		reqPub:      pub,
		reqNonce:    initNonce,
		reqRandPriv: randPriv,
		reqRandPub:  randPub,
		reqRandSig:  randSig,
	}

	return proof[:], req, nil
}

func (s *TcpHandShaker) checkProof(proofload []byte, addr *net.TCPAddr) (*discover.Node, common.ChainID, *HandShakeReq, error) {
	hasLen := SECLen + MACLen
	pubLen := common.RealCipher.LengthOfPublicKey()
	sigLen := common.RealCipher.LengthOfSignature()

	proofLen := len(proofload) - (common.NodeIDBytes + 17 + hasLen + pubLen + sigLen + sigLen)
	nid := common.BytesToNodeID(proofload[0:common.NodeIDBytes])

	pub := common.RealCipher.PubFromNodeId(nid[:])
	sig := proofload[common.NodeIDBytes+17+proofLen+hasLen+pubLen+sigLen:]
	if !common.VerifyMsg(proofload[:common.NodeIDBytes+17+proofLen+hasLen+pubLen+sigLen], pub, sig) {
		return nil, common.NilChainID, nil, DiscProtocolError
	}

	// ip := net.IP(proofload[64:80])
	// tcp := binary.BigEndian.Uint16(proofload[80:82])
	// udp := binary.BigEndian.Uint16(proofload[82:84])
	// rpc := binary.BigEndian.Uint16(proofload[84:86])
	cid := common.ChainID(binary.BigEndian.Uint32(proofload[common.NodeIDBytes : common.NodeIDBytes+4]))
	if s.netType == common.BasicNet || s.netType == common.ConsensusNet1 || s.netType == common.ConsensusNet2 {
		if s.chainId != cid {
			return nil, common.NilChainID, nil, DiscDifferentChain
		}
	}
	bid := common.ChainID(binary.BigEndian.Uint32(proofload[common.NodeIDBytes+4 : common.NodeIDBytes+8]))
	if bid != s.bootId {
		return nil, common.NilChainID, nil, DiscDifferentChain
	}
	ntt := common.NetType(proofload[common.NodeIDBytes+8])
	if ntt != s.netType {
		return nil, common.NilChainID, nil, DiscDifferentNet
	}
	vsn := binary.BigEndian.Uint64(proofload[common.NodeIDBytes+9 : common.NodeIDBytes+17])
	if vsn != s.version {
		return nil, common.NilChainID, nil, DiscIncompatibleVersion
	}

	proof := make([]byte, proofLen)
	copy(proof, proofload[common.NodeIDBytes+17:common.NodeIDBytes+17+proofLen])
	if err := s.checkFunc(cid, nid, ntt, proof); err != nil {
		s.logger.Errorf("check permission %d %s %s error %v", cid, ntt, nid, err)
		return nil, common.NilChainID, nil, DiscUnexpectedIdentity
	}

	initNonce := make([]byte, hasLen)
	copy(initNonce, proofload[common.NodeIDBytes+17+proofLen:common.NodeIDBytes+17+proofLen+hasLen])
	initPub, err := common.RealCipher.BytesToPub(pub)
	if err != nil {
		return nil, common.NilChainID, nil, err
	}

	shared, err := common.SystemPrivKey.GenerateShared(initPub, SECLen, MACLen)
	if err != nil {
		return nil, common.NilChainID, nil, err
	}

	token := xor(shared, initNonce)

	initRandPub := proofload[common.NodeIDBytes+17+proofLen+hasLen : common.NodeIDBytes+17+proofLen+hasLen+pubLen]
	initRandSig := proofload[common.NodeIDBytes+17+proofLen+hasLen+pubLen : common.NodeIDBytes+17+proofLen+hasLen+pubLen+sigLen]

	if !common.RealCipher.Verify(initRandPub, token, initRandSig) {
		s.logger.Errorf("check rand sig failed %d %s %s ", cid, ntt, nid)
		return nil, common.NilChainID, nil, DiscProtocolError
	}

	reqRandPub, err := common.RealCipher.BytesToPub(initRandPub)
	if err != nil {
		s.logger.Errorf("check rand pub failed %d %s %s ", cid, ntt, nid)
		return nil, common.NilChainID, nil, DiscProtocolError
	}

	req := &HandShakeReq{
		reqPub:     pub,
		reqNonce:   initNonce,
		reqRandPub: reqRandPub,
		reqRandSig: initRandSig,
	}

	return discover.NewNode(nid, addr.IP, uint16(addr.Port), 0, 0), cid, req, nil
}

func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}
