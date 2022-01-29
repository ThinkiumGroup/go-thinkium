package rpcserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/dao"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
	"github.com/stephenfire/go-rtl"
	"google.golang.org/grpc"
)

func init() {
	dao.TryRpcGetBlock = _tryRpcGetBlock
	dao.RpcReplayBlock = _rpcReplayBlock
	dao.RpcGetRRProof = _rpcGetRRProof
}

func _grpcDial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	conn, err := grpc.Dial(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %v", target, err)
	}
	return conn, nil
}

func _tryRpcGetBlock(chain models.DataHolder, h common.Height) (ret *models.BlockEMessage, err error) {
	mi, ok := chain.GetChainInfo()
	if !ok {
		return nil, errors.New("chain info not found")
	}
	defer func() {
		if config.IsLogOn(config.NetDebugLog) {
			log.Debugf("_tryRpcGetBlock block: %s err: %v", ret, err)
		}
	}()
	var dataNodeConns *grpc.ClientConn
	dataNodeConns, err = _grpcDial(mi.BootNodes[0].GetRpcAddr(), grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = dataNodeConns.Close()
	}()
	rpcClient := NewNodeClient(dataNodeConns)

	req := &RpcBlockHeight{
		Chainid: uint32(mi.ID),
		Height:  uint64(h),
	}

	res, err := rpcClient.GetBlock(context.Background(), req)
	// log.Debugf("[rpc] GetBlock(), res=%+v, err=%v", res, err)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, errors.New("remote block not found")
	}
	block := new(models.BlockEMessage)
	err = rtl.Unmarshal(res.Stream, block)
	return block, err
}

func _rpcReplayBlock(target string, request *models.SyncRequest, holder models.DataHolder, end common.Height,
	logger logrus.FieldLogger) {
	rpcConn, err := _grpcDial(target, grpc.WithInsecure())
	if err != nil {
		log.MustErrorf(logger, "[REPLAY] %s", err)
		return
	}
	defer func() {
		_ = rpcConn.Close()
	}()
	rpcClient := NewNodeClient(rpcConn)

	for i := request.StartHeight; i <= end; i++ {
		block, err := holder.GetBlock(i)
		if err != nil || block == nil {
			log.MustErrorf(logger, "[REPLAY] missing block %d", i)
			continue
		}

		if config.IsLogOn(config.DataDebugLog) {
			log.MustDebugf(logger, "[REPLAY] send a block %d %x to full node %s", i,
				block.Hash().Bytes()[:5], request.NodeID)
		}

		bm, err := rtl.Marshal(block)
		if err != nil {
			log.MustErrorf(logger, "[REPLAY] marshal block %d error %v", i, err)
			break
		}
		req := &RpcMsgReq{
			Type: 0,
			Msg:  bm,
		}

		resp, err := rpcClient.SendBlock(context.Background(), req)
		if err != nil || resp.Code != SuccessCode {
			log.MustErrorf(logger, "[REPLAY] rpc send block %d error %v", i, err)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func _rpcGetRRProof(rewardChainInfo *common.ChainInfos, rrRoot []byte, logger logrus.FieldLogger) (*models.RRProofs, error) {
	rpcTarget := rewardChainInfo.BootNodes[0].GetRpcAddr()
	rpcConn, err := _grpcDial(rpcTarget, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpcConn.Close()
	}()
	rpcClient := NewNodeClient(rpcConn)

	req := &RpcRRProofReq{
		ChainId:  uint32(rewardChainInfo.ID),
		RootHash: rrRoot,
		NodeHash: common.SystemNodeID.Hash().Bytes(),
	}
	pub, sig, err := common.SignMsg(req)
	if err != nil {
		return nil, fmt.Errorf("sign %s failed: %v", req, err)
	}
	req.Pub = pub
	req.Sig = sig
	resp, err := rpcClient.GetRRProofs(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("rpc GetRRProofs failed: %v", err)
	} else if resp.Code != SuccessCode {
		log.MustErrorf(logger, "rpc GetRRProofs(root:%x, NIDH:%x) failed, Code:%d %s", common.ForPrint(rrRoot),
			req.NodeHash[:5], resp.Code, resp.Data)
		return nil, nil
	} else {
		prf := &models.RRProofs{}
		bs, err := hex.DecodeString(resp.Data)
		if err != nil {
			return nil, fmt.Errorf("decode response data failed: %v", err)
		}
		if err := rtl.Unmarshal(bs, prf); err != nil {
			return nil, fmt.Errorf("unmarshal proofs data failed: %v", err)
		} else {
			return prf, nil
		}
	}
}
