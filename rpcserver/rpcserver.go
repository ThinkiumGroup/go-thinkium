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

package rpcserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/consts"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
	"github.com/stephenfire/go-rtl"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type RPCServer struct {
	common.AbstractService

	local    common.Endpoint
	listener net.Listener
	nmanager models.NetworkManager
	dmanager models.DataManager
	engine   models.Engine
	eventer  models.Eventer
	logger   logrus.FieldLogger

	UnimplementedNodeServer
}

func NewRPCServer(local common.Endpoint, nmanager models.NetworkManager, dmanager models.DataManager, engine models.Engine,
	eventer models.Eventer) (*RPCServer, error) {
	server := &RPCServer{
		local:    local,
		nmanager: nmanager,
		dmanager: dmanager,
		engine:   engine,
		eventer:  eventer,
		logger:   log.WithField("L", "RPCServer"),
	}
	server.SetChanger(server)

	return server, nil
}

func (s *RPCServer) String() string {
	return "RPC@" + s.local.String()
}

func (s *RPCServer) Initializer() error {
	if s.local.IsNil() {
		return errors.New("empty server endpoint setting for RPC Server")
	}
	s.logger.Debug("[RPCServer] initialized")
	return nil
}

func (s *RPCServer) Starter() error {
	l, err := net.Listen(s.local.NetType, s.local.Address)
	if err != nil {
		return err
	}
	s.listener = l
	srv := grpc.NewServer()
	RegisterNodeServer(srv, s)
	reflection.Register(srv)
	go func() {
		if err := srv.Serve(s.listener); err != nil {
			s.logger.Errorf("[RPCServer] failed to serve: %v", err)
		}
		s.logger.Debug("[RPCServer] serve stoped")
	}()

	s.logger.Debugf("[RPCServer] started @ %s", s.local)
	return nil
}

func (s *RPCServer) Closer() error {
	if err := s.listener.Close(); err != nil {
		s.logger.Errorf("[RPCServer] closing rpc server listener error: %v", err)
	}
	s.logger.Debug("[RPCServer] closed")
	return nil
}

func newResponse(code int32, msg ...string) *RpcResponse {
	if len(msg) == 0 || len(msg[0]) == 0 {
		return &RpcResponse{Code: code, Data: RpcErrMsgMap[code]}
	} else {
		return &RpcResponse{Code: code, Data: msg[0]}
	}
}

func (s *RPCServer) Ping(ctx context.Context, req *RpcRequest) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	ni := NodeInfo{
		NodeId:        common.SystemNodeID,
		Version:       consts.Version,
		IsDataNode:    s.dmanager.IsDataNode(),
		DataNodeOf:    s.dmanager.DataNodeOf(),
		LastMsgTime:   common.LastMsgTime,
		LastEventTime: common.LastEventTime,
		LastBlockTime: common.LastBlockTime,
		LastBlocks:    common.LastBlocks.CopyMap(),
		Overflow:      common.Overflow,
		OpTypes:       s.eventer.GetNodeOpTypes(),
	}
	if jsons, err := json.Marshal(ni); err != nil {
		s.logger.Error("[RPCServer] Marshal NodeInfo error,", err.Error())
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetAccount return resp.data as models.Account in JSON format
func (s *RPCServer) GetAccount(ctx context.Context, addr *RpcAddress) (*RpcResponse, error) {
	if addr == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	if len(addr.Address) != common.AddressLength {
		return newResponse(InvalidParamsCode, "invalid address"), nil
	}
	chainId := common.ChainID(addr.Chainid)
	comaddr := common.BytesToAddress(addr.Address)

	cdata, err := s.dmanager.GetChainData(chainId)
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}

	var code []byte
	acc, _ := cdata.GetAccount(&comaddr)
	// acc, ok := s.dmanager.GetAccount(&comaddr, chainId)
	// if !ok {
	if acc == nil {
		acc = models.NewAccount(comaddr, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}

	ach := &AccountWithCode{
		Addr:            acc.Addr,
		Nonce:           acc.Nonce,
		Balance:         acc.Balance,
		LocalCurrency:   acc.LocalCurrency,
		StorageRoot:     acc.StorageRoot,
		CodeHash:        acc.CodeHash,
		LongStorageRoot: acc.LongStorageRoot,
		Code:            code,
	}
	if jsons, err := json.Marshal(ach); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetAccountWithChainHeight Get account information and current chain height
func (s *RPCServer) GetAccountWithChainHeight(ctx context.Context, addr *RpcAddress) (*RpcResponse, error) {
	if addr == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	if len(addr.Address) != common.AddressLength {
		return newResponse(InvalidParamsCode, "invalid address"), nil
	}
	chainId := common.ChainID(addr.Chainid)
	comaddr := common.BytesToAddress(addr.Address)

	cdata, err := s.dmanager.GetChainData(chainId)
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}

	var code []byte
	acc, _ := cdata.GetAccount(&comaddr)
	// acc, ok := s.dmanager.GetAccount(&comaddr, chainId)
	// if !ok {
	if acc == nil {
		acc = models.NewAccount(comaddr, nil)
	} else {
		if acc.IsUserContract() {
			code = cdata.GetCodeByHash(common.BytesToHash(acc.CodeHash))
		}
	}

	ach := &AccountHeight{
		Height:          cdata.GetCurrentHeight(),
		Addr:            acc.Addr,
		Nonce:           acc.Nonce,
		Balance:         acc.Balance,
		LocalCurrency:   acc.LocalCurrency,
		StorageRoot:     acc.StorageRoot,
		CodeHash:        acc.CodeHash,
		LongStorageRoot: acc.LongStorageRoot,
		Code:            code,
	}
	if jsons, err := json.Marshal(ach); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func deltaFromToAccountChange(header *models.BlockHeader, key models.DeltaFromKey, delta *models.AccountDelta) *AccountChange {
	if delta == nil {
		return nil
	}
	return &AccountChange{
		ChainID:   key.ShardID,
		Height:    key.Height,
		From:      nil,
		To:        &delta.Addr,
		Nonce:     0,
		Val:       delta.Delta,
		TimeStamp: header.TimeStamp,
	}
}

func txToAccountChange(header *models.BlockHeader, height common.Height, tx *models.Transaction) *AccountChange {
	if tx == nil {
		return nil
	}
	return &AccountChange{
		ChainID:   tx.ChainID,
		Height:    height,
		From:      tx.From,
		To:        tx.To,
		Nonce:     tx.Nonce,
		Val:       tx.Val,
		Input:     tx.Input,
		UseLocal:  tx.UseLocal,
		Extra:     tx.Extra,
		TimeStamp: header.TimeStamp,
		Version:   tx.Version,
	}
}

func checkRpcTx(tx *RpcTx, verifySig bool) (txmsg *models.Transaction, resp *RpcResponse) {

	var err error
	txmsg, err = tx.ToTx()
	if err != nil {
		return nil, newResponse(InvalidParamsCode, err.Error())
	}
	if txmsg.ChainID.IsMain() {
		// Only system contracts can be called on the main chain
		if txmsg.To == nil || !txmsg.To.IsSystemContract() {
			return nil, newResponse(InvalidBCCode)
		}
	}
	if txmsg.From != nil && txmsg.From.IsReserved() {
		return nil, newResponse(ReservedFromAddrErrCode)
	}
	if len(txmsg.Input) == 0 && (txmsg.Val == nil || txmsg.Val.Sign() == 0) {
		return nil, newResponse(InvalidParamsCode, "invalid transfer value")
	}
	if verifySig {
		if txmsg.From == nil {
			return nil, newResponse(InvalidParamsCode, "no from address")
		}
		address, err := common.AddressFromPubSlice(tx.Pub)
		if err != nil {
			return nil, newResponse(InvalidPublicKey, err.Error())
		}
		if !bytes.Equal(txmsg.From.Slice(), address[:]) {
			return nil, newResponse(InvalidPublicKey, "signature not match with from address")
		}
		hoe, err := common.HashObject(txmsg)
		if err != nil {
			return nil, newResponse(HashObjectErrCode, err.Error())
		}
		if v := common.VerifyHash(hoe, tx.Pub, tx.Sig); !v {
			return nil, newResponse(InvalidSignatureCode)
		}
		// verify multi signaturesa
		if len(txmsg.MultiSigs) > 0 {
			for i, pas := range txmsg.MultiSigs {
				if pas == nil {
					return nil, newResponse(InvalidMultiSigsCode, fmt.Sprintf("nil pas found at index %d", i))
				}
				if !common.VerifyHash(hoe, pas.PublicKey, pas.Signature) {
					return nil, newResponse(InvalidMultiSigsCode, fmt.Sprintf("signature verify failed at index %d", i))
				}
			}
		}
	}
	return txmsg, nil

	// if tx == nil {
	// 	return nil, nil, newResponse(InvalidParamsCode, "nil tx")
	// }
	// if tx.From == nil || len(tx.From.Address) != common.AddressLength {
	// 	return nil, nil, newResponse(InvalidParamsCode, "illegal from address")
	// }
	// if len(tx.Multipubs) != len(tx.Multisigs) {
	// 	return nil, nil, newResponse(InvalidParamsCode, "multipubs and multisigs not match")
	// }
	//
	// if tx.Chainid == uint32(common.MainChainID) {
	// 	// Only system contracts can be called on the main chain
	// 	if tx.To == nil || len(tx.To.Address) == 0 || !common.BytesToAddress(tx.To.Address).IsSystemContract() {
	// 		return nil, nil, newResponse(InvalidBCCode)
	// 	}
	// }
	//
	// from := common.Address{}
	// copy(from[:], tx.From.Address)
	// if from.IsReserved() {
	// 	return nil, nil, newResponse(ReservedFromAddrErrCode)
	// }
	// var pto *common.Address = nil
	// if tx.To != nil && len(tx.To.Address) > 0 {
	// 	to := common.Address{}
	// 	copy(to[:], tx.To.Address)
	// 	pto = &to
	// }
	//
	// val, ok := math.ParseBig256(tx.Val)
	// if !ok || (len(tx.Input) == 0 && val.Sign() == 0) {
	// 	return nil, nil, newResponse(InvalidParamsCode, "invalid value")
	// }
	//
	// var msigs models.PubAndSigs
	// if len(tx.Multisigs) > 0 {
	// 	msigs = make(models.PubAndSigs, len(tx.Multisigs))
	// 	for i := 0; i < len(tx.Multisigs); i++ {
	// 		if len(tx.Multisigs[i]) == 0 || len(tx.Multipubs[i]) == 0 {
	// 			return nil, nil, newResponse(InvalidMultiSigsCode)
	// 		}
	// 		if !common.VerifyHash(hoe, tx.Multipubs[i], tx.Multisigs[i]) {
	// 			return nil, nil, newResponse(InvalidMultiSigsCode)
	// 		}
	// 		msigs[i] = &models.PubAndSig{PublicKey: tx.Multipubs[i], Signature: tx.Multisigs[i]}
	// 	}
	// }
	//
	// txmsg = &models.Transaction{
	// 	ChainID:  common.ChainID(tx.Chainid),
	// 	From:     &from,
	// 	To:       pto,
	// 	Nonce:    tx.Nonce,
	// 	Val:      val,
	// 	Input:    tx.Input,
	// 	UseLocal: tx.Uselocal,
	// 	// Extra:     tx.Extra,
	// 	MultiSigs: msigs,
	// 	Version:   models.TxVersion,
	// }
	//
	// {
	// 	// generate tx.extra
	// 	if len(tx.Sig) == 65 || len(tx.Extra) > 0 {
	// 		extras := &models.Extra{Type: models.LegacyTxType}
	// 		if len(tx.Sig) == 65 {
	// 			r, s, v := models.DecodeSignature(tx.Sig)
	// 			extras.R = r
	// 			extras.S = s
	// 			extras.V = v
	// 		}
	// 		if err := txmsg.SetExtraKeys(extras); err != nil {
	// 			return nil, nil, newResponse(InvalidParamsCode, err.Error())
	// 		}
	// 		if len(tx.Extra) > 0 {
	// 			if err := txmsg.SetTkmExtra(tx.Extra); err != nil {
	// 				return nil, nil, newResponse(InvalidParamsCode, err.Error())
	// 			}
	// 		}
	// 	}
	// }
	// if len(tx.Sig) == 65 {
	// 	r, s, v := models.DecodeSignature(tx.Sig)
	// 	extra := &models.Extra{
	// 		Type: 0,
	// 		V:    v,
	// 		R:    r,
	// 		S:    s,
	// 	}
	// 	var txextramap1 map[string]interface{}
	// 	if tx.Extra == nil {
	// 		tx.Extra, _ = json.Marshal(extra)
	// 	} else {
	// 		if err := json.Unmarshal(tx.Extra, &txextramap1); err != nil {
	// 			return nil, nil, newResponse(InvalidParamsCode, "invalid value")
	// 		}
	// 		if gas, ok := txextramap1["gas"]; ok {
	// 			extra.Gas = uint64(gas.(float64))
	// 		}
	// 		extra.TkmExtra = txextramap1
	// 		extrab, err := json.Marshal(extra)
	// 		if err != nil {
	// 			return nil, nil, newResponse(InvalidParamsCode, "invalid value")
	// 		}
	// 		tx.Extra = extrab
	// 	}
	// }
	//
	// if verifySig {
	// 	address, err := common.AddressFromPubSlice(tx.Pub)
	// 	if err != nil {
	// 		return nil, nil, newResponse(InvalidPublicKey, err.Error())
	// 	}
	// 	if !bytes.Equal(tx.From.Address[:], address.Bytes()) {
	// 		return nil, nil, newResponse(InvalidPublicKey)
	// 	}
	// 	hoe, err = common.HashObject(txmsg)
	// 	if err != nil {
	// 		return nil, nil, newResponse(HashObjectErrCode, err.Error())
	// 	}
	//
	// 	if v := common.VerifyHash(hoe, tx.Pub, tx.Sig); !v {
	// 		return nil, nil, newResponse(InvalidSignatureCode)
	// 	}
	// }
	// return hoe, txmsg, nil
}

// CallTransaction return resp.data as TransactionReceipt in JSON format
func (s *RPCServer) CallTransaction(ctx context.Context, tx *RpcTx) (*RpcResponse, error) {
	chainData, err := s.dmanager.GetChainData(common.ChainID(tx.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	txmsg, resp := checkRpcTx(tx, false)
	if resp != nil {
		return resp, nil
	}
	if txmsg.To == nil {
		return newResponse(InvalidParamsCode, "illegal to address"), nil
	}
	if len(txmsg.Input) == 0 {
		return newResponse(InvalidParamsCode, "no input found"), nil
	}
	bc := chainData.GetBlockChain()
	if bc == nil {
		return newResponse(InvalidBCCode), nil
	}
	if bc.CurrentBlock() == nil {
		return newResponse(NilBlockCode), nil
	}
	rec, err := chainData.CallProcessTx(txmsg, &models.PubAndSig{PublicKey: tx.Pub, Signature: tx.Sig}, bc.CurrentBlock().BlockHeader)
	if err != nil {
		return newResponse(CallProcessTxErrCode, err.Error()), nil
	}
	receipt := rec.(*models.Receipt)

	// result := TransactionReceipt{
	// 	Transaction: *txmsg, PostState: receipt.PostState, Status: receipt.Status,
	// 	Logs: receipt.Logs, TxHash: receipt.TxHash, ContractAddress: receipt.ContractAddress,
	// 	Out: receipt.Out, Error: receipt.Error}
	result := new(TransactionReceipt).PartReceipt(txmsg, receipt)
	if jsons, err := json.Marshal(result); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetTransactionByHash return resp.data as TransactionReceipt in JSON format
func (s *RPCServer) GetTransactionByHash(ctx context.Context, txs *RpcTXHash) (*RpcResponse, error) {
	if txs == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	chainData, err := s.dmanager.GetChainData(common.ChainID(txs.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	hash := common.Hash{}
	hash.SetBytes(txs.Hash)
	bc := chainData.GetBlockChain()
	if bc == nil {
		return newResponse(InvalidBCCode), nil
	}
	txI, err := bc.GetBlockTxIndexs(hash[:])

	if err != nil || txI == nil {
		// s.logger.Errorf("[RPCServer] GetTransactionByHash error: %s", RpcErrMsgMap[NilTransactionCode])
		return newResponse(NilTransactionCode), nil
	}
	block, err := bc.GetBlockByHash(txI.BlockHash[:])
	if err != nil {
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil {
		return newResponse(NilBlockCode), nil
	}

	if block.BlockHeader == nil || block.BlockBody == nil {
		// s.logger.Error("[RPCServer] GetTransactionByHash -> block.BlockBody: ", RpcErrMsgMap[NilTransactionCode])
		return newResponse(NilBlockCode), nil
	}
	if int(txI.Index) < 0 || int(txI.Index) >= len(block.BlockBody.Txs) {
		// s.logger.Error("[RPCServer] GetTransactionByHash -> txI.Index: ", RpcErrMsgMap[NilTransactionCode])
		return newResponse(NilTransactionCode), nil
	}
	transaction := block.BlockBody.Txs[txI.Index]

	var receipt *models.Receipt
	if block.BlockHeader.ReceiptRoot != nil && !block.BlockHeader.ReceiptRoot.SliceEqual(common.NilHashSlice) {
		receiptHash := *(block.BlockHeader.ReceiptRoot)

		receipts := models.ReadReceipts(chainData.GetDb(), receiptHash)
		receipt, err = models.ReadReceipt(receipts, (int)(txI.Index))
		if err != nil {
			s.logger.Error("[RPCServer] GetTransactionByHash ReadReceipt error:", err.Error())
			return newResponse(ReadReceiptErrCode, err.Error()), nil
		}
	}
	if receipt == nil {
		return newResponse(ReadReceiptErrCode), nil
	}
	// result := TransactionReceipt{
	// 	Transaction: *transaction, PostState: receipt.PostState, Status: receipt.Status,
	// 	Logs: receipt.Logs, TxHash: receipt.TxHash, ContractAddress: receipt.ContractAddress,
	// 	Out: receipt.Out, Height: block.GetHeight(), GasUsed: receipt.GasUsed, GasFee: receipt.GasFeeString(),
	// 	PostRoot: receipt.GetPostRoot(), Error: receipt.Error}
	result := new(TransactionReceipt).FullReceipt(transaction, block.GetHeight(), receipt)
	if jsons, err := json.Marshal(result); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetTransactions return resp.data as []models.Transaction in JSON format
func (s *RPCServer) GetTransactions(ctx context.Context, txs *RpcTxList) (*RpcResponse, error) {
	if txs == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	chainData, err := s.dmanager.GetChainData(common.ChainID(txs.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	changes := make([]*AccountChange, 0)
	targetAddr := common.BytesToAddress(txs.Address.Address)
	for h := txs.StartHeight; h < txs.EndHeight; h++ {
		height := common.Height(h)
		block, err := chainData.GetBlock(common.Height(h))
		if err != nil || block == nil || block.BlockBody == nil {
			if err != nil {
				s.logger.Error("[RPCServer] get block(chainid=%d, height=%d) error: %v", txs.Chainid, h, err)
				return newResponse(NilBlockCode, err.Error()), nil
			} else {
				s.logger.Warnf("[RPCServer] get block(chainid=%d, height=%d) body nil", txs.Chainid, h)
				break
			}
		} else {
			if config.IsLogOn(config.DataDebugLog) {
				s.logger.Debugf("[RPCServer] get block (chainid=%d,height=%d) DeltaFroms(%d) txs(%d)", block.BlockHeader.ChainID,
					block.BlockHeader.Height, len(block.BlockBody.DeltaFroms), len(block.BlockBody.Txs))
			}
			// DeltaFroms
			for i := 0; i < len(block.BlockBody.DeltaFroms); i++ {
				for j := 0; j < len(block.BlockBody.DeltaFroms[i].Deltas); j++ {
					if block.BlockBody.DeltaFroms[i].Deltas[j] == nil {
						continue
					}
					if block.BlockBody.DeltaFroms[i].Deltas[j].Addr == targetAddr {
						change := deltaFromToAccountChange(block.BlockHeader, block.BlockBody.DeltaFroms[i].Key,
							block.BlockBody.DeltaFroms[i].Deltas[j])
						if change != nil {
							changes = append(changes, change)
						}
					}
				}
			}

			// Txs
			for i := 0; i < len(block.BlockBody.Txs); i++ {
				if block.BlockBody.Txs[i] == nil {
					continue
				}

				if *(block.BlockBody.Txs[i].From) == targetAddr ||
					(block.BlockBody.Txs[i].To != nil && *(block.BlockBody.Txs[i].To) == targetAddr) {
					change := txToAccountChange(block.BlockHeader, height, block.BlockBody.Txs[i])
					if change != nil {
						changes = append(changes, change)
					}
				}
			}
		}
	}

	if jsons, err := json.Marshal(changes); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// SendTx return resp.data as returned information
func (s *RPCServer) SendTx(ctx context.Context, tx *RpcTx) (*RpcResponse, error) {

	txmsg, resp := checkRpcTx(tx, true)
	if resp != nil {
		return resp, nil
	}

	cid := txmsg.ChainID

	var acc *models.Account
	var exist bool
	cdata, err := s.dmanager.GetChainData(cid)
	if err == nil {
		acc, exist = cdata.GetAccount(txmsg.From)
	}
	// acc, exist := s.dmanager.GetAccount(txmsg.From, cid)
	if !exist && ((txmsg.Val != nil && txmsg.Val.Sign() > 0) || len(txmsg.Input) == 0) {
		// The from account does not exist, transfer transactions, or contract calls with amounts
		// are prohibited
		return newResponse(InvalidFromAddressCode), nil
	}
	if acc == nil {
		acc = models.NewAccount(*txmsg.From, nil)
	}
	if acc.Nonce > txmsg.Nonce {
		return newResponse(InvalidParamsCode, "invalid nonce"), nil
	}

	if s.dmanager.IsDataNodeOf(txmsg.ChainID) || (s.dmanager.IsMemoNode() && *common.ForChain == txmsg.ChainID) {
		if config.IsLogOn(config.DataDebugLog) {
			s.logger.Debugf("[RPCServer] receive to queue: %s", txmsg)
		}
		// If the local node is the data node of the target chain, TX will be directly put into the queue
		if err := s.eventer.PostEvent(txmsg, tx.Pub, tx.Sig); err != nil {
			return newResponse(PostEventErrCode, err.Error()), nil
		}
	} else {
		// In order to prevent attacks, transaction forwarding of other chains is not supported
		if config.IsLogOn(config.DataDebugLog) {
			s.logger.Debugf("[RPCServer] not a local tx, ignored")
		}
		// // If it is a node of other types, TX will be broadcasted to the basic network of the main chain
		// relay := &models.RelayEventMsg{
		// 	RType:     models.RelayBroadcast,
		// 	ToChainID: common.MainChainID,
		// 	ToNetType: common.BasicNet,
		// 	Msg:       reshashmsg,
		// 	Pub:       tx.Pub,
		// 	Sig:       tx.Sig,
		// }
		// if config.IsLogOn(config.DataDebugLog) {
		// 	log.Debugf("[RPCServer] receive to relay: %s, %s", reshashmsg, relay)
		// }
		// s.eventer.Post(relay)
	}
	// hs := common.BytesToHash(hashOfEvent)
	hs := txmsg.Hash()
	return &RpcResponse{Code: SuccessCode, Data: hs.Hex()}, nil
}

func (s *RPCServer) GetStats(ctx context.Context, req *RpcStatsReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	reqChainID := common.ChainID(req.Chainid)
	stats, err := s.dmanager.GetChainStats(reqChainID)
	if err != nil {
		return newResponse(InvalidParamsCode, err.Error()), nil
	}
	comm, err := s.engine.ChainComm(reqChainID)
	if err == nil && comm != nil {
		stats.CurrentComm = comm.Members
	}
	if jsons, err := json.Marshal(stats); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

func headerToBlockInfo(header *models.BlockHeader) *BlockInfo {
	if header == nil {
		return nil
	}
	return &BlockInfo{
		Hash:             header.Hash(),
		PreviousHash:     header.PreviousHash,
		ChainID:          header.ChainID,
		Height:           header.Height,
		Empty:            header.Empty,
		RewardAddress:    header.RewardAddress,
		MergedDeltaRoot:  header.MergedDeltaRoot,
		BalanceDeltaRoot: header.BalanceDeltaRoot,
		StateRoot:        header.StateRoot,
		RREra:            header.RREra,
		RRCurrent:        header.RRRoot,
		RRNext:           header.RRNextRoot,
		TxCount:          0,
		TimeStamp:        header.TimeStamp,
	}
}

func summaryToBlockInfo(header *models.BlockSummary) *BlockInfo {
	if header == nil {
		return nil
	}

	return &BlockInfo{
		Hash:    header.Hash(),
		ChainID: header.ChainId,
		Height:  header.Height,
	}
}

func (s *RPCServer) GetBlockHeader(ctx context.Context, req *RpcBlockHeight) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock %d Error:", common.Height(req.Height), err.Error())
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil || block.BlockHeader == nil {
		return newResponse(NilBlockCode), nil
	}
	info := headerToBlockInfo(block.BlockHeader)
	if block.BlockBody != nil {
		info.TxCount = len(block.BlockBody.NCMsg) + len(block.BlockBody.Txs)
	}
	if jsons, err := json.Marshal(info); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// Returns the serialized bytes of block data of the specified height (not JSON)
func (s *RPCServer) GetBlock(ctx context.Context, req *RpcBlockHeight) (*RpcRespondStream, error) {
	if req == nil {
		return &RpcRespondStream{Code: InvalidParamsCode, Msg: "nil request"}, nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return &RpcRespondStream{Code: GetChainDataErrCode, Msg: err.Error()}, nil
	}
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock %d Error:", common.Height(req.Height), err.Error())
		return &RpcRespondStream{Code: NilBlockCode, Msg: err.Error()}, nil
	}
	if block == nil {
		return &RpcRespondStream{Code: NilBlockCode, Msg: RpcErrMsgMap[NilBlockCode]}, nil
	}

	bs, err := rtl.Marshal(block)
	if err != nil {
		return &RpcRespondStream{Code: MarshalErrCode, Msg: err.Error()}, nil
	}
	return &RpcRespondStream{Code: SuccessCode, Stream: bs}, nil
}

// Returns the sub chain block header information (block hash, Chain ID, block height) contained
// in the specified block
func (s *RPCServer) GetBlockHeaders(ctx context.Context, req *RpcBlockHeight) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock(ChainID:%d, Height:%d) Error: %v", req.Chainid, req.Height, err)
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil || block.BlockBody == nil {
		return newResponse(NilTransactionCode), nil
	}
	var ret []*BlockInfo
	for _, hd := range block.BlockBody.Hds {
		info := summaryToBlockInfo(hd)
		// info.TxCount = len(block.BlockBody.NCMsg) + len(block.BlockBody.Txs)
		ret = append(ret, info)
	}
	if jsons, err := json.Marshal(ret); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// Returns multiple transactions in the specified location (page+size) of the specified
// block (chainid+height), and the return value is []*ElectMessage+[]*AccountChange
func (s *RPCServer) GetBlockTxs(ctx context.Context, req *RpcBlockTxsReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	height := common.Height(req.Height)
	block, err := cdata.GetBlock(common.Height(req.Height))
	if err != nil {
		s.logger.Errorf("[RPCServer] GetBlock %d Error:", common.Height(req.Height), err.Error())
		return newResponse(NilBlockCode, err.Error()), nil
	}
	if block == nil || block.BlockBody == nil {
		return newResponse(NilBlockCode), nil
	}

	page := req.Page - 1
	if page < 0 {
		page = 0
	}
	size := req.Size
	if size < 0 {
		size = 10
	}
	start := page * size
	end := start + size

	messages := &BlockMessage{}
	if req.Chainid == uint32(common.MainChainID) {
		elections := make([]*models.ElectMessage, 0)
		elength := int32(len(block.BlockBody.NCMsg))
		if start < elength {
			for i := start; i < elength && i < end; i++ {
				if block.BlockBody.NCMsg[i] == nil {
					continue
				}
				elections = append(elections, block.BlockBody.NCMsg[i])
			}
		}
		messages.Elections = elections
	}
	changes := make([]*AccountChange, 0)
	length := int32(len(block.BlockBody.Txs))
	if start < length {
		for i := start; i < length && i < end; i++ {
			if block.BlockBody.Txs[i] == nil {
				continue
			}
			changes = append(changes, txToAccountChange(block.BlockHeader, height, block.BlockBody.Txs[i]))
		}
	}
	messages.AccountChanges = changes
	if jsons, err := json.Marshal(messages); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetChainInfo Returns the chain information of the specified chain ID, which can be multiple. Return all
// when not specified
func (s *RPCServer) GetChainInfo(ctx context.Context, req *RpcChainInfoReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cids := req.Chainid
	if len(cids) == 0 {
		// When there is no input, it means to get all chain information
		cl := s.dmanager.GetChainList()
		for i := 0; i < len(cl); i++ {
			cids = append(cids, uint32(cl[i]))
		}
	}

	// De-duplication
	cidMap := make(map[uint32]struct{})
	for _, cid := range cids {
		cidMap[cid] = struct{}{}
	}
	infoMap := make(map[uint32]*ChainInfo)
	for cid, _ := range cidMap {
		info, exist := s.dmanager.GetChainInfos(common.ChainID(cid))
		if !exist {
			continue
		}
		var datanodes []DataNodeInfo
		for _, v := range info.BootNodes {
			var datanode DataNodeInfo
			id, _ := hex.DecodeString(v.NodeIDString)
			nodeid, _ := common.ParseNodeIDBytes(id)
			datanode.DataNodeId = *nodeid
			datanode.DataNodeIp = v.IP
			datanode.DataNodePort = v.DataRpcPort
			datanodes = append(datanodes, datanode)
		}
		ci := &ChainInfo{
			ChainId:   common.ChainID(cid),
			DataNodes: datanodes,
			Mode:      info.Mode,
			ParentId:  info.ParentID,
		}
		infoMap[cid] = ci
	}

	// Return in the order of request (it may return nil if there is an illegal ID corresponding
	// to the index)
	ret := make([]*ChainInfo, len(cids))
	for i, cid := range cids {
		ci, exist := infoMap[cid]
		if exist {
			ret[i] = ci
		} else {
			ret[i] = nil
		}
	}

	//
	// chaininfos := s.dmanager.GetAllChainInfos()
	// for i := 0; i < len(cids); i++ {
	// 	for _, info := range chaininfos {
	// 		if common.ChainID(cids[i]) == info.ID {
	// 			var datanodes []DataNodeInfo
	// 			for _, v := range info.BootNodes {
	// 				var datanode DataNodeInfo
	// 				id, _ := hex.DecodeString(v.NodeIDString)
	// 				nodeid, _ := common.ParseNodeIDBytes(id)
	// 				datanode.DataNodeId = *nodeid
	// 				datanode.DataNodeIp = v.IP
	// 				datanode.DataNodePort = v.DataRpcPort
	// 				datanodes = append(datanodes, datanode)
	// 			}
	// 			ci := &ChainInfo{
	// 				ChainId:   common.ChainID(cids[i]),
	// 				DataNodes: datanodes,
	// 				Mode:      info.Mode,
	// 				ParentId:  info.ParentID,
	// 			}
	// 			ret[i] = ci
	// 		}
	// 	}
	// }
	if jsons, err := json.Marshal(ret); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// MakeVccProof Get the information needed for cashing the check, serialized (not JSON)
func (s *RPCServer) MakeVccProof(ctx context.Context, req *RpcCashCheck) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	vcc, err := req.ToCashCheck()
	if err != nil {
		s.logger.Errorf("MakeVccProof ToCashCheck error: %v", err)
		return newResponse(ToCashCheckErrCode, err.Error()), nil
	}
	if config.IsLogOn(config.DataDebugLog) {
		s.logger.Debugf("MakeVccProof(RpcCashCheck{%s}<=>%s)", req, vcc)
	}
	cdata, err := s.dmanager.GetChainData(vcc.FromChain)
	if err != nil {
		s.logger.Errorf("MakeVccProof GetChainData error: %v", err)
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	// The current block height confirmed by the parent chain and the proof of vcc to the block hash
	height, proofChain, hashOfHeader, err := cdata.VccProof(vcc)
	if err != nil {
		s.logger.Errorf("MakeVccProof VccProof error: %v", err)
		return newResponse(VccProofErrCode, err.Error()), nil
	}
	// Get the block information of the main chain, where the block used in the above proof was
	// packaged into.
	summaries, err := s.dmanager.GetHeaderSummaries(vcc.FromChain, height)
	if err != nil {
		s.logger.Errorf("MakeVccProof GetHeaderSummaries error: %v", err)
		return newResponse(HeaderSummaryNotFound, err.Error()), nil
	}
	if summaries == nil {
		s.logger.Error("MakeVccProof summaries==nil error")
		return newResponse(HeaderSummaryNotFound), nil
	}
	chainId := vcc.FromChain
	hash := hashOfHeader
	for _, sum := range summaries { // generate the proof of the confirmed blocks, to form the proof chain
		if hs, err := sum.HeaderProof(hash, &proofChain); err != nil {
			s.logger.Errorf("MakeVccProof HeaderProof failed: %v", err)
			return newResponse(InvalidProofCode, err.Error()), nil
		} else {
			hash = hs
		}
		chainId = sum.GetChainID()
		height = sum.Header.Height
	}
	if chainId != common.MainChainID {
		return newResponse(InvalidProofCode, "the target chain of proof must be the main chain"), nil
	}

	cashRequest := &models.CashRequest{
		Check:           vcc,
		ProofedChainID:  chainId,
		ProofHeight:     height,
		ProofHeaderHash: common.BytesToHash(hash),
		Proofs:          proofChain,
	}
	buf, err := rtl.Marshal(cashRequest)
	if err != nil {
		s.logger.Errorf("MakeVccProof rtl.Marshal error: %v", err)
		return newResponse(MarshalErrCode, err.Error()), nil
	}
	// jsons, _ := json.Marshal(cashRequest)
	if response, err := hexutil.Bytes(buf).MarshalText(); err != nil {
		s.logger.Errorf("MakeVccProof MarshalText error: %v", err)
		return newResponse(MarshalTextErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(response)}, nil
	}
}

// GetCommittee Get the nodeid list of consensus committee members of the specified epoch of the specified chain
func (s *RPCServer) GetCommittee(ctx context.Context, req *RpcChainEpoch) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	comm, err := cdata.GetCommittee(common.ChainID(req.Chainid), common.EpochNum(req.Epoch))
	if err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("GetCommittee error: %v", err)), nil
	}
	if comm == nil {
		return newResponse(InvalidParamsCode), nil
	}
	if jsons, err := json.Marshal(comm.Members); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// MakeCCCExistenceProof Generate the proof of non-payment to be used for revoking the check
func (s *RPCServer) MakeCCCExistenceProof(ctx context.Context, req *RpcCashCheck) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	ccc, err := req.ToCashCheck()
	if err != nil {
		return newResponse(ToCashCheckErrCode, err.Error()), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.To.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	height, existence, existProof, cashedRootProof, hashOfHeader, err := cdata.CCCExsitenceProof(ccc)
	if err != nil {
		return newResponse(CCCExsitenceProofErrCode, err.Error()), nil
	}

	// get the main chain block summaries which confirmed block in target chain at "height"
	summaries, err := s.dmanager.GetHeaderSummaries(ccc.ToChain, height)
	if err != nil {
		s.logger.Errorf("MakeCCCExistenceProof GetHeaderSummaries error: %v", err)
		return newResponse(HeaderSummaryNotFound, err.Error()), nil
	}
	if summaries == nil {
		s.logger.Error("MakeCCCExistenceProof summaries==nil error")
		return newResponse(HeaderSummaryNotFound), nil
	}
	chainId := ccc.ToChain
	confirmedHeight := height
	proofTargetHash := hashOfHeader
	for _, sum := range summaries { // generate the proof of the confirmed blocks, to form the proof chain
		if hs, err := sum.HeaderProof(proofTargetHash, &cashedRootProof); err != nil {
			s.logger.Errorf("MakeCCCExistenceProof HeaderProof failed: %v", err)
			return newResponse(InvalidProofCode, err.Error()), nil
		} else {
			proofTargetHash = hs
		}
		chainId = sum.GetChainID()
		confirmedHeight = sum.Header.Height
	}
	if chainId != common.MainChainID {
		return newResponse(InvalidProofCode, "the target chain of proof must be the main chain"), nil
	}

	cccr := &models.CancelCashCheckRequest{
		Check:             ccc,
		AbsenceChainID:    common.ChainID(req.To.Chainid),
		AbsenceHeight:     height,
		AbsenceHeaderHash: common.BytesToHash(proofTargetHash),
		CCCProofs:         existProof,
		Proofs:            cashedRootProof,
		ConfirmedHeight:   confirmedHeight,
	}
	buf, err := rtl.Marshal(cccr)
	if err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	}
	input, err := hexutil.Bytes(buf).MarshalText()
	if err != nil {
		return newResponse(MarshalTextErrCode, err.Error()), nil
	}
	cce := CashedCheckExistence{
		Existence: existence,
		Input:     string(input),
	}
	if jsons, err := json.Marshal(cce); err != nil {
		return newResponse(MarshalErrCode, err.Error()), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}

// GetCCCRelativeTx Get the hash of the transaction of the check cashed
func (s *RPCServer) GetCCCRelativeTx(ctx context.Context, req *RpcCashCheck) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	ccc, err := req.ToCashCheck()
	if err != nil {
		return newResponse(InvalidParamsCode, fmt.Sprintf("ToCashCheck error: %v", err)), nil
	}
	cdata, err := s.dmanager.GetChainData(common.ChainID(req.To.Chainid))
	if err != nil {
		return newResponse(GetChainDataErrCode, err.Error()), nil
	}
	hashOfCcc, err := common.HashObject(ccc)
	if err != nil {
		return newResponse(HashObjectErrCode, err.Error()), nil
	}
	hashOfTx, err := cdata.GetCCCRelativeTx(hashOfCcc)
	if err != nil {
		return newResponse(GetCCCRelativeTxErrCode, err.Error()), nil
	}
	if hashOfTx == nil {
		return newResponse(NilTransactionCode, "hashOfTx is nil"), nil
	}
	h := common.BytesToHash(hashOfTx)
	return &RpcResponse{Code: SuccessCode, Data: h.Hex()}, nil
}

// GetRRProofs Get the proof of node pledge at the specified era (a specified root of required reserver tree)
func (s *RPCServer) GetRRProofs(ctx context.Context, req *RpcRRProofReq) (*RpcResponse, error) {
	return newResponse(OperationFailedCode), errors.New("unsupport operation")
}

func (s *RPCServer) GetRRCurrent(ctx context.Context, req *RpcChainRequest) (*RpcResponse, error) {
	return newResponse(OperationFailedCode), errors.New("unsupport operation")
}

func (s *RPCServer) SendBlock(ctx context.Context, req *RpcMsgReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}
	block := new(models.BlockEMessage)
	if err := rtl.Unmarshal(req.Msg, block); err != nil {
		return newResponse(UnmarshalErrCode, err.Error()), nil
	}
	s.logger.Infof("[RPC] receive %s", block)
	s.eventer.Post(block)
	return &RpcResponse{Code: SuccessCode, Data: "Success"}, nil
}

const (
	TCSecp256k1   uint32 = 0x0
	TCGM          uint32 = 0x1
	TCGenerateKey uint32 = 0x2
	TCHash        uint32 = 0x4
	TCSign        uint32 = 0x8
	TCVerify      uint32 = 0x10
)

// TryCrypto req.Type Bitwise operation:
//
// If TCVerify exists, the input Msg must be: Signature+Hash+PublicKey, if the verification is
// successful, return success, otherwise the verification fails
//
// If TCGenerateKey exists, generate a key pair and put it in the corresponding attribute of the
// return value
//
// If TCHash exists, all (without pre-private key) or part (with pre-private key) in req.Msg are
// the data to be hashed, and put the corresponding attribute of the return value after the hash.
//
// If TCSign exists, if there is no TCGenerateKey exists, the first N bytes of req.Msg are the
// private key. If there is TCHash, then the private key is followed by the data to be hashed,
// otherwise the hash value is calculated as required. The return value is put into the corresponding
// attribute.
func (s *RPCServer) TryCrypto(ctx context.Context, req *RpcMsgReq) (*RpcResponse, error) {
	if req == nil {
		return newResponse(InvalidParamsCode, "nil request"), nil
	}

	type result struct {
		PrivateKey hexutil.Bytes `json:"privatekey"`
		PublicKey  hexutil.Bytes `json:"publickey"`
		Hash       hexutil.Bytes `json:"hash"`
		Signature  hexutil.Bytes `json:"signature"`
	}

	ret := new(result)

	var cc cipher.Cipher
	cc = cipher.NewCipher(cipher.SECP256K1SHA3)
	log.Infof("[TRYCRYPTO] %s created, with Req:%s", cc, req)

	if req.Type&TCVerify > 0 {
		if len(req.Msg) != (cc.LengthOfSignature() + cc.LengthOfHash() + cc.LengthOfPublicKey()) {
			log.Debugf("[TRYCRYPTO] len of message (%d) should be %d",
				len(req.Msg), cc.LengthOfSignature()+cc.LengthOfHash()+cc.LengthOfPublicKey())
			return newResponse(InvalidParamsCode), nil
		}
		sig := req.Msg[:cc.LengthOfSignature()]
		hashb := req.Msg[cc.LengthOfSignature() : cc.LengthOfSignature()+cc.LengthOfHash()]
		pub := req.Msg[cc.LengthOfSignature()+cc.LengthOfHash():]
		if cc.Verify(pub, hashb, sig) {
			log.Debugf("[TRYCRYPTO] sig:%x hashb:%x pub:%x verified", sig, hashb, pub)
			return &RpcResponse{Code: SuccessCode, Data: "{}"}, nil
		}
		log.Debugf("[TRYCRYPTO] sig:%x hashb:%x pub:%x verify failed", sig, hashb, pub)
		return newResponse(InvalidSignatureCode), nil
	}

	if req.Type&TCGenerateKey > 0 {
		pk, err := cc.GenerateKey()
		if err != nil {
			log.Debugf("[TRYCRYPTO] generate key error: %v", err)
			return newResponse(OperationFailedCode), err
		}
		ret.PrivateKey = pk.ToBytes()
		ret.PublicKey = pk.GetPublicKey().ToBytes()
		log.Debugf("[TRYCRYPTO] priv:%x pub:%x generated", ret.PrivateKey, ret.PublicKey)
	}

	if req.Type&TCSign > 0 {
		if req.Type&TCGenerateKey == 0 && len(req.Msg) < cc.LengthOfPrivateKey() {
			log.Debugf("[TRYCRYPTO] len of message (%d) should not less than %d",
				len(req.Msg), cc.LengthOfPrivateKey())
			return newResponse(InvalidParamsCode), nil
		}

		p := 0
		priv := []byte(ret.PrivateKey)
		if req.Type&TCGenerateKey == 0 {
			priv = req.Msg[:cc.LengthOfPrivateKey()]
			p = cc.LengthOfPrivateKey()
		}
		log.Debugf("[TRYCRYPTO] priv:%x", priv)

		bs := req.Msg[p:]
		if req.Type&TCHash > 0 {
			ret.Hash = common.CipherHash256(cc, bs)
			log.Debugf("[TRYCRYPTO] len(data):%d, hash:%x", len(bs), ret.Hash)
			bs = ret.Hash
		} else {
			log.Debugf("[TRYCRYPTO] hash:%x", bs)
		}

		sig, err := cc.Sign(priv, bs)
		if err != nil {
			log.Debugf("[TRYCRYPTO] sign error: %v", err)
			return newResponse(OperationFailedCode), err
		}
		ret.Signature = sig
		log.Debugf("[TRYCRYPTO] signed: %x", sig)
	} else if req.Type&TCHash > 0 {
		data := req.Msg
		ret.Hash = common.CipherHash256(cc, data)
		log.Debugf("[TRYCRYPTO] len(data):%d, hash:%x", len(data), ret.Hash)
	}

	if jsons, err := json.Marshal(ret); err != nil {
		return newResponse(MarshalErrCode), nil
	} else {
		return &RpcResponse{Code: SuccessCode, Data: string(jsons)}, nil
	}
}
