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

package dao

import (
	"context"
	"errors"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/ThinkiumGroup/go-thinkium/rpcserver"
	"github.com/stephenfire/go-rtl"
	"google.golang.org/grpc"
)

func TryRpcGetBlock(chain models.DataHolder, h common.Height) (ret *models.BlockEMessage, err error) {
	mi, ok := chain.GetChainInfo()
	if !ok {
		return nil, errors.New("chain info not found")
	}
	defer func() {
		if config.IsLogOn(config.NetDebugLog) {
			log.Debugf("TryRpcGetBlock block: %s err: %v", ret, err)
		}
	}()
	dataNodeConns, _ := grpc.Dial(mi.BootNodes[0].GetRpcAddr(), grpc.WithInsecure())
	defer dataNodeConns.Close()
	rpcClient := rpcserver.NewNodeClient(dataNodeConns)

	req := &rpcserver.RpcBlockHeight{
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
