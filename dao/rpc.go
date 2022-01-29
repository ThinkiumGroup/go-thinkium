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
	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-thinkium/models"
	"github.com/sirupsen/logrus"
)

var (
	TryRpcGetBlock func(chain models.DataHolder, h common.Height) (ret *models.BlockEMessage, err error)
	RpcReplayBlock func(target string, request *models.SyncRequest, holder models.DataHolder, end common.Height, logger logrus.FieldLogger)
	RpcGetRRProof  func(rewardChainInfo *common.ChainInfos, rrRoot []byte, logger logrus.FieldLogger) (*models.RRProofs, error)
)
