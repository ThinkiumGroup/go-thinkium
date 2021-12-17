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

package models

import "math/big"

const (
	// Data forwarding mode
	RelayBroadcast     RelayType = iota // broadcast
	RelaySendTo                         // Directional transmission to a specific node
	RelayRandBroadcast                  // Random sending
)

const (
	// The identity type of the node on the chain
	CtrlOp      OperatorType = iota // Control class. The context has no chain information when the control event is executed
	DataOp                          // Data node
	CommitteeOp                     // Consensus node
	InitialOp                       // Initial class of consensus node
	PreelectOp                      // Preelect class, higher than SPEC and lower than COMM
	SpectatorOp                     // Spectator class
	MemoOp                          // Full class
	StartOp                         // Starting class
	FailureOp                       // Failure class
)

const (
	// Number of bytes occupied by event type
	EventTypeLength = 2

	// delta pool related
	MaxPopOfOneShardDelta = 10 // Delta number threshold per chain

	MaxTxCountPerBlock = 2000 // The maximum number of transactions packed in a block
	// The maximum number of deltas that can be merged in each block is twice the maximum number of TX
	MaxDeltasPerBlock = int(MaxTxCountPerBlock) << 1

	// When the transaction execution is incompatible, the version number can be used to distinguish

	// compatible with Ethereum's transaction hash, pay attention to the tx.Hash() and tx.HashValue()
	// methods when upgrading the version
	ETHHashTxVersion      = 2
	NewBaseChainTxVersion = 3
	// There is a bug in V0, which leads to insufficient amount when creating or invoking the
	// contract, and the transaction will be packaged, but the nonce value does not increase
	TxVersion = NewBaseChainTxVersion
	// V0's BlockSummary.Hash Only a through transmission of BlockHash, can't reflect the location
	// information of the block, and can't complete the proof of cross chain. V1 adds chainid and
	// height to hash
	SummaryVersion = 1
)

const (
	MinDataNodes = 1
	MinBootNodes = 1
	MinAdmins    = 3
)

var (
	BigShannon = big.NewInt(1000000000)
	BigTKM     = big.NewInt(0).Mul(BigShannon, BigShannon)
	BigBillion = big.NewInt(0).Mul(BigShannon, BigTKM)

	SystemNoticer Noticer
)
