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

import (
	"errors"

	"github.com/ThinkiumGroup/go-common"
)

type (
	Engine interface {
		common.Service
		ChainComm(ChainID common.ChainID) (*Committee, error)
		ChainNextComm(ChainID common.ChainID) (*Committee, error)
		StartConsensus()
		CreateSubChain(chainID common.ChainID)
		InitSubChain(chainID common.ChainID) bool // If the creation is successful, true is returned, and false is returned from the existing subchains
		RemoveSubChain(chainID common.ChainID)
		SetChainComm(cid common.ChainID, nids *Committee) error
	}

	ElectCallback func(keepComm bool, oldcomm *Committee, newcomm *Committee)

	Elector interface {
		// Returns whether the election of current chain is dynamic. False means that dynamic election is not needed
		IsDynamic() bool
		// Is the current node a legal candidate
		IsCandidate() bool
		// // Has the next election been completed
		// HasNextCommittee() bool
		// Filter for receiving block data
		BlockReceived(ctx *Context, block *BlockEMessage)
		// Filter for generating block data
		BlockGenerated(block *BlockEMessage) error
		// Set callback function after successful election
		RegisterElectedCallback(callback ElectCallback)
		// Election message processing
		Electioneer(ctx *Context, msg interface{}) error
		// Switch epoch, return whether switched to a new epoch with new committee
		SwitchEpoch(oldEpoch common.EpochNum) (keepComm bool)
		// Electing according to electMsg
		ElectToChain(ctx *Context, electMsg interface{}) error
		// Preelect according to electMsg
		PreElectToChain(ctx *Context, electMsg interface{}) error
		// Is the current node elected as the member of committee which specified by epoch number: epoch
		Chosen(ctx *Context, epoch common.EpochNum) bool
		// reset current elector
		Reset()
		// Returns committee of next epoch, return nil when the current election is not completed
		NextComm() *Committee
	}
)

var (
	ErrIllegalChainID  = errors.New("illegal chain id")
	ErrDelayEpochNum   = errors.New("delay epoch num")
	ErrDelayBlockNum   = errors.New("delay block num")
	ErrWrongState      = errors.New("wrong state")
	ErrShouldIgnore    = errors.New("should ignore this error")
	ErrWrongEvent      = errors.New("wrong event")
	ErrNeedBuffer      = errors.New("need to buf")
	ErrBufferByState   = errors.New("bufferred by state")
	ErrNoMatching      = errors.New("no matching event")
	ErrConsensusFailed = errors.New("consensus failed")
	ErrHeightExceeded  = errors.New("height exceeded")
)

func ReachPrepare(commSize, prepared int) bool {
	return prepared > commSize*2/3
}

func ReachCommit(commSize, committed int) bool {
	// To avoid the situation of that when the size of the committee is small, the condition of
	// failing to meet the commit condition due to excessive concentration of Prepare Events
	// 避免当committee size比较小时，出现由于prepare消息过度集中导致无法满足commit条件的情况
	return committed > (commSize-1)/2
	// return committed > commSize*2/3
}

func ReachConfirm(commSize, confirmed int) bool {
	return confirmed > commSize*2/3
}

// Deprecated
func ParseToAddress(bitLength uint, shardPos uint16, nodePos uint16, index uint64) (addr common.Address) {
	src := make([]byte, 2+2+8)
	src[0] = byte(shardPos >> 8)
	src[1] = byte(shardPos)
	src[2] = byte(nodePos >> 8)
	src[3] = byte(nodePos)
	for i := uint(0); i < 8; i++ {
		src[4+i] = byte(index >> (8 * i))
	}

	hashOfSrc, _ := common.Hash256s(src)
	copy(addr[:], hashOfSrc[common.HashLength-common.AddressLength:])

	shardPos <<= 16 - bitLength

	if bitLength > 8 {
		addr[0] = byte(shardPos >> 8)
		masklen := bitLength & 0x7
		mask := byte(0xff) >> masklen
		addr[1] &= mask
		addr[1] |= byte(shardPos)
	} else {
		mask := byte(0xff) >> bitLength
		addr[0] &= mask
		addr[0] |= byte(shardPos >> 8)
	}
	return
}
