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
	"fmt"
	"sort"

	"github.com/ThinkiumGroup/go-common"
)

type ShardWaterline struct {
	ShardID common.ChainID // shard id
	Line    common.Height  // the height of the shard that deltas are to be merged next
}

func (s ShardWaterline) String() string {
	return fmt.Sprintf("{C:%d W:%s}", s.ShardID, s.Line)
}

func (s ShardWaterline) HashValue() ([]byte, error) {
	return common.Hash256s(s.ShardID.Bytes(), s.Line.Bytes())
}

func (s ShardWaterline) Equals(o ShardWaterline) bool {
	return s.ShardID == o.ShardID && s.Line == o.Line
}

// It is used to save the ordered waterlines of all other shards in the same group after the
// execution of this block in this chain
type Waterlines []ShardWaterline

func (ws Waterlines) Len() int {
	return len(ws)
}

func (ws Waterlines) Swap(i, j int) {
	ws[i], ws[j] = ws[j], ws[i]
}

func (ws Waterlines) Less(i, j int) bool {
	return ws[i].ShardID < ws[j].ShardID || (ws[i].ShardID == ws[j].ShardID && ws[i].Line < ws[j].Line)
}

func (ws Waterlines) HashValue() ([]byte, error) {
	if len(ws) == 0 {
		return nil, nil
	}
	hashlist := make([][]byte, 0, len(ws))
	for _, w := range ws {
		h, err := common.HashObject(w)
		if err != nil {
			return nil, err
		}
		hashlist = append(hashlist, h)
	}
	return common.MerkleHash(hashlist, -1, nil)
}

func (ws Waterlines) Equals(os Waterlines) bool {
	if ws == nil || os == nil {
		if ws == nil && os == nil {
			return true
		}
		return false
	}
	if len(ws) != len(os) {
		return false
	}
	for i := 0; i < len(ws); i++ {
		if ws[i].Equals(os[i]) == false {
			return false
		}
	}
	return true
}

// shardid -> [0]:start height, [1]:length of missing heights
type MissingHeights map[common.ChainID][2]uint64

func (m MissingHeights) IDs() common.ChainIDs {
	if len(m) == 0 {
		return nil
	}
	var ids common.ChainIDs
	for id, _ := range m {
		ids = append(ids, id)
	}
	if len(ids) > 1 {
		sort.Sort(ids)
	}
	return ids
}

func (m MissingHeights) Get(id common.ChainID) (start common.Height, length int, exist bool) {
	if vs, ok := m[id]; ok {
		return common.Height(vs[0]), int(vs[1]), true
	}
	return 0, 0, false
}

func (m MissingHeights) Put(id common.ChainID, start common.Height, length int) {
	if length < 0 {
		length = 0
	}
	m[id] = [2]uint64{uint64(start), uint64(length)}
}

func (m MissingHeights) MostUrgent() (id common.ChainID, start common.Height, length int, exist bool) {
	if len(m) == 0 {
		return 0, 0, 0, false
	}
	exist = true
	length = 0
	for cid, vs := range m {
		l := int(vs[1])
		if l > length {
			id = cid
			start = common.Height(vs[0])
			length = l
		}
	}
	return
}
