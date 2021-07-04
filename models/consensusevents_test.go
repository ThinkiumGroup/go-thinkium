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
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

func TestRewardRequests(t *testing.T) {
	rs := make(RewardRequests, 100)
	for i := 0; i < len(rs); i++ {
		cid := i % 4
		epoch := i / 4
		if i%10 == 0 {
			continue
		}
		rs[i] = &RewardRequest{ChainId: common.ChainID(cid), Epoch: common.EpochNum(epoch)}
	}
	fmt.Printf("%+v\n", rs)
	sort.Sort(rs)
	fmt.Printf("%+v\n", rs)
}
