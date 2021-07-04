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
	"sync"

	"github.com/ThinkiumGroup/go-common"
)

type HeighterSet struct {
	pool      map[common.Height]BlockHeighter
	sortedkey []common.Height
	lock      sync.Mutex
}

func NewHeighterSet() *HeighterSet {
	return &HeighterSet{
		pool:      make(map[common.Height]BlockHeighter),
		sortedkey: make([]common.Height, 0),
	}
}

func (s *HeighterSet) String() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s == nil {
		return "HeighterSet<nil>"
	}
	l := len(s.sortedkey)
	if l == 0 {
		return "{0}"
	} else if l == 1 {
		return fmt.Sprintf("HeighterSet{1:[%d]}", s.sortedkey[0])
	} else {
		return fmt.Sprintf("HeighterSet{%d:[%d-%d]}", l, s.sortedkey[0], s.sortedkey[l-1])
	}
}

func (s *HeighterSet) Len() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return len(s.sortedkey)
}

func (s *HeighterSet) Put(x BlockHeighter) bool {
	if x == nil {
		return true
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	height, h := x.GetHeight(), x.Hash()
	if height == 0 && (h.IsNil() || h.IsEmpty()) {
		// nil obj
		return false
	}
	_, exist := s.pool[height]
	if exist {
		// already in map
		return false
	}
	s.pool[height] = x
	s.sortedkey = append(s.sortedkey, height)
	sort.Slice(s.sortedkey, func(i, j int) bool {
		return s.sortedkey[i] < s.sortedkey[j]
	})
	return true
}

func (s *HeighterSet) Pop() BlockHeighter {
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(s.sortedkey) == 0 {
		return nil
	}
	y := s.sortedkey[0]
	s.sortedkey = s.sortedkey[1:]
	x, ok := s.pool[y]
	if ok {
		delete(s.pool, y)
		return x
	}
	return nil
}

type (
	CachedHeighter struct {
		heighter BlockHeighter
		pub      []byte
		sig      []byte
	}

	// HeighterHashMap Different objects with different hashs are allowed at the same height
	HeighterHashMap struct {
		heighterPool map[common.Hash]BlockHeighter
		hashPool     map[common.Height][]common.Hash
		keys         []common.Height
		lock         sync.Mutex
	}

	// RangeBufferCallback if need continue the range, goon return true
	// if need step to next height, nextHeight return true
	RangeBufferCallback func(height common.Height, hob common.Hash,
		o BlockHeighter) (goon bool, nextHeight bool, err error)
)

func NewCacheHeighter(event BlockHeighter, pub, sig []byte) *CachedHeighter {
	return &CachedHeighter{
		heighter: event,
		pub:      pub,
		sig:      sig,
	}
}

func (h *CachedHeighter) GetObject() BlockHeighter {
	return h.heighter
}

func (h *CachedHeighter) GetHeight() common.Height {
	return h.heighter.GetHeight()
}

func (h *CachedHeighter) Hash() common.Hash {
	return h.heighter.Hash()
}

func (h *CachedHeighter) PubAndSig() (pub, sig []byte) {
	return h.pub, h.sig
}

func NewHeighterHashMap() *HeighterHashMap {
	return &HeighterHashMap{
		heighterPool: make(map[common.Hash]BlockHeighter),
		hashPool:     make(map[common.Height][]common.Hash),
	}
}

func (m *HeighterHashMap) String() string {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m == nil {
		return "HeighterMap<nil>"
	}
	l := len(m.keys)
	if l == 0 {
		return "HeighterMap{0}"
	} else if l == 1 {
		return fmt.Sprintf("HeighterMap{1:[%d]:%d}", m.keys[0], len(m.heighterPool))
	} else {
		return fmt.Sprintf("HeighterMap{%d:[%d-%d]:%d}", l, m.keys[0], m.keys[l-1], len(m.heighterPool))
	}
}

func (m *HeighterHashMap) Size() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.heighterPool)
}

func (m *HeighterHashMap) MinHeight() (common.Height, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.keys) > 0 {
		return m.keys[0], true
	}
	return common.NilHeight, false
}

func (m *HeighterHashMap) Get(height common.Height) ([]BlockHeighter, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	hs, exist := m.hashPool[height]
	if !exist {
		return nil, false
	}
	ret := make([]BlockHeighter, len(hs))
	for i := 0; i < len(hs); i++ {
		ret[i] = m.heighterPool[hs[i]]
	}
	return ret, true
}

func (m *HeighterHashMap) Put(heighter BlockHeighter) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	h := heighter.Hash()
	_, exist := m.heighterPool[h]
	if exist {
		return false
	}
	k := heighter.GetHeight()
	m.heighterPool[h] = heighter

	hs := m.hashPool[k]
	if len(hs) == 0 {
		m.keys = append(m.keys, k)
		sort.Slice(m.keys, func(i, j int) bool {
			return m.keys[i] < m.keys[j]
		})
	}
	hs = append(hs, h)
	m.hashPool[k] = hs
	return true
}

func (m *HeighterHashMap) Delete(hob common.Hash) bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	o, exist := m.heighterPool[hob]
	if !exist {
		return false
	}
	delete(m.heighterPool, hob)

	k := o.GetHeight()
	hs, _ := m.hashPool[k]
	if len(hs) > 1 {
		after := make([]common.Hash, len(hs)-1)
		i := 0
		for ; i < len(hs); i++ {
			if hs[i] == hob {
				break
			}
		}
		copy(after, hs[:i])
		copy(after[i:], hs[i+1:])
		m.hashPool[k] = after
	} else {
		delete(m.hashPool, k)
	}
	return true
}

func (m *HeighterHashMap) clearHeightLocked(height common.Height) bool {
	hs, exist := m.hashPool[height]
	if !exist {
		return false
	}
	delete(m.hashPool, height)
	for _, h := range hs {
		delete(m.heighterPool, h)
	}
	if height == m.keys[0] {
		m.keys = m.keys[1:]
	} else {
		i := sort.Search(len(m.keys), func(i int) bool {
			return m.keys[i] >= height
		})
		if i < len(m.keys) {
			if m.keys[i] == height {
				if i == len(m.keys)-1 {
					m.keys = m.keys[:i]
				} else {
					ks := make([]common.Height, len(m.keys)-1)
					copy(ks, m.keys[:i])
					copy(ks[i:], m.keys[i+1:])
					m.keys = ks
				}
			}
		}
	}
	return true
}

func (m *HeighterHashMap) ClearHeight(height common.Height) bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.clearHeightLocked(height)
}

func (m *HeighterHashMap) Peek() (height common.Height, hob common.Hash, o BlockHeighter, exist bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.keys) == 0 {
		return common.NilHeight, common.Hash{}, nil, false
	}
	height = m.keys[0]
	hs := m.hashPool[height]
	o = m.heighterPool[hs[0]]
	return height, hs[0], o, true
}

func (m *HeighterHashMap) Range(callback RangeBufferCallback) error {
	for {
		height, hob, o, exist := m.Peek()
		if !exist {
			return nil
		}
		if goon, nextHeight, err := callback(height, hob, o); err != nil {
			return err
		} else if goon {
			if nextHeight {
				m.ClearHeight(height)
			} else {
				m.Delete(hob)
			}
		} else {
			return nil
		}
	}
}

func (m *HeighterHashMap) PopIfEarlier(target common.Height) (height common.Height, hob common.Hash, o BlockHeighter, exist bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if target.IsNil() {
		return common.NilHeight, common.Hash{}, nil, false
	}

	for {
		if len(m.keys) == 0 || m.keys[0] > target {
			return common.NilHeight, common.Hash{}, nil, false
		}
		// there's must be an unempty m.keys[0]->[]Hash, or it's an illegal state
		height = m.keys[0]
		hs := m.hashPool[height]
		hob = hs[0]
		o = m.heighterPool[hob]
		if len(hs) == 1 {
			// clear height
			delete(m.heighterPool, hob)
			delete(m.hashPool, height)
			m.keys = m.keys[1:]
		} else {
			// delete one heighter
			delete(m.heighterPool, hob)
			m.hashPool[height] = hs[1:]
		}
		return height, hob, o, true
	}
}
