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

package network

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/models"
	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/golang-lru/simplelru"
)

var (
	ErrInsertSameMsg    = errors.New("insert the same msg")
	ErrAlreadyConnected = errors.New("already connect to net")
)

type PortPool struct {
	m    map[uint16]struct{}
	pool []uint16
	lock sync.Mutex
}

func NewPortPool(start uint16, end uint16) *PortPool {
	var l uint16
	if start > 0 && end > start {
		l = end - start
	}
	m := make(map[uint16]struct{}, l)
	p := make([]uint16, l)
	for i := start; i < end; i++ {
		m[i] = common.EmptyPlaceHolder
		p[i-start] = i
	}
	log.Infof("new port pool: [%d, %d)", start, end)
	return &PortPool{
		m:    m,
		pool: p,
	}
}

func (p *PortPool) Get() (uint16, bool) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if len(p.m) == 0 {
		return 0, false
	}
	port := p.pool[0]
	p.pool = p.pool[1:]
	delete(p.m, port)
	return port, true
}

func (p *PortPool) Put(port uint16) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if _, ok := p.m[port]; ok {
		return
	}
	p.m[port] = common.EmptyPlaceHolder
	p.pool = append(p.pool, port)
}

var (
	cache, _            = simplelru.NewLRU(RecentReceivePoolSize, nil)
	SystemRecentRecPool = RecentReceivePool{
		cache: cache,
	}
)

type RecentReceivePool struct {
	cache *simplelru.LRU
	lock  sync.RWMutex
}

func (p *RecentReceivePool) Add(hashOfLoad common.Hash, fromid *common.NodeID) bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.cache.Contains(hashOfLoad) {
		m := make(map[common.NodeID]struct{})
		m[*fromid] = common.EmptyPlaceHolder
		p.cache.Add(hashOfLoad, m)
		return true
	}
	v, _ := p.cache.Get(hashOfLoad)
	m := v.(map[common.NodeID]struct{})
	if _, ok := m[*fromid]; !ok {
		m[*fromid] = common.EmptyPlaceHolder
	}
	return false
}

func (p *RecentReceivePool) IsExist(hashOfLoad common.Hash, fromid *common.NodeID) (exist bool, inNodes bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	exist = p.cache.Contains(hashOfLoad)
	if !exist {
		return
	}
	if fromid == nil {
		return
	}
	vl, _ := p.cache.Get(hashOfLoad)
	m := vl.(map[common.NodeID]struct{})
	if _, ok := m[*fromid]; ok {
		inNodes = true
		return
	}
	return
}

// lock for WantDetailEvent
type WantDetailLock struct {
	msgHashs *lru.Cache
}

func NewWantDetailLock(size int) *WantDetailLock {
	cache, _ := lru.New(size)
	return &WantDetailLock{msgHashs: cache}
}

func (w *WantDetailLock) Lock(h common.Hash) bool {
	if loaded, _ := w.msgHashs.ContainsOrAdd(h, common.EmptyPlaceHolder); loaded {
		return false
	}
	return true
}

func (w *WantDetailLock) Unlock(h common.Hash) {
	w.msgHashs.Remove(h)
}

func (w *WantDetailLock) UnlockAll() {
	w.msgHashs.Purge()
}

type RecentMsgPool struct {
	hashToMsg *lru.Cache
	lastTime  int64
	ticker    *time.Ticker
	quit      chan bool
	wg        sync.WaitGroup
	lock      sync.Mutex
}

func NewRecentMsgPool(size int) *RecentMsgPool {
	cache, err := lru.New(size)
	if err != nil {
		panic(err)
	}
	duration := rand.Intn(10) + 10
	pool := &RecentMsgPool{
		hashToMsg: cache,
		ticker:    time.NewTicker(time.Duration(duration) * time.Second),
		quit:      make(chan bool),
	}
	pool.Start()
	return pool
}

func (rm *RecentMsgPool) clearLocked() {
	rm.hashToMsg.Purge()
	rm.lastTime = 0
}

func (rm *RecentMsgPool) Clear() {
	rm.lock.Lock()
	defer rm.lock.Unlock()
	rm.clearLocked()
}

func (rm *RecentMsgPool) IsExist(loadHash common.Hash) bool {
	rm.lock.Lock()
	defer rm.lock.Unlock()
	return rm.hashToMsg.Contains(loadHash)
}

func (rm *RecentMsgPool) GetLoad(loadHash common.Hash) (load []byte, exist bool) {
	rm.lock.Lock()
	defer rm.lock.Unlock()
	o, ok := rm.hashToMsg.Get(loadHash)
	if !ok {
		return nil, false
	}
	rm.lastTime = time.Now().Unix()
	return o.([]byte), true
}

func (rm *RecentMsgPool) PutLoad(key common.Hash, load []byte) error {
	rm.lock.Lock()
	defer rm.lock.Unlock()

	if ok, _ := rm.hashToMsg.ContainsOrAdd(key, load); ok {
		return ErrInsertSameMsg
	}
	rm.lastTime = time.Now().Unix()
	return nil
}

func (rm *RecentMsgPool) tryClear() {
	rm.lock.Lock()
	defer rm.lock.Unlock()
	if rm.lastTime <= 0 {
		return
	}
	c := time.Now().Unix()
	if c-300 >= rm.lastTime {
		rm.clearLocked()
	}
}

func (rm *RecentMsgPool) Start() {
	if rm.ticker != nil {
		rm.wg.Add(1)
		go func() {
		outer:
			for {
				select {
				case <-rm.quit:
					break outer
				case <-rm.ticker.C:
					rm.tryClear()
				}
			}
			rm.wg.Done()
		}()
	}
}

func (rm *RecentMsgPool) Stop() {
	if rm.ticker != nil {
		rm.quit <- true
		rm.ticker.Stop()
		rm.wg.Wait()
	}
	rm.clearLocked()
}

func GetEventTypeFromPayLoad(payLoad []byte) (models.EventType, error) {
	l := len(payLoad)
	kl := common.RealCipher.LengthOfPublicKey()
	sl := common.RealCipher.LengthOfSignature()
	if l <= models.EventTypeLength+kl+sl {
		return models.UNSETEVENT, errors.New("message length is too short")
	}
	eventType := models.ToEventType(payLoad[l-models.EventTypeLength-kl-sl : l-kl-sl])
	return eventType, nil
}

func GetEventTypeFromMsgLoad(msgLoad []byte) (models.EventType, error) {
	return GetEventTypeFromPayLoad(msgLoad)
}

func PayLoad2Body(payLoad []byte) (eventType models.EventType, body []byte, pub []byte, sig []byte, err error) {
	l := len(payLoad)
	kl := common.RealCipher.LengthOfPublicKey()
	sl := common.RealCipher.LengthOfSignature()
	if l <= models.EventTypeLength+kl+sl {
		return 0, nil, nil, nil, errors.New("message length is too short")
	}
	body = payLoad[:l-models.EventTypeLength-kl-sl]
	eventType = models.ToEventType(payLoad[l-models.EventTypeLength-kl-sl : l-kl-sl])
	pub = payLoad[l-kl-sl : l-sl]
	sig = payLoad[l-sl:]
	return
}

func Body2EventLoad(eventType models.EventType, body []byte) (eventLoad []byte) {
	eventLoad = append(body, eventType.Bytes()...)
	return
}

func packMsg(pb interface{}, needSign bool) (eventType models.EventType, body []byte, pub, sig []byte, err error) {
	eventType, body, err = models.MarshalEvent(pb)
	if needSign {
		pub, sig, err = common.SignMsg(pb)
	}
	if err != nil {
		log.Error("marshal message error: ", err)
		return eventType, nil, nil, nil, err
	}
	return
}

// msgLoad: body + eventType + pub + sig
// eventType: msg type 2 bytes
// body: serialized msg
// pub: public key
// sig: signature for eventType+bydy
func UnpackP2PMsg(msg *Msg) (eventLoad []byte, eventType models.EventType, body []byte, pub, sig []byte, err error) {
	if msg.LoadSize() <= models.EventTypeLength+
		common.RealCipher.LengthOfPublicKey()+
		common.RealCipher.LengthOfSignature() {
		return nil, 0, nil, nil, nil, errors.New("message length is too short")
	}
	// payLoad := make([]byte, msg.Size)
	// msg.Payload.Read(payLoad)
	eventType, body, pub, sig, err = PayLoad2Body(msg.Payload)
	eventLoad = Body2EventLoad(eventType, body)
	return
}

func PackP2PMsg(eventOrPayLoad, pub, sig []byte) *Msg {
	var payLoad []byte
	if sig == nil {
		payLoad = eventOrPayLoad
	} else {
		pl := append(eventOrPayLoad, pub...)
		payLoad = append(pl, sig...)
	}
	return &Msg{MsgType: &EventMsgType, Payload: payLoad}
}

func WriteEventLoad(v interface{}, needSign bool) (eventType models.EventType, eventLoad, pub, sig []byte, err error) {
	eventType, body, pub, sig, err := packMsg(v, needSign)
	if err != nil {
		return eventType, nil, nil, nil, err
	}
	eventLoad = Body2EventLoad(eventType, body)
	if err != nil {
		return eventType, nil, nil, nil, err
	}
	return eventType, eventLoad, pub, sig, nil
}

// message to p2p.Msg
func WriteP2PMsg(pb interface{}, needSign bool) (models.EventType, *Msg, error) {
	eventType, eventLoad, pub, sig, err := WriteEventLoad(pb, needSign)
	if err != nil {
		return eventType, nil, err
	}
	return eventType, PackP2PMsg(eventLoad, pub, sig), nil
}

// p2p.Msg to MsgEvent
func ReadP2PMsg(msg *Msg) (models.EventType, interface{}, error) {
	_, eventType, body, _, _, err := UnpackP2PMsg(msg)
	if err != nil {
		return eventType, nil, err
	}
	m, err := models.UnmarshalEvent(eventType, body)
	return eventType, m, err
}

func CopyP2PMsg(pm Msg) Msg {
	msg := pm
	return msg
}
