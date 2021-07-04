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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func randomAddress() common.Address {
	return common.BytesToAddress(common.RandomBytes(common.AddressLength))
}

func objectcodectest(t *testing.T, a interface{}, createor func() interface{}) bool {
	buf := new(bytes.Buffer)
	err := rtl.Encode(a, buf)
	if err != nil {
		t.Errorf("encode error: %v", err)
		return false
	}

	bs := buf.Bytes()
	buf2 := bytes.NewBuffer(bs)

	a1 := createor()
	err = rtl.Decode(buf2, a1)
	if err != nil {
		t.Errorf("decode error: %v", err)
		return false
	}

	typ := reflect.TypeOf(a1).Elem()
	if reflect.DeepEqual(a, a1) {
		t.Logf("%v -> %x, %s encode and decode ok", a, bs, typ.Name())
	} else {
		t.Errorf("%v -> %x -> %v, %s encode/decode failed", a, bs, a1, typ.Name())
		return false
	}
	return true
}

// func TestExchangerAdminData_Deserialization(t *testing.T) {
// 	buf, _ := hex.DecodeString("f6bcc52246967b9eb1371ff0e5a58c1b50521b3bb77cd5a655ce3042ceff7f17")
// 	data := new(ExchangerAdminData)
// 	err := rtl.Unmarshal(buf, data)
// 	if err != nil {
// 		t.Errorf("%v", err)
// 	} else {
// 		t.Logf("%v", data)
// 	}
// }

func TestCashCheck_Deserialization(t *testing.T) {
	// buf, _ := hex.DecodeString("000000016437623138393865353239333936613635633233000000000000000000000002306561316364663264363761343139656162346400000000000003e80312d687")
	// buf, _ := hex.DecodeString("000000016c71a4cd51da3c79af06bed11b4dfe7b3353dd7c0000000000000004000000029d684f4486131c486b4144a730c735e95b49f0b400000000000000d30405f5e100")
	buf, _ := hex.DecodeString("0010000000000000016c71a4cd51da3c79af06bed11b4dfe7b3353dd7c0000000000000005000000029d684f4486131c486b4144a730c735e95b49f0b4000000000000009a0405f5e100")
	cc := &CashCheck{}
	if err := rtl.Unmarshal(buf, cc); err != nil {
		t.Errorf("unmarshal failed: %v", err)
		return
	}
	j, err := json.Marshal(cc)
	if err != nil {
		t.Errorf("json marshal error: %v", err)
		return
	}
	t.Logf("cc=%s", string(j))
	t.Logf("from: %x", cc.FromAddress[:])
	t.Logf("to: %x", cc.ToAddress[:])
}

func TestCashCheck(t *testing.T) {
	vcc := &CashCheck{
		FromChain:    1,
		FromAddress:  common.BytesToAddress([]byte("UUUUUUUUUUUUUUUUUUUU")),
		Nonce:        100,
		ToChain:      2,
		ToAddress:    common.BytesToAddress([]byte("ffffffffffffffffffff")),
		ExpireHeight: 200000,
		Amount:       big.NewInt(math.MaxInt64),
	}

	bs, err := rtl.Marshal(vcc)
	if err != nil {
		t.Errorf("marshal error: %v", err)
		return
	}
	j, err := json.Marshal(vcc)
	if err != nil {
		t.Errorf("json marshal error: %v", err)
		return
	}
	t.Logf("vcc=%s", string(j))

	t.Logf("stream: %x", bs)

	vcc2 := new(CashCheck)
	err = rtl.Unmarshal(bs, vcc2)
	if err != nil {
		t.Errorf("unmarshal error: %v", err)
		return
	}

	j, err = json.Marshal(vcc2)
	if err != nil {
		t.Errorf("json marshal error: %v", err)
		return
	}
	t.Logf("vcc2=%s", string(j))

}

func TestExchangerAdminData(t *testing.T) {
	creator := func() interface{} {
		return &ExchangerAdminData{}
	}

	var a *ExchangerAdminData
	a = &ExchangerAdminData{
		Sender: randomAddress(),
		Nonce:  1123,
	}

	objectcodectest(t, a, creator)

	a = &ExchangerAdminData{
		Sender:       randomAddress(),
		Nonce:        0,
		NewRate:      new(big.Rat).SetFrac64(21325, 8907347),
		NewNeedSigns: 3,
		NewAdminPubs: [][]byte{
			common.RandomBytes(32),
			common.RandomBytes(32),
			common.RandomBytes(32),
			common.RandomBytes(32),
		},
	}

	objectcodectest(t, a, creator)

	a.NewNeedSigns = -1
	objectcodectest(t, a, creator)

	a.NewRate = nil
	objectcodectest(t, a, creator)
}

func TestExchangerAdminRequest(t *testing.T) {
	creator := func() interface{} {
		return &ExchangerAdminRequest{}
	}

	r := &ExchangerAdminRequest{}
	var a *ExchangerAdminData
	a = &ExchangerAdminData{
		Sender: randomAddress(),
		Nonce:  1123,
	}

	r.Data = a
	objectcodectest(t, r, creator)

	r.Sigs = [][]byte{
		common.RandomBytes(131),
	}

	objectcodectest(t, r, creator)

	a = &ExchangerAdminData{
		Sender:       randomAddress(),
		Nonce:        0,
		NewRate:      new(big.Rat).SetFrac64(21325, 8907347),
		NewNeedSigns: 3,
		NewAdminPubs: [][]byte{
			common.RandomBytes(32),
			common.RandomBytes(32),
			common.RandomBytes(32),
			common.RandomBytes(32),
		},
	}

	r = &ExchangerAdminRequest{
		Data: a,
	}
	objectcodectest(t, r, creator)
	r.Sigs = [][]byte{
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
	}
	objectcodectest(t, r, creator)

	r.Pubs = [][]byte{
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
	}
	a.NewNeedSigns = -1
	objectcodectest(t, r, creator)

	a.NewRate = nil
	objectcodectest(t, r, creator)
}

func TestExchangerWithdrawData(t *testing.T) {
	creator := func() interface{} {
		return &ExchangerWithdrawData{}
	}

	a := &ExchangerWithdrawData{
		RequestAddr: randomAddress(),
		Nonce:       23434,
		WithdrawTo:  randomAddress(),
		UseLocal:    true,
		Value:       nil,
	}

	objectcodectest(t, a, creator)

	a.Value, _ = new(big.Int).SetString("2341232454623455354909873453", 10)
	objectcodectest(t, a, creator)
}

func TestExchangerWithdrawRequest(t *testing.T) {
	creator := func() interface{} {
		return &ExchangerWithdrawRequest{}
	}

	a := &ExchangerWithdrawData{
		RequestAddr: randomAddress(),
		Nonce:       23434,
		WithdrawTo:  randomAddress(),
		UseLocal:    true,
		Value:       nil,
	}

	r := &ExchangerWithdrawRequest{
		Data: a,
	}

	objectcodectest(t, r, creator)

	r.Sigs = [][]byte{
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
	}
	objectcodectest(t, r, creator)

	r.Pubs = [][]byte{
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
		common.RandomBytes(131),
	}
	objectcodectest(t, r, creator)
}

func TestChainSetting(t *testing.T) {
	creator := func() interface{} {
		return new(ChainSetting)
	}

	a := &ChainSetting{
		Name: "",
		Data: nil,
	}
	objectcodectest(t, a, creator)

	a.Sender = randomAddress()
	a.Nonce = 232323
	a.Name = "whoami"
	objectcodectest(t, a, creator)

	a.Data = common.RandomBytes(672)
	objectcodectest(t, a, creator)
}

func TestSetChainSettingRequest(t *testing.T) {
	creator := func() interface{} {
		return new(SetChainSettingRequest)
	}

	a := &SetChainSettingRequest{
		Data: nil,
		Sigs: nil,
		Pubs: nil,
	}

	a.Data = new(ChainSetting)
	objectcodectest(t, a, creator)

	a.Sigs = [][]byte{
		common.RandomBytes(131),
		common.RandomBytes(131),
	}
	objectcodectest(t, a, creator)

	a.Pubs = [][]byte{
		common.RandomBytes(131),
		common.RandomBytes(131),
	}
	objectcodectest(t, a, creator)

	a.Data.Sender = randomAddress()
	a.Data.Nonce = 88273
	a.Data.Name = "whereami"
	a.Data.Data = common.RandomBytes(783)
	objectcodectest(t, a, creator)
}
