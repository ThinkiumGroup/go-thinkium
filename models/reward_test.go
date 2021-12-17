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
	"math/big"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/stephenfire/go-rtl"
)

func TestUnmarshalRRProof(t *testing.T) {
	s := "9298c087b3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e400008000b10a043c33c1937564800000a70200000001010cd4000000000000000000000000000000000001000492941093a1b7dfb3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4c2000080809408934080c2d61f80810004e63d45f35e23dcf91c883e014a837ea9b7b5d7cb296b859e6cc2873303f095eafb1c8382c9a71b1166cec32716b8b0f834100199ec1bcde91b3b6ab5909ac9aa8213d6ebae436259e0c4d74d46132539aae3fc329272d4d3f2ff3ecaed192bec061bd6c8a66afc1b16eac7c44c66d583399fc256878d12a7d0c0a14f4cc48bcc000105"
	bs, _ := hex.DecodeString(s)
	p := new(RRProofs)
	if err := rtl.Unmarshal(bs, p); err != nil {
		t.Errorf("%v", err)
		return
	}
	t.Logf("%s", p)
}

func TestRRProofs(t *testing.T) {
	bs, err := hex.DecodeString("9298c087b3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4" +
		"00008000b10a043c33c1937564800000a70200000001010cd4000000000000000000000000000000000001000492941093a1b7dfb3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4c2000080809408934080c2d61f80810004e63d45f35e23dcf91c883e014a837ea9b7b5d7cb296b859e6cc2873303f095eafb1c8382c9a71b1166cec32716b8b0f834100199ec1bcde91b3b6ab5909ac9aa8213d6ebae436259e0c4d74d46132539aae3fc329272d4d3f2ff3ecaed192bec061bd6c8a66afc1b16eac7c44c66d583399fc256878d12a7d0c0a14f4cc48bcc000105")
	if err != nil {
		t.Error(err)
		return
	}
	p := new(RRProofs)
	if err = rtl.Unmarshal(bs, p); err != nil {
		t.Error(err)
		return
	}
	h, err := common.HashObject(p)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("Hash: %x, Object: %s", h, p)

	bs1, err := rtl.Marshal(p)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(bs, bs1) {
		t.Errorf("encoding error mismatch stream: %x", bs1)
		return
	}

	pp := new(RRProofs)
	if err = rtl.Unmarshal(bs1, pp); err != nil {
		t.Error(err)
		return
	}
	hh, err := common.HashObject(pp)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("Hash: %x, Object: %s", hh, pp)

	if !bytes.Equal(hh, h) {
		t.Errorf("hash not match")
	} else {
		t.Logf("hash match")
	}
}

func TestRRStatusAct(t *testing.T) {
	type test struct {
		a, b int64
		n    int64
		err  bool
	}

	vs := []test{
		{0, 1, 0, true},
		{1, 0, 0, true},
		{-1, 1, 0, true},
		{-(math.MaxUint16 + 1), -1, 0, true},
		{1, math.MaxUint16 + 1, 0, true},
		{1, 1, 1, false},
		{-1, -1, -1, false},
		{256, 1, 257, false},
		{255, 1, 255, false},
		{-256, -1, -257, false},
		{-255, -9, -255, false},
	}

	for _, v := range vs {
		a := (*RRStatusAct)(big.NewInt(v.a))
		b := (*RRStatusAct)(big.NewInt(v.b))
		err := a.Merge(b)
		witherr := err != nil
		if (witherr && !v.err) || (witherr == false && (*big.Int)(a).Int64() != v.n) {
			t.Fatalf("%d merge %d expecting %d with(%t) error, but: %d with(%t) error:%v", v.a, v.b, v.n, v.err, (*big.Int)(a).Int64(), err != nil, err)
		}
	}
	t.Logf("RRStatusAct.Merge check")
}

func TestRRStatus(t *testing.T) {
	type test struct {
		changing int64
		nvalue   RRStatus
		msg      string
		changed  bool
	}
	vs := []test{
		{0, 0, "", false},
		{1, 1, "SET", true},
		{2, 3, "SET", true},
		{math.MaxUint16, math.MaxUint16, "SET", true},
		{math.MaxUint16 + 1, math.MaxUint16, "", false},
		{-1, math.MaxUint16 - 1, "CLR", true},
		{7, math.MaxUint16, "SET", true},
		{7, math.MaxUint16, "SET", false},
		{-(math.MaxUint16 + 1), math.MaxUint16, "", false},
		{-15, math.MaxUint16 - 15, "CLR", true},
		{-8, math.MaxUint16 - 15, "CLR", false},
		{-math.MaxUint16, 0, "CLR", true},
		{-255, 0, "CLR", false},
	}

	status := RRStatus(0)
	var nvalue RRStatus
	var msg string
	var changed bool
	for _, v := range vs {
		act := big.NewInt(v.changing)
		nvalue, msg, changed = status.Change(act)
		if nvalue != v.nvalue || msg != v.msg || changed != v.changed {
			t.Fatalf("%d(%s)->(%d,%s,%t) but expecting:(%d,%s,%t)", status, act, v.nvalue, v.msg, v.changed, nvalue, msg, changed)
		}
		status = nvalue
	}

	t.Logf("RRStatus.Change checked")

	status = 0x8083
	if status.Match(0x1) {
		t.Logf("%x matchs 0x1 check", status)
	} else {
		t.Fatalf("%x matchs 0x1 failed", status)
	}
	if status.Match(0x0f80) == false {
		t.Logf("%x not match 0x0f80 check", status)
	} else {
		t.Fatalf("%x not match 0x0f80 failed", status)
	}
}
