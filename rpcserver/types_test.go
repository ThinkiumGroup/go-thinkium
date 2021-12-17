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

package rpcserver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

func TestJSON(t *testing.T) {
	type resultObj struct {
		PrivateKey string `json:"privatekey"`
		PublicKey  string `json:"publickey"`
		Hash       string `json:"hash"`
		Signature  string `json:"signature"`
	}

	s := "{}"
	o := new(resultObj)
	if err := json.Unmarshal([]byte(s), o); err != nil {
		t.Errorf("%v", err)
	} else {
		t.Logf("%+v", o)
	}
}

func TestCashCheck(t *testing.T) {
	addr, _ := hex.DecodeString("f167a1c5c5fab6bddca66118216817af3fa86827")
	rcc := &RpcCashCheck{
		Chainid: 1,
		From: &RpcAddress{
			Chainid: 1,
			Address: common.CopyBytes(addr),
		},
		To: &RpcAddress{
			Chainid: 2,
			Address: common.CopyBytes(addr),
		},
		Nonce:        174,
		ExpireHeight: 5607804,
		Amount:       "100000000000000000000",
		Uselocal:     false,
	}

	cc, err := rcc.ToCashCheck()
	if err != nil {
		t.Fatal(err)
	}

	hh, _ := hex.DecodeString("6f3f2fcefbd61b20496a49f19835dca2683f659fc8e5866d6b2b0816fd2f8817")
	h, err := common.HashObject(cc)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(h, hh) {
		t.Logf("%s hash:%x", cc, h)
	} else {
		t.Fatalf("%s hash:%x but expecting:%x", cc, h, hh)
	}
}

func TestRpcTx_HashValue(t *testing.T) {
	from, _ := hex.DecodeString("3438b5f0abbcc929d01ecc83e3507d4adb134674")
	to, _ := hex.DecodeString("3438b5f0abbcc929d01ecc83e3507d4adb134674")
	pub, _ := hex.DecodeString("040143f425a7a5c34a8660975fade424e4b523a6c6ba896ddde1c91c815f27f564e8c49dfaadebfb39b72d6dccec35e1b24a3c01bf2245a36c3f52144f06faa22e")
	sig, _ := hex.DecodeString("8d7e63a7f9b5fe7c93f227287964a28d7c5c7df508acfbbaf788f3474095596066f9b436c06117a3ca9c8e30c5ea953be097742fd607133d787c13f94aff4e211c")

	var mpubs, msigs [][]byte
	for i := 0; i < 3; i++ {
		mpubs = append(mpubs, common.RandomBytes(65))
		msigs = append(msigs, common.RandomBytes(65))
	}

	rpctx := &RpcTx{
		Chainid: 1,
		From: &RpcAddress{
			Chainid: 1,
			Address: from,
		},
		To: &RpcAddress{
			Chainid: 1,
			Address: to,
		},
		Nonce:    63,
		Val:      "100000000000000000",
		Input:    nil,
		Uselocal: false,
		Extra:    nil,
	}

	hashChecker := func(rpctx *RpcTx, expecting []byte) []byte {
		if expecting == nil {
			tx, err := rpctx.ToTx()
			if err != nil {
				t.Fatalf("to Transaction failed: %v", err)
			}
			expecting, err = common.HashObject(tx)
			if err != nil {
				t.Fatalf("tx object hash failed: %v", err)
			}
			t.Logf("rpx:%s to %s, hash: %x", rpctx.PrintString(), tx.FullString(), expecting)
		}
		h, err := common.HashObject(rpctx)
		if err != nil {
			t.Fatalf("rpctx hash failed: %v", err)
		}
		if bytes.Equal(expecting, h) {
			t.Logf("expecting:%x ok", h)
		} else {
			t.Fatalf("expecting:%x rpxtxHash:%x", expecting, h)
		}
		return h
	}

	h1 := hashChecker(rpctx, nil)

	rpctx.Pub = pub
	rpctx.Sig = sig
	hashChecker(rpctx, h1)

	rpctx.Multipubs = mpubs
	rpctx.Multisigs = msigs
	hashChecker(rpctx, h1)

	rpctx.Extra = []byte("{\"ok\":true}")
	hh, _ := common.HashObject(rpctx)
	if bytes.Equal(h1, hh) {
		t.Fatalf("hash of rpctx with extra should not be: %x", hh)
	} else {
		t.Logf("different extra with different hash ok, h1:%x hh:%x", h1, hh)
	}
}
