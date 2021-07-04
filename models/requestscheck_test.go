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
	"math/rand"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

func TestCashCheck_Serialization(t *testing.T) {
	for i := 0; i < 100; i++ {
		x := rand.Uint32()
		c := common.ChainID(x)
		y := rand.Uint64()
		check1 := &CashCheck{
			ParentChain:  c,
			IsShard:      x%2 == 0,
			FromChain:    c + 1,
			FromAddress:  randomAddress(),
			Nonce:        uint64(x) << 1,
			ToChain:      c - 1,
			ToAddress:    randomAddress(),
			ExpireHeight: common.Height(y),
			UserLocal:    y%2 == 0,
			Amount:       big.NewInt(int64(x)),
			CurrencyID:   common.CoinID(y),
		}

		buf := new(bytes.Buffer)
		if err := rtl.Encode(check1, buf); err != nil {
			t.Errorf("encode error: %v", err)
			return
		}

		check2 := new(CashCheck)
		if err := rtl.Decode(buf, check2); err != nil {
			t.Errorf("decode error: %v", err)
			return
		}

		if check1.Equal(check2) {
			t.Logf("%s check", check2)
		} else {
			t.Errorf("%s -> %s", check1, check2)
		}
	}
}

func TestCancelCashCheckRequest(t *testing.T) {
	buf, _ := hex.DecodeString("9700000001b0b0b030c7fb86977ef5c094f407b9a011ad16b9000000000000000000000002b0b0b030c7fb86977ef5c094f407b9a011ad16b90000000000fe2abc0a0a96f069a642b660000001a3fe29f8c0ea5f4c4d35aeaed6c8bc0473f728e52877f2af26e6c6fdd7638ab745663ad9fc9394a1fe934080c20088808100013b0c1351455da4699161f38299c6d78fa29cf9afc18d9d5094af62b1ea6a18fd00009404934080c2ffff808100043e4fe1f161d15e3dc5186ffd626f8609524be4a56e29569cd4c7a197a49f6b5878d916dcd6d14e59289ac8986b4168b96db4d61ea4492f4bcf082a34e99ff5b23f176008d3e30a574a9e4ba05fba96850cec7961581be190f78c7fa5726b7cd4aa4205064497e78539b59a68e9d55ef6a5c1d320bd99fbb752505a2ae29bb00f000104940e934080c2ffff80810004320dac5fe6060595072f614b616a9db101cad314d456e974ed2a5127fb9c7f8e93af6e50244864a71c3fb71411a918ea903b2792ac8639c10bcd825c393e292f6bf2256bc4f73a91673cd5ac6b188f595f6fd0b2c2b4894fc92e86cc45e2906be55feab745d9252912ebc9501c3a1fed90c275d756785f2bfce7d1602428d08900010e939425930080c20000c014a0a481822346b5012c97d082b66caeb07834135538980b5129a97a80e7d9f68100053d53c5d866b7f03a5b384f240d7aa038c52cbb9cd9f707531afe351f7a9ea8394efde10e69994e7e679fc87ccb0915af0dc07f8241a106c5225c1a09694b3caed1622965a7715ee416a888818a0df91446403e08034e024528b8c0ffb019cefba4e6c6a432a742dd110d9a539a62db6b6a0bcdc0088c0062c36326984e2c2df08f795ce7a9ee76775be3cdc8b1c6f109dcabe0867dd4919d601c5227863be0620001119411930080c20000c0301be411f3c51066451d5af5e5e39f941ef686b702a0afcb1c6506489c5587cd810002028099a463312da2ce099837c68966bbc7ba4e230b9bb63db98149566b40786eeae70af94a0983929ec799dc3640f331139023ae4d18368f995414b785c22e240001019426930080c20000c01ab5fa845de30aff91ead27f41188354c719042ec4ba9235c0dffdce693e8a5c81000549ea787dbb83a86792a097f0a34929f8a9bc24235224710967b9e82c49a3b20bb8257c1c0035bae5f734c34d0cd712dce56a6a9d3e09d5ecbf5c7f04c94a0e2942f9b19433d2d24315168ef285ceea182fe56e70e22762cd48def781d013e7a5458947256293f4046f0e208c5a71bfc62efd6c4b52d8f4b6f1a95125e57f4f9be1d765c21aba89d2947883d137dad86fb35357c847e0001f06464925ac28fe2b000114a3ff7114")
	cccr := &CancelCashCheckRequest{}
	err := rtl.Unmarshal(buf, cccr)
	if err != nil {
		t.Fatalf("unmarshal %v", err)
	}
	t.Logf("%v", cccr)

	hoc, hot, hoh, err := cccr.Verify(false)
	t.Logf("%x %x %x %v", hoc, hot, hoh, err)

	hoc, hot, hoh, err = cccr.Verify(true)
	t.Logf("%x %x %x %v", hoc, hot, hoh, err)
}

func TestCashRequest(t *testing.T) {
	buf, _ := hex.DecodeString("9500000002ee78172635edfe35de830b91bfc01bef8e14972e000000000000001f00000001ee78172635edfe35de830b91bfc01bef8e14972e00000000005539680904d31f847531c4000000a354a086c0cbddea6a020a7dfe5ecfb640a6f570864b5a1ed4b02162325d06341e06e749f797941093a1b3def955d9378195a6d1768762dabf5162f71ef8f90ab1f3d65a2ea8ee17c9e4c2000080809401934080c21e10808100033f85989d37ac5834f7a6400765e7019f318bbe6a61e1ebf34c689136f8a870be5671dd9c7e11ec8bf1fa3b81e33b514561b71a4a00ef2ff231cf2b4d162ee1c5cb9fc8107f15919ce0f2b9b0373621bf2e61981b9923fb3fd3a8ef66b23fd42d00009405934080c2ffff808100040b9f0edb44ece4ebdd1b3c92b358dee645f026f3c97a5e01f8fcad79209e9f061ef31f53282089d67f38a2f9ead5fa5683b0e721a963d5eeac186441f4315e20213ca9ae1407560b4e16d29536783d5fd791ab929ef1bf1d6e8d1a054bf7ffc8f22ece2e67d701142bf389e3675ef039119087dd85b34a085e062d25c4363b4e000105940e934080c2ffff80810004513e5d9d3549b19b19cd590b6c030b2c34344d9fd6216108067cad1cece05bc95b73e5c2bbc2d8c4011fba5f3eb94b5d92d4154e439e78504cd9f88f1441514fa33638208f68cc5b07298b340f994535233b570240aad07f7ba2e38074d2a574b8d9c2fb2240b9151b443c884a8c69a0cd72e0d4bc348d3cdb04e2285736c8c800010e9424930080c20000c0ac1fc4bab74cf200e4c6418e829fa9679a355cdd2539e26517073f673e8266dc8100057a9ecc83cd2fd0c77e64b411890929d1c01df8b80c15a612a252c59918972bc58bfc4bb4f3e8f79601374f723e8d9b19eadef47473f2a3771d4de2cc9cbc17df52abde9fa77cf1c8ac1b903622a3274b7784285ce62fc67557b2b95b535576b7fb73112093567d93935e0c8a8573efbd7c4d231d153916c060975800dbe0bee0b0be42db9c19824b4c313abd5705287c322a641cd0fdc48d63855f26882d4b1c00011094a1ff930080c200008081000201c63682d664ba0dbd54ede72fbbe8fa0752f0ebcbdc1c21e9a62555b44496d69dee29b89e31cf06e9c1320bc5f04ac4918eb77a7b624e3b40bc54241c0439b50001019426930080c20000c075b495faeac6223a81b703d9900c7039747a5aeaeeb9238aff2ed75b9bd766318100057b420cd1af0b155c98978ab45e007abbe3fa0d75596644de21ed07574ef4c12e880d946ff2a710e1e9e076f72d56e2d2a65b26646912f8ddfc5e728bd79f224cfb926bbbe94e62316795550a28abb9ab5b9746f1916f69fe5ac305381fc4b6cff8fa68ffffbc020076b2ad6b741e633c9d7c44d4a90bc7da32ddf8688f97fb5a6166b5e68bbe452929b97be649ca56a116217921133f3776828368da4fd1d0fc000114")
	cr := new(CashRequest)
	if err := rtl.Unmarshal(buf, cr); err != nil {
		t.Errorf("unmarshal %v", err)
		return
	}
	t.Logf("%v", cr)
	if _, err := cr.Verify(); err != nil {
		t.Errorf("verify %v", err)
	} else {
		t.Logf("verify ok")
	}
}

func TestWriteCashCheck(t *testing.T) {
	buf, _ := hex.DecodeString("000000016efa68acc13cfa097fc2ae372daea660e86cdccd0000000000000010000000026efa68acc13cfa097fc2ae372daea660e86cdccd000000000013fcef2000000000000000000000000000000000000000000000001b1ae4d6e2ef500000")
	cc := new(CashCheck)
	if err := rtl.Unmarshal(buf, cc); err != nil {
		t.Errorf("unmarshal %v", err)
		return
	}
	t.Logf("%v", cc)
}
