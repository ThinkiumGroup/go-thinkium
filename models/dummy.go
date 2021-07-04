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
	"encoding/hex"

	"github.com/ThinkiumGroup/go-common"
)

type DummyCurrencier struct {
	pubs           [][]byte
	privs          [][]byte
	exchangerPubs  [][]byte
	exchangerPrivs [][]byte
}

var (
	dummycurrencier *DummyCurrencier
	// dummyprivs      [][]byte
)

func parseOnePair(privHex, pubHex string) ([]byte, []byte, error) {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, nil, err
	}
	priv, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func appendOnePair(privs, pubs [][]byte, privHex, pubHex string) ([][]byte, [][]byte) {
	priv, pub, err := parseOnePair(privHex, pubHex)
	if err != nil {
		panic(err)
	}
	privs = append(privs, priv)
	pubs = append(pubs, pub)
	return privs, pubs
}

func init() {
	dummycurrencier = new(DummyCurrencier)
	var privs, pubs [][]byte
	privs, pubs = appendOnePair(privs, pubs, "e9b294f79f41bc1751bbd3f60eb15cb94828a734376088d5c34c3d3f9fcf9477",
		"04c2154e245d5726e5c54498c821a7aa96966b05e8d829927b9e55ca98b565dc9c41433e8afc90d06ea0ff4d384d25d0d1307887dfbaaf002c78bdf3d0a8529027")
	privs, pubs = appendOnePair(privs, pubs, "537a8de3ee90cbab6bd890600793a875be55e1b55b3174f2654023fe502a091d",
		"047cecfd2e39942ebdb963c6fd6aa24158ab3798c9f95dd739006455269c338106815b5a5bc9601aa997f17307fabbc13313e6c85081ed7a4d3f52aab9c16a732d")
	privs, pubs = appendOnePair(privs, pubs, "8450b1940a4b277b0a173065b50e0da9c2dfacc354f3539509d071cb34a5cb21",
		"042554d0a87632f638dab13bdbfbd2785bc717ab18e1c1c009859fb4550b45bfa4e59e32a553686f906b9e892d7f1780e702af7a5a23d608938082d138e8981f9e")
	dummycurrencier.privs = privs
	dummycurrencier.pubs = pubs

	privs, pubs = nil, nil
	privs, pubs = appendOnePair(privs, pubs, "2606733910a2ad80e35b2017423e6fa55819623ce2105bc6de7136f213e629a6",
		"044f86cf6f56a422140cc7a8a13fefcb11be37afafb2b36ea7c981daff7896944ce848cfd9783bd1d910ad7c4e21e7be915509c128c4a5eba1bf95cd59ea121e3c")
	privs, pubs = appendOnePair(privs, pubs, "b0cf495b2c46a457aa0a136579bdfebb049c7d494e004a70c97ac1d79ce2ed7d",
		"04aceef5f61f1fbb777001355ce936a41eda49b6c3115c16b8132148e6d0631ba7e36e406343668c12fd30b5853a4c4bc91f2528688c246d7a25748fee05d15c25")
	privs, pubs = appendOnePair(privs, pubs, "7fb698b95198a2a256b0b3165c0acd2fba551c63c13bcef11bee178ca48dcefe",
		"040a52f0a66361f1e25d034442e434ea8ffd73d0437ecba5cc98795c92108cafd4d8e7fac8f18a667d452f0e48ae6f075c09cf86ad59f9de4c43d2a924d06123c7")
	dummycurrencier.exchangerPrivs = privs
	dummycurrencier.exchangerPubs = pubs
}

func (d *DummyCurrencier) GetChainLocalCurrencyInfo(id common.ChainID) (common.CoinID, string) {
	return common.CoinID(1), "USDT"
}

func (d *DummyCurrencier) GetChainAdmins(id common.ChainID) ([][]byte, bool) {
	return d.pubs, true
}

func (d *DummyCurrencier) GetChainAdminPrivs(id common.ChainID) ([][]byte, bool) {
	return d.privs, true
}

func (d *DummyCurrencier) HasLocalCurrency() bool {
	return true
}

func (d *DummyCurrencier) GetLocalCurrency() (common.CoinID, string) {
	return d.GetChainLocalCurrencyInfo(common.ChainID(1))
}

func (d *DummyCurrencier) GetAdmins() ([][]byte, bool) {
	return d.GetChainAdmins(1)
}

func (d *DummyCurrencier) GetAdminPrivs() ([][]byte, bool) {
	return d.GetChainAdminPrivs(1)
}

func (d *DummyCurrencier) GetCurrencyAdmins() (privs, pubs [][]byte) {
	return d.exchangerPrivs, d.exchangerPubs
}

func (d *DummyCurrencier) IsPocChain(chainid common.ChainID) bool {
	return false
}

func (d *DummyCurrencier) IsPoc() bool {
	return false
}

func GetDummyCurrencier() *DummyCurrencier {
	return dummycurrencier
}
