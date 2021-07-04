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
	"testing"

	"github.com/stephenfire/go-rtl"
)

func TestReceiptsCodec(t *testing.T) {
	s := "91988001a26e5880c05c2fd29c9c0a64455478b0f434767183496b9ae378248fc63212dce7183972c5d40000000000000000000000000000000000000000a26e58e2010a9298c087b3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e400008000b10a043c33c1937564800000a70200000001010cd4000000000000000000000000000000000001000492941093a1b7dfb3ba18dae356aa041f25b20bdd61fc5f8ecaae89f275263c3db79f1c34c9e4c2000080809408934080c2d61f80810004e63d45f35e23dcf91c883e014a837ea9b7b5d7cb296b859e6cc2873303f095eafb1c8382c9a71b1166cec32716b8b0f834100199ec1bcde91b3b6ab5909ac9aa8213d6ebae436259e0c4d74d46132539aae3fc329272d4d3f2ff3ecaed192bec061bd6c8a66afc1b16eac7c44c66d583399fc256878d12a7d0c0a14f4cc48bcc000105"
	bs, _ := hex.DecodeString(s)
	receipts := make(Receipts, 0)
	if err := rtl.Decode(bytes.NewBuffer(bs), &receipts); err != nil {
		t.Errorf("decode receipts error: %v", err)
		return
	}
	t.Logf("%v", receipts)
	t.Logf("%x", receipts[0].Out)
}
