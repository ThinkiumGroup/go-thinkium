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
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

type ChainSetting struct {
	Sender common.Address // Address of sender, should same with TX.From
	Nonce  uint64         // TX.Nonce, Sender+Nonce combination should prevent replay attacks
	Name   string         // setting name to be set
	Data   []byte         // setting value to be set
}

func (s *ChainSetting) String() string {
	if s == nil {
		return "ChainSetting<nil>"
	}
	if len(s.Data) > 0 && len(s.Data) < 30 {
		return fmt.Sprintf("ChainSetting{Sender:%s Nonce:%d Name:%s Data:%x}", s.Sender, s.Nonce, s.Name, s.Data)
	}
	return fmt.Sprintf("ChainSetting{Sender:%s Nonce:%d Name:%s Len(Data):%d}", s.Sender, s.Nonce, s.Name, len(s.Data))
}

func (s *ChainSetting) Serialization(w io.Writer) error {
	if s == nil {
		return common.ErrNil
	}

	buf := make([]byte, common.AddressLength)
	copy(buf, s.Sender.Bytes())
	_, err := w.Write(buf)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint64(buf[:8], s.Nonce)
	_, err = w.Write(buf[:8])
	if err != nil {
		return err
	}

	err = writeByteSlice(w, 2, []byte(s.Name))
	if err != nil {
		return err
	}

	err = writeByteSlice(w, 4, s.Data)
	if err != nil {
		return err
	}
	return nil
}

func (s *ChainSetting) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	if s == nil {
		return false, common.ErrNil
	}

	// 20bytes adddress
	buf := make([]byte, common.AddressLength)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	s.Sender.SetBytes(buf)

	// 8bytes nonce
	_, err = io.ReadFull(r, buf[:8])
	if err != nil {
		return false, err
	}
	s.Nonce = binary.BigEndian.Uint64(buf[:8])

	bs, err := readByteSlice(r, 2)
	if err != nil {
		return false, err
	}
	s.Name = string(bs)

	bs, err = readByteSlice(r, 4)
	if err != nil {
		return false, err
	}
	s.Data = bs
	return false, nil
}

type SetChainSettingRequest struct {
	Data *ChainSetting // request content of setting
	Sigs [][]byte      // signature list
	Pubs [][]byte      // public key list corresponding to signature one by one
}

func (s *SetChainSettingRequest) String() string {
	if s == nil {
		return "Request<nil>"
	}
	return fmt.Sprintf("Request{%s Len(Sigs):%d Len(Pubs):%d}", s.Data, len(s.Sigs), len(s.Pubs))
}

func (s *SetChainSettingRequest) DataSerialize(w io.Writer) error {
	return rtl.Encode(s.Data, w)
}

func (s *SetChainSettingRequest) DataDeserialize(vr rtl.ValueReader) error {
	data := new(ChainSetting)
	err := rtl.Decode(vr, data)
	if err != nil {
		return err
	}
	s.Data = data
	return nil
}

func (s *SetChainSettingRequest) GetData() (o interface{}, exist bool) {
	return s.Data, s.Data != nil
}

func (s *SetChainSettingRequest) GetSigs() [][]byte {
	return s.Sigs
}

func (s *SetChainSettingRequest) SetSigs(sigs [][]byte) {
	s.Sigs = sigs
}

func (s *SetChainSettingRequest) GetPubs() [][]byte {
	return s.Pubs
}

func (s *SetChainSettingRequest) SetPubs(pubs [][]byte) {
	s.Pubs = pubs
}

func (s *SetChainSettingRequest) Serialization(w io.Writer) error {
	return dataRequesterSerialize(s, w)
}

func (s *SetChainSettingRequest) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	return dataRequesterDeserialize(s, r)
}

type ChainInfoChange struct {
	Sender common.Address // TX.From
	Nonce  uint64         // TX.Nonce, Sender + Nonce combination should prevent replay attacks
	Data   []byte         // information to be modified
}

func (s *ChainInfoChange) String() string {
	if s == nil {
		return "ChainInfoChange<nil>"
	}
	if len(s.Data) > 0 && len(s.Data) < 30 {
		return fmt.Sprintf("ChainInfoChange{Sender:%s Nonce:%d Data:%x}", s.Sender, s.Nonce, s.Data)
	}
	return fmt.Sprintf("ChainInfoChange{Sender:%s Nonce:%d Len(Data):%d}", s.Sender, s.Nonce, len(s.Data))
}

func (s *ChainInfoChange) Serialization(w io.Writer) error {
	if s == nil {
		return common.ErrNil
	}

	buf := make([]byte, common.AddressLength)
	dl := len(s.Data)
	binary.BigEndian.PutUint32(buf[:4], uint32(dl))
	_, err := w.Write(buf[:4])
	if err != nil {
		return err
	}

	copy(buf, s.Sender.Bytes())
	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint64(buf[:8], s.Nonce)
	_, err = w.Write(buf[:8])
	if err != nil {
		return err
	}

	_, err = w.Write(s.Data)
	if err != nil {
		return err
	}
	return nil
}

func (s *ChainInfoChange) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	if s == nil {
		return false, common.ErrNil
	}

	// 20bytes adddress
	buf := make([]byte, common.AddressLength)
	_, err = io.ReadFull(r, buf[:4])
	if err != nil {
		return false, err
	}
	dl := binary.BigEndian.Uint32(buf[:4])

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	s.Sender.SetBytes(buf)

	// 8bytes nonce
	_, err = io.ReadFull(r, buf[:8])
	if err != nil {
		return false, err
	}
	s.Nonce = binary.BigEndian.Uint64(buf[:8])

	buf = make([]byte, dl)
	i, err := io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	s.Data = buf[:i]
	return false, nil
}

type ChangeChainInfoRequest struct {
	Data *ChainInfoChange
	Sigs [][]byte // signature list
	Pubs [][]byte // public key list corresponding to signature one by one
}

func (s *ChangeChainInfoRequest) String() string {
	if s == nil {
		return "Request<nil>"
	}
	return fmt.Sprintf("Request{%s Len(Sigs):%d Len(Pubs):%d}", s.Data, len(s.Sigs), len(s.Pubs))
}

func (s *ChangeChainInfoRequest) DataSerialize(w io.Writer) error {
	return rtl.Encode(s.Data, w)
}

func (s *ChangeChainInfoRequest) DataDeserialize(vr rtl.ValueReader) error {
	data := new(ChainInfoChange)
	err := rtl.Decode(vr, data)
	if err != nil {
		return err
	}
	s.Data = data
	return nil
}

func (s *ChangeChainInfoRequest) GetData() (o interface{}, exist bool) {
	return s.Data, s.Data != nil
}

func (s *ChangeChainInfoRequest) GetSigs() [][]byte {
	return s.Sigs
}

func (s *ChangeChainInfoRequest) SetSigs(sigs [][]byte) {
	s.Sigs = sigs
}

func (s *ChangeChainInfoRequest) GetPubs() [][]byte {
	return s.Pubs
}

func (s *ChangeChainInfoRequest) SetPubs(pubs [][]byte) {
	s.Pubs = pubs
}

func (s *ChangeChainInfoRequest) Serialization(w io.Writer) error {
	return dataRequesterSerialize(s, w)
}

func (s *ChangeChainInfoRequest) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	return dataRequesterDeserialize(s, r)
}
