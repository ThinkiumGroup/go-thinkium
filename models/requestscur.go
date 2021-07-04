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
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

type ExchangerAdminData struct {
	Sender       common.Address // Address of sender, should same with TX.From
	Nonce        uint64         // TX.Nonce, Sender+Nonce combination should prevent replay attacks
	NewRate      *big.Rat       // New consideration base currency: second currency
	NewNeedSigns int16          // During management operations, the number of valid signatures needs to be verified. <0 means no modification
	NewAdminPubs [][]byte       // The public key list of the administrator account, len(NewAdminPubs)==0 means no modification. Either don't change it, or change it all.
}

func (c *ExchangerAdminData) String() string {
	if c == nil {
		return "Admin<nil>"
	}
	if c.NewRate == nil {
		return fmt.Sprintf("Admin{Sender:%s Nonce:%d Rate:<nil> NeedSigns:%d len(AdminPubs):%d}",
			c.Sender, c.Nonce, c.NewNeedSigns, len(c.NewAdminPubs))
	}
	return fmt.Sprintf("Admin{Sender:%s Nonce:%d Rate:%s NeedSigns:%d len(AdminPubs):%d}",
		c.Sender, c.Nonce, c.NewRate, c.NewNeedSigns, len(c.NewAdminPubs))
}

func (c *ExchangerAdminData) Serialization(w io.Writer) error {
	if c == nil {
		return common.ErrNil
	}

	// 20bytes address
	buf := make([]byte, common.AddressLength)
	copy(buf, c.Sender.Bytes())
	_, err := w.Write(buf)
	if err != nil {
		return err
	}

	// 8bytes nonce, high bit first, big-endian
	binary.BigEndian.PutUint64(buf[:8], c.Nonce)
	_, err = w.Write(buf[:8])
	if err != nil {
		return err
	}

	// 2bytes length N (high bit first, big-endian), if N==0, it means NewRate is nil. Otherwise:
	// followed by N bytes, (base currency decimal digit string) + "/" + (local currency decimal
	// digit string)
	if c.NewRate == nil {
		err = writeByteSlice(w, 2, nil)
	} else {
		err = writeByteSlice(w, 2, []byte(c.NewRate.String()))
	}
	if err != nil {
		return err
	}

	// 2bytes NewNeedSigns, signed, high-order first, big-endian. Negative numbers are complement.
	// It can also be used as a maximum of 32767:0x7FFF, 0:0x0000, -1:0xFFFF
	binary.BigEndian.PutUint16(buf[:2], uint16(c.NewNeedSigns))
	_, err = w.Write(buf[:2])
	if err != nil {
		return err
	}

	// 2bytes N is the number of public keys，when N==0, it means NewAdminPubs is nil;
	// 1byte M is the bytes length of one public key, followed by N M bytes
	err = write2DByteSlice(w, c.NewAdminPubs)
	if err != nil {
		return err
	}

	return nil
}

func (c *ExchangerAdminData) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	if c == nil {
		return false, common.ErrNil
	}

	// 20bytes adddress
	buf := make([]byte, common.AddressLength)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return
	}
	c.Sender.SetBytes(buf)

	// 8bytes nonce
	_, err = io.ReadFull(r, buf[:8])
	if err != nil {
		return
	}
	c.Nonce = binary.BigEndian.Uint64(buf[:8])

	// rate
	rate, err := readByteSlice(r, 2)
	if err != nil {
		return false, err
	}
	if len(rate) > 0 {
		rat, ok := new(big.Rat).SetString(string(rate))
		if !ok || rat == nil {
			return false, errors.New(fmt.Sprintf("illegal exchange rate: %s", string(rate)))
		}
		c.NewRate = rat
	} else {
		c.NewRate = nil
	}

	// need signs
	_, err = io.ReadFull(r, buf[:2])
	if err != nil {
		return false, err
	}
	c.NewNeedSigns = int16(binary.BigEndian.Uint16(buf[:2]))

	// pubs
	pubs, err := read2DByteSlice(r)
	if err != nil {
		return false, err
	}
	c.NewAdminPubs = pubs

	return false, nil
}

type ExchangerAdminRequest struct {
	Data *ExchangerAdminData // The content of this management request
	SigsAndPubs
}

func (c *ExchangerAdminRequest) String() string {
	if c == nil {
		return "Request<nil>"
	}
	return fmt.Sprintf("Request{%s Len(Sigs):%d Len(Pubs):%d}", c.Data, len(c.Sigs), len(c.Pubs))
}

func (c *ExchangerAdminRequest) DataSerialize(w io.Writer) error {
	return rtl.Encode(c.Data, w)
}

func (c *ExchangerAdminRequest) DataDeserialize(vr rtl.ValueReader) error {
	data := new(ExchangerAdminData)
	err := rtl.Decode(vr, data)
	if err != nil {
		return err
	}
	c.Data = data
	return nil
}

func (c *ExchangerAdminRequest) GetData() (o interface{}, exist bool) {
	return c.Data, c.Data != nil
}

func (c *ExchangerAdminRequest) Serialization(w io.Writer) error {
	return dataRequesterSerialize(c, w)
}

func (c *ExchangerAdminRequest) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	return dataRequesterDeserialize(c, r)
}

type ExchangerWithdrawData struct {
	RequestAddr common.Address // sender address
	Nonce       uint64         // nonce of the system contract
	WithdrawTo  common.Address // account address to receive the value
	UseLocal    bool           // true for local-currency, false for basic currency
	Value       *big.Int       // amount to withdraw
}

func (d *ExchangerWithdrawData) String() string {
	if d == nil {
		return "Withdraw<nil>"
	}
	s := ""
	if d.Value != nil {
		s = d.Value.String()
	}
	return fmt.Sprintf("Withdraw{Request:%s Nonce:%d To:%s UseLocal:%t Value:%s}",
		d.RequestAddr, d.Nonce, d.WithdrawTo, d.UseLocal, s)
}

func (d *ExchangerWithdrawData) Serialization(w io.Writer) error {
	if d == nil {
		return common.ErrNil
	}

	// AddressLength bytes RequestAddr
	_, err := w.Write(d.RequestAddr[:])
	if err != nil {
		return err
	}

	// 8bytes nonce big-endian
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, d.Nonce)
	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	// AddressLength bytes WithdrawTo
	_, err = w.Write(d.WithdrawTo[:])
	if err != nil {
		return err
	}

	// 1byte 0x0:false other: true
	if d.UseLocal {
		buf[0] = 0x1
	} else {
		buf[0] = 0x0
	}
	_, err = w.Write(buf[:1])
	if err != nil {
		return err
	}

	// 1byte： Decimal digit length n of value， followed by a decimal digit with a length of n. If n == 0, it means nil
	if d.Value == nil {
		err = writeByteSlice(w, 1, nil)
	} else {
		err = writeByteSlice(w, 1, []byte(d.Value.String()))
	}
	if err != nil {
		return err
	}

	return nil
}

func (d *ExchangerWithdrawData) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	if d == nil {
		return false, common.ErrNil
	}

	buf := make([]byte, common.AddressLength)

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	d.RequestAddr = common.BytesToAddress(buf)

	_, err = io.ReadFull(r, buf[:8])
	if err != nil {
		return false, err
	}
	d.Nonce = binary.BigEndian.Uint64(buf[:8])

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	d.WithdrawTo = common.BytesToAddress(buf)

	// _, err = io.ReadFull(r, buf[:2])
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return false, err
	}
	d.UseLocal = !(buf[0] == 0x0)

	bs, err := readByteSlice(r, 1)
	if err != nil {
		return false, err
	}
	if len(bs) == 0 {
		d.Value = nil
	} else {
		v, ok := new(big.Int).SetString(string(bs), 10)
		if !ok || v == nil {
			return false, errors.New(fmt.Sprintf("restore big.Int failed. (%s)", string(bs)))
		}
		d.Value = v
	}

	return false, nil
}

type ExchangerWithdrawRequest struct {
	Data *ExchangerWithdrawData // The current withdraw data content
	SigsAndPubs
}

func (c *ExchangerWithdrawRequest) String() string {
	if c == nil {
		return "Request<nil>"
	}
	return fmt.Sprintf("Request{%s Len(Sigs):%d Len(Pubs):%d}", c.Data, len(c.Sigs), len(c.Pubs))
}

func (c *ExchangerWithdrawRequest) DataSerialize(w io.Writer) error {
	return rtl.Encode(c.Data, w)
}

func (c *ExchangerWithdrawRequest) DataDeserialize(vr rtl.ValueReader) error {
	data := new(ExchangerWithdrawData)
	if err := rtl.Decode(vr, data); err != nil {
		return err
	}
	c.Data = data
	return nil
}

func (c *ExchangerWithdrawRequest) GetData() (o interface{}, exist bool) {
	return c.Data, c.Data != nil
}

func (c *ExchangerWithdrawRequest) Serialization(w io.Writer) error {
	return dataRequesterSerialize(c, w)
}

func (c *ExchangerWithdrawRequest) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	return dataRequesterDeserialize(c, r)
}

type MinterMintData struct {
	Sender common.Address // request from address
	Nonce  uint64         // nonce of sender can prevent replay attach
	Value  *big.Int       // request value
	To     common.Address // receive value address
}

func (d *MinterMintData) String() string {
	if d == nil {
		return "Mint<nil>"
	}
	v := ""
	if d.Value != nil {
		v = d.Value.String()
	}
	return fmt.Sprintf("Mint{Sender:%s Nonce:%d Value:%s To:%s}", d.Sender, d.Nonce, v, d.To)
}

func (d *MinterMintData) Serialization(w io.Writer) error {
	if d == nil {
		return common.ErrNil
	}

	// AddressLength bytes Sender
	_, err := w.Write(d.Sender[:])
	if err != nil {
		return err
	}

	// 8bytes nonce big-endian
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, d.Nonce)
	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	// 1byte： Decimal digit length n of value， followed by a decimal digit with a length of n. If n == 0, it means nil
	if d.Value == nil {
		err = writeByteSlice(w, 1, nil)
	} else {
		err = writeByteSlice(w, 1, []byte(d.Value.String()))
	}
	if err != nil {
		return err
	}

	// AddressLength bytes To
	_, err = w.Write(d.To[:])
	if err != nil {
		return err
	}

	return nil
}

func (d *MinterMintData) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	if d == nil {
		return false, common.ErrNil
	}

	buf := make([]byte, common.AddressLength)

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	d.Sender = common.BytesToAddress(buf)

	_, err = io.ReadFull(r, buf[:8])
	if err != nil {
		return false, err
	}
	d.Nonce = binary.BigEndian.Uint64(buf[:8])

	bs, err := readByteSlice(r, 1)
	if err != nil {
		return false, err
	}
	if len(bs) == 0 {
		d.Value = nil
	} else {
		v, ok := new(big.Int).SetString(string(bs), 10)
		if !ok || v == nil {
			return false, errors.New(fmt.Sprintf("restore big.Int failed. (%s)", string(bs)))
		}
		d.Value = v
	}

	_, err = io.ReadFull(r, buf)
	if err != nil {
		return false, err
	}
	d.To = common.BytesToAddress(buf)

	return false, nil
}

type MinterMintReqeust struct {
	Data *MinterMintData // request data
	SigsAndPubs
}

func (c *MinterMintReqeust) String() string {
	if c == nil {
		return "Req<nil>"
	}
	return fmt.Sprintf("Req{%s Len(Sigs}:%d Len(Pubs):%d}", c.Data, len(c.Sigs), len(c.Pubs))
}

func (c *MinterMintReqeust) DataSerialize(w io.Writer) error {
	return rtl.Encode(c.Data, w)
}

func (c *MinterMintReqeust) DataDeserialize(vr rtl.ValueReader) error {
	data := new(MinterMintData)
	if err := rtl.Decode(vr, data); err != nil {
		return err
	}
	c.Data = data
	return nil
}

func (c *MinterMintReqeust) GetData() (o interface{}, exist bool) {
	return c.Data, c.Data != nil
}

func (c *MinterMintReqeust) Serialization(w io.Writer) error {
	return dataRequesterSerialize(c, w)
}

func (c *MinterMintReqeust) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	return dataRequesterDeserialize(c, r)
}
