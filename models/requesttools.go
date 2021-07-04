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
	"io"

	"github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

// Write the two-dimensional byte slice pointed to by bss into w. The length of the second
// dimension must be the same, and it cannot be 0 and cannot exceed 255 length.
// 2bytes big-endian, The length of the first dimension N, if it is 0, it means nil
// 1byte The second dimension length M
// Followed by N M bytes
func write2DByteSlice(w io.Writer, bss [][]byte) error {
	buf := make([]byte, 2)
	l := len(bss)
	binary.BigEndian.PutUint16(buf, uint16(l))
	_, err := w.Write(buf)
	if err != nil {
		return err
	}
	if l == 0 {
		return nil
	}
	M := 0
	for i := 0; i < l; i++ {
		if i == 0 {
			M = len(bss[i])
			if M == 0 || M > 0xFF {
				return errors.New("illegal signature size")
			}
		} else {
			if M != len(bss[i]) {
				return errors.New("different signature size found")
			}
		}
	}
	buf[0] = byte(M)
	_, err = w.Write(buf[:1])
	if err != nil {
		return err
	}
	for i := 0; i < l; i++ {
		_, err = w.Write(bss[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func read2DByteSlice(r io.Reader) (bss [][]byte, err error) {
	buf := make([]byte, 2)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint16(buf)
	if l == 0 {
		bss = nil
		return nil, nil
	}
	_, err = io.ReadFull(r, buf[:1])
	if err != nil {
		return nil, err
	}
	M := int(buf[0])
	if M == 0 {
		return nil, errors.New("illegal size")
	}
	// var sigs [][]byte
	for i := uint16(0); i < l; i++ {
		bs := make([]byte, M)
		_, err = io.ReadFull(r, bs)
		if err != nil {
			return nil, err
		}
		bss = append(bss, bs)
	}
	return bss, nil
}

// uintType Specify the use of xbytes to store the length N (high-endian, big-endian), if N==0,
//          the content is nil. Otherwise: followed by N bytes
// uintType: 1: x=1, 2: x=2, 4: x=4, 8: x=8, otherwise error
func writeByteSlice(w io.Writer, uintType int, bs []byte) error {
	n := len(bs)
	var buf []byte
	switch uintType {
	case 1:
		if n > 0xFF {
			return errors.New("length is too big")
		}
		buf = make([]byte, 1)
		buf[0] = byte(n)
	case 2:
		if n > 0xFFFF {
			return errors.New("length is too big")
		}
		buf = make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(n))
	case 4:
		if n > 0xFFFFFFFF {
			return errors.New("length is too big")
		}
		buf = make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(n))
	case 8:
		buf = make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(n))
	default:
		return errors.New("unknown type")
	}
	_, err := w.Write(buf)
	if err != nil {
		return err
	}
	if n > 0 {
		_, err = w.Write(bs)
		if err != nil {
			return err
		}
	}
	return nil
}

func readByteSlice(r io.Reader, uintType int) (bs []byte, err error) {
	var buf []byte
	switch uintType {
	case 1:
		buf = make([]byte, 1)
	case 2:
		buf = make([]byte, 2)
	case 4:
		buf = make([]byte, 4)
	case 8:
		buf = make([]byte, 8)
	default:
		return nil, errors.New("unknown type")
	}
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	var n uint64
	switch uintType {
	case 1:
		n = uint64(buf[0])
	case 2:
		n = uint64(binary.BigEndian.Uint16(buf))
	case 4:
		n = uint64(binary.BigEndian.Uint32(buf))
	case 8:
		n = uint64(binary.BigEndian.Uint64(buf))
	default:
		return nil, errors.New("unknown type")
	}
	if n > 0 {
		bs = make([]byte, n)
		_, err = io.ReadFull(r, bs)
		if err != nil {
			return nil, err
		}
		return bs, nil
	}
	return nil, nil
}

type SigsAndPubs struct {
	Sigs [][]byte // signature list
	Pubs [][]byte // List of public keys corresponding to the signature list one-to-one
}

func (sp *SigsAndPubs) GetSigs() [][]byte {
	return sp.Sigs
}

func (sp *SigsAndPubs) SetSigs(sigs [][]byte) {
	sp.Sigs = sigs
}

func (sp *SigsAndPubs) GetPubs() [][]byte {
	return sp.Pubs
}

func (sp *SigsAndPubs) SetPubs(pubs [][]byte) {
	sp.Pubs = pubs
}

type DataRequester interface {
	DataSerialize(w io.Writer) error
	DataDeserialize(vr rtl.ValueReader) error
	GetData() (o interface{}, exist bool)
	GetSigs() [][]byte
	SetSigs(sigs [][]byte)
	GetPubs() [][]byte
	SetPubs(pubs [][]byte)
}

func dataRequesterSerialize(dr DataRequester, w io.Writer) error {
	if dr == nil {
		return common.ErrNil
	}
	err := dr.DataSerialize(w)
	if err != nil {
		return err
	}

	// Sigs, 2bytes big-endian
	// The number of signatures is N. If N==0, it means that there is no signature; 1byte The
	// length of each signature is M, followed by N M
	err = write2DByteSlice(w, dr.GetSigs())
	if err != nil {
		return err
	}

	// Pubs, 2bytes big-endian
	// The number of signatures is N, if N==0, it means that there is no public key; 1byte The
	// length of each signature is M, followed by N M
	err = write2DByteSlice(w, dr.GetPubs())
	if err != nil {
		return err
	}

	return nil
}

func dataRequesterDeserialize(dr DataRequester, r io.Reader) (shouldBeNil bool, err error) {
	if dr == nil {
		return false, common.ErrNil
	}

	vr, ok := r.(rtl.ValueReader)
	if !ok {
		vr = rtl.NewValueReader(r, 0)
	}

	err = dr.DataDeserialize(vr)
	if err != nil {
		return false, err
	}

	sigs, err := read2DByteSlice(vr)
	if err != nil {
		return false, err
	}
	dr.SetSigs(sigs)

	pubs, err := read2DByteSlice(vr)
	if err != nil {
		return false, err
	}
	dr.SetPubs(pubs)

	return false, nil
}
