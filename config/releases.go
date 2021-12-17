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

package config

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
)

type Release string

const (
	// all letters must be captitalized
	ORIGIN  Release = "ORIGIN"
	V2_10_3 Release = "V2_10_3"

	ORIGINFORKAT  common.Height = 0
	V2_10_3FORKAT common.Height = 30000000
)

var (
	_defaultReleases map[Release]common.Height

	SysReleases *Releases
)

func init() {
	_defaultReleases = map[Release]common.Height{
		ORIGIN:  ORIGINFORKAT,
		V2_10_3: V2_10_3FORKAT,
	}
}

func (r Release) IsValid() bool {
	_, ok := _defaultReleases[r]
	return ok
}

type ReleaseDef struct {
	Name   Release       `yaml:"name"`
	ForkAt common.Height `yaml:"fork"`
}

func (d ReleaseDef) String() string {
	return fmt.Sprintf("Release{%s:%d}", d.Name, d.ForkAt)
}

type ReleaseDefs []ReleaseDef

func (defs ReleaseDefs) Validate() error {
	releases, err := NewReleases(defs)
	if err != nil {
		return err
	}
	SysReleases = releases
	log.Infof("system releases set to %s", releases)
	return nil
}

type Releases struct {
	m map[Release]common.Height
	l []Release
}

func NewReleases(defs ReleaseDefs) (*Releases, error) {
	mm := make(map[Release]common.Height)
	l := make([]Release, 0, len(_defaultReleases))
	for _, def := range defs {
		name := Release(strings.ToUpper(string(def.Name)))
		if !name.IsValid() {
			continue
		}
		if old, exist := mm[name]; !exist {
			mm[name] = def.ForkAt
			l = append(l, name)
		} else {
			if def.ForkAt != old {
				return nil, fmt.Errorf("duplicated release defination: %s", name)
			}
		}
	}

	for name, forkat := range _defaultReleases {
		if _, exist := mm[name]; exist {
			continue
		}
		mm[name] = forkat
		l = append(l, name)
	}

	sort.Slice(l, func(i, j int) bool {
		hi, ei := mm[l[i]]
		if ei == false {
			return true
		}
		hj, ej := mm[l[j]]
		if ej == false {
			return false
		}
		return hi < hj
	})

	return &Releases{
		m: mm,
		l: l,
	}, nil
}

func (rl Releases) String() string {
	if len(rl.m) == 0 {
		return "Releases[]"
	}
	buf := new(bytes.Buffer)
	buf.WriteString("Releases[")
	for i, name := range rl.l {
		if i > 0 {
			buf.WriteString(", ")
		}
		forkat, exist := rl.m[name]
		if !exist {
			forkat = common.NilHeight
		}
		buf.WriteString(fmt.Sprintf("{%s:%s}", name, &forkat))
	}
	buf.WriteByte(']')
	return buf.String()
}

func (rl Releases) IsForked(release Release, current common.Height) bool {
	if len(rl.m) == 0 {
		return false
	}
	forkat, exist := rl.m[release]
	if !exist {
		return false
	}
	return forkat <= current
}

func (rl Releases) Which(height common.Height) (at Release, exist bool) {
	if len(rl.m) == 0 {
		return "", false
	}
	for _, release := range rl.l {
		forkat, ok := rl.m[release]
		if !ok {
			continue
		}
		if forkat == height {
			return release, true
		}
		if forkat < height {
			at = release
			exist = true
		} else {
			return
		}
	}
	return
}
