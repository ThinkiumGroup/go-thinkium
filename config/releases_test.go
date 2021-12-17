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
	"testing"

	"gopkg.in/yaml.v2"
)

func testtoreleases(defines string) (release *Releases, yamlerr error, relerr error) {
	defs := make(ReleaseDefs, 0)
	if err := yaml.Unmarshal([]byte(defines), &defs); err != nil {
		return nil, err, nil
	}
	release, relerr = NewReleases(defs)
	return release, nil, relerr
}

func TestReleasesMarshal(t *testing.T) {
	defs := ReleaseDefs{ReleaseDef{
		Name:   "falseOne",
		ForkAt: 98765,
	}, ReleaseDef{
		Name:   "v2_10_3",
		ForkAt: 100000,
	}}
	buf, err := yaml.Marshal(defs)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	t.Logf("%s -> %s", defs, string(buf))
}

func TestReleases(t *testing.T) {
	{
		releases, err := NewReleases(nil)
		if err != nil {
			t.Fatalf("creating Releases with nil failed: %v", err)
		}
		if len(releases.l) != 2 ||
			releases.l[1] != "V2_10_3" {
			t.Fatalf("invalid releases: %s", releases)
		} else {
			t.Logf("releases ok: %s", releases)
		}
	}

	{
		releases, yamlerr, relerr := testtoreleases(`
- name: falseOne
  fork: 98765
- name: v2_10_3
  fork: 100000`)
		if yamlerr != nil || relerr != nil {
			t.Fatalf("yamlerror: %v, release error: %v", yamlerr, relerr)
		}
		if len(releases.l) != 2 ||
			releases.l[1] != "V2_10_3" {
			t.Fatalf("invalid releases: %s", releases)
		} else {
			t.Logf("releases ok: %s", releases)
		}
	}

	{
		releases, yamlerr, relerr := testtoreleases(`
- name: falseOne
  fork: 98765
- name: falseTwo
  fork: 98365
- name: v2_10_3
  fork: 100000
- name: V2_10_3
  fork: 100000
`)
		if yamlerr != nil || relerr != nil {
			t.Fatalf("yamlerror: %v, release error: %v", yamlerr, relerr)
		}
		if len(releases.l) != 2 ||
			releases.l[1] != "V2_10_3" {
			t.Fatalf("invalid releases: %s", releases)
		} else {
			t.Logf("releases ok: %s", releases)
		}
	}

	{
		releases, yamlerr, relerr := testtoreleases(`
- name: falseOne
  fork: 98765
- name: falseTwo
  fork: 98365
- name: v2_10_3
  fork: 100000
- name: V2_10_3
  fork: 100002
`)
		if yamlerr != nil {
			t.Fatalf("yamlerror: %v", yamlerr)
		}
		if relerr == nil {
			t.Fatalf("there should an error, but %s", releases)
		}
		t.Logf("got error: %s", relerr)
	}

}

func TestReleases_Which(t *testing.T) {
	releases, err := NewReleases(nil)
	if err != nil {
		t.Fatalf("create releases from nil failed: %v", err)
	}

	{
		h := ORIGINFORKAT
		r, exist := releases.Which(h)
		if !exist || r != ORIGIN {
			t.Fatalf("failed Which(%d)=%s, expecting %s", h, r, ORIGIN)
		} else {
			t.Logf("%s.Which(%d)=%s", releases, h, r)
		}
	}
	{
		h := ORIGINFORKAT + 1
		r, exist := releases.Which(h)
		if !exist || r != ORIGIN {
			t.Fatalf("failed Which(%d)=%s, expecting %s", h, r, ORIGIN)
		} else {
			t.Logf("%s.Which(%d)=%s", releases, h, r)
		}
	}
	{
		h := V2_10_3FORKAT - 1
		r, exist := releases.Which(h)
		if !exist || r != ORIGIN {
			t.Fatalf("failed Which(%d)=%s, expecting %s", h, r, ORIGIN)
		} else {
			t.Logf("%s.Which(%d)=%s", releases, h, r)
		}
	}
	{
		h := V2_10_3FORKAT
		r, exist := releases.Which(h)
		if !exist || r != V2_10_3 {
			t.Fatalf("failed Which(%d)=%s, expecting %s", h, r, V2_10_3)
		} else {
			t.Logf("%s.Which(%d)=%s", releases, h, r)
		}
	}
	{
		h := V2_10_3FORKAT + 100
		r, exist := releases.Which(h)
		if !exist || r != V2_10_3 {
			t.Fatalf("failed Which(%d)=%s, expecting %s", h, r, V2_10_3)
		} else {
			t.Logf("%s.Which(%d)=%s", releases, h, r)
		}
	}
}
