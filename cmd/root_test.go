// Copyright © 2018 Everbridge, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// withGlobals saves and restores the cobra package globals that root_test
// mutates, so tests can run in any order without leaking state.
func withGlobals(t *testing.T, f func()) {
	t.Helper()
	prevKey, prevHome, prevCfg := pgpKeyName, gnupgHome, cfgFile
	t.Cleanup(func() {
		pgpKeyName, gnupgHome, cfgFile = prevKey, prevHome, prevCfg
		viper.Reset()
	})
	f()
}

func TestGetPki_RejectsEmptyKeyName(t *testing.T) {
	withGlobals(t, func() {
		pgpKeyName = ""
		gnupgHome = "/tmp"
		_, err := getPki()
		if err == nil || !strings.Contains(err.Error(), "PGP key name") {
			t.Errorf("expected empty-key error, got %v", err)
		}
	})
}

func TestGetPki_RejectsEmptyHome(t *testing.T) {
	withGlobals(t, func() {
		pgpKeyName = "Test"
		gnupgHome = ""
		_, err := getPki()
		if err == nil || !strings.Contains(err.Error(), "GnuPG home") {
			t.Errorf("expected empty-home error, got %v", err)
		}
	})
}

func TestInitConfigE_RejectsTraversalInCfgFile(t *testing.T) {
	withGlobals(t, func() {
		cfgFile = "../etc/passwd"
		err := initConfigE()
		if err == nil || !strings.Contains(err.Error(), "directory traversal") {
			t.Errorf("expected directory traversal error, got %v", err)
		}
	})
}

func TestReadProfileE_NoProfilesIsNoop(t *testing.T) {
	withGlobals(t, func() {
		viper.Reset()
		pgpKeyName = "original"
		gnupgHome = "/original"
		if err := readProfileE(); err != nil {
			t.Errorf("unexpected err: %v", err)
		}
		if pgpKeyName != "original" || gnupgHome != "/original" {
			t.Errorf("globals should be untouched, got key=%q home=%q", pgpKeyName, gnupgHome)
		}
	})
}

func TestReadProfileE_MalformedProfilesArrayReturnsError(t *testing.T) {
	withGlobals(t, func() {
		viper.Reset()
		viper.Set("profiles", "not-an-array")
		pgpKeyName = "" // force the profile-application branch
		err := readProfileE()
		if err == nil || !strings.Contains(err.Error(), "not a valid array") {
			t.Errorf("expected malformed-array error, got %v", err)
		}
	})
}

func TestReadProfileE_AppliesDefaultProfile(t *testing.T) {
	withGlobals(t, func() {
		viper.Reset()
		viper.Set("profiles", []interface{}{
			map[string]interface{}{
				"default":     true,
				"gnupg_home":  "/profile/home",
				"default_key": "ProfileKey",
			},
		})
		pgpKeyName = "" // empty triggers profile read
		gnupgHome = "/original"
		if err := readProfileE(); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if pgpKeyName != "ProfileKey" {
			t.Errorf("pgpKeyName should be set from profile, got %q", pgpKeyName)
		}
		if gnupgHome != "/profile/home" {
			t.Errorf("gnupgHome should be set from profile, got %q", gnupgHome)
		}
	})
}

func TestReadProfileE_RejectsTraversalInProfileHome(t *testing.T) {
	withGlobals(t, func() {
		viper.Reset()
		viper.Set("profiles", []interface{}{
			map[string]interface{}{
				"default":    true,
				"gnupg_home": "../etc",
			},
		})
		pgpKeyName = ""
		gnupgHome = "/original"
		if err := readProfileE(); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if gnupgHome != "/original" {
			t.Errorf("traversal in profile.gnupg_home should be rejected; gnupgHome=%q", gnupgHome)
		}
	})
}
