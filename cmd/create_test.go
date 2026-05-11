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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCreate_Validation(t *testing.T) {
	fc := &fakeCrypter{}
	cases := []struct {
		name   string
		opts   CreateOpts
		errSub string
	}{
		{
			"output traversal",
			CreateOpts{Crypter: fc, OutputFilePath: "../out.sls", NameStr: "k", ValueStr: "v"},
			"invalid output file path",
		},
		{
			"missing names",
			CreateOpts{Crypter: fc, OutputFilePath: "/tmp/x.sls", NameStr: "", ValueStr: "v"},
			"no secret names",
		},
		{
			"length mismatch",
			CreateOpts{Crypter: fc, OutputFilePath: "/tmp/x.sls", NameStr: "k1,k2", ValueStr: "v1"},
			"mismatch",
		},
		{
			"empty name in list",
			CreateOpts{Crypter: fc, OutputFilePath: "/tmp/x.sls", NameStr: "k1, ,k3", ValueStr: "v1,v2,v3"},
			"empty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runCreate(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestRunCreate_HappyPath(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "new.sls")

	fc := &fakeCrypter{}
	if err := runCreate(CreateOpts{
		Crypter:        fc,
		OutputFilePath: out,
		NameStr:        "key1,key2",
		ValueStr:       "val1,val2",
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.encrypted) != 2 {
		t.Errorf("expected 2 encryptions, got %d", len(fc.encrypted))
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for _, want := range []string{"ENC[val1]", "ENC[val2]", "key1:", "key2:"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("output missing %q: %s", want, got)
		}
	}
}

func TestRunCreate_StripsBrackets(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "n.sls")

	fc := &fakeCrypter{}
	if err := runCreate(CreateOpts{
		Crypter:        fc,
		OutputFilePath: out,
		NameStr:        "[k1,k2]",
		ValueStr:       "[v1,v2]",
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.encrypted) != 2 || fc.encrypted[0] != "v1" {
		t.Errorf("bracket stripping should yield clean tokens, got %v", fc.encrypted)
	}
}
