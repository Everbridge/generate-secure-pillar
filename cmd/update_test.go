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
	"strings"
	"testing"
)

func TestRunUpdate_Validation(t *testing.T) {
	fc := &fakeCrypter{}
	cases := []struct {
		name   string
		opts   UpdateOpts
		errSub string
	}{
		{"input traversal", UpdateOpts{Crypter: fc, InputFilePath: "../etc/x.sls", NameStr: "k", ValueStr: "v"}, "invalid file path"},
		{"missing names", UpdateOpts{Crypter: fc, InputFilePath: "/tmp/x.sls", NameStr: "", ValueStr: "v"}, "no secret names"},
		{"length mismatch", UpdateOpts{Crypter: fc, InputFilePath: "/tmp/x.sls", NameStr: "k1,k2", ValueStr: "v1"}, "mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runUpdate(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestRunUpdate_HappyPath(t *testing.T) {
	dir := t.TempDir()
	in := writeSlsFile(t, dir, "in.sls", "key1: oldvalue\n")

	fc := &fakeCrypter{}
	if err := runUpdate(UpdateOpts{
		Crypter:       fc,
		InputFilePath: in,
		NameStr:       "key1",
		ValueStr:      "newvalue",
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.encrypted) != 1 || fc.encrypted[0] != "newvalue" {
		t.Errorf("expected one encryption of newvalue, got %v", fc.encrypted)
	}
	got, err := os.ReadFile(in)
	if err != nil {
		t.Fatalf("read updated file: %v", err)
	}
	if !strings.Contains(string(got), "ENC[newvalue]") {
		t.Errorf("updated file missing new ciphertext: %s", got)
	}
}
