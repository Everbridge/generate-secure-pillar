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
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestRunKeys_Validation(t *testing.T) {
	fc := &fakeCrypter{}
	cases := []struct {
		name   string
		opts   KeysOpts
		errSub string
	}{
		{"input traversal", KeysOpts{Crypter: fc, Subcommand: all, InputFilePath: "../etc/passwd"}, "invalid input file path"},
		{"recurse traversal", KeysOpts{Crypter: fc, Subcommand: recurse, RecurseDir: "../foo"}, "invalid directory path"},
		{"unknown subcommand", KeysOpts{Crypter: fc, Subcommand: "snarf"}, "unknown subcommand"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runKeys(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestRunKeys_AllReportsKeyCount(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf("k1: |\n  %s\nk2: |\n  %s\n",
		strings.ReplaceAll(fakeEncrypt("v1"), "\n", "\n  "),
		strings.ReplaceAll(fakeEncrypt("v2"), "\n", "\n  "),
	)
	in := writeSlsFile(t, dir, "in.sls", body)

	fc := &fakeCrypter{}
	var out bytes.Buffer
	res, err := runKeys(KeysOpts{
		Crypter:       fc,
		Subcommand:    all,
		InputFilePath: in,
		Out:           &out,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.KeyCount < 1 {
		t.Errorf("expected positive key count, got %d", res.KeyCount)
	}
	// `all` prints the YAML form of KeyMap (one entry per top-level key);
	// the "N keys found" summary lives in s.KeyMeta and is shown by `count -v`.
	if !strings.Contains(out.String(), "TEST KEY") {
		t.Errorf("expected per-key info in output, got %q", out.String())
	}
}

func TestRunKeys_CountSubcommand(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf("k1: |\n  %s\n", strings.ReplaceAll(fakeEncrypt("v"), "\n", "\n  "))
	in := writeSlsFile(t, dir, "in.sls", body)

	fc := &fakeCrypter{}
	var out bytes.Buffer
	res, err := runKeys(KeysOpts{
		Crypter:       fc,
		Subcommand:    count,
		InputFilePath: in,
		Verbose:       true,
		Out:           &out,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.KeyCount < 1 {
		t.Errorf("expected positive key count, got %d", res.KeyCount)
	}
	if !strings.Contains(out.String(), "DEADBEEF") {
		t.Errorf("verbose mode should print KeyMeta containing key fingerprint, got %q", out.String())
	}
}
