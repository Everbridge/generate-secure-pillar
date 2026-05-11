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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDecrypt_Validation(t *testing.T) {
	fc := &fakeCrypter{}
	cases := []struct {
		name   string
		opts   DecryptOpts
		errSub string
	}{
		{"input traversal", DecryptOpts{Crypter: fc, Subcommand: all, InputFilePath: "../etc/passwd"}, "invalid input file path"},
		{"output traversal", DecryptOpts{Crypter: fc, Subcommand: all, OutputFilePath: "../out"}, "invalid output file path"},
		{"recurse traversal", DecryptOpts{Crypter: fc, Subcommand: recurse, RecurseDir: "../bad"}, "invalid directory path"},
		{"unknown subcommand", DecryptOpts{Crypter: fc, Subcommand: "wat"}, "unknown subcommand"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runDecrypt(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestRunDecrypt_AllRoundTrip(t *testing.T) {
	dir := t.TempDir()
	contents := fmt.Sprintf("k1: |\n  %s\n", strings.ReplaceAll(fakeEncrypt("hidden"), "\n", "\n  "))
	in := writeSlsFile(t, dir, "in.sls", contents)
	out := filepath.Join(dir, "out.sls")

	fc := &fakeCrypter{}
	if err := runDecrypt(DecryptOpts{
		Crypter:        fc,
		Subcommand:     all,
		InputFilePath:  in,
		OutputFilePath: out,
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.decrypted) != 1 {
		t.Errorf("expected one decrypt call, got %d", len(fc.decrypted))
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(got), "hidden") {
		t.Errorf("decrypted output missing plaintext: %s", got)
	}
}

func TestRunDecrypt_DecryptErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	contents := fmt.Sprintf("k1: |\n  %s\n", strings.ReplaceAll(fakeEncrypt("x"), "\n", "\n  "))
	in := writeSlsFile(t, dir, "in.sls", contents)

	fc := &fakeCrypter{decryptErr: errors.New("bad key")}
	err := runDecrypt(DecryptOpts{
		Crypter:        fc,
		Subcommand:     all,
		InputFilePath:  in,
		OutputFilePath: filepath.Join(dir, "out.sls"),
	})
	if err == nil || !strings.Contains(err.Error(), "bad key") {
		t.Errorf("expected decrypt error to bubble up, got %v", err)
	}
}
