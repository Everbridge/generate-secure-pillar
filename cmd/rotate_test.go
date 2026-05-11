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

func TestRunRotate_Validation(t *testing.T) {
	fc := &fakeCrypter{}
	cases := []struct {
		name   string
		opts   RotateOpts
		errSub string
	}{
		{"input traversal", RotateOpts{Crypter: fc, InputFilePath: "../etc/passwd"}, "invalid input file path"},
		{"recurse traversal", RotateOpts{Crypter: fc, RecurseDir: "../foo"}, "invalid directory path"},
		{"output traversal", RotateOpts{Crypter: fc, InputFilePath: "/tmp/in", OutputFilePath: "../out"}, "invalid output file path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRotate(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestRunRotate_NoInputReturnsSentinel(t *testing.T) {
	err := runRotate(RotateOpts{Crypter: &fakeCrypter{}})
	if !errors.Is(err, errRotateNoInput) {
		t.Errorf("expected errRotateNoInput, got %v", err)
	}
}

func TestRunRotate_HappyPath(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf("k1: |\n  %s\n", strings.ReplaceAll(fakeEncrypt("v1"), "\n", "\n  "))
	in := writeSlsFile(t, dir, "in.sls", body)
	out := filepath.Join(dir, "out.sls")

	fc := &fakeCrypter{}
	if err := runRotate(RotateOpts{
		Crypter:        fc,
		InputFilePath:  in,
		OutputFilePath: out,
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.decrypted) != 1 || len(fc.encrypted) != 1 {
		t.Errorf("expected one decrypt+encrypt cycle, got %d/%d", len(fc.decrypted), len(fc.encrypted))
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(got), "ENC[v1]") {
		t.Errorf("re-encrypted output missing fake marker: %s", got)
	}
}
