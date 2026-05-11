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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEncrypt_Validation(t *testing.T) {
	fc := &fakeCrypter{}
	cases := []struct {
		name    string
		opts    EncryptOpts
		errSub  string
	}{
		{
			"input file path traversal",
			EncryptOpts{Crypter: fc, Subcommand: all, InputFilePath: "../etc/passwd", OutputFilePath: "/tmp/out"},
			"invalid input file path",
		},
		{
			"output file path traversal",
			EncryptOpts{Crypter: fc, Subcommand: all, OutputFilePath: "../bad"},
			"invalid output file path",
		},
		{
			"recurse dir traversal",
			EncryptOpts{Crypter: fc, Subcommand: recurse, RecurseDir: "../etc"},
			"invalid directory path",
		},
		{
			"unknown subcommand",
			EncryptOpts{Crypter: fc, Subcommand: "frobnicate"},
			"unknown subcommand",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runEncrypt(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected error containing %q, got %v", tc.errSub, err)
			}
		})
	}
}

func TestRunEncrypt_AllHappyPath(t *testing.T) {
	dir := t.TempDir()
	in := writeSlsFile(t, dir, "in.sls", "key1: value1\nkey2: value2\n")
	out := filepath.Join(dir, "out.sls")

	fc := &fakeCrypter{}
	if err := runEncrypt(EncryptOpts{
		Crypter:        fc,
		Subcommand:     all,
		InputFilePath:  in,
		OutputFilePath: out,
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
	if !strings.Contains(string(got), "ENC[value1]") {
		t.Errorf("output missing encrypted value1: %s", got)
	}
}

func TestRunEncrypt_RejectsIncludeFile(t *testing.T) {
	dir := t.TempDir()
	in := writeSlsFile(t, dir, "in.sls", "include:\n  - other.sls\nkey: value\n")
	fc := &fakeCrypter{}
	err := runEncrypt(EncryptOpts{
		Crypter:        fc,
		Subcommand:     all,
		InputFilePath:  in,
		OutputFilePath: filepath.Join(dir, "out.sls"),
	})
	if err == nil || !strings.Contains(err.Error(), "include") {
		t.Errorf("expected include error, got %v", err)
	}
}

func TestRunEncrypt_PerformActionErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	in := writeSlsFile(t, dir, "in.sls", "key: value\n")
	fc := &fakeCrypter{encryptErr: errors.New("simulated crypto failure")}
	err := runEncrypt(EncryptOpts{
		Crypter:        fc,
		Subcommand:     all,
		InputFilePath:  in,
		OutputFilePath: filepath.Join(dir, "out.sls"),
	})
	if err == nil || !strings.Contains(err.Error(), "simulated crypto failure") {
		t.Errorf("expected crypto failure error, got %v", err)
	}
}

func TestRunEncrypt_RecurseEncryptsAllFiles(t *testing.T) {
	dir := t.TempDir()
	writeSlsFile(t, dir, "a.sls", "k: va\n")
	writeSlsFile(t, dir, "b.sls", "k: vb\n")
	fc := &fakeCrypter{}
	if err := runEncrypt(EncryptOpts{
		Crypter:    fc,
		Subcommand: recurse,
		RecurseDir: dir,
	}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(fc.encrypted) != 2 {
		t.Errorf("expected 2 encryptions (one per file), got %d", len(fc.encrypted))
	}
}
