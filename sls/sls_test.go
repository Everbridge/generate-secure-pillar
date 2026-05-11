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

package sls

import (
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
)

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"plain text", "hello world", false},
		{"pgp message", "-----BEGIN PGP MESSAGE-----\nblah\n-----END PGP MESSAGE-----", true},
		{"pgp header only", pki.PGPHeader, true},
		{"partial header", "BEGIN PGP MESSAGE", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEncrypted(tt.input); got != tt.want {
				t.Errorf("isEncrypted(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{Encrypt, true},
		{Decrypt, true},
		{Validate, true},
		{Rotate, true},
		{"", false},
		{"delete", false},
		{"ENCRYPT", false}, // case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			if got := validAction(tt.action); got != tt.want {
				t.Errorf("validAction(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestContainsDirectoryTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// safe paths
		{"empty", "", false},
		{"plain file", "file.txt", false},
		{"nested", "dir/subdir/file.txt", false},
		{"absolute", "/usr/local/bin", false},
		{"dots in filename", "file.v1.0.txt", false},
		// regressions: previous implementation flagged any ".." substring
		{"double dots in filename", "my..file.txt", false},
		{"double dots inside component", "dir/with..in/middle", false},
		// dangerous paths
		{"basic traversal", "../file.txt", true},
		{"double traversal", "../../etc/passwd", true},
		{"backslash traversal", "..\\file.txt", true},
		{"mixed separators", "../dir\\file", true},
		{"middle traversal", "dir/../etc", true},
		{"just dot dot", "..", true},
		{"trailing dot dot", "dir/..", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsDirectoryTraversal(tt.path); got != tt.want {
				t.Errorf("containsDirectoryTraversal(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all same", []string{"x", "x", "x"}, []string{"x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeDuplicates(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("removeDuplicates(%v) length = %d, want %d", tt.in, len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("removeDuplicates(%v)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestScanForIncludes(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{"no includes", "key: value\nother: 1\n", false},
		{"top-level include", "include:\n  - other.sls\nkey: value\n", true},
		{"include later in file", "foo: bar\ninclude: thing\n", true},
		{"empty input", "", false},
		{"include in quoted value", "comment: 'include: foo'\n", true}, // matches by substring
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("", &pki.Pki{}, "")
			err := s.ScanForIncludes(strings.NewReader(tt.input))
			if (err != nil) != tt.wantError {
				t.Errorf("ScanForIncludes(%q): err=%v, wantError=%v", tt.input, err, tt.wantError)
			}
		})
	}
}

func TestReadBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantError   bool
		wantInclude bool
	}{
		{"valid yaml", "foo: bar\nbaz: qux\n", false, false},
		{"invalid yaml", "foo: [unclosed\n", true, false},
		{"include sets flag", "include:\n  - other.sls\n", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("", &pki.Pki{}, "")
			err := s.ReadBytes([]byte(tt.input))
			if (err != nil) != tt.wantError {
				t.Errorf("ReadBytes: err=%v, wantError=%v", err, tt.wantError)
			}
			if s.IsInclude != tt.wantInclude {
				t.Errorf("IsInclude = %v, want %v", s.IsInclude, tt.wantInclude)
			}
		})
	}
}

func TestFormatBuffer(t *testing.T) {
	t.Run("empty data returns error", func(t *testing.T) {
		s := New("", &pki.Pki{}, "")
		if _, err := s.FormatBuffer(Encrypt); err == nil {
			t.Errorf("expected error for empty data, got nil")
		}
	})

	t.Run("encrypt prepends gpg header", func(t *testing.T) {
		s := New("", &pki.Pki{}, "")
		s.Yaml.Values = map[string]interface{}{"key": "value"}
		buf, err := s.FormatBuffer(Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !strings.HasPrefix(buf.String(), "#!yaml|gpg\n") {
			t.Errorf("expected gpg header, got %q", buf.String())
		}
	})

	t.Run("validate omits gpg header", func(t *testing.T) {
		s := New("", &pki.Pki{}, "")
		s.KeyMap = map[string]interface{}{"key": "value"}
		buf, err := s.FormatBuffer(Validate)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if strings.HasPrefix(buf.String(), "#!yaml|gpg") {
			t.Errorf("validate should not prepend gpg header, got %q", buf.String())
		}
	})
}

func TestGetNode(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want interface{}
	}{
		{"nil", nil, nil},
		{"string", "hello", "hello"},
		{"int", 42, "42"},
		// regression: slice case was previously empty and dropped all values
		{"single-element slice", []interface{}{"a"}, "a"},
		{"empty slice", []interface{}{}, nil},
		{"map", map[string]interface{}{"k": "v"}, "v"},
		{"nested map", map[string]interface{}{"k": map[string]interface{}{"inner": "x"}}, "x"},
		{"slice of map", []interface{}{map[string]interface{}{"k": "v"}}, "v"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getNode(tt.in)
			if got != tt.want {
				t.Errorf("getNode(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
