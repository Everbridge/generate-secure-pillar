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

package pki

import (
	"os/user"
	"path/filepath"
	"testing"
)

func TestContainsDirectoryTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// safe
		{"plain file", "file.txt", false},
		{"nested", "dir/sub/file.txt", false},
		{"absolute", "/usr/local/bin", false},
		{"dotfile", ".gitkeep", false},
		{"double-dot in filename", "my..file.txt", false},
		// dangerous
		{"prefix traversal", "../file.txt", true},
		{"deep traversal", "../../etc/passwd", true},
		{"middle traversal", "dir/../file", true},
		{"trailing traversal", "dir/..", true},
		{"just dot dot", "..", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.FromSlash(tt.path)
			if got := containsDirectoryTraversal(path); got != tt.want {
				t.Errorf("containsDirectoryTraversal(%q) = %v, want %v", path, got, tt.want)
			}
		})
	}
}

func TestExpandTilde(t *testing.T) {
	usr, err := user.Current()
	if err != nil {
		t.Skipf("cannot get current user: %v", err)
	}

	tests := []struct {
		name      string
		in        string
		want      string
		wantError bool
	}{
		{"empty path", "", "", true},
		{"plain absolute path", "/usr/local/bin", "/usr/local/bin", false},
		{"tilde alone", "~", usr.HomeDir, false},
		{"tilde with subdir", "~/Documents", filepath.Join(usr.HomeDir, "Documents"), false},
		{"explicit traversal rejected", "../etc/passwd", "", true},
	}

	p := &Pki{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.ExpandTilde(tt.in)
			if (err != nil) != tt.wantError {
				t.Fatalf("ExpandTilde(%q): err=%v, wantError=%v", tt.in, err, tt.wantError)
			}
			if !tt.wantError && got != tt.want {
				t.Errorf("ExpandTilde(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
