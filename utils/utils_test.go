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

package utils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
)

// TestContainsDirectoryTraversalUnit tests the directory traversal detection function
func TestContainsDirectoryTraversalUnit(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Safe paths
		{"empty path", "", false},
		{"current dir", ".", false},
		{"simple file", "file.txt", false},
		{"nested path", "dir/subdir/file.txt", false},
		{"absolute path", "/usr/local/bin", false},
		{"windows absolute", "C:\\Users\\test", false},
		{"dot in filename", "file.v1.0.txt", false},
		{"triple dots", "file...txt", false},

		// Dangerous paths
		{"basic traversal", "../file.txt", true},
		{"double traversal", "../../etc/passwd", true},
		{"windows traversal", "..\\file.txt", true},
		{"mixed separators", "../dir\\file", true},
		{"clean traversal", "dir/../../../etc", true},
		{"just double dots", "..", true},
		{"traversal in middle", "dir/../../../file", true},
		{"encoded dots", "%2e%2e/file", false}, // This should be handled at HTTP layer
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsDirectoryTraversal(tt.path)
			if result != tt.expected {
				t.Errorf("ContainsDirectoryTraversal(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestFindFilesByExtEdgeCases tests FindFilesByExt with edge cases
func TestFindFilesByExtEdgeCases(t *testing.T) {
	tempDir := t.TempDir()

	// Create test directory structure
	subDir := filepath.Join(tempDir, "subdir")
	err := os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	deepDir := filepath.Join(subDir, "deep")
	err = os.Mkdir(deepDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Create test files
	testFiles := []struct {
		path string
		ext  string
	}{
		{filepath.Join(tempDir, "file1.sls"), ".sls"},
		{filepath.Join(tempDir, "file2.txt"), ".txt"},
		{filepath.Join(subDir, "file3.sls"), ".sls"},
		{filepath.Join(deepDir, "file4.sls"), ".sls"},
		{filepath.Join(tempDir, "no_extension"), ""},
		{filepath.Join(tempDir, ".hidden.sls"), ".sls"},
	}

	for _, tf := range testFiles {
		err := os.WriteFile(tf.path, []byte("test content"), 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name          string
		searchDir     string
		ext           string
		expectedCount int
		expectError   bool
	}{
		{"find sls files", tempDir, ".sls", 4, false},
		{"find txt files", tempDir, ".txt", 1, false},
		{"find nonexistent ext", tempDir, ".xyz", 0, false},
		{"nonexistent directory", "/nonexistent", ".sls", 0, true},
		{"file instead of directory", testFiles[0].path, ".sls", 0, true},
		{"empty extension", tempDir, "", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, count := FindFilesByExt(tt.searchDir, tt.ext)

			if tt.expectError {
				// For error cases, we expect count to be 0
				if count != 0 || len(files) != 0 {
					t.Errorf("Expected error case to return 0 files, got %d files", count)
				}
			} else {
				if count != tt.expectedCount {
					t.Errorf("Expected %d files, got %d", tt.expectedCount, count)
				}
				if len(files) != count {
					t.Errorf("Files slice length %d doesn't match count %d", len(files), count)
				}

				// Verify all returned files have the correct extension
				for _, file := range files {
					if tt.ext != "" && !strings.HasSuffix(file, tt.ext) {
						t.Errorf("File %s doesn't have expected extension %s", file, tt.ext)
					}
				}
			}
		})
	}
}

// TestSafeWriteErrorHandling tests SafeWrite function error handling
func TestSafeWriteErrorHandling(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		buffer      bytes.Buffer
		outputPath  string
		inputError  error
		expectPanic bool
		setupFunc   func() string
	}{
		{
			name:        "successful write",
			buffer:      *bytes.NewBufferString("#!yaml|gpg\ntest: value"),
			outputPath:  filepath.Join(tempDir, "success.sls"),
			inputError:  nil,
			expectPanic: false,
		},
		{
			name:        "input error should panic",
			buffer:      *bytes.NewBufferString(""),
			outputPath:  "",
			inputError:  fmt.Errorf("input processing failed"),
			expectPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := tt.outputPath
			if tt.setupFunc != nil {
				outputPath = tt.setupFunc()
			}

			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("SafeWrite should have panicked but didn't")
					}
				}()
			}

			SafeWrite(tt.buffer, outputPath, tt.inputError)

			if !tt.expectPanic {
				// Verify file was written
				if _, err := os.Stat(outputPath); os.IsNotExist(err) {
					t.Errorf("File %s was not created", outputPath)
				}
			}
		})
	}
}

// TestProcessDirErrorConditions tests ProcessDir with various error conditions
func TestProcessDirErrorConditions(t *testing.T) {
	tests := []struct {
		name        string
		searchDir   string
		expectError bool
		errorMsg    string
	}{
		{"empty search directory", "", true, "search directory not specified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a dummy PKI struct - in real tests this would be properly initialized
			var dummyPKI pki.Pki

			err := ProcessDir(tt.searchDir, ".sls", "encrypt", "", "", dummyPKI)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tt.name)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}
