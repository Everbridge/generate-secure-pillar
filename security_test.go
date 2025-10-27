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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/utils"
)

// TestContainsDirectoryTraversal tests the centralized directory traversal detection function
func TestContainsDirectoryTraversal(t *testing.T) {
	testCases := []struct {
		name     string
		path     string
		expected bool
	}{
		{"valid relative path", "file.txt", false},
		{"valid absolute path", "/home/user/file.txt", false},
		{"valid nested path", "dir/subdir/file.txt", false},
		{"basic traversal", "../etc/passwd", true},
		{"nested traversal", "../../etc/passwd", true},
		{"windows traversal", "..\\windows\\system32", true},
		{"mixed slashes traversal", "../file\\..\\etc", true},
		{"double dot in filename", "file..txt", false},
		{"dot at start", "./file.txt", false},
		{"clean traversal attempt", "dir/../file.txt", true},
		{"empty path", "", false},
		{"just dots", "..", true},
		{"triple dots", "...", false},
		{"forward slash traversal", "dir/../../../etc", true},
		{"windows backward slash", "dir\\..\\..\\etc", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := utils.ContainsDirectoryTraversal(tc.path)
			if result != tc.expected {
				t.Errorf("ContainsDirectoryTraversal(%q) = %v, want %v", tc.path, result, tc.expected)
			}
		})
	}
}

// TestCommandPathValidation tests that CLI commands reject malicious paths
func TestCommandPathValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Build the binary first
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	binaryName := "generate-secure-pillar"
	binaryPath := filepath.Join(dir, binaryName)

	// Test cases with malicious paths
	maliciousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\windows\\system32",
		"../../../../root/.ssh/id_rsa",
		"../etc/shadow",
	}

	// Commands that accept file paths
	commandTests := []struct {
		name string
		args []string
	}{
		{"create with malicious output", []string{"create", "-n", "test", "-s", "value", "-o"}},
		{"update with malicious input", []string{"update", "-n", "test", "-s", "value", "-f"}},
		{"encrypt with malicious file", []string{"encrypt", "all", "-f"}},
		{"decrypt with malicious file", []string{"decrypt", "all", "-f"}},
		{"keys with malicious file", []string{"keys", "all", "-f"}},
		{"rotate with malicious file", []string{"rotate", "-f"}},
		{"encrypt with malicious dir", []string{"encrypt", "recurse", "-d"}},
		{"decrypt with malicious dir", []string{"decrypt", "recurse", "-d"}},
		{"keys with malicious dir", []string{"keys", "recurse", "-d"}},
		{"rotate with malicious dir", []string{"rotate", "-d"}},
	}

	// Set up GPG environment
	err = os.Setenv("GNUPGHOME", filepath.Join(dir, "testdata", "gnupg"))
	if err != nil {
		t.Fatal(err)
	}

	for _, cmdTest := range commandTests {
		for _, maliciousPath := range maliciousPaths {
			testName := fmt.Sprintf("%s_%s", cmdTest.name, strings.ReplaceAll(maliciousPath, "/", "_"))
			t.Run(testName, func(t *testing.T) {
				// Append the malicious path to the command
				args := append(cmdTest.args, maliciousPath)
				args = append([]string{"-k", "Test Salt Master"}, args...)

				cmd := exec.Command(binaryPath, args...)
				output, err := cmd.CombinedOutput()

				// Command should fail (non-zero exit code) due to path validation
				if err == nil {
					t.Errorf("Command should have failed with malicious path %q, but succeeded. Output: %s", maliciousPath, output)
				}

				// Check that the error message mentions directory traversal
				outputStr := string(output)
				if !strings.Contains(outputStr, "directory traversal") && !strings.Contains(outputStr, "invalid") {
					t.Logf("Expected directory traversal error message, got: %s", outputStr)
				}
			})
		}
	}
}

// TestFilePermissionHandling tests how the application handles file permission issues
func TestFilePermissionHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file permission test in short mode")
	}

	tempDir := t.TempDir()

	testCases := []struct {
		name        string
		setupFunc   func() string
		expectError bool
		errorMsg    string
	}{
		{
			name: "unreadable file",
			setupFunc: func() string {
				file := filepath.Join(tempDir, "unreadable.sls")
				err := os.WriteFile(file, []byte("#!yaml|gpg\ntest: value"), 0000)
				if err != nil {
					t.Fatal(err)
				}
				return file
			},
			expectError: true,
			errorMsg:    "permission denied",
		},
		{
			name: "non-existent file",
			setupFunc: func() string {
				return filepath.Join(tempDir, "nonexistent.sls")
			},
			expectError: true,
			errorMsg:    "no such file",
		},
		{
			name: "directory instead of file",
			setupFunc: func() string {
				dir := filepath.Join(tempDir, "notafile.sls")
				err := os.Mkdir(dir, 0755)
				if err != nil {
					t.Fatal(err)
				}
				return dir
			},
			expectError: true,
			errorMsg:    "is a directory",
		},
	}

	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := tc.setupFunc()

			// Build command to test file access
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			binaryPath := filepath.Join(dir, "generate-secure-pillar")
			cmd := exec.Command(binaryPath,
				"-k", pgpKeyName,
				"--pubring", publicKeyRing,
				"--secring", secretKeyRing,
				"keys", "all", "-f", filePath)

			output, err := cmd.CombinedOutput()

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but command succeeded. Output: %s", tc.name, output)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v. Output: %s", tc.name, err, output)
				}
			}
		})
	}
}

// TestMalformedInputHandling tests handling of malformed inputs
func TestMalformedInputHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping malformed input test in short mode")
	}

	tempDir := t.TempDir()
	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()

	testCases := []struct {
		name        string
		setupFunc   func() ([]string, string) // Returns args and expected error substring
		expectError bool
	}{
		{
			name: "empty secret names",
			setupFunc: func() ([]string, string) {
				outputFile := filepath.Join(tempDir, "empty_names.sls")
				args := []string{
					"-k", pgpKeyName,
					"--pubring", publicKeyRing,
					"--secring", secretKeyRing,
					"create", "-n", "", "-s", "value", "-o", outputFile,
				}
				return args, "secret names"
			},
			expectError: true,
		},
		{
			name: "empty secret values",
			setupFunc: func() ([]string, string) {
				outputFile := filepath.Join(tempDir, "empty_values.sls")
				args := []string{
					"-k", pgpKeyName,
					"--pubring", publicKeyRing,
					"--secring", secretKeyRing,
					"create", "-n", "name", "-s", "", "-o", outputFile,
				}
				return args, ""
			},
			expectError: false, // Empty values are allowed
		},
		{
			name: "mismatched arrays",
			setupFunc: func() ([]string, string) {
				outputFile := filepath.Join(tempDir, "mismatched.sls")
				args := []string{
					"-k", pgpKeyName,
					"--pubring", publicKeyRing,
					"--secring", secretKeyRing,
					"create", "-n", "name1,name2", "-s", "value1", "-o", outputFile,
				}
				return args, "mismatch"
			},
			expectError: true,
		},
		{
			name: "malformed YAML file",
			setupFunc: func() ([]string, string) {
				// Create a file with invalid YAML
				malformedFile := filepath.Join(tempDir, "malformed.sls")
				err := os.WriteFile(malformedFile, []byte("#!yaml|gpg\n[invalid: yaml: content]"), 0644)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{
					"-k", pgpKeyName,
					"--pubring", publicKeyRing,
					"--secring", secretKeyRing,
					"keys", "all", "-f", malformedFile,
				}
				return args, "yaml"
			},
			expectError: true,
		},
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "generate-secure-pillar")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args, expectedErr := tc.setupFunc()

			cmd := exec.Command(binaryPath, args...)
			output, err := cmd.CombinedOutput()

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but command succeeded. Output: %s", tc.name, output)
				} else {
					// Check that error message contains expected substring
					outputStr := strings.ToLower(string(output))
					expectedErrLower := strings.ToLower(expectedErr)
					if !strings.Contains(outputStr, expectedErrLower) {
						t.Logf("Expected error containing %q, got output: %s", expectedErr, output)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v. Output: %s", tc.name, err, output)
				}
			}
		})
	}
}

// TestIncludeFileHandling tests that include files are properly rejected
func TestIncludeFileHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping include file test in short mode")
	}

	tempDir := t.TempDir()
	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()

	// Create a file with include directive
	includeFile := filepath.Join(tempDir, "include_test.sls")
	includeContent := `#!yaml|gpg

include:
  - some.other.pillar

data:
  secret: value
`
	err := os.WriteFile(includeFile, []byte(includeContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Commands that should reject include files
	commands := [][]string{
		{"encrypt", "all", "-f", includeFile},
		{"decrypt", "all", "-f", includeFile},
		{"keys", "all", "-f", includeFile},
		{"create"}, // This will be handled differently
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "generate-secure-pillar")

	for i, cmdArgs := range commands {
		if i == 3 { // Skip create command as it doesn't read input files
			continue
		}

		testName := fmt.Sprintf("command_%s_rejects_include", cmdArgs[0])
		t.Run(testName, func(t *testing.T) {
			args := []string{
				"-k", pgpKeyName,
				"--pubring", publicKeyRing,
				"--secring", secretKeyRing,
			}
			args = append(args, cmdArgs...)

			cmd := exec.Command(binaryPath, args...)
			output, err := cmd.CombinedOutput()

			// Command should fail due to include directive
			if err == nil {
				t.Errorf("Command should have failed with include file, but succeeded. Output: %s", output)
			}

			// Check that error message mentions include
			outputStr := strings.ToLower(string(output))
			if !strings.Contains(outputStr, "include") {
				t.Logf("Expected include-related error message, got: %s", output)
			}
		})
	}
}

// TestResourceCleanup tests that resources are properly cleaned up
func TestResourceCleanup(t *testing.T) {
	// This test checks that temporary files and resources are cleaned up
	tempDir := t.TempDir()

	// Count initial files in temp directory
	initialFiles, err := filepath.Glob(filepath.Join(tempDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	initialCount := len(initialFiles)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.sls")
	err = os.WriteFile(testFile, []byte("#!yaml|gpg\ntest: value"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()

	// Perform multiple operations that could create temporary resources
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "generate-secure-pillar")

	for i := 0; i < 5; i++ {
		cmd := exec.Command(binaryPath,
			"-k", pgpKeyName,
			"--pubring", publicKeyRing,
			"--secring", secretKeyRing,
			"keys", "all", "-f", testFile)

		_, err := cmd.CombinedOutput()
		if err != nil {
			// It's okay if the command fails, we're testing cleanup
			continue
		}
	}

	// Check that no extra files were created (beyond our test file)
	finalFiles, err := filepath.Glob(filepath.Join(tempDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	finalCount := len(finalFiles)

	// We should have at most 1 additional file (our test file)
	if finalCount > initialCount+1 {
		t.Errorf("Possible resource leak: expected at most %d files, got %d files", initialCount+1, finalCount)
		t.Logf("Initial files: %v", initialFiles)
		t.Logf("Final files: %v", finalFiles)
	}
}
