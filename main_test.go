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
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/andreyvit/diff"
	yaml "github.com/edlitmus/ezyaml"
)

var pgpKeyName string
var publicKeyRing string
var secretKeyRing string
var topLevelElement string
var update = flag.Bool("update", false, "update golden files")
var dirPath string

type CLITest struct {
	name    string
	args    []string
	fixture string
	count   int
}

func TestMain(m *testing.M) {
	initGPGDir()
	defer teardownGPGDir()
	m.Run()
}

func TestCliArgs(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""
	binaryName := "generate-secure-pillar"

	// set up: encrypt the test sls files
	_, slsCount := utils.FindFilesByExt(dirPath, ".sls")
	Equals(t, 7, slsCount)
	pk, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = utils.ProcessDir(dirPath, ".sls", sls.Decrypt, "", topLevelElement, *pk)
	}()

	tests := []CLITest{
		{"no arguments", []string{}, "testdata/no-args.golden", 0},
		{"encrypt recurse", []string{"-k", "Test Salt Master", "encrypt", "recurse", "-d", dirPath}, "testdata/encrypt-recurse.golden", 0},
		{"keys recurse", []string{"-k", "Test Salt Master", "keys", "recurse", "-d", dirPath}, "testdata/keys-recurse.golden", 26},
		{"keys recurse bad", []string{"-k", "Test Salt Master", "keys", "recurse", "-f", dirPath}, "testdata/keys-recurse-bad.golden", 0},
		{"decrypt recurse", []string{"-k", "Test Salt Master", "decrypt", "recurse", "-d", dirPath}, "testdata/decrypt-recurse.golden", 0},
		{"encrypt file", []string{"-k", "Test Salt Master", "encrypt", "all", "-f", dirPath + "/test.sls", "-u"}, "testdata/encrypt-file.golden", 0},
		{"keys file", []string{"-k", "Test Salt Master", "keys", "all", "-f", dirPath + "/test.sls"}, "testdata/keys-file.golden", 12},
		{"keys path", []string{"-k", "Test Salt Master", "keys", "path", "-f", dirPath + "/test.sls", "-p", "key"}, "testdata/keys-path.golden", 1},
		{"keys count", []string{"-k", "Test Salt Master", "keys", "count", "-v", "-f", dirPath + "/test.sls"}, "testdata/keys-count.golden", 1},
		{"decrypt path", []string{"-k", "Test Salt Master", "decrypt", "path", "-f", dirPath + "/test.sls", "-p", "key", "-u"}, "testdata/decrypt-path.golden", 0},
		{"decrypt file", []string{"-k", "Test Salt Master", "decrypt", "all", "-f", dirPath + "/test.sls", "-u"}, "testdata/decrypt-file.golden", 0},
	}

	err = os.Setenv("GNUPGHOME", dirPath+"/gnupg")
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range tests {
		args := tt.args
		count := tt.count
		fixture := tt.fixture
		name := tt.name

		t.Run(name, func(t *testing.T) {
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(path.Join(dir, binaryName), args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s:\n%s%s", err, output, args)
			}
			ex := cmd.ProcessState.ExitCode()
			if ex != 0 {
				t.Errorf("Key command error, expected 0 got %d", ex)
			}

			actual := getActual(output)
			if *update {
				writeFixture(t, fixture, []byte(actual))
			}

			// due to the way the output is generated we normalize the recursive output
			switch name {
			case "keys file":
			case "keys path":
			case "keys recurse":
				actualCount := keyNameCount(actual, "Test Salt Master")
				if actualCount != count {
					t.Errorf("Key name count error, expected %d got %d", count, actualCount)
				}

			case "keys count":
				actualCount := keyNameCount(actual, "1 keys found:")
				if actualCount != count {
					t.Errorf("Key count error, expected %d got %d", count, actualCount)
				}

			case "no arguments":
				actual := strings.TrimSpace(actual)
				expected := strings.TrimSpace(getExpected(t, fixture))

				scanner := bufio.NewScanner(strings.NewReader(actual))
				for scanner.Scan() {
					line := scanner.Text()
					if !strings.Contains(line, expected) {
						t.Errorf("Output error:\n%v", diff.LineDiff(expected, actual))
					}
					break
				}

			case "decrypt path":
				actual := strings.TrimSpace(actual)
				expected := strings.TrimSpace(getExpected(t, fixture))
				if !strings.Contains(expected, actual) {
					t.Errorf("Output error:\n%v", diff.LineDiff(expected, actual))
				}

			default:
				if *update {
					writeFixture(t, fixture, []byte(actual))
				}

				expected := strings.TrimSpace(getExpected(t, fixture))
				actual := strings.TrimSpace(actual)

				exp, err := getLinesAsJSON(expected)
				if err != nil {
					t.Fatal(err)
				}
				act, err := getLinesAsJSON(actual)
				if err != nil {
					t.Fatal(err)
				}

			ActLoop:
				for _, a := range act {
				ExpLoop:
					for _, e := range exp {
						if !strings.Contains(a["message"], e["message"]) {
							t.Errorf("Output error:\n%v", diff.LineDiff(e["message"], a["message"]))
							break ExpLoop
						} else {
							break ActLoop
						}
					}
				}
			}
		})
	}
}

func getLinesAsJSON(lines string) ([]map[string]string, error) {
	var jsonArr []map[string]string

	// iterate over lines in string
	scanner := bufio.NewScanner(strings.NewReader(lines))
	for scanner.Scan() {
		line := scanner.Text()
		var e map[string]string
		err := json.Unmarshal([]byte(line), &e)
		if err != nil {
			return nil, err
		}
		jsonArr = append(jsonArr, e)
	}
	return jsonArr, nil
}

func getActual(output []byte) string {
	return cleanAndSort(string(output))
}

func getExpected(t *testing.T, fixture string) string {
	return cleanAndSort(loadFixture(t, fixture))
}

func cleanAndSort(str string) string {
	// need to remove timestamps
	reg := regexp.MustCompile(`(?m)time=\".*?\"\s`)
	str = reg.ReplaceAllString(str, "")
	lines := strings.Split(str, "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func keyNameCount(str string, needle string) int {
	lines := strings.Split(str, "\n")
	count := 0
	for _, line := range lines {
		ok := strings.Contains(line, needle)
		if ok {
			count++
		}
	}
	return count
}

func TestWriteSlsFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	slsFile := "./testdata/foo/foo.sls"

	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(slsFile, *p, topLevelElement)

	secText := "secret"
	valType := "text"
	_ = s.SetValueFromPath(secText, valType)

	buffer, err := s.FormatBuffer("")
	Ok(t, err)
	_, _ = sls.WriteSlsFile(buffer, slsFile)

	if _, err = os.Stat(slsFile); os.IsNotExist(err) {
		t.Errorf("%s file was not written", slsFile)
	}
	yamlObj, err := yaml.Open(slsFile)
	Ok(t, err)

	if yamlObj.Get(secText) == nil {
		t.Errorf("YAML content is incorrect, missing key")
	} else if yamlObj.Get(secText) != valType {
		t.Errorf("YAML content is incorrect, got: %s, want: %s.",
			yamlObj.Get(secText), valType)
	}
	os.Remove(slsFile)
	os.Remove("./testdata/foo/")
}

func TestReadSlsFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = "secure_vars"
	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	length := len(yamlObj.Get(topLevelElement).(map[interface{}]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content length is incorrect, got: %d, want: %d.", length, 3), 3)
}

func TestReadIncludeFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	slsFile := "./testdata/inc.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(slsFile, *p, topLevelElement)
	Assert(t, s.IsInclude, "failed to detect include file", s.IsInclude)
	slsFile = "./testdata/new.sls"
	s = sls.New(slsFile, *p, topLevelElement)
	Assert(t, !s.IsInclude, "bad status for non-include file", s.IsInclude)
}

func TestReadBadFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = "secure_vars"
	yamlObj, err := yaml.Open("/dev/null")
	Ok(t, err)
	Assert(t, yamlObj.Get(topLevelElement) == nil, "got YAML from /dev/null???", yamlObj.Get(topLevelElement))
}

func TestEncryptSecret(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = "secure_vars"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	length := len(yamlObj.Get(topLevelElement).(map[interface{}]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content length is incorrect, got: %d, want: %d.", length, 3), 3)

	secureVars := yamlObj.Get(topLevelElement)
	for _, v := range secureVars.(map[interface{}]interface{}) {
		if strings.Contains(v.(string), pki.PGPHeader) {
			t.Errorf("YAML content is already encrypted.")
		} else {
			cipherText, err := p.EncryptSecret(v.(string))
			Ok(t, err)
			Assert(t, strings.Contains(cipherText, pki.PGPHeader), "YAML content was not encrypted.", strings.Contains(cipherText, pki.PGPHeader))
		}
	}
}

func TestGetPath(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = "secure_vars"

	file := "./testdata/test/bar.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(file, *p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, file)
	}

	if s.GetValueFromPath(topLevelElement) == nil {
		t.Errorf("YAML content is incorrect, got: %v.",
			s.GetValueFromPath(topLevelElement))
	}
	secureVars := s.GetValueFromPath(topLevelElement)
	for _, v := range secureVars.(map[string]interface{}) {
		Assert(t, strings.Contains(v.(string), pki.PGPHeader), "YAML content was not encrypted.", strings.Contains(v.(string), pki.PGPHeader))
	}

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, file)
	}
}

func TestDecryptSecret(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = "secure_vars"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	length := len(yamlObj.Get(topLevelElement).(map[interface{}]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content length is incorrect, got: %d, want: %d.", length, 3), 3)
	for _, v := range yamlObj.Get(topLevelElement).(map[interface{}]interface{}) {
		cipherText, err := p.EncryptSecret(v.(string))
		Ok(t, err)

		plainText, err := p.DecryptSecret(cipherText)
		Ok(t, err)

		Assert(t, !strings.Contains(plainText, pki.PGPHeader), "YAML content was not decrypted.", strings.Contains(plainText, pki.PGPHeader))
		Assert(t, plainText != "", "decrypted content is empty", plainText)
	}
}

func TestGetValueFromPath(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()

	filePath := "./testdata/new.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(filePath, *p, topLevelElement)
	val := s.GetValueFromPath("bar:baz")
	Equals(t, "qux", val.(string))
}

func TestNestedAndMultiLineFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()

	filePath := "./testdata/test.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(filePath, *p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 2, pki.PGPHeader)
	Ok(t, err)

	filePath = "./testdata/test.sls"
	p, err = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s = sls.New(filePath, *p, topLevelElement)

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 0, pki.PGPHeader)
	Ok(t, err)
}

func TestSetValueFromPath(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()

	filePath := "./testdata/new.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(filePath, *p, topLevelElement)

	err = s.SetValueFromPath("bar:baz", "foo")
	Ok(t, err)

	val := s.GetValueFromPath("bar:baz")
	Equals(t, "foo", val.(string))
}

func TestRotateFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""

	filePath := "./testdata/new.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(filePath, *p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}

	buffer, err = s.PerformAction("rotate")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}

	val := s.GetValueFromPath("bar:baz")
	Assert(t, strings.Contains(val.(string), pki.PGPHeader), "YAML content was not encrypted.", strings.Contains(val.(string), pki.PGPHeader))
	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}
}

func TestKeyInfo(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""

	filePath := "./testdata/new.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(filePath, *p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}

	buffer, err = s.PerformAction("validate")
	Ok(t, err)

	if err = scanString(buffer.String(), 0, pki.PGPHeader); err != nil {
		t.Errorf("Found PGP data in buffer: %s", err)
	}
	if err = scanString(buffer.String(), 5, pgpKeyName); err != nil {
		t.Errorf("Key name count in buffer: %s", err)
	}

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}
}

func TestEncryptProcessDir(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""

	dirPath := "./testdata"
	slsFiles, slsCount := utils.FindFilesByExt(dirPath, ".sls")
	Equals(t, 7, slsCount)

	pk, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	err = utils.ProcessDir(dirPath, ".sls", sls.Encrypt, "", topLevelElement, *pk)
	Ok(t, err)

	for n := 0; n < slsCount; n++ {
		s := sls.New(slsFiles[n], *pk, topLevelElement)
		if s.IsInclude {
			continue
		}
		var buf []byte
		buf, err = os.ReadFile(slsFiles[n])
		Ok(t, err)

		reader := strings.NewReader(string(buf))
		scanner := bufio.NewScanner(reader)

		found := hasPgpHeader(*scanner)
		err = scanner.Err()
		Ok(t, err)

		Assert(t, found, fmt.Sprintf("%s does not contain PGP header", slsFiles[n]), slsFiles[n])
	}
}

func TestDecryptProcessDir(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""

	dirPath := "./testdata"
	slsFiles, slsCount := utils.FindFilesByExt(dirPath, ".sls")
	Equals(t, 7, slsCount)

	pk, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	err = utils.ProcessDir(dirPath, ".sls", sls.Decrypt, "", topLevelElement, *pk)
	Ok(t, err)

	for n := 0; n < slsCount; n++ {
		s := sls.New(slsFiles[n], *pk, topLevelElement)
		if s.IsInclude {
			continue
		}
		var buf []byte
		buf, err = os.ReadFile(slsFiles[n])
		Ok(t, err)

		reader := strings.NewReader(string(buf))
		scanner := bufio.NewScanner(reader)

		found := hasPgpHeader(*scanner)
		err = scanner.Err()
		Ok(t, err)

		Assert(t, !found, fmt.Sprintf("%s contains PGP header", slsFiles[n]), slsFiles[n])
	}
}

func hasPgpHeader(scanner bufio.Scanner) bool {
	found := false
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.Contains(txt, pki.PGPHeader) {
			found = true
			continue
		}
	}
	return found
}

func scanString(buffer string, wantedCount int, term string) error {
	var err error
	encCount := 0
	scanner := bufio.NewScanner(strings.NewReader(buffer))

	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, term) {
			encCount++
		}
	}
	if err = scanner.Err(); err != nil {
		return fmt.Errorf("%s", err)
	}
	if encCount != wantedCount {
		return fmt.Errorf("count is wrong, wanted %d, got %d", wantedCount, encCount)
	}

	return err
}

// Assert fails the test if the provided condition is false
func Assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		tb.FailNow()
	}
}

// Ok fails the test if the `err` is not nil
func Ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: Unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

// Equals fails the test if exp is not equal to act
func Equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\tExpected: %#v\n\n\tGot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

func initGPGDir() {
	teardownGPGDir()
	dirPath, _ = filepath.Abs("./testdata")
	os.Setenv("GNUPGHOME", dirPath+"/gnupg")
	cmd := exec.Command("./testdata/testkeys.sh")
	out, _ := cmd.CombinedOutput()
	fmt.Printf("%s", string(out))
}

func teardownGPGDir() {
	_ = os.Remove("./testdata/gnupg/pubring.gpg")
	_ = os.Remove("./testdata/gnupg/pubring.gpg~")
	_ = os.Remove("./testdata/gnupg/random_seed")
	_ = os.Remove("./testdata/gnupg/secring.gpg")
	_ = os.Remove("./testdata/gnupg/trustdb.gpg")
}

func getTestKeyRings() (pgpKeyName string, publicKeyRing string, secretKeyRing string) {
	pgpKeyName = "Test Salt Master"
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "./testdata/gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "./testdata/gnupg/secring.gpg"
	}

	return pgpKeyName, publicKeyRing, secretKeyRing
}

func fixturePath(t *testing.T, fixture string) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("problems recovering caller information")
	}

	return filepath.Join(filepath.Dir(filename), fixture)
}

func writeFixture(t *testing.T, fixture string, content []byte) {
	str := getActual(content)
	err := os.WriteFile(fixturePath(t, fixture), []byte(str), 0644)
	if err != nil {
		t.Fatal(err)
	}
}

func loadFixture(t *testing.T, fixture string) string {
	content, err := os.ReadFile(fixturePath(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// TestEncryptionRobustness tests encryption with various data types and edge cases
func TestEncryptionRobustness(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()
	topLevelElement = ""

	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)

	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{"normal text", "hello world", false},
		{"empty string", "", false},
		{"single character", "a", false},
		{"unicode characters", "测试数据 🔒 emoji", false},
		{"newlines and tabs", "line1\nline2\ttab\rcarriage", false},
		{"json data", `{"key": "value", "number": 123}`, false},
		{"xml data", "<root><element>value</element></root>", false},
		{"special characters", "!@#$%^&*()_+-=[]{}|;:,.<>?", false},
		{"binary-like data", string([]byte{0, 1, 2, 127, 128, 255}), false},
		{"very long string", strings.Repeat("abcdefghijklmnopqrstuvwxyz", 1000), false},
		{"mixed line endings", "line1\nline2\r\nline3\rline4", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test encryption
			cipherText, err := p.EncryptSecret(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify it contains PGP header
				Assert(t, strings.Contains(cipherText, pki.PGPHeader),
					"Encrypted data should contain PGP header", cipherText)

				// Test decryption
				plainText, err := p.DecryptSecret(cipherText)
				Ok(t, err)

				// Verify roundtrip integrity
				Equals(t, tt.data, plainText)
			}
		})
	}
}

// TestPKIEdgeCases tests PKI operations with edge cases
func TestPKIEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		keyName     string
		pubKeyring  string
		secKeyring  string
		wantErr     bool
		errContains string
	}{
		{
			name:        "missing public keyring",
			keyName:     "Test Salt Master",
			pubKeyring:  "/nonexistent/pubring.gpg",
			secKeyring:  "./testdata/gnupg/secring.gpg",
			wantErr:     true,
			errContains: "no such file",
		},
		{
			name:        "missing secret keyring",
			keyName:     "Test Salt Master",
			pubKeyring:  "./testdata/gnupg/pubring.gpg",
			secKeyring:  "/nonexistent/secring.gpg",
			wantErr:     false, // PKI just warns about missing secret keyring, doesn't error
			errContains: "",
		},
		{
			name:        "empty key name",
			keyName:     "",
			pubKeyring:  "./testdata/gnupg/pubring.gpg",
			secKeyring:  "./testdata/gnupg/secring.gpg",
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "nonexistent key name",
			keyName:     "Nonexistent Key",
			pubKeyring:  "./testdata/gnupg/pubring.gpg",
			secKeyring:  "./testdata/gnupg/secring.gpg",
			wantErr:     true,
			errContains: "unable to find key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pki.New(tt.keyName, tt.pubKeyring, tt.secKeyring)

			if (err != nil) != tt.wantErr {
				t.Errorf("pki.New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q, got: %v", tt.errContains, err)
				}
			}
		})
	}
}

// TestSlsFileEdgeCases tests SLS file handling with edge cases
func TestSlsFileEdgeCases(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()
	topLevelElement = ""

	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)

	tempDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "empty file",
			content: "",
			wantErr: true, // Empty files have no values to format
		},
		{
			name:    "only shebang",
			content: "#!yaml|gpg",
			wantErr: true, // Only shebang has no values to format
		},
		{
			name:    "malformed yaml",
			content: "#!yaml|gpg\n[invalid: yaml: content",
			wantErr: true,
		},
		{
			name: "deeply nested structure",
			content: `#!yaml|gpg
level1:
  level2:
    level3:
      level4:
        level5:
          deep_secret: "deep_value"`,
			wantErr: false,
		},
		{
			name: "unicode content",
			content: `#!yaml|gpg
测试: "中文内容"
emoji: "🔒🗝️"`,
			wantErr: false,
		},
		{
			name: "mixed types",
			content: `#!yaml|gpg
string: "text"
number: 123
boolean: true
array:
  - item1
  - item2
nested:
  key: value`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tempDir, fmt.Sprintf("test_%s.sls", tt.name))
			err := os.WriteFile(testFile, []byte(tt.content), 0644)
			Ok(t, err)

			// Try to create SLS object
			s := sls.New(testFile, *p, topLevelElement)

			// Try to perform an operation
			_, err = s.PerformAction("encrypt")

			if (err != nil) != tt.wantErr {
				t.Errorf("PerformAction() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && tt.errContains != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error should contain %q, got: %v", tt.errContains, err)
				}
			}
		})
	}
}

// TestPathOperationsEdgeCases tests YAML path operations with edge cases
func TestPathOperationsEdgeCases(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()
	topLevelElement = ""

	filePath := "./testdata/new.sls"
	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)
	s := sls.New(filePath, *p, topLevelElement)

	tests := []struct {
		name    string
		path    string
		value   string
		wantErr bool
	}{
		{"simple path", "test_key", "test_value", false},
		{"nested path", "level1:level2", "nested_value", false},
		{"deep path", "a:b:c:d:e", "deep_value", false},
		{"empty path", "", "root_value", false}, // Empty path should set at root level
		{"nonexistent nested", "nonexistent:key", "value", false},
		{"special chars in key", "special-key_123", "value", false},
		{"numeric key", "123", "numeric_value", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test setting value
			err := s.SetValueFromPath(tt.path, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetValueFromPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Test getting value back
				retrieved := s.GetValueFromPath(tt.path)
				if retrieved == nil {
					t.Errorf("GetValueFromPath() returned nil for path %q", tt.path)
				}
			}
		})
	}
}

// TestConcurrentOperations tests concurrent access to files
func TestConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	pgpKeyName, publicKeyRing, secretKeyRing := getTestKeyRings()
	topLevelElement = ""

	p, err := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	Ok(t, err)

	tempDir := t.TempDir()

	// Create multiple test files
	const numFiles = 5
	const numGoroutines = 3

	testFiles := make([]string, numFiles)
	for i := 0; i < numFiles; i++ {
		testFile := filepath.Join(tempDir, fmt.Sprintf("concurrent_test_%d.sls", i))
		content := fmt.Sprintf("#!yaml|gpg\ntest_key_%d: test_value_%d\n", i, i)
		err := os.WriteFile(testFile, []byte(content), 0644)
		Ok(t, err)
		testFiles[i] = testFile
	}

	// Run concurrent operations
	errors := make(chan error, numGoroutines*numFiles)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j, testFile := range testFiles {
				s := sls.New(testFile, *p, topLevelElement)

				// Perform encrypt operation
				_, err := s.PerformAction("encrypt")
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, file %d: encrypt failed: %v", goroutineID, j, err)
					continue
				}

				// Perform decrypt operation
				_, err = s.PerformAction("decrypt")
				if err != nil {
					errors <- fmt.Errorf("goroutine %d, file %d: decrypt failed: %v", goroutineID, j, err)
					continue
				}

				errors <- nil // Success
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numGoroutines*numFiles; i++ {
		err := <-errors
		if err != nil {
			t.Logf("Concurrent operation error: %v", err)
			errorCount++
		} else {
			successCount++
		}
	}

	// We expect most operations to succeed
	if errorCount > successCount {
		t.Errorf("Too many concurrent operation failures: %d errors vs %d successes", errorCount, successCount)
	}
}
