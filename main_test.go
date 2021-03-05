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
	"flag"
	"fmt"
	"io/ioutil"
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
	yaml "github.com/esilva-everbridge/yaml"
)

var pgpKeyName string
var publicKeyRing string
var secretKeyRing string
var topLevelElement string
var update = flag.Bool("update", false, "update golden files")
var dirPath string

func TestMain(m *testing.M) {
	initGPGDir()
	defer teardownGPGDir()
	retCode := m.Run()
	os.Exit(retCode)
}

func TestCliArgs(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""
	binaryName := "generate-secure-pillar"

	// set up: encrypt the test sls files
	_, slsCount := utils.FindFilesByExt(dirPath, ".sls")
	Equals(t, 7, slsCount)
	pk := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	defer func() {
		_ = utils.ProcessDir(dirPath, ".sls", sls.Decrypt, "", topLevelElement, pk)
	}()

	tests := []struct {
		name    string
		args    []string
		fixture string
		count   int
	}{
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

	os.Setenv("GNUPGHOME", dirPath+"/gnupg")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(path.Join(dir, binaryName), tt.args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s:\n%s", err, output)
			}
			ex := cmd.ProcessState.ExitCode()
			if ex != 0 {
				t.Errorf("Key command error, expected 0 got %d", ex)
			}

			actual := getActual(output)
			if *update {
				writeFixture(t, tt.fixture, []byte(actual))
			}

			// due to the way the output is generated we normalize the recursive output
			switch tt.name {
			case "keys file":
			case "keys path":
			case "keys recurse":
				actualCount := keyNameCount(actual, "Test Salt Master")
				if actualCount != tt.count {
					t.Errorf("Key name count error, expected %d got %d", tt.count, actualCount)
				}

			case "keys count":
				actualCount := keyNameCount(actual, "1 keys found:")
				if actualCount != tt.count {
					t.Errorf("Key count error, expected %d got %d", tt.count, actualCount)
				}

			default:
				expected := getExpected(t, tt.fixture)

				if *update {
					writeFixture(t, tt.fixture, []byte(actual))
				}

				if a, e := strings.TrimSpace(actual), strings.TrimSpace(expected); a != e {
					t.Errorf("Output error:\n%v", diff.LineDiff(e, a))
				}
			}
		})
	}
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

	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(slsFile, p, topLevelElement)

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

	length := len(yamlObj.Get(topLevelElement).(map[string]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content length is incorrect, got: %d, want: %d.", length, 3), 3)
}

func TestReadIncludeFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	slsFile := "./testdata/inc.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(slsFile, p, topLevelElement)
	Assert(t, s.IsInclude, "failed to detect include file", s.IsInclude)
	slsFile = "./testdata/new.sls"
	s = sls.New(slsFile, p, topLevelElement)
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
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	length := len(yamlObj.Get(topLevelElement).(map[string]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content lenth is incorrect, got: %d, want: %d.", length, 3), 3)

	secureVars := yamlObj.Get(topLevelElement)
	for _, v := range secureVars.(map[string]interface{}) {
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
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(file, p, topLevelElement)

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
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	length := len(yamlObj.Get(topLevelElement).(map[string]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content length is incorrect, got: %d, want: %d.", length, 3), 3)
	for _, v := range yamlObj.Get(topLevelElement).(map[string]interface{}) {
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
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)
	val := s.GetValueFromPath("bar:baz")
	Equals(t, "qux", val.(string))
}

func TestNestedAndMultiLineFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()

	filePath := "./testdata/test.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	Ok(t, err)
	if err == nil {
		_, _ = sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 2, pki.PGPHeader)
	Ok(t, err)

	filePath = "./testdata/test.sls"
	p = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s = sls.New(filePath, p, topLevelElement)

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
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	err := s.SetValueFromPath("bar:baz", "foo")
	Ok(t, err)

	val := s.GetValueFromPath("bar:baz")
	Equals(t, "foo", val.(string))
}

func TestRotateFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

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
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

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

	pk := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	err := utils.ProcessDir(dirPath, ".sls", sls.Encrypt, "", topLevelElement, pk)
	Ok(t, err)

	for n := 0; n < slsCount; n++ {
		s := sls.New(slsFiles[n], pk, topLevelElement)
		if s.IsInclude {
			continue
		}
		var buf []byte
		buf, err = ioutil.ReadFile(slsFiles[n])
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

	pk := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	err := utils.ProcessDir(dirPath, ".sls", sls.Decrypt, "", topLevelElement, pk)
	Ok(t, err)

	for n := 0; n < slsCount; n++ {
		s := sls.New(slsFiles[n], pk, topLevelElement)
		if s.IsInclude {
			continue
		}
		var buf []byte
		buf, err = ioutil.ReadFile(slsFiles[n])
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
	err := ioutil.WriteFile(fixturePath(t, fixture), []byte(str), 0644)
	if err != nil {
		t.Fatal(err)
	}
}

func loadFixture(t *testing.T, fixture string) string {
	content, err := ioutil.ReadFile(fixturePath(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
