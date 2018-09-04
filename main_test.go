package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	yaml "github.com/esilva-everbridge/yaml"
)

// pgpHeader header const
const pgpHeader = "-----BEGIN PGP MESSAGE-----"

func TestMain(m *testing.M) {
	initGPGDir()
	defer teardownGPGDir()
	retCode := m.Run()
	os.Exit(retCode)
}

func TestWriteSlsFile(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	slsFile := "./testdata/foo/foo.sls"

	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(slsFile, p, topLevelElement)

	s.SetValueFromPath("secret", "text")

	buffer, err := s.FormatBuffer("")
	Ok(t, err)
	sls.WriteSlsFile(buffer, slsFile)

	if _, err = os.Stat(slsFile); os.IsNotExist(err) {
		t.Errorf("%s file was not written", slsFile)
	}
	yamlObj, err := yaml.Open(slsFile)
	Ok(t, err)

	if yamlObj.Get("secret") == nil {
		t.Errorf("YAML content is incorrect, missing key")
	} else if yamlObj.Get("secret") != "text" {
		t.Errorf("YAML content is incorrect, got: %s, want: %s.",
			yamlObj.Get("secret"), "text")
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

	length := len(yamlObj.Get(topLevelElement).(map[interface{}]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content lenth is incorrect, got: %d, want: %d.", length, 3), 3)

	secureVars := yamlObj.Get(topLevelElement)
	for _, v := range secureVars.(map[interface{}]interface{}) {
		if strings.Contains(v.(string), pgpHeader) {
			t.Errorf("YAML content is already encrypted.")
		} else {
			cipherText, err := p.EncryptSecret(v.(string))
			Ok(t, err)
			Assert(t, strings.Contains(cipherText, pgpHeader), "YAML content was not encrypted.", strings.Contains(cipherText, pgpHeader))
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
		sls.WriteSlsFile(buffer, file)
	}

	if s.GetValueFromPath(topLevelElement) == nil {
		t.Errorf("YAML content is incorrect, got: %v.",
			s.GetValueFromPath(topLevelElement))
	}
	secureVars := s.GetValueFromPath(topLevelElement)
	for _, v := range secureVars.(map[interface{}]interface{}) {
		Assert(t, strings.Contains(v.(string), pgpHeader), "YAML content was not encrypted.", strings.Contains(v.(string), pgpHeader))
	}

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, file)
	}
}

func TestDecryptSecret(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = "secure_vars"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	length := len(yamlObj.Get(topLevelElement).(map[interface{}]interface{}))
	Assert(t, length == 3, fmt.Sprintf("YAML content lenth is incorrect, got: %d, want: %d.", length, 3), 3)
	for _, v := range yamlObj.Get(topLevelElement).(map[interface{}]interface{}) {
		cipherText, err := p.EncryptSecret(v.(string))
		Ok(t, err)

		plainText, err := p.DecryptSecret(cipherText)
		Ok(t, err)

		Assert(t, !strings.Contains(plainText, pgpHeader), "YAML content was not decrypted.", strings.Contains(plainText, pgpHeader))
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
		sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 2, pgpHeader)
	Ok(t, err)

	filePath = "./testdata/test.sls"
	p = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s = sls.New(filePath, p, topLevelElement)

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 0, pgpHeader)
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
		sls.WriteSlsFile(buffer, filePath)
	}

	buffer, err = s.PerformAction("rotate")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, filePath)
	}

	val := s.GetValueFromPath("bar:baz")
	Assert(t, strings.Contains(val.(string), pgpHeader), "YAML content was not encrypted.", strings.Contains(val.(string), pgpHeader))
	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, filePath)
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
		sls.WriteSlsFile(buffer, filePath)
	}

	buffer, err = s.PerformAction("validate")
	Ok(t, err)

	if err = scanString(buffer.String(), 0, pgpHeader); err != nil {
		t.Errorf("Found PGP data in buffer: %s", err)
	}
	if err = scanString(buffer.String(), 5, pgpKeyName); err != nil {
		t.Errorf("Key name count in buffer: %s", err)
	}

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, filePath)
	}
}

func TestEncryptProcessDir(t *testing.T) {
	pgpKeyName, publicKeyRing, secretKeyRing = getTestKeyRings()
	topLevelElement = ""

	dirPath := "./testdata"
	slsFiles, slsCount := utils.FindFilesByExt(dirPath, ".sls")
	Equals(t, 6, slsCount)

	pk = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
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
	Equals(t, 6, slsCount)

	pk = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
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
		if strings.Contains(txt, pgpHeader) {
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

func getTestKeyRings() (string, string, string) {
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
