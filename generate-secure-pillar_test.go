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
	"github.com/gosexy/to"
	"github.com/prometheus/common/log"
)

// pgpHeader header const
const pgpHeader = "-----BEGIN PGP MESSAGE-----"

var pwd string

func TestMain(m *testing.M) {
	pwd, _ = filepath.Abs(filepath.Dir(os.Args[0]))
	initGPGDir(pwd)
	retCode := m.Run()
	teardownGPGDir(pwd)
	os.Exit(retCode)
}

func TestWriteSlsFile(t *testing.T) {
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
	topLevelElement = "secure_vars"
	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	if len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.",
			len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})), 3)
	}
}

func TestReadIncludeFile(t *testing.T) {
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

	slsFile := "./testdata/inc.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(slsFile, p, topLevelElement)
	if !s.IsInclude {
		t.Errorf("failed to detect include file")
	}
	slsFile = "./testdata/new.sls"
	s = sls.New(slsFile, p, topLevelElement)
	if s.IsInclude {
		t.Errorf("bad status for non-include file")
	}
}

func TestReadBadFile(t *testing.T) {
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
	topLevelElement = "secure_vars"
	yamlObj, err := yaml.Open("/dev/null")
	Ok(t, err)

	if yamlObj.Get(topLevelElement) != nil {
		t.Errorf("got YAML from /dev/nul???")
	}
}

func TestEncryptSecret(t *testing.T) {
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
	topLevelElement = "secure_vars"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	if len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})), 1)
	}
	secureVars := yamlObj.Get(topLevelElement)
	for _, v := range secureVars.(map[interface{}]interface{}) {
		if strings.Contains(v.(string), pgpHeader) {
			t.Errorf("YAML content is already encrypted.")
		} else {
			cipherText, err := p.EncryptSecret(v.(string))
			Ok(t, err)

			if !strings.Contains(cipherText, pgpHeader) {
				t.Errorf("YAML content was not encrypted.")
			}
		}
	}
}

func TestGetPath(t *testing.T) {
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
		if !strings.Contains(v.(string), pgpHeader) {
			t.Errorf("YAML content was not encrypted.")
		}
	}

	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, file)
	}

}

func TestDecryptSecret(t *testing.T) {
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
	topLevelElement = "secure_vars"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	Ok(t, err)

	if len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})), 1)
	}
	for _, v := range yamlObj.Get(topLevelElement).(map[interface{}]interface{}) {
		cipherText, err := p.EncryptSecret(v.(string))
		Ok(t, err)

		plainText, err := p.DecryptSecret(cipherText)
		Ok(t, err)

		if strings.Contains(plainText, pgpHeader) {
			t.Errorf("YAML content was not decrypted.")
		}
		if plainText == "" {
			t.Errorf("decrypted content is empty")
		}
	}
}

func TestGetValueFromPath(t *testing.T) {
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

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)
	val := s.GetValueFromPath("bar:baz")
	Equals(t, "qux", to.String(val))
}

func TestNestedAndMultiLineFile(t *testing.T) {
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

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	err := s.SetValueFromPath("bar:baz", "foo")
	Ok(t, err)

	val := s.GetValueFromPath("bar:baz")
	Equals(t, "foo", to.String(val))
}

func TestRotateFile(t *testing.T) {
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
	if !strings.Contains(val.(string), pgpHeader) {
		t.Errorf("YAML content was not encrypted.")
	}
	buffer, err = s.PerformAction("decrypt")
	Ok(t, err)
	if err == nil {
		sls.WriteSlsFile(buffer, filePath)
	}
}

func TestKeyInfo(t *testing.T) {
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

		if !found {
			t.Errorf("%s does not contain PGP header", slsFiles[n])
		}
	}
}

func TestDecryptProcessDir(t *testing.T) {
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

		if found {
			t.Errorf("%s contains PGP header", slsFiles[n])
		}
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
// func Assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
// 	if !condition {
// 		_, file, line, _ := runtime.Caller(1)
// 		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
// 		tb.FailNow()
// 	}
// }

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

func initGPGDir(pwd string) {
	teardownGPGDir(pwd)
	cmd := exec.Command("/bin/bash", "-c", "./testdata/testkeys.sh")
	out, err := cmd.CombinedOutput()
	fmt.Printf("%s", string(out))
	if err != nil {
		log.Errorf("%s", err)
	}
}

func teardownGPGDir(pwd string) {
	err := filepath.Walk("./testdata/gnupg", func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			os.Remove(f.Name())
		}
		return nil
	})
	if err != nil {
		logger.Fatal("error walking file path: ", err)
	}
}
