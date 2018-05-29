package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	yaml "github.com/esilva-everbridge/yaml"
	"github.com/gosexy/to"
)

// pgpHeader header const
const pgpHeader = "-----BEGIN PGP MESSAGE-----"

func TestWriteSlsFile(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}

	slsFile := "./testdata/foo/foo.sls"

	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(slsFile, p, topLevelElement)

	s.SetValueFromPath("secret", "text")

	buffer, err := s.FormatBuffer("")
	if err != nil {
		t.Fatalf("FormatBuffer returned error")
	}
	sls.WriteSlsFile(buffer, slsFile)

	if _, err = os.Stat(slsFile); os.IsNotExist(err) {
		t.Errorf("%s file was not written", slsFile)
	}
	yamlObj, err := yaml.Open(slsFile)
	if err != nil {
		t.Fatalf("Returned error")
	}
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
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = "secure_vars"
	yamlObj, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.",
			len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})), 3)
	}
}

func TestReadIncludeFile(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
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
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = "secure_vars"
	yamlObj, err := yaml.Open("/dev/null")
	if err != nil {
		t.Errorf("Returned error")
	}
	if yamlObj.Get(topLevelElement) != nil {
		t.Errorf("got YAML from /dev/nul???")
	}
}

func TestEncryptSecret(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = "secure_vars"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
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
			if err != nil {
				t.Errorf("YAML encryption threw an error.")
			}
			if !strings.Contains(cipherText, pgpHeader) {
				t.Errorf("YAML content was not encrypted.")
			}
		}
	}
}

func TestGetPath(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = "secure_vars"

	file := "./testdata/test/bar.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(file, p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
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
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, file)
	}

}

func TestDecryptSecret(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = "secure_vars"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)

	yamlObj, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yamlObj.Get(topLevelElement).(map[interface{}]interface{})), 1)
	}
	for _, v := range yamlObj.Get(topLevelElement).(map[interface{}]interface{}) {
		cipherText, err := p.EncryptSecret(v.(string))
		if err != nil {
			t.Errorf("got error: %s", err)
		}
		plainText, err := p.DecryptSecret(cipherText)
		if err != nil {
			t.Errorf("got error: %s", err)
		}
		if strings.Contains(plainText, pgpHeader) {
			t.Errorf("YAML content was not decrypted.")
		}
		if plainText == "" {
			t.Errorf("decrypted content is empty")
		}
	}
}

func TestGetValueFromPath(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)
	val := s.GetValueFromPath("bar:baz")
	if to.String(val) != "qux" {
		t.Errorf("Content from path '%s' is wrong: %#v", filePath, val)
	}
}

func TestNestedAndMultiLineFile(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}

	filePath := "./testdata/test.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 2, pgpHeader)
	if err != nil {
		t.Errorf("%s", err)
	}

	filePath = "./testdata/test.sls"
	p = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s = sls.New(filePath, p, topLevelElement)

	buffer, err = s.PerformAction("decrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	err = scanString(buffer.String(), 0, pgpHeader)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestSetValueFromPath(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	err := s.SetValueFromPath("bar:baz", "foo")
	if err != nil {
		t.Errorf("Error setting value from path: %s", err)
	}
	val := s.GetValueFromPath("bar:baz")
	if to.String(val) != "foo" {
		t.Errorf("Content from path '%s' is wrong: %#v", filePath, val)
	}
}

func TestRotateFile(t *testing.T) {
	pgpKeyName = "Dev Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = ""

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	buffer, err = s.PerformAction("rotate")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	val := s.GetValueFromPath("bar:baz")
	if !strings.Contains(val.(string), pgpHeader) {
		t.Errorf("YAML content was not encrypted.")
	}
	buffer, err = s.PerformAction("decrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}
}

func TestKeyInfo(t *testing.T) {
	pgpKeyName = "Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = ""

	filePath := "./testdata/new.sls"
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	s := sls.New(filePath, p, topLevelElement)

	buffer, err := s.PerformAction("encrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	buffer, err = s.PerformAction("validate")
	if err != nil {
		t.Errorf("%s", err)
	}
	if err = scanString(buffer.String(), 0, pgpHeader); err != nil {
		t.Errorf("Found PGP data in buffer: %s", err)
	}
	if err = scanString(buffer.String(), 5, pgpKeyName); err != nil {
		t.Errorf("Key name count in buffer: %s", err)
	}

	buffer, err = s.PerformAction("decrypt")
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}
}

func TestEncryptProcessDir(t *testing.T) {
	pgpKeyName = "Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = ""

	dirPath := "./testdata"
	slsFiles, slsCount := utils.FindFilesByExt(dirPath, ".sls")

	if len(slsFiles) != 6 {
		t.Errorf("sls file list lenth is incorrect, got: %d, want: %d.",
			len(slsFiles), 6)
	}
	if slsCount != 6 {
		t.Errorf("sls file count is incorrect, got: %d, want: %d.",
			slsCount, 6)
	}

	pk = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	err := utils.ProcessDir(dirPath, ".sls", sls.Encrypt, "", topLevelElement, pk)
	if err != nil {
		t.Fatalf("utils.ProcessDir error: %s", err)
	}

	for n := 0; n < slsCount; n++ {
		s := sls.New(slsFiles[n], pk, topLevelElement)
		if s.IsInclude {
			continue
		}
		var buf []byte
		buf, err = ioutil.ReadFile(slsFiles[n])
		if err != nil {
			t.Fatalf("read file error: %s", err)
		}
		reader := strings.NewReader(string(buf))
		scanner := bufio.NewScanner(reader)

		found := hasPgpHeader(*scanner)
		err = scanner.Err()
		if err != nil {
			t.Errorf("scanner error: %s", err)
		}

		if !found {
			t.Errorf("%s does not contain PGP header", slsFiles[n])
		}
	}
}

func TestDecryptProcessDir(t *testing.T) {
	pgpKeyName = "Salt Master"

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	topLevelElement = ""

	dirPath := "./testdata"
	slsFiles, slsCount := utils.FindFilesByExt(dirPath, ".sls")

	if len(slsFiles) != 6 {
		t.Errorf("sls file list lenth is incorrect, got: %d, want: %d.",
			len(slsFiles), 6)
	}
	if slsCount != 6 {
		t.Errorf("sls file count is incorrect, got: %d, want: %d.",
			slsCount, 6)
	}

	pk = pki.New(pgpKeyName, publicKeyRing, secretKeyRing)
	err := utils.ProcessDir(dirPath, ".sls", sls.Decrypt, "", topLevelElement, pk)
	if err != nil {
		t.Fatalf("utils.ProcessDir error: %s", err)
	}

	for n := 0; n < slsCount; n++ {
		s := sls.New(slsFiles[n], pk, topLevelElement)
		if s.IsInclude {
			continue
		}
		var buf []byte
		buf, err = ioutil.ReadFile(slsFiles[n])
		if err != nil {
			t.Fatalf("read file error: %s", err)
		}
		reader := strings.NewReader(string(buf))
		scanner := bufio.NewScanner(reader)

		found := hasPgpHeader(*scanner)
		err = scanner.Err()
		if err != nil {
			t.Errorf("scanner error: %s", err)
		}

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
