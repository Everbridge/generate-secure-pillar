package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"eb-github.com/ed-silva/generate-secure-pillar/pki"
	"eb-github.com/ed-silva/generate-secure-pillar/sls"
	yaml "github.com/esilva-everbridge/yaml"
	"github.com/gosexy/to"
)

// pgpHeader header const
const pgpHeader = "-----BEGIN PGP MESSAGE-----"

func TestWriteSlsFile(t *testing.T) {
	publicKeyRing = defaultPubRing
	s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, nil)

	slsFile := "./testdata/foo/foo.sls"
	s.SetValueFromPath("secret", "text")

	buffer := s.FormatBuffer()
	sls.WriteSlsFile(buffer, slsFile)

	if _, err := os.Stat(slsFile); os.IsNotExist(err) {
		t.Errorf("%s file was not written", slsFile)
	}
	yaml, err := yaml.Open(slsFile)
	if err != nil {
		t.Errorf("Returned error")
	}
	if yaml.Get("secret") == nil {
		t.Errorf("YAML content is incorrect, missing key")
	} else if yaml.Get("secret") != "text" {
		t.Errorf("YAML content is incorrect, got: %s, want: %s.",
			yaml.Get("secret"), "text")
	}
	os.Remove(slsFile)
	os.Remove("./testdata/foo/")
}

func TestFindSlsFiles(t *testing.T) {
	slsFiles, count := sls.FindSlsFiles("./testdata")
	if count != 6 {
		t.Errorf("File count was incorrect, got: %d, want: %d.",
			len(slsFiles), 6)
	}
}

func TestEmptyDir(t *testing.T) {
	slsFiles, count := sls.FindSlsFiles("./testdata/empty")
	if count != 0 {
		t.Errorf("File count was incorrect, got: %d, want: %d.",
			len(slsFiles), 0)
	}
}

func TestReadSlsFile(t *testing.T) {
	topLevelElement = "secure_vars"
	yaml, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml.Get(topLevelElement).(map[interface{}]interface{})) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.",
			len(yaml.Get(topLevelElement).(map[interface{}]interface{})), 3)
	}
}

func TestReadIncludeFile(t *testing.T) {
	s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, nil)
	err := s.ReadSlsFile("./testdata/inc.sls")
	if err == nil {
		t.Errorf("failed to throw error for include file")
	}
	err = s.ReadSlsFile("./testdata/new.sls")
	if err != nil {
		t.Errorf("threw error for non-include file")
	}
}

func TestReadBadFile(t *testing.T) {
	topLevelElement = "secure_vars"
	yaml, err := yaml.Open("/dev/null")
	if err != nil {
		t.Errorf("Returned error")
	}
	if yaml.Get(topLevelElement) != nil {
		t.Errorf("got YAML from /dev/nul???")
	}
}

func TestEncryptSecret(t *testing.T) {
	topLevelElement = "secure_vars"
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing, nil)

	yaml, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml.Get(topLevelElement).(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yaml.Get(topLevelElement).(map[interface{}]interface{})), 1)
	}
	secureVars := yaml.Get(topLevelElement)
	for _, v := range secureVars.(map[interface{}]interface{}) {
		if strings.Contains(v.(string), pgpHeader) {
			t.Errorf("YAML content is already encrypted.")
		} else {
			cipherText := p.EncryptSecret(v.(string))
			if !strings.Contains(cipherText, pgpHeader) {
				t.Errorf("YAML content was not encrypted.")
			}
		}
	}
}

func TestRecurseEncryptSecret(t *testing.T) {
	topLevelElement = "secure_vars"
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}
	s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, nil)

	recurseDir := "./testdata/test"
	s.ProcessDir(recurseDir, "encrypt")
	slsFiles, count := sls.FindSlsFiles(recurseDir)
	if count == 0 {
		t.Errorf("%s has no sls files", recurseDir)
	}
	for _, file := range slsFiles {
		err := s.ReadSlsFile(file)
		if err != nil {
			t.Errorf("Returned error")
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
	}
}

func TestDecryptSecret(t *testing.T) {
	var err error
	topLevelElement = "secure_vars"
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		if secretKeyRing, err = filepath.Abs(os.Getenv("SALT_SEC_KEYRING")); err != nil {
			t.Error(err)
		}
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing, nil)
	// privringFile, err := os.Open(p.SecretKeyRing)
	// if err != nil {
	// 	t.Errorf("unable to open secring: %s", err)
	// }
	// privring, err := openpgp.ReadKeyRing(privringFile)
	// var keys []*openpgp.Entity
	// keys = append(keys, p.GetKeyByID(privring, "ed@gnzo.org"))
	// pass, err := p.PromptFunction(keys, false)

	yaml, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml.Get(topLevelElement).(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yaml.Get(topLevelElement).(map[interface{}]interface{})), 1)
	}
	for _, v := range yaml.Get(topLevelElement).(map[interface{}]interface{}) {
		cipherText := p.EncryptSecret(v.(string))
		plainText, err := p.DecryptSecret(cipherText)
		if err != nil {
			t.Errorf("got error: %s", err)
		}
		if strings.Contains(plainText, pgpHeader) {
			t.Errorf("YAML content was not decrypted.")
		}
	}
}

func TestRecurseDecryptSecret(t *testing.T) {
	topLevelElement = "secure_vars"
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, nil)

	recurseDir := "./testdata/test"
	s.ProcessDir(recurseDir, "decrypt")
	slsFiles, count := sls.FindSlsFiles(recurseDir)
	if count == 0 {
		t.Errorf("%s has no sls files", recurseDir)
	}
	for _, file := range slsFiles {
		yaml, err := yaml.Open(file)
		if err != nil {
			t.Errorf("Returned error")
		}
		if len(yaml.Get(topLevelElement).(map[interface{}]interface{})) <= 0 {
			t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
				len(yaml.Get(topLevelElement).(map[interface{}]interface{})), 2)
		}
		secureVars := yaml.Get(topLevelElement)
		for _, v := range secureVars.(map[interface{}]interface{}) {
			if strings.Contains(v.(string), pgpHeader) {
				t.Errorf("YAML content is still encrypted.")
			}
		}
	}
}

func TestGetValueFromPath(t *testing.T) {
	s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, nil)
	filePath := "./testdata/new.sls"
	err := s.ReadSlsFile(filePath)
	if err != nil {
		t.Errorf("Error getting test file: %s", err)
	}
	val := s.GetValueFromPath("bar:baz")
	if to.String(val) != "qux" {
		t.Errorf("Content from path '%s' is wrong: %#v", filePath, val)
	}
}

func TestNestedAndMultiLineFile(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}
	s := sls.New(secretNames, secretValues, "", publicKeyRing, secretKeyRing, pgpKeyName, nil)
	filePath := "./testdata/test.sls"
	err := s.ReadSlsFile(filePath)
	if err != nil {
		t.Errorf("Error getting test file: %s", err)
	}
	buffer, err := s.CipherTextYamlBuffer(filePath)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	err = checkLineCount(buffer.String(), 12)
	if err != nil {
		t.Errorf("%s", err)
	}

	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secretKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secretKeyRing = "~/.gnupg/secring.gpg"
	}
	s = sls.New(secretNames, secretValues, "", publicKeyRing, secretKeyRing, pgpKeyName, nil)
	filePath = "./testdata/test.sls"
	err = s.ReadSlsFile(filePath)
	if err != nil {
		t.Errorf("Error getting test file: %s", err)
	}
	buffer, err = s.PlainTextYamlBuffer(filePath)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}

	err = checkLineCount(buffer.String(), 0)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestSetValueFromPath(t *testing.T) {
	s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, nil)
	filePath := "./testdata/new.sls"
	err := s.ReadSlsFile(filePath)
	if err != nil {
		t.Errorf("Error getting test file: %s", err)
	}
	err = s.SetValueFromPath("bar:baz", "foo")
	if err != nil {
		t.Errorf("Error setting value from path: %s", err)
	}
	val := s.GetValueFromPath("bar:baz")
	if to.String(val) != "foo" {
		t.Errorf("Content from path '%s' is wrong: %#v", filePath, val)
	}
}

func TestRotateFile(t *testing.T) {
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

	cores := runtime.GOMAXPROCS(0)
	limChan := make(chan bool, cores)

	for i := 0; i < cores; i++ {
		limChan <- true
	}

	<-limChan
	s := sls.New(secretNames, secretValues, "", publicKeyRing, secretKeyRing, pgpKeyName, nil)
	filePath := "./testdata/new.sls"
	s.RotateFile(filePath, limChan)
	close(limChan)

	val := s.GetValueFromPath("bar:baz")
	if !strings.Contains(val.(string), pgpHeader) {
		t.Errorf("YAML content was not encrypted.")
	}
	buffer, err := s.PlainTextYamlBuffer(filePath)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		sls.WriteSlsFile(buffer, filePath)
	}
}

func checkLineCount(buffer string, wantedCount int) error {
	var err error
	encCount := 0
	scanner := bufio.NewScanner(strings.NewReader(buffer))

	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, pgpHeader) {
			encCount++
		}
	}
	if err = scanner.Err(); err != nil {
		return fmt.Errorf("%s", err)
	}
	if encCount != wantedCount {
		return fmt.Errorf("encryption count is wrong, wanted %d, got %d", wantedCount, encCount)
	}

	return err
}
