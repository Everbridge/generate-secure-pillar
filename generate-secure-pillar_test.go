package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "menteslibres.net/gosexy/yaml"
)

func TestWriteSlsFile(t *testing.T) {
	var pillar = yaml.New()
	publicKeyRing = defaultPubRing

	slsFile := "./testdata/foo.sls"
	pillar.Set("secret", "text")
	buffer := formatBuffer(pillar)
	writeSlsFile(buffer, slsFile)
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
}

func TestFindSlsFiles(t *testing.T) {
	slsFiles, count := findSlsFiles("./testdata")
	if count != 4 {
		t.Errorf("File count was incorrect, got: %d, want: %d.",
			len(slsFiles), 4)
	}
}

func TestEmptyDir(t *testing.T) {
	slsFiles, count := findSlsFiles("./testdata/empty")
	if count != 0 {
		t.Errorf("File count was incorrect, got: %d, want: %d.",
			len(slsFiles), 0)
	}
}

func TestReadSlsFile(t *testing.T) {
	yaml, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml.Get("secure_vars").(map[interface{}]interface{})) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.",
			len(yaml.Get("secure_vars").(map[interface{}]interface{})), 3)
	}
}

func TestReadBadFile(t *testing.T) {
	yaml, err := yaml.Open("/dev/null")
	if err != nil {
		t.Errorf("Returned error")
	}
	if yaml.Get("secure_vars") != nil {
		t.Errorf("got YAML from /dev/nul???")
	}
}

func TestEncryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}
	yaml, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml.Get("secure_vars").(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yaml.Get("secure_vars").(map[interface{}]interface{})), 1)
	}
	secureVars := yaml.Get("secure_vars")
	for _, v := range secureVars.(map[interface{}]interface{}) {
		if strings.Contains(v.(string), pgpHeader) {
			t.Errorf("YAML content is already encrypted.")
		} else {
			cipherText := encryptSecret(v.(string))
			if !strings.Contains(cipherText, pgpHeader) {
				t.Errorf("YAML content was not encrypted.")
			}
		}
	}
}

func TestRecurseEncryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = "~/.gnupg/pubring.gpg"
	}
	recurseDir := "./testdata/test"
	processDir(recurseDir, "encrypt")
	slsFiles, count := findSlsFiles(recurseDir)
	if count == 0 {
		t.Errorf("%s has no sls files", recurseDir)
	}
	for _, file := range slsFiles {
		yaml, err := yaml.Open(file)
		if err != nil {
			t.Errorf("Returned error")
		}
		if len(yaml.Get("secure_vars").(map[interface{}]interface{})) <= 0 {
			t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
				len(yaml.Get("secure_vars").(map[interface{}]interface{})), 2)
		}
		secureVars := yaml.Get("secure_vars")
		for _, v := range secureVars.(map[interface{}]interface{}) {
			if !strings.Contains(v.(string), pgpHeader) {
				t.Errorf("YAML content was not encrypted.")
			}
		}
	}
}

func TestDecryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secureKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secureKeyRing = "~/.gnupg/secring.gpg"
	}
	yaml, err := yaml.Open("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml.Get("secure_vars").(map[interface{}]interface{})) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yaml.Get("secure_vars").(map[interface{}]interface{})), 1)
	}
	for _, v := range yaml.Get("secure_vars").(map[interface{}]interface{}) {
		cipherText := encryptSecret(v.(string))
		plainText := decryptSecret(cipherText)
		if strings.Contains(plainText, pgpHeader) {
			t.Errorf("YAML content was not decrypted.")
		}
	}
}

func TestRecurseDecryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secureKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secureKeyRing = "~/.gnupg/secring.gpg"
	}
	recurseDir := "./testdata/test"
	processDir(recurseDir, "decrypt")
	slsFiles, count := findSlsFiles(recurseDir)
	if count == 0 {
		t.Errorf("%s has no sls files", recurseDir)
	}
	for _, file := range slsFiles {
		yaml, err := yaml.Open(file)
		if err != nil {
			t.Errorf("Returned error")
		}
		if len(yaml.Get("secure_vars").(map[interface{}]interface{})) <= 0 {
			t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
				len(yaml.Get("secure_vars").(map[interface{}]interface{})), 2)
		}
		secureVars := yaml.Get("secure_vars")
		for _, v := range secureVars.(map[interface{}]interface{}) {
			if strings.Contains(v.(string), pgpHeader) {
				t.Errorf("YAML content is still encrypted.")
			}
		}
	}
}
