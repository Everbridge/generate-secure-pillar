package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewSlsData(t *testing.T) {
	publicKeyRing = defaultPubRing
	var pillar = newSlsData()

	if !keyExists(pillar, "secure_vars") {
		t.Errorf("pillar content is incorrect, missing key")
	}
}

func TestWriteSlsFile(t *testing.T) {
	var pillar = make(SlsData)
	publicKeyRing = defaultPubRing

	slsFile := "./testdata/foo.sls"
	pillar["secret"] = "text"
	buffer := formatBuffer(pillar)
	writeSlsFile(buffer, slsFile)
	if _, err := os.Stat(slsFile); os.IsNotExist(err) {
		t.Errorf("%s file was not written", slsFile)
	}
	yaml, err := readSlsFile(slsFile)
	if err != nil {
		t.Errorf("Returned error")
	}
	if !keyExists(yaml, "secret") {
		t.Errorf("YAML content is incorrect, missing key")
	} else if yaml["secret"] != "text" {
		t.Errorf("YAML content is incorrect, got: %s, want: %s.",
			yaml["secret"], "text")
	}
	os.Remove(slsFile)
}

func TestFindSlsFiles(t *testing.T) {
	slsFiles, count := findSlsFiles("./testdata")
	if count != 1 {
		t.Errorf("File count was incorrect, got: %d, want: %d.",
			len(slsFiles), 1)
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
	yaml, err := readSlsFile("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml["secure_vars"].(SlsData)) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.",
			len(yaml["secure_vars"].(SlsData)), 3)
	}
}

func TestReadBadFile(t *testing.T) {
	yaml, err := readSlsFile("/dev/null")
	if err != nil {
		t.Errorf("Returned error")
	}
	if keyExists(yaml, "secure_vars") {
		t.Errorf("got YAML from /dev/nul???")
	}
}

func TestEncryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = filepath.Join(usr.HomeDir, ".gnupg/pubring.gpg")
	}
	yaml, err := readSlsFile("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml["secure_vars"].(SlsData)) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yaml["secure_vars"].(SlsData)), 1)
	}
	for _, v := range yaml["secure_vars"].(SlsData) {
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

func TestDecryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		secureKeyRing, _ = filepath.Abs(os.Getenv("SALT_SEC_KEYRING"))
	} else {
		secureKeyRing = filepath.Join(usr.HomeDir, ".gnupg/secring.gpg")
	}
	yaml, err := readSlsFile("./testdata/new.sls")
	if err != nil {
		t.Errorf("Returned error")
	}
	if len(yaml["secure_vars"].(SlsData)) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.",
			len(yaml["secure_vars"].(SlsData)), 1)
	}
	for _, v := range yaml["secure_vars"].(SlsData) {
		cipherText := encryptSecret(v.(string))
		plainText := decryptSecret(cipherText)
		if strings.Contains(plainText, pgpHeader) {
			t.Errorf("YAML content was not decrypted.")
		}
	}
}
