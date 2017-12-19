package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindSlsFiles(t *testing.T) {
	slsFiles := findSlsFiles("./testdata")
	if len(slsFiles) != 1 {
		t.Errorf("File count was incorrect, got: %d, want: %d.",
			len(slsFiles), 1)
	}
}

func TestReadSlsFile(t *testing.T) {
	yaml := readSlsFile("./testdata/new.sls")
	if len(yaml["secure_vars"].(SlsData)) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.",
			len(yaml["secure_vars"].(SlsData)), 3)
	}
}

func TestEncryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = filepath.Join(usr.HomeDir, ".gnupg/pubring.gpg")
	}
	yaml := readSlsFile("./testdata/new.sls")
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
	yaml := readSlsFile("./testdata/new.sls")
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
