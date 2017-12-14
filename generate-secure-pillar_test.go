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
		t.Errorf("File count was incorrect, got: %d, want: %d.", len(slsFiles), 1)
	}
}

func TestReadSlsFile(t *testing.T) {
	yaml := readSlsFile("./testdata/new.sls")
	if len(yaml.SecureVars) != 3 {
		t.Errorf("YAML content length is incorrect, got: %d, want: %d.", len(yaml.SecureVars), 3)
	}
}

func TestEncryptSecret(t *testing.T) {
	if os.Getenv("SALT_SEC_KEYRING") != "" {
		publicKeyRing, _ = filepath.Abs(os.Getenv("SALT_PUB_KEYRING"))
	} else {
		publicKeyRing = filepath.Join(usr.HomeDir, ".gnupg/pubring.gpg")
	}
	yaml := readSlsFile("./testdata/new.sls")
	if len(yaml.SecureVars) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.", len(yaml.SecureVars), 1)
	}
	for _, v := range yaml.SecureVars {
		if strings.Contains(v, pgpHeader) {
			t.Errorf("YAML content is already encrypted.")
		} else {
			cipherText := encryptSecret(v)
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
	if len(yaml.SecureVars) <= 0 {
		t.Errorf("YAML content lenth is incorrect, got: %d, want: %d.", len(yaml.SecureVars), 1)
	}
	for _, v := range yaml.SecureVars {
		cipherText := encryptSecret(v)
		plainText := decryptSecret(cipherText)
		if strings.Contains(plainText, pgpHeader) {
			t.Errorf("YAML content was not decrypted.")
		}
	}
}
